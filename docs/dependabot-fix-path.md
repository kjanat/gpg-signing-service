# The trusted Dependabot write path

A Dependabot pull request that breaks the build usually breaks it mechanically:
a renamed export, a changed type, a regenerated client, lockfile drift. Those
are worth fixing automatically, and fixing one means pushing to a branch.

Pushing to a branch means holding a token that can write to this repository, in
a job that has just run somebody else's dependency update. That is the entire
problem this document is about.

## Why the review workflow cannot do it

`.github/workflows/claude-code-review.yml` runs on `pull_request`. When
Dependabot is what triggered that event, GitHub treats the run as if it came
from a fork:

- the `GITHUB_TOKEN` is **read-only**, whatever the workflow's `permissions:`
  block says; and
- `secrets.*` resolves from the **Dependabot** secrets store, not the Actions
  store.

Both are platform behaviour, and neither can be changed from inside a workflow
file. So the review workflow cannot push to a Dependabot branch, and adding
`contents: write` to it would only make the file describe something that cannot
happen.

## Why not `pull_request_target`

`pull_request_target` is the escape GitHub's own Dependabot documentation
names, and it does work: the run is not a Dependabot event, so it gets the
Actions secrets and a writable token.

It was rejected here. `pull_request_target` fires on **every** pull request,
including a first-time contributor's, and it does so with the elevated token
already in the job. Every safety property then rests on an `if:` condition
holding, on nobody adding a step that checks out `github.event.pull_request
.head.sha` above the guard, and on the guard itself being right. The privileged
job and the untrusted pull request are one `if:` apart for the whole file.

## What this repository does instead

[`claude-dependabot-fix.yml`](../.github/workflows/claude-dependabot-fix.yml)
triggers on `workflow_run`, on completion of CI. That gives the same elevation
with a different shape:

- `workflow_run` is not a Dependabot event, so it gets the Actions secrets and
  a write token — _"The workflow started by the `workflow_run` event is able to
  access secrets and write tokens, even if the previous workflow was not."_
- Its `GITHUB_SHA` and `GITHUB_REF` are the **default branch**. A checkout with
  no `ref:` is `master` and cannot be made to be anything else.
- It does not run at all unless the workflow file is on the default branch. A
  contributor cannot introduce a privileged workflow in their own branch, and
  cannot change this one by editing it in a pull request.
- It fires after CI, so the privileged path opens only when something is
  actually broken.

The workflow is three jobs, and the split between them is the security
property:

| Job         | Sees the pull request | Can write | What it does                                                                                     |
| ----------- | --------------------- | --------- | ------------------------------------------------------------------------------------------------ |
| `authorize` | no                    | no        | Decides, from the GitHub API, whether this is an open Dependabot pull request in this repository |
| `propose`   | **yes — runs it**     | no        | Installs, tests, lets Claude fix. Produces a diff as an artifact                                 |
| `apply`     | no                    | **yes**   | Re-authorizes, applies that diff with git alone, signs, pushes                                   |

**The job that runs the code cannot push, and the job that pushes does not run
the code.** Everything else here is in support of that sentence.

## The authorization gate

[`.github/scripts/dependabot-fix-gate.sh`](../.github/scripts/dependabot-fix-gate.sh)
runs in `authorize` and again in `apply`. It refuses by default and only
authorizes a run where all of the following hold:

- the triggering run's event was `pull_request`;
- its actor was literally `dependabot[bot]` — not `dependabot-preview[bot]`,
  not `renovate[bot]`, not a user;
- its head repository is this repository, which excludes every fork;
- its head branch is under `dependabot/`;
- its head SHA is a full 40-character object id;
- and the **GitHub API** agrees: exactly one open pull request on that branch,
  authored by `dependabot[bot]`, with its head repository and base repository
  both this repository, and its head ref and head SHA equal to what the event
  claimed.

The event payload is checked first because it is cheap; the API is checked
because the event payload is attacker-influenced. A contributor can make CI
fail on a branch they named `dependabot/…`, which is why the API's answer about
who authored the pull request is the one that decides.

An API call that _fails_ is not a decline. It exits non-zero, so an outage can
never be mistaken for a refusal.

The gate runs a second time inside the privileged job because the two jobs are
minutes apart. In between, the pull request can be closed or the branch
force-pushed. The second call is the one whose answer the push depends on.

## The patch allowlist

[`.github/scripts/dependabot-fix-apply.sh`](../.github/scripts/dependabot-fix-apply.sh)
never runs anything from the branch. It fetches the authorized object id into
`RUNNER_TEMP`, applies the diff with `git apply`, commits, and pushes. No
install, no build, no test, no hook.

A diff is inert data right up until git writes it to disk. From that moment the
files it wrote are what the _next_ run executes, so the script accepts only:

```text
bun.lock  package.json  go.work  go.work.sum
client/go.mod  client/go.sum  client/openapi.json
src/**.ts  client/**.go
```

Absent from that list, deliberately: `.github/` in any form, `Taskfile.yml`,
`scripts/`, `.mise.toml`, `.lefthook.yml`, `action.yml`, `bunfig.toml`,
`.claude/`. Those decide what CI runs, and a patch that could edit them would
turn this path back into arbitrary code execution in a privileged job.

That includes Dependabot's own `github-actions` ecosystem, whose bumps land in
`.github/workflows/`. Those pull requests get reviewed and merged by a human;
this path will not push to them.

The script also accepts **modifications to existing files only**. A new file, a
deletion, a mode change, a symlink and a binary patch are each refused, because
each is a way for a diff to stop being an edit and start being a program.

Other limits: 2 MiB, 50 files, a commit message that is fixed text with nothing
Dependabot controls interpolated into it, and a plain non-force push — if the
branch moved, being rejected is the correct outcome.

## Commit signing

The commit is made in `apply`, and it is signed by this service like every other
commit CI makes. `gpg.program` is set to the shim inside `GITHUB_WORKSPACE`,
which is the default-branch checkout and is never switched to the pull request
— otherwise `gpg.program` would name a file the branch controls, and git would
execute it with the write token in the environment.

`propose` sets up no signing at all: it makes no commits, so it needs no
`id-token: write` and no access to the OIDC minting endpoint. A job that runs
third-party install scripts should not also be able to sign things.

The escape hatch and the fail-closed contract are unchanged from #107. A job
that means to sign and cannot fails, rather than quietly producing an unsigned
commit; `GPG_SIGN_DISABLE` remains the only way to sign nothing on purpose.

## Where it lives, and why the tests care

`.github/workflows/claude-dependabot-fix.yml`. It is active.

It briefly was not. The file was first committed to
`.github/workflows-pending/`, because a GitHub App token has no `workflows`
permission and the automation that wrote it could not create a file under
`.github/workflows/` — the push is rejected outright, and the rejection kills
the whole push rather than just that one file. A human completed the move with
a `git mv`.

`task test:dependabot-fix` now **requires** the live path and fails if the file
is missing, or if a copy is left behind in `.github/workflows-pending/`. That is
deliberate rather than tidiness: a security suite whose subject is a file
nothing runs goes green exactly as fast as one guarding a live workflow, and the
difference between the two is the entire point. Every structural and mutation
assertion in that suite is read off the file GitHub actually executes.

## What the review workflow says about Dependabot

[`claude-code-review.yml`](../.github/workflows/claude-code-review.yml) once
told Claude, on a Dependabot pull request, to fix the bump and push to the
branch. That instruction was never executable — see
[the section above](#why-the-review-workflow-cannot-do-it) — and it is gone. The
prompt now scopes that run to **diagnosis**: reproduce the failure, name the
mechanical repair, and leave the commit to this path.

`test-claude-review-gate.sh` asserts that, because a prompt is prose and nothing
else in the repository would notice it drifting back. It rejects any instruction
of the shape "push … to the PR/branch" in the Dependabot paragraphs, requires
the paragraph to name `claude-dependabot-fix.yml`, and requires it to state that
the run has no write authority. Both guards are mutation-tested against a copy
with the pre-#71 wording restored.

## Secret provisioning

**Nothing needs to be added for the fix path to work.** `workflow_run` reads the
ordinary Actions secrets, so the existing `CLAUDE_CODE_OAUTH_TOKEN` repository
secret is what `propose` uses.

There is one thing an operator may still want to add, and it is optional:

> To have Dependabot pull requests **reviewed** by
> `.github/workflows/claude-code-review.yml`, `CLAUDE_CODE_OAUTH_TOKEN` must
> also exist under **Settings → Secrets and variables → Dependabot**. The
> Actions copy is not visible to a Dependabot-triggered run.

No workflow file can create that secret; it is a one-time manual step. Without
it, the review job skips with a notice explaining exactly this, and the fix path
is unaffected.

## Verifying a change to any of this

```bash
task test:dependabot-fix   # alias: task dbf
```

The suite has three parts. It drives both scripts against fixtures, including
every shape the gate must decline and every patch the apply script must refuse.
It reads the privilege boundary off the workflow YAML — which jobs may hold a
write permission, which may check out the pull request, and that those two sets
do not intersect. And it then breaks each of those guards in turn and requires
the checker to catch it, because a structural assertion that has never been
watched failing is one nobody knows works.

## What is still trusted

`propose` runs Dependabot's branch: `bun install` executes whatever install
scripts the bumped dependency ships, in a job that holds
`CLAUDE_CODE_OAUTH_TOKEN`. That is the same exposure CI already has on every
Dependabot pull request, and the job has `contents: read` and nothing else — it
cannot write to the repository, mint an OIDC token, or reach the signing
service. The write token is in a different job entirely and never enters this
one.

Dependabot itself is trusted to propose only registry version bumps. If the
Dependabot account or the upstream registry is compromised, this path narrows
the blast radius to the allowlist above but does not eliminate it.
