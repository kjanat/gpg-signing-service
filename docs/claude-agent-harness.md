# The `@claude` implementation harness

The workflow owns publication. Claude edits or answers; separate jobs preserve,
verify, sign and publish its result. This follows the split used by
[Zed's upstream sync workflow](https://github.com/kjanat/zed-editor/blob/master/.github/workflows/fork_upstream_sync.yaml).

Run [37348176618](https://github.com/kjanat/gpg-signing-service/actions/runs/37348176618)
returned success after producing local signed work that was never pushed.
The upstream action logged missing-branch and compare 404s without failing.
A successful model invocation therefore cannot establish publication success.

## Lifecycle

1. **Prepare and edit.** The trusted harness authorizes the request and selects
   its starting branch. It uploads `claude-input` before starting the pinned
   `claude-code-action/base-action`. That immutable artifact records routing,
   starting commit and completion policy. Claude receives read-only GitHub
   access and its model credential, but no signing or publication credentials.
   It leaves edits in the checkout and writes its answer to the response file.
2. **Preserve.** Export and upload steps run even after model failure. Candidate
   and recovery artifacts preserve local commits and working-tree changes,
   including staged, unstaged and non-ignored untracked files. The model timeout
   is shorter than the job timeout to reserve time for this handoff.
3. **Verify.** A clean runner downloads the input and candidate, validates their
   Git relationship and runs repository checks with read-only permissions.
   The trusted verifier seals the exact tree that passed. Failed validation
   cannot produce a publishable result.
4. **Sign and publish.** A fresh trusted checkout imports verified Git objects
   without checking out or executing candidate code. Only this job receives
   signing OIDC and publication credentials. It creates the final service-signed
   commit with Kaj as author and committer, pushes it, and verifies the remote
   branch, commit comparison and expected PR head. Missing branches, API errors
   including compare 404, or a missing/mismatched PR fail the job.

Artifacts are retained for **30 days**. Download `claude-candidate` from the run
when editing, validation, signing or publication fails. Local work is retained
for inspection rather than disappearing with the runner. Export/upload failures
still fail the run; cancellation or runner loss before upload cannot guarantee
recovery.

A question or review with no changed files can complete without a branch or PR.
It must still produce a successful, validated answer. No-change handling cannot
turn a failed implementation or local-only commit into success.

## Completion modes

The default is `CLAUDE_PUBLICATION_MODE=pull-request`. Issue implementations
create or reuse the matching PR; requests on an existing PR update that PR's
head. Both paths verify the published commit.

A maintainer can set repository variables `CLAUDE_PUBLICATION_MODE=branch-only`
and a nonempty `CLAUDE_NO_PR_REASON` to explicitly permit a published branch
without a PR. The branch and comparison checks still apply. Unknown modes or
an unexplained exemption fail preparation. The model cannot change this policy
through its response or candidate artifact.

## Authorization and routing

Native issue/comment/review events require the repository owner, a human
sender and `@claude` in the relevant event field. The shell harness repeats
these checks. It derives `issue-<number>-<slug>` for an issue, continuing that
branch if it already exists. An existing PR uses its existing same-repository
head. Fork heads, closed PRs, default-branch heads and invalid refs are refused.
The model must not rename branches: the trusted input fixes the publication
route before editing begins.

The live workflow uses native `issue_comment`. The pending variant replaces
that trigger with App-authorized `workflow_dispatch`, accepting `issue_number`,
`comment_id` and `requested_by`. The harness fetches the comment, checks its
entity and author, and checks the requester's write/admin permission. Enable the
App dispatch path and replace the live workflow together; subscribing to both
comment delivery routes would launch duplicate runs. See [GitHub App](github-app.md).

Concurrency is per entity with `cancel-in-progress: false`. GitHub retains one
running and one pending run in a concurrency group; newer queued requests can
replace older pending ones. Submit one request per entity at a time.

## Trust boundaries and provenance

The request title and body are fenced as `UNTRUSTED INPUT`; they never become
shell code or workflow expressions. Fences grow when the request contains the
current delimiter. Routing metadata is validated separately.

The edit job can execute repository code, so its read-only GitHub permissions
and lack of signing credentials matter. Verification also runs candidate code
without publication credentials. The privileged publisher executes only the
trusted workflow revision, its trusted helpers and signing setup.

Publication uses a Claude App installation token obtained through the existing
OIDC exchange. There is no workflow `GITHUB_TOKEN` fallback: that token would
suppress ordinary PR-triggered CI. Failure to obtain publication credentials
fails the publisher while retaining the artifacts.

The existing signing preflight and Kaj author/committer identity remain in
force. `GPG_SIGN_DISABLE` remains the explicit existing signing escape hatch;
model output cannot enable it. Attribution checks cover published text and
commit messages. The temporary artifact commit is transport data, not the
final published commit.

An App token may lack permission to change `.github/workflows/`. Such a push
must fail and retain the candidate; it must not silently omit files or report
completion. `.github/workflows-pending/` remains available for changes requiring
maintainer activation.

## Tests

- `task test:agent-harness`: real-Git request authorization and routing, existing
  attribution/token guard regressions, and workflow lifecycle wiring.
- `task test:claude-publication`: candidate handoff and fail-closed publication,
  including local-only commits, compare failures, no-change answers and verified
  branch/PR completion.
- `task lint:ci`: eslint, Biome, shell and workflow checks without formatting
  mutations. Verification runs this with formatting, type and test checks before
  sealing the candidate.

The implementation does not redispatch failed tasks. Recovery comes from the
saved work and an honest failed run.
