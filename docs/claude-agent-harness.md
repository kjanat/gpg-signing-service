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
   The verifier checks for changes made during testing before sealing the tree.
   This is a quality check for ordinary mistakes, not a security attestation
   against hostile candidate code; see the limits below.
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

This repository is public: any logged-in GitHub user can
[download these artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)
during retention. They contain code, patches, recovery history and
the response, but no exported model transcript. Do not place secrets in those
files. Omitting transcripts does not make arbitrary file contents confidential.

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

Only eligible requests share the entity's concurrency group, using the same
event-specific owner, human-sender and mention checks as the job gate; the
pending variant also admits its dispatch path. Skipped bot and non-mention
events receive unique groups, so completion comments and unrelated traffic
cannot displace a queued request. This workflow uses the default queue with
`cancel-in-progress: false`: one running and one pending run per group. A newer
actual request can replace an older pending request on the same entity.

## Trust boundaries and provenance

The request title and body are fenced as `UNTRUSTED INPUT`; they never become
shell code or workflow expressions. Fences grow when the request contains the
current delimiter. Routing metadata is validated separately.

The edit job can execute repository code, so its read-only GitHub permissions
and lack of signing credentials matter. Verification also runs candidate code
without publication credentials. The privileged publisher executes only the
trusted workflow revision, its trusted helpers and signing setup.

Verification executes the candidate's task definitions, scripts and tests.
That code can replace its own checks, modify the copied verifier, or tamper
with artifacts in the same runner account. The publisher independently
revalidates Git structure, parentage, protected paths and publication refs; it
does not establish that candidate code is safe or that hostile checks really
ran. The SDK conclusion is a liveness signal, not tamper-proof evidence: the
model can write step outputs. These gates detect ordinary incomplete work;
they do not replace human review.

Verification installs tools from `github.workflow_sha` before materializing
the candidate. A candidate that changes tool versions is therefore checked
with the existing toolchain; its proposed toolchain still needs normal CI.

Publication uses a Claude App installation token obtained through the existing
OIDC exchange. There is no workflow `GITHUB_TOKEN` fallback: that token would
suppress ordinary PR-triggered CI. Failure to obtain publication credentials
fails the publisher while retaining the artifacts. Maintainer PAT overrides
are not accepted. The exchange follows the pinned action's
[`src/github/token.ts`](https://github.com/anthropics/claude-code-action/blob/ed670b4cf9de2a5a570d130d2f6197b9e543cd64/src/github/token.ts);
review that contract when updating the action pin.

The existing signing preflight and Kaj author/committer identity remain in
force. `GPG_SIGN_DISABLE` remains the explicit existing signing escape hatch;
model output cannot enable it. Attribution checks cover published text and
commit messages. The temporary artifact commit is transport data, not the
final published commit.

Before signing, the publisher rejects changes to the exact
`.github/workflows` path or any descendant, including additions, modifications,
deletions and renames. This policy is independent of token permissions. The
candidate remains available for maintainer activation through
`.github/workflows-pending/`; files are never silently omitted. This restriction
does not make other candidate code safe: existing workflows may execute changed
scripts with secrets after publication. Human review remains necessary.

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
