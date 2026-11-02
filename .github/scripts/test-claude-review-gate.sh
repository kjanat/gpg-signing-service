#!/usr/bin/env bash
# Covers .github/scripts/claude-review-gate.sh and the workflow that reads it.
#
# The gate decides whether the review job runs Claude, and therefore whether it
# configures commit signing. Getting that wrong is not a lint-level mistake in
# either direction: too loose and a fork pull request fails on signing setup it
# was never going to use, too tight and a trusted run makes unsigned commits.
# Neither shows up locally, so it is pinned here.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
gate="${repo_root}/.github/scripts/claude-review-gate.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

# run_gate [VAR=value ...] — a job-shaped environment, then the case's overrides.
run_gate() {
	local rc=0
	: >"${tmp_dir}/github_env"
	: >"${tmp_dir}/summary"
	env \
		-u CLAUDE_CODE_OAUTH_TOKEN \
		-u PR_HEAD_REPO \
		-u GITHUB_ACTOR \
		-u GITHUB_REPOSITORY_OWNER \
		-u GITHUB_WORKSPACE \
		GITHUB_REPOSITORY='kjanat/gpg-signing-service' \
		GITHUB_REPOSITORY_OWNER='kjanat' \
		GITHUB_ACTOR='kjanat' \
		GITHUB_ENV="${tmp_dir}/github_env" \
		GITHUB_STEP_SUMMARY="${tmp_dir}/summary" \
		"$@" \
		bash "${gate}" >"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
	printf '%s' "${rc}"
}

fail() {
	echo "FAIL: $*" >&2
	echo '--- stdout' >&2
	cat "${tmp_dir}/out" >&2
	echo '--- github_env' >&2
	cat "${tmp_dir}/github_env" >&2
	exit 1
}

expect_rc() { [[ "$2" == "$1" ]] || fail "expected exit $1, got $2"; }
expect_env() { grep -qxF -- "$1" "${tmp_dir}/github_env" || fail "expected GITHUB_ENV line: $1"; }
expect_stdout() { grep -qF -- "$1" "${tmp_dir}/out" || fail "expected stdout to contain: $1"; }
refute_stdout() {
	if grep -qF -- "$1" "${tmp_dir}/out"; then fail "expected stdout NOT to contain: $1"; fi
}

# --- the trusted run ---------------------------------------------------------
#
# A token means Claude runs, which means the job will push commits, which means
# it must sign them. HAS_CLAUDE_TOKEN=true is what turns both steps on, and
# nothing about this path may become conditional on the service being reachable
# — that decision belongs to the preflight, which fails closed.
rc="$(run_gate CLAUDE_CODE_OAUTH_TOKEN='oauth-token-that-must-never-be-printed')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN=true'
refute_stdout 'oauth-token-that-must-never-be-printed'
[[ ! -s "${tmp_dir}/summary" ]] || fail 'a run that proceeds should not write a skip summary'

# Same-repo pull requests are the ordinary case and must not be treated as forks.
rc="$(run_gate CLAUDE_CODE_OAUTH_TOKEN='t' PR_HEAD_REPO='kjanat/gpg-signing-service')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN=true'

# --- the fork pull request ---------------------------------------------------
#
# The acceptance criterion this whole change exists for: no token, no OIDC, and
# the workflow completes. Exit 0 here is load-bearing — a non-zero status would
# be the red check the gate was written to remove.
rc="$(run_gate PR_HEAD_REPO='someone-else/gpg-signing-service')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN='
expect_stdout '::notice title=Claude review skipped (fork pull request)::'
grep -qF 'fork pull request' "${tmp_dir}/summary" || fail 'the fork skip should reach the job summary'

# The value must be empty, not the string "false" — the workflow tests it with
# `env.HAS_CLAUDE_TOKEN == 'true'`, and "false" would pass a `-n` reading of it
# if anyone ever writes one.
if grep -qxF 'HAS_CLAUDE_TOKEN=false' "${tmp_dir}/github_env"; then
	fail 'HAS_CLAUDE_TOKEN should be empty, not the string false'
fi

# --- the Renovate pull request -------------------------------------------------
#
# Renovate pull requests auto-merge on their required checks and are not
# reviewed. They are same-repo and Renovate runs read the ordinary Actions
# secrets, so the token IS present: the gate has to decide the run is a no-op
# even with it.
rc="$(run_gate CLAUDE_CODE_OAUTH_TOKEN='t' PR_HEAD_REPO='kjanat/gpg-signing-service' GITHUB_ACTOR='renovate[bot]')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN='
if grep -qxF 'HAS_CLAUDE_TOKEN=true' "${tmp_dir}/github_env"; then
	fail 'a Renovate run with a token would still invoke the Claude action'
fi
expect_stdout '::notice title=Claude review skipped (Renovate pull request)::'
refute_stdout '::warning'
grep -qF 'Renovate pull request' "${tmp_dir}/summary" || fail 'the Renovate skip should reach the job summary'

# Without a token it is the same deliberate skip, not the "misconfigured" warning.
rc="$(run_gate PR_HEAD_REPO='kjanat/gpg-signing-service' GITHUB_ACTOR='renovate[bot]')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN='
expect_stdout '::notice title=Claude review skipped (Renovate pull request)::'

# The spelling a display name is allowed to have.
rc="$(run_gate CLAUDE_CODE_OAUTH_TOKEN='t' GITHUB_ACTOR='Renovate[Bot]')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN='

# --- runs the owner did not start ---------------------------------------------
#
# Beepboop issues the review token only to runs the repository owner starts.
# Anyone else's run, a Beepboop fix push included, is a deliberate no-op rather
# than a review that fails to get its token.
for actor in kjanat KJANAT; do
	rc="$(run_gate CLAUDE_CODE_OAUTH_TOKEN='t' PR_HEAD_REPO='kjanat/gpg-signing-service' GITHUB_ACTOR="${actor}")"
	expect_rc 0 "${rc}"
	expect_env 'HAS_CLAUDE_TOKEN=true'
done
for actor in 'beepboop[bot]' 'github-actions[bot]' renovate renovate-bot 'kjanat-fan' 'not-kjanat'; do
	rc="$(run_gate CLAUDE_CODE_OAUTH_TOKEN='t' PR_HEAD_REPO='kjanat/gpg-signing-service' GITHUB_ACTOR="${actor}")"
	expect_rc 0 "${rc}"
	expect_env 'HAS_CLAUDE_TOKEN='
	expect_stdout '::notice title=Claude review skipped (run not started by the owner)::'
	refute_stdout '::warning'
	grep -qF 'not started by the owner' "${tmp_dir}/summary" || fail 'the owner skip should reach the job summary'
done

# An owner the gate cannot read is not the actor, whoever the actor is.
rc="$(run_gate CLAUDE_CODE_OAUTH_TOKEN='t' GITHUB_REPOSITORY_OWNER='')"
expect_env 'HAS_CLAUDE_TOKEN='
expect_stdout '::notice title=Claude review skipped (run not started by the owner)::'

# --- the missing secret on a trusted run -------------------------------------
#
# Same outcome, different level. This one is a repository misconfiguration
# rather than the platform behaving correctly, so it warns instead of noting —
# otherwise a silently disabled review looks exactly like a fork.
rc="$(run_gate PR_HEAD_REPO='kjanat/gpg-signing-service')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN='
expect_stdout '::warning title=Claude review skipped (no CLAUDE_CODE_OAUTH_TOKEN)::'

# A workflow_dispatch or any event without a pull request carries no head repo,
# and "cannot tell" has to read as the conservative half: warn, do not claim the
# absence was expected.
rc="$(run_gate)"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN='
expect_stdout '::warning title=Claude review skipped (no CLAUDE_CODE_OAUTH_TOKEN)::'

# --- outside a job -----------------------------------------------------------
#
# Without GITHUB_ENV the gate cannot communicate its decision at all, and a
# silent success would leave both downstream steps reading an unset variable.
rc=0
env -u CLAUDE_CODE_OAUTH_TOKEN -u GITHUB_ENV bash "${gate}" \
	>"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
expect_rc 1 "${rc}"
expect_stdout '::error title=Claude review gate::'

# --- every job that publishes commits still sets up signing ------------------
#
# Scheduled runs still sign unconditionally. Implementation runs move signing
# into the trusted publisher; a verified no-change answer creates no commit.
# Neither editing nor checking candidate code may receive signing credentials.
python3 - "${repo_root}" <<'TRUSTED'
import sys, pathlib, yaml

root = pathlib.Path(sys.argv[1])

for name in ("claude.yml", "claude-scheduled.yml"):
    wf = yaml.safe_load((root / ".github/workflows" / name).read_text())
    steps = [s for j in wf["jobs"].values() for s in j["steps"]]
    signing = [s for s in steps if s.get("uses", "").endswith("setup-claude-signing")]
    assert len(signing) == 1, f"{name}: expected one signing setup step, got {len(signing)}"
    if name == "claude-scheduled.yml":
        assert "if" not in signing[0], (
            f"{name}: scheduled commit signing must remain unconditional"
        )
    else:
        assert signing[0].get("if") == "needs.verify.outputs.status == 'changed'", (
            f"{name}: signing must run for every changed candidate"
        )
        for job_name in ("edit", "verify"):
            job = wf["jobs"][job_name]
            assert job.get("permissions", {}).get("id-token") != "write", (
                f"{name}: {job_name} must not mint signing credentials"
            )
            assert not any(
                step.get("uses", "").endswith("setup-claude-signing")
                for step in job["steps"]
            ), f"{name}: {job_name} must not configure signing"
        publisher = wf["jobs"]["publish"]["steps"]
        publish_index = next(
            i for i, step in enumerate(publisher)
            if step.get("id") == "publish_result"
        )
        assert signing[0] in publisher and publisher.index(signing[0]) < publish_index, (
            f"{name}: trusted signing setup must precede publication"
        )
    # And the escape hatch is still the only way to sign nothing on purpose.
    assert signing[0]["with"]["disable-signing"] == "${{ vars.GPG_SIGN_DISABLE }}", (
        f"{name}: the GPG_SIGN_DISABLE escape hatch is no longer wired up"
    )
TRUSTED

# --- the review workflow actually wires this up ------------------------------
#
# Everything above tests the gate script in isolation, which proves nothing
# about the workflow that has to call it. #46 was not a broken script; it was a
# correct script the workflow never ran, with signing setup still unconditional
# in front of it. So assert the wiring: checkout before the gate (the script
# lives in the tree being reviewed), the gate before both steps that read its
# decision, and one shared condition so the two can never drift apart.
cat >"${tmp_dir}/check_review_workflow.py" <<'REVIEW'
"""Assert the review workflow's wiring. Argument: the workflow file."""
import sys
import pathlib
import yaml

wf = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
steps = wf["jobs"]["claude-review"]["steps"]


def index_of(predicate, what):
    for i, step in enumerate(steps):
        if predicate(step):
            return i
    raise AssertionError(f"claude-code-review.yml has no {what}")


gate = index_of(lambda s: "claude-review-gate.sh" in s.get("run", ""), "gate step")
signing = index_of(
    lambda s: s.get("uses", "").endswith("setup-claude-signing"), "signing setup step"
)
review = index_of(
    lambda s: s.get("uses", "").startswith("anthropics/claude-code-action/base-action@"),
    "claude-code-action base-action step",
)
checkout = index_of(
    lambda s: s.get("uses", "").startswith("actions/checkout"), "checkout step"
)

assert checkout < gate, "the gate step runs before actions/checkout"
assert gate < signing < review, (
    "the gate must run before the signing setup, which must run before the review"
)

condition = "env.HAS_CLAUDE_TOKEN == 'true'"
assert steps[signing].get("if") == condition, (
    "the signing setup is no longer gated on HAS_CLAUDE_TOKEN — a fork pull "
    "request will fail on setup it was never going to use"
)
assert steps[review].get("if") == condition, (
    "the review step and the signing setup no longer share a condition"
)

gate_env = steps[gate].get("env", {})
assert "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}" in gate_env.get(
    "CLAUDE_CODE_OAUTH_TOKEN", ""
), "the gate step no longer receives CLAUDE_CODE_OAUTH_TOKEN"
assert "head.repo.full_name" in gate_env.get("PR_HEAD_REPO", ""), (
    "the gate step no longer receives the head repository, so it cannot "
    "distinguish a fork from a missing secret"
)

assert steps[signing]["with"]["disable-signing"] == "${{ vars.GPG_SIGN_DISABLE }}", (
    "the GPG_SIGN_DISABLE escape hatch is no longer wired up"
)

print("review workflow ok")
REVIEW

# Deliberately not the `fail` helper: that one dumps ${tmp_dir}/out and
# ${tmp_dir}/github_env, which at this point still hold leftovers from the last
# run_gate call above.
review_workflow="${repo_root}/.github/workflows/claude-code-review.yml"
if ! python3 "${tmp_dir}/check_review_workflow.py" "${review_workflow}" \
	>"${tmp_dir}/review_out" 2>"${tmp_dir}/review_err"; then
	echo "FAIL: ${review_workflow} fails its own wiring checks" >&2
	sed 's/^/      /' "${tmp_dir}/review_err" >&2
	exit 1
fi

# --- the workflow posts the review, and fails without one ---------------------
#
# The base action reports success whenever the session ends cleanly, so the post
# step is what turns "no review" into a red run. Its script is covered by
# test-claude-review-post.py; this asserts the workflow runs it on the review
# step's structured output.
python3 - "${repo_root}/.github/workflows/claude-code-review.yml" <<'POST' || exit 1
import sys, pathlib, yaml
steps = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())["jobs"]["claude-review"]["steps"]
review = next(i for i, s in enumerate(steps) if s.get("id") == "claude-review")
assert "--json-schema" in steps[review]["with"]["claude_args"], "the review step no longer asks for structured output"
post = next(i for i, s in enumerate(steps) if s.get("name") == "Post the review")
assert post > review, "the review is posted before Claude runs"
assert steps[post].get("if") == steps[review].get("if"), "the post step and the review step no longer share a condition"
assert steps[post]["run"].strip() == "python3 .github/scripts/claude-review-post.py", "the post step no longer runs claude-review-post.py"
assert steps[post]["env"]["OUTPUT"] == "${{ steps.claude-review.outputs.structured_output }}", (
    "the post step no longer reads the review step's structured output"
)
POST
printf '  post step: wired to the structured output\n'

# --- pushes and the review use the Beepboop App token -------------------------
python3 - "${repo_root}/.github/workflows/claude-code-review.yml" <<'APP' || exit 1
import sys, pathlib, yaml
steps = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())["jobs"]["claude-review"]["steps"]
index = {s.get("id") or s.get("name") or s.get("uses") or s.get("run"): i for i, s in enumerate(steps)}
mint, push = index["beepboop"], index["Push as Beepboop"]
token = "${{ steps.beepboop.outputs.token }}"
assert steps[mint]["uses"].startswith("kjanat/beepboop/actions/token@"), "the token no longer comes from Beepboop"
assert steps[push]["env"]["TOKEN"] == token and "extraheader" in steps[push]["run"], "pushes no longer use the Beepboop App token"
condition = steps[index["claude-review"]].get("if")
assert steps[mint].get("if") == condition and steps[push].get("if") == condition, (
    "the token steps and the review step no longer share a condition"
)
assert index["Check for Claude token"] < mint < push < index["claude-review"] < index["Post the review"], (
    "the Beepboop App token has to be in place after the gate and before Claude runs"
)
for name in ("claude-review", "Post the review"):
    assert steps[index[name]]["env"].get("GH_TOKEN") == token, f"{name} no longer acts as the Beepboop App"
checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout"))
assert checkout["with"].get("persist-credentials") is False, (
    "checkout persists GITHUB_TOKEN through an includeIf file, so pushes would send it beside the Beepboop token"
)
assert checkout["with"].get("ref") == "${{ github.event.pull_request.head.sha }}", (
    "the review no longer checks out the PR head it posts against"
)
post_env = steps[index["Post the review"]]["env"]
assert post_env.get("HEAD_SHA") == "${{ github.event.pull_request.head.sha }}", "the review is not posted against the commit Claude reviewed"
assert post_env.get("BASE_SHA") == "${{ github.event.pull_request.base.sha }}", "the review's diff is not the reviewed commit's"
APP
printf '  beepboop token: issued, used to push, post and run gh\n'

printf 'claude review gate tests passed\n'
