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
		GITHUB_REPOSITORY='kjanat/gpg-signing-service' \
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

# --- the Dependabot pull request ---------------------------------------------
#
# Same-repo, so the fork test above does not catch it, and the secret really is
# absent — but not because anything is misconfigured. GitHub resolves `secrets.*`
# for a Dependabot-triggered run from the Dependabot store rather than the
# Actions store, so a CLAUDE_CODE_OAUTH_TOKEN that exists as an Actions secret is
# simply not visible here.
#
# Before this branch existed the run landed in the "repository is misconfigured"
# warning below and told the operator to set a secret that was already set. The
# level is the assertion: a notice, because skipping is correct until someone
# decides they want Dependabot pull requests reviewed too.
rc="$(run_gate PR_HEAD_REPO='kjanat/gpg-signing-service' GITHUB_ACTOR='dependabot[bot]')"
expect_rc 0 "${rc}"
expect_env 'HAS_CLAUDE_TOKEN='
expect_stdout '::notice title=Claude review skipped (Dependabot secrets store)::'
refute_stdout '::warning'

# And it must say where the secret goes, because that is the only actionable
# thing about this case — no workflow file can provision it.
grep -qF 'Secrets and variables > Dependabot' "${tmp_dir}/out" \
	|| fail 'the Dependabot skip should name the store the secret has to go in'

# It must NOT claim the branch cannot be fixed. Pushing a mechanical fix never
# depended on this run: that is the trusted workflow_run path, which reads the
# ordinary Actions secrets and needs nothing added to the Dependabot store.
grep -qF 'claude-dependabot-fix.yml' "${tmp_dir}/out" \
	|| fail 'the Dependabot skip should point at the trusted fix path'

# A Dependabot pull request from a fork is still a fork first: that is the
# platform withholding secrets, and naming the Dependabot store there would be
# advice that does not help.
rc="$(run_gate PR_HEAD_REPO='someone-else/gpg-signing-service' GITHUB_ACTOR='dependabot[bot]')"
expect_rc 0 "${rc}"
expect_stdout '::notice title=Claude review skipped (fork pull request)::'

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

# --- the trusted Claude jobs still sign unconditionally ----------------------
#
# The gate loosens exactly one workflow. #107 made signing setup the default for
# every job that lets Claude commit, and the review job's `if:` is a statement
# about a run that will not commit at all — not a precedent for making signing
# optional. Assert the other two never grew a condition of their own.
python3 - "${repo_root}" <<'TRUSTED'
import sys, pathlib, yaml

root = pathlib.Path(sys.argv[1])

for name in ("claude.yml", "claude-scheduled.yml"):
    wf = yaml.safe_load((root / ".github/workflows" / name).read_text())
    steps = [s for j in wf["jobs"].values() for s in j["steps"]]
    signing = [s for s in steps if s.get("uses", "").endswith("setup-claude-signing")]
    assert len(signing) == 1, f"{name}: expected one signing setup step, got {len(signing)}"
    assert "if" not in signing[0], (
        f"{name}: commit signing became conditional. These jobs run Claude with"
        " write access on every invocation, so a run that cannot sign is a run"
        " that must fail — see #107."
    )
    # And the escape hatch is still the only way to sign nothing on purpose.
    assert signing[0]["with"]["disable-signing"] == "${{ vars.GPG_SIGN_DISABLE }}", (
        f"{name}: the GPG_SIGN_DISABLE escape hatch is no longer wired up"
    )
TRUSTED

printf 'claude review gate tests passed\n'
