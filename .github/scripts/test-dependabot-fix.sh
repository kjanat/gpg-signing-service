#!/usr/bin/env bash
# Covers the trusted Dependabot write path: .github/workflows/claude-dependabot-fix.yml,
# .github/scripts/dependabot-fix-gate.sh and .github/scripts/dependabot-fix-apply.sh.
#
# The thing being protected is narrow and the cost of losing it is not. That
# workflow is the only place in this repository where a token that can write to
# a branch meets content somebody else wrote. It is safe because of an
# arrangement — the job that runs the branch has no write token, the job that
# writes never runs the branch — and an arrangement is exactly the kind of
# property that survives review and then dies quietly in a later edit that looks
# reasonable on its own.
#
# So this file tests in three registers:
#
#   BEHAVIOUR   the two scripts, driven with fixtures, including every way the
#               gate is supposed to say no and every patch the apply script is
#               supposed to refuse.
#   STRUCTURE   assertions read off the workflow YAML: which jobs may hold a
#               write permission, which may check out the pull request, and that
#               those two sets do not intersect.
#   MUTATION    the structural checker run against deliberately weakened copies
#               of the workflow, asserting it fails. A guard nobody has watched
#               fail is a guard nobody knows works; these are the tests for the
#               tests.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
gate="${repo_root}/.github/scripts/dependabot-fix-gate.sh"
apply="${repo_root}/.github/scripts/dependabot-fix-apply.sh"

# shellcheck source-path=SCRIPTDIR source=dependabot-activation.sh
source "${repo_root}/.github/scripts/dependabot-activation.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

# The workflow must be at the live path, and that is an assertion rather than a
# lookup. It was not always there: a GitHub App token has no `workflows`
# permission, so the automation that wrote the file could not create it under
# .github/workflows/ — the push is rejected outright, and the rejection kills
# the whole push rather than just that file. It waits in
# .github/workflows-pending/ next to the patch that activates it, for a human
# holding a credential that can write the directory.
#
# Requiring the live path is what stops that from being quietly undone. A
# security suite whose subject is a file nothing runs goes green exactly as fast
# as one guarding a live workflow, and the difference between the two is the
# entire value of the thing. So `pending` exits non-zero, and always will.
#
# What it does NOT do is stop there. Before activation the suite runs in full
# against the tree the checked-in patch produces, so every structural and
# mutation assertion below keeps its meaning during the wait, and the patch
# itself is proven to still apply — a patch nothing exercises is how the old
# issue-comment handoff went stale unnoticed. The single deferred failure is
# raised at the end, naming the two commands that clear it.
#
# This is not the live-first-with-fallback lookup that was here before #114 and
# should not be mistaken for it: that one went GREEN on the pending file. This
# one is red until the file GitHub executes is the file being guarded.
activation="$(activation_state)"
deferred_failure=''

case "${activation}" in
	active)
		workflow="${ACTIVATION_WORKFLOW}"
		;;
	pending)
		if ! activation_apply "${tmp_dir}/activated"; then
			echo 'FAIL: the trusted Dependabot fix path is not active, and the' >&2
			echo '      checked-in activation patch cannot produce it (above).' >&2
			exit 1
		fi
		workflow="${tmp_dir}/activated/.github/workflows/claude-dependabot-fix.yml"
		deferred_failure='pending'
		printf '  activation: pending — asserting against the patched tree\n'
		;;
	*)
		# both and absent, from the shared helper, so test-claude-review-gate.sh
		# cannot describe the same state in different words.
		activation_unusable "${activation}"
		exit 1
		;;
esac

# The activation patch is a one-shot artifact. Left behind next to a workflow
# that is already live it is a second, stale description of the same change.
if [[ "${activation}" == active && -f "${ACTIVATION_PATCH}" ]]; then
	echo 'FAIL: the workflow is active but the activation patch is still checked in;' >&2
	echo '      git rm .github/workflows-pending/activate.patch' >&2
	exit 1
fi

bin_dir="${tmp_dir}/bin"
mkdir -p "${bin_dir}"

fail() {
	echo "FAIL: $*" >&2
	[[ -s "${tmp_dir}/out" ]] && {
		echo '--- stdout' >&2
		cat "${tmp_dir}/out" >&2
	}
	[[ -s "${tmp_dir}/err" ]] && {
		echo '--- stderr' >&2
		cat "${tmp_dir}/err" >&2
	}
	[[ -f "${tmp_dir}/github_output" ]] && {
		echo '--- outputs' >&2
		cat "${tmp_dir}/github_output" >&2
	}
	exit 1
}

expect_rc() { [[ "$2" == "$1" ]] || fail "$3: expected exit $1, got $2"; }
expect_out() { grep -qF -- "$1" "${tmp_dir}/out" || fail "$2: expected stdout to contain: $1"; }
expect_output_line() { grep -qxF -- "$1" "${tmp_dir}/github_output" || fail "$2: expected output line: $1"; }
refute_anywhere() {
	if grep -rqF -- "$1" "${tmp_dir}/out" "${tmp_dir}/err" "${tmp_dir}/github_output" "${tmp_dir}/summary" 2>/dev/null; then
		fail "$2: '$1' leaked into the job's output"
	fi
}

################################################################################
# BEHAVIOUR: the authorization gate
################################################################################
#
# `gh` is replaced on PATH rather than the script being given an injection seam.
# The seam would be a second code path that only tests take, and the argument
# construction — which is where a query gets built out of event data — is
# exactly what should not be bypassed.

cat >"${bin_dir}/gh" <<'FAKE'
#!/usr/bin/env bash
if [[ "${GH_FAKE_FAIL-}" == 1 ]]; then
	printf 'gh: HTTP 503 Service Unavailable\n' >&2
	exit 1
fi
printf '%s' "$*" >>"${GH_FAKE_CALLS-/dev/null}"
printf '\n' >>"${GH_FAKE_CALLS-/dev/null}"
cat "${GH_FAKE_BODY}"
FAKE
chmod +x "${bin_dir}/gh"

readonly REPO='kjanat/gpg-signing-service'
readonly BRANCH='dependabot/bun/hono-4.14.0'
readonly SHA='1111111111111111111111111111111111111111'
readonly TOKEN_CANARY='ghs-token-that-must-never-be-printed'

# pr_json [jq filter] — one open Dependabot pull request, optionally bent.
pr_json() {
	local filter="${1-.}"
	jq "${filter}" >"${tmp_dir}/pr.json" <<JSON
[{
  "number": 42,
  "state": "open",
  "user": { "login": "dependabot[bot]" },
  "head": { "ref": "${BRANCH}", "sha": "${SHA}", "repo": { "full_name": "${REPO}" } },
  "base": { "repo": { "full_name": "${REPO}" } }
}]
JSON
}

# run_gate [VAR=value ...] — an eligible run, then the case's overrides.
run_gate() {
	local rc=0
	: >"${tmp_dir}/github_output"
	: >"${tmp_dir}/summary"
	PATH="${bin_dir}:${PATH}" env \
		GITHUB_REPOSITORY="${REPO}" \
		RUN_EVENT='pull_request' \
		RUN_ACTOR='dependabot[bot]' \
		RUN_HEAD_REPO="${REPO}" \
		RUN_HEAD_BRANCH="${BRANCH}" \
		RUN_HEAD_SHA="${SHA}" \
		GH_TOKEN="${TOKEN_CANARY}" \
		GH_FAKE_BODY="${tmp_dir}/pr.json" \
		GITHUB_OUTPUT="${tmp_dir}/github_output" \
		GITHUB_STEP_SUMMARY="${tmp_dir}/summary" \
		"$@" \
		bash "${gate}" >"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
	printf '%s' "${rc}"
}

# --- the one shape that is allowed through -----------------------------------
pr_json
rc="$(run_gate)"
expect_rc 0 "${rc}" 'eligible run'
expect_output_line 'eligible=true' 'eligible run'
expect_output_line 'pr-number=42' 'eligible run'
expect_output_line "head-ref=${BRANCH}" 'eligible run'
expect_output_line "head-sha=${SHA}" 'eligible run'
refute_anywhere "${TOKEN_CANARY}" 'eligible run'

# --- everything else ---------------------------------------------------------
#
# Each of these is a way an ordinary contributor, or a stale event, could reach
# the privileged job. `eligible=false` is the only acceptable answer to all of
# them, and it must be exit 0 — a red check on every unrelated CI failure in the
# repository would train everyone to ignore this workflow.

# reject NAME [VAR=value ...] — assert this shape is declined, not authorized.
reject() {
	local name="$1"
	shift
	local rc
	rc="$(run_gate "$@")"
	expect_rc 0 "${rc}" "${name}"
	expect_output_line 'eligible=false' "${name}"
	if grep -qxF 'eligible=true' "${tmp_dir}/github_output"; then
		fail "${name}: the gate authorized a run it must decline"
	fi
	grep -qF 'eligible=' "${tmp_dir}/github_output" || fail "${name}: no decision was written"
}

# The impersonation cases: the event says one thing, and it is not Dependabot.
reject 'a human actor' RUN_ACTOR='some-contributor'
reject 'a lookalike bot' RUN_ACTOR='dependabot-preview[bot]'
reject 'renovate' RUN_ACTOR='renovate[bot]'
reject 'an empty actor' RUN_ACTOR=''

# A fork's head repository is not this one, and this path pushes to branches in
# this repository only.
reject 'a fork head repository' RUN_HEAD_REPO='attacker/gpg-signing-service'
reject 'an empty head repository' RUN_HEAD_REPO=''

# A `push` or `workflow_dispatch` run carries no pull request to write to.
reject 'a push-triggered run' RUN_EVENT='push'
reject 'a dispatch-triggered run' RUN_EVENT='workflow_dispatch'

# A contributor can name their branch anything. Naming it dependabot/... is not
# enough on its own — but a branch outside the prefix is not even a candidate.
reject 'an ordinary branch' RUN_HEAD_BRANCH='feature/add-a-thing'
reject 'a branch that only looks like one' RUN_HEAD_BRANCH='not-dependabot/bun/x'

# Everything downstream fetches this object id and refuses anything else, so it
# has to be one.
reject 'an abbreviated sha' RUN_HEAD_SHA='1111111'
reject 'a ref instead of a sha' RUN_HEAD_SHA='refs/heads/master'
reject 'a sha with upper case' RUN_HEAD_SHA='AAAA111111111111111111111111111111111111'

# ...and the same questions asked again of the API, which is the authority. The
# branch name check above passes in every one of these; only the API answer
# separates them from the eligible run.
pr_json '.[0].user.login = "some-contributor"'
reject 'a human-authored pull request on a dependabot/ branch'

pr_json '.[0].state = "closed"'
reject 'a closed pull request'

pr_json '.[0].head.repo.full_name = "attacker/gpg-signing-service"'
reject 'a pull request whose head is a fork'

pr_json '.[0].base.repo.full_name = "somewhere/else"'
reject 'a pull request targeting another repository'

pr_json '.[0].head.ref = "dependabot/bun/something-else"'
reject 'a head ref that disagrees with the run'

pr_json '.[0].head.sha = "2222222222222222222222222222222222222222"'
reject 'a branch that moved since the run'

pr_json '.[0].number = 0'
reject 'a pull request number that is not positive'

pr_json '[]'
reject 'no open pull request'

pr_json '. + .'
reject 'two matching pull requests'

# --- failure to ask is not permission ----------------------------------------
#
# The one case that must NOT be a quiet `eligible=false`. If the API stops
# answering, the gate has not decided anything, and a decline written on an
# outage would look identical to a decline written on an attacker — which is
# how a path like this fails open without anyone noticing.
pr_json
rc="$(run_gate GH_FAKE_FAIL=1)"
expect_rc 1 "${rc}" 'an API outage'
expect_out '::error title=Dependabot fix gate::' 'an API outage'
if grep -qF 'eligible=' "${tmp_dir}/github_output"; then
	fail 'an API outage: the gate wrote a decision it did not make'
fi

# Without GITHUB_OUTPUT there is nowhere to put the answer, and a silent success
# leaves the downstream `if:` reading an unset value — which is falsey, so it
# would fail closed, but by accident rather than on purpose.
rc=0
PATH="${bin_dir}:${PATH}" env -u GITHUB_OUTPUT GITHUB_REPOSITORY="${REPO}" \
	bash "${gate}" >"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
expect_rc 1 "${rc}" 'no GITHUB_OUTPUT'
expect_out '::error title=Dependabot fix gate::' 'no GITHUB_OUTPUT'

printf '  gate: behaviour ok\n'

################################################################################
# BEHAVIOUR: the privileged apply
################################################################################
#
# Driven against a real bare repository over file://, so the push either lands
# or does not — the assertions are about where the branch actually points
# afterwards, not about what the script said it would do.

git_quiet() { git -c init.defaultBranch=main -c user.name=t -c user.email=t@t "$@"; }

origin="${tmp_dir}/origin.git"
git_quiet init -q --bare "${origin}"
# GitHub serves a fetch of any reachable object id; the local transport needs
# telling. Without this the apply script's fetch-by-sha would fail here for a
# reason that has nothing to do with what is being tested.
git_quiet -C "${origin}" config uploadpack.allowAnySHA1InWant true

seed="${tmp_dir}/seed"
mkdir -p "${seed}/src/utils" "${seed}/client" "${seed}/.github/workflows"
printf 'lockfileVersion: 1\nhono: 4.13.2\n' >"${seed}/bun.lock"
printf '{ "dependencies": { "hono": "4.13.2" } }\n' >"${seed}/package.json"
printf 'export const thing = 1;\n' >"${seed}/src/utils/thing.ts"
printf 'package client\n' >"${seed}/client/api.go"
printf 'module client\n' >"${seed}/client/go.mod"
printf 'name: CI\non: push\n' >"${seed}/.github/workflows/ci.yml"
printf 'version: "3"\ntasks: { t: { cmd: echo } }\n' >"${seed}/Taskfile.yml"
git_quiet init -q "${seed}"
git_quiet -C "${seed}" add -A
git_quiet -C "${seed}" commit -qm 'chore(deps): bump hono'
git_quiet -C "${seed}" branch -M "${BRANCH}"
git_quiet -C "${seed}" push -q "${origin}" "${BRANCH}"
head_sha="$(git -C "${seed}" rev-parse HEAD)"

# The privileged job's workspace: the default-branch checkout. The apply script
# reaches the signing shim through this and only through this, which is what
# stops `gpg.program` from becoming a file the pull request controls.
workspace="${tmp_dir}/workspace"
mkdir -p "${workspace}/.github/scripts"
git_quiet init -q "${workspace}"
cat >"${workspace}/.github/scripts/gpg-sign-git-program.sh" <<'SHIM'
#!/usr/bin/env bash
# Stands in for the real signing shim. git only requires an armored blob on
# stdout and SIG_CREATED on the status stream.
printf -- '-----BEGIN PGP SIGNATURE-----\n\nZmFrZXNpZ25hdHVyZQ==\n-----END PGP SIGNATURE-----\n'
printf '[GNUPG:] SIG_CREATED D 1 8 00 0 0\n' >&2
SHIM
chmod +x "${workspace}/.github/scripts/gpg-sign-git-program.sh"

branch_tip() { git -C "${origin}" rev-parse "refs/heads/${BRANCH}"; }

# craft_patch COMMANDS — a diff produced by actually doing the thing to a
# checkout of the branch, rather than a unified diff written by hand. Hand-built
# context lines are how a test ends up asserting that git rejected a malformed
# patch when it meant to assert that this script rejected a forbidden one.
craft_patch() {
	rm -rf "${tmp_dir}/craft"
	git_quiet clone -q --branch "${BRANCH}" "${origin}" "${tmp_dir}/craft" 2>/dev/null
	(cd "${tmp_dir}/craft" && eval "$1")
	git_quiet -C "${tmp_dir}/craft" diff --no-color >"${tmp_dir}/patch"
}

# run_apply [VAR=value ...] — a valid invocation, then the case's overrides.
run_apply() {
	local rc=0
	: >"${tmp_dir}/summary"
	rm -rf "${tmp_dir}/runner_temp"
	mkdir -p "${tmp_dir}/runner_temp"
	env \
		GITHUB_REPOSITORY="${REPO}" \
		PR_NUMBER='42' \
		HEAD_REF="${BRANCH}" \
		HEAD_SHA="${head_sha}" \
		GH_TOKEN="${TOKEN_CANARY}" \
		GITHUB_WORKSPACE="${workspace}" \
		RUNNER_TEMP="${tmp_dir}/runner_temp" \
		SIGNING_ENABLED='false' \
		GIT_REMOTE_URL="file://${origin}" \
		GITHUB_STEP_SUMMARY="${tmp_dir}/summary" \
		GIT_CONFIG_GLOBAL=/dev/null \
		GIT_CONFIG_SYSTEM=/dev/null \
		"$@" \
		bash "${apply}" "${tmp_dir}/patch" >"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
	printf '%s' "${rc}"
}

# --- the fix that is supposed to work ----------------------------------------
before="$(branch_tip)"
craft_patch "printf 'lockfileVersion: 1\nhono: 4.14.0\n' > bun.lock
            printf 'export const thing = 2;\n' > src/utils/thing.ts"
rc="$(run_apply)"
expect_rc 0 "${rc}" 'a mechanical fix'
[[ "$(branch_tip)" != "${before}" ]] || fail 'a mechanical fix: the branch did not move'
git -C "${origin}" show --stat --format= "refs/heads/${BRANCH}" | grep -q 'bun.lock' \
	|| fail 'a mechanical fix: the pushed commit does not touch bun.lock'
# The commit message is fixed text. Nothing Dependabot controls — not the pull
# request title, not the branch's own commit messages — is interpolated into it.
git -C "${origin}" log -1 --format=%s "refs/heads/${BRANCH}" | grep -q '^fix(deps): repair ' \
	|| fail 'a mechanical fix: unexpected commit subject'
[[ "$(git -C "${origin}" log -1 --format=%P "refs/heads/${BRANCH}")" == "${head_sha}" ]] \
	|| fail 'a mechanical fix: the commit is not a child of the authorized head'
refute_anywhere "${TOKEN_CANARY}" 'a mechanical fix'
# ...and the token is not left behind on disk either. A credential helper that
# reads the environment is the whole reason for that indirection; a helper that
# had baked the value into the scratch repository's config would defeat it.
if grep -rqF "${TOKEN_CANARY}" "${tmp_dir}/runner_temp" 2>/dev/null; then
	fail 'a mechanical fix: the write token was written to disk'
fi

# Reset for the refusal cases, which all assert the branch does NOT move.
git_quiet -C "${origin}" update-ref "refs/heads/${BRANCH}" "${head_sha}"

# refuse_patch NAME COMMANDS — craft a patch, run, assert refusal and stillness.
refuse_patch() {
	local name="$1" commands="$2"
	shift 2
	local before rc
	before="$(branch_tip)"
	craft_patch "${commands}"
	rc="$(run_apply "$@")"
	expect_rc 1 "${rc}" "${name}"
	expect_out '::error title=Dependabot fix refused::' "${name}"
	[[ "$(branch_tip)" == "${before}" ]] || fail "${name}: the branch moved on a refused patch"
}

# --- the patches that must never be written ----------------------------------
#
# This is the list that makes the write token narrow. Every entry is a file that
# decides what a later CI run executes, which is to say a way to turn "push a
# lockfile fix" into "run anything, privileged". The github-actions ecosystem
# genuinely does produce bumps under .github/workflows/ — and those must stay a
# human's decision, which is why the first case is not a hypothetical.
refuse_patch 'a workflow edit' "printf 'name: CI\non: push\njobs: {}\n' > .github/workflows/ci.yml"
refuse_patch 'a Taskfile edit' "printf 'version: \"3\"\ntasks: { t: { cmd: curl evil } }\n' > Taskfile.yml"

# The three ways a patch stops being a modification and starts being a program.
refuse_patch 'a new file' "printf 'x\n' > src/utils/new.ts && git add -N src/utils/new.ts"
refuse_patch 'a deletion' 'rm src/utils/thing.ts'
refuse_patch 'a mode change' 'chmod +x src/utils/thing.ts'
refuse_patch 'a file replaced by a symlink' 'rm bun.lock && ln -s /etc/passwd bun.lock'

# --- the identity, re-checked here rather than trusted from the gate ---------
#
# These values arrive from a previous step. If that step ever stops validating
# them, this script must not be the reason it went unnoticed.
craft_patch "printf 'lockfileVersion: 1\nhono: 4.14.0\n' > bun.lock"
for bad in 'HEAD_REF=master' 'HEAD_REF=feature/x' 'HEAD_REF=dependabot/../../evil' \
	'HEAD_SHA=deadbeef' 'HEAD_SHA=refs/heads/master' 'PR_NUMBER=0' 'PR_NUMBER=42; rm -rf /'; do
	before="$(branch_tip)"
	rc="$(run_apply "${bad}")"
	expect_rc 1 "${rc}" "rejecting ${bad}"
	[[ "$(branch_tip)" == "${before}" ]] || fail "rejecting ${bad}: the branch moved"
done

# A commit id that is well-formed but is not on the branch. Real cause:
# Dependabot rebased between the gate and here.
before="$(branch_tip)"
rc="$(run_apply HEAD_SHA='3333333333333333333333333333333333333333')"
expect_rc 1 "${rc}" 'a head that is not there'
expect_out 'force-pushed' 'a head that is not there'
[[ "$(branch_tip)" == "${before}" ]] || fail 'a head that is not there: the branch moved'

# --- nothing to do is not a failure ------------------------------------------
: >"${tmp_dir}/patch"
rc="$(run_apply)"
expect_rc 3 "${rc}" 'an empty patch'

# --- signing -----------------------------------------------------------------
#
# The shim is addressed through GITHUB_WORKSPACE, which in the real job is the
# default-branch checkout and never the pull request. If it is not there, this
# job means to sign and cannot, and #107 says that fails rather than quietly
# producing an unsigned commit.
craft_patch "printf 'lockfileVersion: 1\nhono: 4.14.0\n' > bun.lock"
before="$(branch_tip)"
rc="$(run_apply SIGNING_ENABLED='true' GITHUB_WORKSPACE="${tmp_dir}/seed")"
expect_rc 1 "${rc}" 'signing on with no shim'
expect_out 'shim is missing' 'signing on with no shim'
[[ "$(branch_tip)" == "${before}" ]] || fail 'signing on with no shim: the branch moved'

# With the shim present the commit carries a signature.
rc="$(run_apply SIGNING_ENABLED='true')"
expect_rc 0 "${rc}" 'signing on'
git -C "${origin}" cat-file commit "refs/heads/${BRANCH}" | grep -q '^gpgsig' \
	|| fail 'signing on: the pushed commit is not signed'
git_quiet -C "${origin}" update-ref "refs/heads/${BRANCH}" "${head_sha}"

printf '  apply: behaviour ok\n'

################################################################################
# STRUCTURE: the workflow's privilege boundary, read off the file
################################################################################
#
# The scripts above can only refuse what they are shown. What decides whether
# they are ever shown a fix computed by a job that could also have pushed it is
# the shape of the workflow, and nothing in a script can assert that. So it is
# asserted here, against the YAML.
#
# The checker takes the workflow as an argument rather than hard-coding the
# path, because the mutation section below runs it against deliberately broken
# copies. A structural guard that has never been watched failing is a guard
# nobody knows works.

cat >"${tmp_dir}/check_workflow.py" <<'CHECK'
"""Assert the Dependabot fix workflow's privilege boundary. Exits 1 on the first
violation, naming it. Argument: the workflow file."""
import sys
import pathlib
import yaml

path = pathlib.Path(sys.argv[1])
wf = yaml.safe_load(path.read_text())
problems = []


def require(condition, message):
    if not condition:
        problems.append(message)


# PyYAML resolves the bare key `on` to the boolean True (YAML 1.1). GitHub means
# the string, and a checker that silently looked at the wrong key would pass
# forever.
triggers = wf.get("on", wf.get(True))
require(isinstance(triggers, dict), "`on:` is not a mapping")
trigger_names = set(triggers or {})

# 1. workflow_run and nothing else. This is the elevation, and it is only safe
#    because of what workflow_run is: not a Dependabot event, so it gets the
#    Actions secrets and a write token; GITHUB_SHA pinned to the default branch;
#    and it does not run at all unless this file is on the default branch. Add
#    `pull_request_target` alongside it and a contributor's pull request reaches
#    the same jobs.
require(
    trigger_names == {"workflow_run"},
    f"the trusted workflow must trigger on workflow_run alone, got {sorted(trigger_names)}",
)

# 2. Nothing granted by default. Every job then opens what it needs, which is
#    what makes the per-job permissions below meaningful rather than decorative.
require(wf.get("permissions") == {}, "the workflow must declare `permissions: {}` at the top level")

jobs = wf.get("jobs", {})
require(bool(jobs), "the workflow declares no jobs")


def perms_of(job):
    p = job.get("permissions")
    if p is None:
        return None
    if isinstance(p, str):
        return {"__all__": p.replace("-all", "")}
    return p


def is_privileged(job):
    p = perms_of(job)
    return bool(p) and any(v == "write" for v in p.values())


def checkouts(job):
    return [s for s in job.get("steps", []) if str(s.get("uses", "")).startswith("actions/checkout")]


def pr_checkouts(job):
    """A checkout with an explicit `ref:` is a checkout of something other than
    the default branch, which on workflow_run is what a bare checkout gets."""
    return [s for s in checkouts(job) if (s.get("with") or {}).get("ref")]


for name, job in jobs.items():
    require(perms_of(job) is not None, f"job `{name}` does not declare permissions")
    for step in checkouts(job):
        require(
            (step.get("with") or {}).get("persist-credentials") is False,
            f"job `{name}`: every checkout must set persist-credentials: false",
        )

# 3. The prefilter. Not the security boundary — the gate script is — but it is
#    what keeps every unrelated CI failure in the repository out of these jobs.
first = next(iter(jobs.values()))
gate_if = str(first.get("if", ""))
for needle in ("dependabot[bot]", "head_repository.full_name == github.repository", "'pull_request'"):
    require(needle in gate_if, f"the first job's `if:` no longer requires {needle!r}")

privileged = {n: j for n, j in jobs.items() if is_privileged(j)}
require(len(privileged) == 1, f"expected exactly one privileged job, found {sorted(privileged)}")

# 4. THE BOUNDARY. The one assertion the whole design reduces to.
for name, job in jobs.items():
    if pr_checkouts(job):
        require(
            not is_privileged(job),
            f"job `{name}` checks out the pull request AND holds a write permission "
            f"({perms_of(job)}). The job that runs the branch must not be able to push it.",
        )
        require(
            "id-token" not in (perms_of(job) or {}),
            f"job `{name}` checks out the pull request and can mint an OIDC token. "
            "A job running third-party install scripts must not be able to sign things.",
        )
        for step in pr_checkouts(job):
            with_ = step.get("with") or {}
            require(
                "head-sha" in str(with_.get("ref")),
                f"job `{name}`: the pull request must be checked out at the validated "
                f"object id, not at {with_.get('ref')!r} — a ref re-resolves.",
            )
            require(
                bool(with_.get("path")),
                f"job `{name}`: the pull request must go in a subdirectory, so the "
                "workspace root stays the trusted default-branch checkout.",
            )

pr_paths = {
    (s.get("with") or {}).get("path") for j in jobs.values() for s in pr_checkouts(j)
}
pr_paths.discard(None)

for name, job in privileged.items():
    steps = job.get("steps", [])

    # 5. Exactly these scopes: the push, the OIDC token the signing shim
    #    exchanges, and the one comment. A scope added here is a scope that has
    #    to be argued for in this file too.
    require(
        perms_of(job) == {"contents": "write", "id-token": "write", "pull-requests": "write"},
        f"privileged job `{name}` permissions changed: {perms_of(job)}",
    )

    # 6. Its workspace is the default branch and stays that way — that is what
    #    keeps `gpg.program` pointing at a script the pull request cannot edit.
    require(not pr_checkouts(job), f"privileged job `{name}` checks out a non-default ref")
    require(steps and str(steps[0].get("uses", "")).startswith("actions/checkout"),
            f"privileged job `{name}` must check out the default branch first")
    require(not (steps[0].get("with") or {}).get("path"),
            f"privileged job `{name}`'s first checkout must land in the workspace root")

    # 7. It never touches the unprivileged job's working copy.
    for step in steps:
        body = str(step.get("run", "")) + " " + str(step.get("working-directory", ""))
        for p in pr_paths:
            require(
                f"{p}/" not in body and step.get("working-directory") != p,
                f"privileged job `{name}` reads `{p}`, the pull request's checkout",
            )

    # 8. It runs only trusted, non-executing actions. Adding a toolchain setup
    #    here — setup-bun, mise — would be the quiet way to start running the
    #    branch's code in the job that holds the token.
    allowed_uses = {"actions/checkout", "actions/download-artifact", "./.github/actions/setup-claude-signing"}
    for step in steps:
        uses = str(step.get("uses", "")).split("@")[0]
        if uses:
            require(uses in allowed_uses, f"privileged job `{name}` uses `{uses}`, which is not on its allowlist")

    # 9. It re-authorizes before it writes, and everything after that is
    #    conditional on the answer.
    gate_index = next(
        (i for i, s in enumerate(steps) if "dependabot-fix-gate.sh" in str(s.get("run", ""))),
        None,
    )
    require(gate_index is not None, f"privileged job `{name}` does not re-run the authorization gate")
    apply_index = next(
        (i for i, s in enumerate(steps) if "dependabot-fix-apply.sh" in str(s.get("run", ""))),
        None,
    )
    require(apply_index is not None, f"privileged job `{name}` does not run the apply script")
    if gate_index is not None and apply_index is not None:
        require(gate_index < apply_index, f"privileged job `{name}` writes before it re-authorizes")
        gate_id = steps[gate_index].get("id")
        require(bool(gate_id), f"privileged job `{name}`'s gate step has no id to guard on")
        for i, step in enumerate(steps[gate_index + 1:], start=gate_index + 1):
            require(
                f"steps.{gate_id}.outputs.eligible == 'true'" in str(step.get("if", "")),
                f"privileged job `{name}` step {i} "
                f"({step.get('name', step.get('uses', '?'))!r}) is not guarded by the gate's answer",
            )

if problems:
    for p in problems:
        print(f"BOUNDARY VIOLATION: {p}", file=sys.stderr)
    sys.exit(1)
print("boundary ok")
CHECK

python3 "${tmp_dir}/check_workflow.py" "${workflow}" >"${tmp_dir}/out" 2>"${tmp_dir}/err" \
	|| {
		cat "${tmp_dir}/err" >&2
		fail 'the workflow as committed violates its own boundary'
	}
printf '  workflow: structure ok\n'

################################################################################
# MUTATION: prove each guard is the thing doing the work
################################################################################
#
# A structural check that has only ever been run against a correct file is a
# check nobody has seen work. Every assertion above is exercised here by
# breaking exactly the property it claims to protect and requiring the checker
# to name it. If one of these stops failing, the corresponding guard has become
# decoration and the boundary is only being enforced by everyone's good memory.
#
# The mutations live in a table rather than being passed in as code, so each one
# is anchored on a literal string from the workflow. A mutation whose anchor has
# drifted changes nothing, and "changed nothing" is itself a failure below —
# otherwise this section would slowly turn into fifteen tests of an empty edit.

cat >"${tmp_dir}/mutate.py" <<'MUTATE'
"""Weaken one guard in the Dependabot fix workflow. Args: source, dest, name."""
import sys
import pathlib

src = pathlib.Path(sys.argv[1]).read_text()

# Split at the privileged job so a mutation can target one job when the same
# line appears in three.
head, sep, tail = src.partition("\n  apply:\n")
assert sep, "the workflow no longer has an `apply:` job to split on"

BARE_CHECKOUT = "{ uses: actions/checkout@v7, with: { persist-credentials: false } }"

MUTATIONS = {
    # Let the job that pushes also check out the branch it is pushing.
    "privileged-checks-out-pr": lambda: head + sep + tail.replace(
        BARE_CHECKOUT,
        "{ uses: actions/checkout@v7, with: { persist-credentials: false, "
        'ref: "${{ needs.authorize.outputs.head-sha }}", path: pr } }',
        1,
    ),
    # ...and from the other side: let the job that runs the branch also push.
    "unprivileged-gains-write": lambda: head.replace(
        "permissions: { contents: read }", "permissions: { contents: write }", 1
    ) + sep + tail,
    "unprivileged-gains-oidc": lambda: head.replace(
        "permissions: { contents: read }",
        "permissions: { contents: read, id-token: write }",
        1,
    ) + sep + tail,
    # The elevation mechanism itself. pull_request_target is what the issue
    # suggested; it runs on a contributor's pull request, which is the whole
    # reason this workflow does not use it.
    "trigger-becomes-pull-request-target": lambda: head.replace(
        "  workflow_run:\n    workflows: [CI]\n    types: [completed]",
        "  pull_request_target:\n    types: [opened, synchronize]",
        1,
    ) + sep + tail,
    "trigger-gains-pull-request": lambda: head.replace(
        "  workflow_run:\n", "  pull_request:\n    types: [opened]\n  workflow_run:\n", 1
    ) + sep + tail,
    # The identity checks.
    "prefilter-drops-dependabot": lambda: head.replace(
        "github.event.workflow_run.actor.login == 'dependabot[bot]' &&", "true &&", 1
    ) + sep + tail,
    "prefilter-drops-same-repo": lambda: head.replace(
        "github.event.workflow_run.head_repository.full_name == github.repository", "true", 1
    ) + sep + tail,
    "privileged-stops-reauthorizing": lambda: head + sep + tail.replace(
        "bash .github/scripts/dependabot-fix-gate.sh", "true", 1
    ),
    "write-step-loses-guard": lambda: head + sep + tail.replace(
        "      - name: Apply and push\n        if: steps.gate.outputs.eligible == 'true'\n",
        "      - name: Apply and push\n",
        1,
    ),
    # The quiet way in: a toolchain action in the privileged job runs the
    # branch's install scripts without any checkout looking suspicious.
    "privileged-gains-toolchain": lambda: head + sep + tail.replace(
        "      - name: Re-authorize before writing",
        "      - { uses: ./.github/actions/setup-bun }\n      - name: Re-authorize before writing",
        1,
    ),
    # The pull request escaping its subdirectory puts it in the workspace root,
    # where the local composite actions and scripts live.
    "pr-lands-in-workspace-root": lambda: head.replace("          path: pr\n", "", 1) + sep + tail,
    "pr-checked-out-by-ref": lambda: head.replace(
        "ref: ${{ needs.authorize.outputs.head-sha }}",
        "ref: ${{ github.event.workflow_run.head_branch }}",
        1,
    ) + sep + tail,
    "checkout-persists-credentials": lambda: head + sep + tail.replace(
        BARE_CHECKOUT, "{ uses: actions/checkout@v7 }", 1
    ),
    "default-deny-removed": lambda: head.replace(
        "permissions: {}\n", "permissions: { contents: read }\n", 1
    ) + sep + tail,
}

name = sys.argv[3]
assert name in MUTATIONS, f"unknown mutation {name!r}"
pathlib.Path(sys.argv[2]).write_text(MUTATIONS[name]())
MUTATE

# mutate NAME EXPECTED_MESSAGE — weaken one guard, require the checker to name it.
mutate() {
	local name="$1" expected="$2"
	python3 "${tmp_dir}/mutate.py" "${workflow}" "${tmp_dir}/mutant.yml" "${name}"
	if cmp -s "${tmp_dir}/mutant.yml" "${workflow}"; then
		fail "mutation '${name}' changed nothing; its anchor has drifted out of the workflow"
	fi
	local rc=0
	python3 "${tmp_dir}/check_workflow.py" "${tmp_dir}/mutant.yml" \
		>"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
	[[ "${rc}" == 1 ]] || fail "mutation '${name}' was NOT caught — the guard for it does nothing"
	grep -qF -- "${expected}" "${tmp_dir}/err" \
		|| fail "mutation '${name}' was caught by the wrong check; wanted: ${expected}
$(cat "${tmp_dir}/err")"
	printf '    caught: %s\n' "${name}"
}

# The headline invariant, from both sides.
mutate privileged-checks-out-pr 'checks out the pull request AND holds a write permission'
mutate unprivileged-gains-write 'checks out the pull request AND holds a write permission'
mutate unprivileged-gains-oidc 'can mint an OIDC token'

mutate trigger-becomes-pull-request-target 'must trigger on workflow_run alone'
mutate trigger-gains-pull-request 'must trigger on workflow_run alone'

mutate prefilter-drops-dependabot "no longer requires 'dependabot[bot]'"
mutate prefilter-drops-same-repo 'head_repository.full_name == github.repository'

mutate privileged-stops-reauthorizing 'does not re-run the authorization gate'
mutate write-step-loses-guard 'is not guarded by the gate'
mutate privileged-gains-toolchain 'is not on its allowlist'

mutate pr-lands-in-workspace-root 'must go in a subdirectory'
mutate pr-checked-out-by-ref 'a ref re-resolves'
mutate checkout-persists-credentials 'persist-credentials: false'
mutate default-deny-removed 'permissions: {}'

printf '  workflow: mutation ok\n'

################################################################################
# MUTATION: the scripts
################################################################################
#
# The structural checker cannot see inside a script, so these two prove the
# behavioural suites are not passing by accident — that the specific line each
# guard lives on is what turns an eligible run away.

# --- the gate's Dependabot identity check ------------------------------------
#
# Removed, a contributor's branch named dependabot/... gets past the event
# checks. It is then caught by the API author check, which is exactly what
# having two layers is for — and is worth demonstrating rather than assuming,
# because a design with a redundant check and a design with a check that never
# fires look identical until one of them is deleted.
# The sed patterns match the literal text `${run_actor}` and `${allowed}` as it
# appears in the target script, so single quotes are required.
# shellcheck disable=SC2016
sed '/^\[\[ "${run_actor}" == "${BOT}" \]\]/,+1d' "${gate}" >"${tmp_dir}/weak-gate.sh"
if cmp -s "${tmp_dir}/weak-gate.sh" "${gate}"; then
	fail 'the gate mutation matched nothing; the actor check has moved'
fi

pr_json '.[0].user.login = "some-contributor"'
: >"${tmp_dir}/github_output"
PATH="${bin_dir}:${PATH}" env \
	GITHUB_REPOSITORY="${REPO}" RUN_EVENT='pull_request' RUN_ACTOR='some-contributor' \
	RUN_HEAD_REPO="${REPO}" RUN_HEAD_BRANCH="${BRANCH}" RUN_HEAD_SHA="${SHA}" \
	GH_TOKEN='x' GH_FAKE_BODY="${tmp_dir}/pr.json" \
	GITHUB_OUTPUT="${tmp_dir}/github_output" GITHUB_STEP_SUMMARY="${tmp_dir}/summary" \
	bash "${tmp_dir}/weak-gate.sh" >"${tmp_dir}/out" 2>"${tmp_dir}/err" || true
grep -qxF 'eligible=false' "${tmp_dir}/github_output" \
	|| fail 'with the event actor check removed, NOTHING refused a contributor'
printf '    layered: the API author check still refuses a contributor without the event check\n'

# ...but with both layers gone, it is authorized. This is the assertion that
# gives the one above its meaning.
# The sed patterns match the literal text `${run_actor}` and `${allowed}` as it
# appears in the target script, so single quotes are required.
# shellcheck disable=SC2016
sed -e '/^\[\[ "${run_actor}" == "${BOT}" \]\]/,+1d' \
	-e '/^\[\[ "${pr_author}" == "${BOT}" \]\]/,+1d' "${gate}" >"${tmp_dir}/weak-gate.sh"
: >"${tmp_dir}/github_output"
PATH="${bin_dir}:${PATH}" env \
	GITHUB_REPOSITORY="${REPO}" RUN_EVENT='pull_request' RUN_ACTOR='some-contributor' \
	RUN_HEAD_REPO="${REPO}" RUN_HEAD_BRANCH="${BRANCH}" RUN_HEAD_SHA="${SHA}" \
	GH_TOKEN='x' GH_FAKE_BODY="${tmp_dir}/pr.json" \
	GITHUB_OUTPUT="${tmp_dir}/github_output" GITHUB_STEP_SUMMARY="${tmp_dir}/summary" \
	bash "${tmp_dir}/weak-gate.sh" >"${tmp_dir}/out" 2>"${tmp_dir}/err" || true
grep -qxF 'eligible=true' "${tmp_dir}/github_output" \
	|| fail 'both Dependabot checks removed and the run was still declined; something else is deciding, and the suite above is testing the wrong thing'
printf '    caught: with both identity checks gone, a contributor is authorized\n'

# --- the apply script's path allowlist ---------------------------------------
#
# Removed, a patch that edits .github/workflows/ is pushed to the branch, and
# the next run of that workflow executes whatever it says. This is the single
# mutation that turns the design back into the vulnerability.
# Anchored on the variable rather than on the whole `||` construction: the
# formatter moves `||` onto the continuation line, and a mutation whose anchor
# only matches unformatted source is one that quietly stops mutating anything.
# shellcheck disable=SC2016  # the pattern matches literal `${allowed}` in the target
sed '/^\t"${allowed}"/,+1d' "${apply}" >"${tmp_dir}/weak-apply.sh"
if grep -qF 'is not on the mechanical-fix allowlist' "${tmp_dir}/weak-apply.sh"; then
	fail 'the apply mutation matched nothing; the allowlist check has moved'
fi

git_quiet -C "${origin}" update-ref "refs/heads/${BRANCH}" "${head_sha}"
before="$(branch_tip)"
craft_patch "printf 'name: CI\non: push\njobs: { pwn: { runs-on: ubuntu-latest, steps: [{ run: curl evil }] } }\n' > .github/workflows/ci.yml"
rc=0
env GITHUB_REPOSITORY="${REPO}" PR_NUMBER='42' HEAD_REF="${BRANCH}" HEAD_SHA="${head_sha}" \
	GH_TOKEN='x' GITHUB_WORKSPACE="${workspace}" RUNNER_TEMP="${tmp_dir}/runner_temp" \
	SIGNING_ENABLED='false' GIT_REMOTE_URL="file://${origin}" \
	GITHUB_STEP_SUMMARY="${tmp_dir}/summary" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
	bash "${tmp_dir}/weak-apply.sh" "${tmp_dir}/patch" >"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
[[ "${rc}" == 0 && "$(branch_tip)" != "${before}" ]] \
	|| fail 'the allowlist mutation did not reach a push, so the refusal test above proves less than it claims'
printf '    caught: without the allowlist, a .github/workflows/ patch reaches the branch\n'
git_quiet -C "${origin}" update-ref "refs/heads/${BRANCH}" "${head_sha}"

# --- the deferred activation failure ------------------------------------------
#
# Everything above has now run for real. If the file GitHub executes is not the
# file those assertions were read off, the suite is guarding a document, and
# says so as its last act rather than its first — so the run reports the state
# of the guards AND the state of the activation, instead of only the second.
if [[ -n "${deferred_failure}" ]]; then
	echo >&2
	echo 'FAIL: every assertion above passed, against the tree the checked-in' >&2
	echo '      activation patch produces — but .github/workflows/claude-dependabot-fix.yml' >&2
	echo '      does not exist, so nothing they describe is running.' >&2
	activation_procedure
	exit 1
fi

printf 'dependabot fix path tests passed\n'
