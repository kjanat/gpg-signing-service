#!/usr/bin/env bash
# Drive .github/scripts/check-commit-provenance.sh over the identities the
# merge paths actually produce.
#
# The guard is what turns the Aug 30 failure from silent into loud: those
# twenty commits were only noticed once the branch was signed and GitHub
# reported the signatures against identities that had never written anything.
# The cases below are the shapes that must stay refused, and — just as
# important — the ordinary ones that must not start failing every merge.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
check_script="${repo_root}/.github/scripts/check-commit-provenance.sh"

# GIT_DIR and GIT_WORK_TREE would aim the fixture at the caller's repository,
# and GIT_AUTHOR_*/GIT_COMMITTER_* — which GitHub Actions exports — would
# overwrite the identities under test, which is the whole subject here.
unset "${!GIT_@}"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

test_repo="${tmp_dir}/repo"
mkdir -p "${test_repo}"
git -C "${test_repo}" init --quiet --initial-branch=master
git -C "${test_repo}" config commit.gpgsign false

# add <file> <author name> <author email> <committer name> <committer email> [trailer]
add() {
	local message=(-m "add $1")
	if [[ -n "${6-}" ]]; then
		message+=(-m "$6")
	fi
	printf '%s\n' "$1" >"${test_repo}/$1"
	git -C "${test_repo}" add "$1"
	GIT_AUTHOR_NAME="$2" GIT_AUTHOR_EMAIL="$3" \
		GIT_COMMITTER_NAME="$4" GIT_COMMITTER_EMAIL="$5" \
		git -C "${test_repo}" commit --quiet "${message[@]}"
	git -C "${test_repo}" rev-parse HEAD
}

# accepts <description> <range>
accepts() {
	local description="$1" range="$2" output
	if ! output="$(cd "${test_repo}" && "${check_script}" "${range}" 2>&1)"; then
		printf 'expected the guard to accept: %s\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
}

# refuses <description> <needle> <range>
refuses() {
	local description="$1" needle="$2" range="$3" output
	if output="$(cd "${test_repo}" && "${check_script}" "${range}" 2>&1)"; then
		printf 'expected the guard to refuse: %s\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
	if ! grep -Fq "${needle}" <<<"${output}"; then
		printf 'the refusal for %s does not mention %q:\n%s\n' "${description}" "${needle}" "${output}" >&2
		exit 1
	fi
}

base="$(add base.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl)"

# An ordinary merge: a person authored it, a person committed it. This is the
# case that must never start failing, because a guard that cries wolf on every
# merge gets turned off and then the real one lands unnoticed.
add ordinary.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl >/dev/null
accepts 'an ordinary person-authored commit' "${base}..HEAD"

# A co-authored commit still names a person in both headers. The trailer that
# credits the assistant is in the message, where it belongs, and the guard must
# not reach into it.
add coauthored.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: claude[bot] <209825114+claude[bot]@users.noreply.github.com>' >/dev/null
accepts 'a commit with a bot Co-authored-by trailer' "${base}..HEAD"
good="$(git -C "${test_repo}" rev-parse HEAD)"

# The incident itself, header by header.
add squashed.txt 'claude[bot]' '209825114+claude[bot]@users.noreply.github.com' 'GitHub' noreply@github.com >/dev/null
refuses 'the REST squash identity' 'identity GitHub stamps on a commit it built itself' "${good}..HEAD"
refuses 'a bot author' 'not the author of the change' "${good}..HEAD"
squashed="$(git -C "${test_repo}" rev-parse HEAD)"

add web-merge.txt 'Kaj Kowalski' info@kajkowalski.nl 'GitHub' noreply@github.com >/dev/null
refuses 'a machine committer under a real author' 'GitHub <noreply@github.com>' "${squashed}..HEAD"
web="$(git -C "${test_repo}" rev-parse HEAD)"

add bot-committer.txt 'Kaj Kowalski' info@kajkowalski.nl 'dependabot[bot]' 'support@github.com' >/dev/null
refuses 'a bot committer' 'not the committer of the change' "${web}..HEAD"
bot_committer="$(git -C "${test_repo}" rev-parse HEAD)"

# The escape hatch has to work, or a repository that genuinely wants a bot
# identity has no way through other than deleting the guard.
output="$(cd "${test_repo}" && PROVENANCE_ALLOW='support@github.com' "${check_script}" "${web}..HEAD" 2>&1)"
grep -Fq '1 commit(s)' <<<"${output}"

# An empty range is not a failure: a push that added nothing has nothing wrong
# with it.
accepts 'an empty range' "${bot_committer}..${bot_committer}"

refuses 'a missing range' 'usage:' ''

# A range git cannot resolve is not an empty range. Reading it as one would
# make every guarded push pass the moment the ref name went stale, which is the
# quietest way a fail-closed check turns into a fail-open one.
refuses 'a range git cannot resolve' 'could not resolve the revision range' \
	'refs/heads/never-existed..HEAD'

printf 'commit provenance guard: all cases passed\n'

# --- the wiring ---------------------------------------------------------------
#
# A guard nothing calls is not a guard. It is wired into .github/workflows/ci.yml
# as a job, and a GitHub App token cannot write under .github/workflows/ — the
# push is rejected outright and takes the whole push with it — so the job
# arrives as a patch a human applies:
#
#   git apply .github/workflows-pending/ci-provenance-job.patch
#   git rm .github/workflows-pending/ci-provenance-job.patch
#
# Resolved PATCH-first, the same way the pending workflow files are. While the
# patch exists the job is not in CI yet and this says so; once it is applied and
# the patch removed, the check below becomes a standing assertion that CI still
# calls the guard.
patch="${repo_root}/.github/workflows-pending/ci-provenance-job.patch"
ci_workflow="${repo_root}/.github/workflows/ci.yml"

if [[ -f "${patch}" ]]; then
	printf '  note: the CI provenance job is still pending (git apply %s)\n' \
		'.github/workflows-pending/ci-provenance-job.patch'
	# A patch that no longer applies is worse than no patch: it is a job
	# everyone believes is one command away.
	if ! git -C "${repo_root}" apply --check "${patch}" 2>/dev/null; then
		printf 'FAIL: %s no longer applies to .github/workflows/ci.yml\n' \
			'.github/workflows-pending/ci-provenance-job.patch' >&2
		exit 1
	fi
	if ! grep -Fq 'check-commit-provenance.sh' "${patch}"; then
		printf 'FAIL: the pending patch does not call check-commit-provenance.sh\n' >&2
		exit 1
	fi
elif ! grep -Fq 'check-commit-provenance.sh' "${ci_workflow}"; then
	printf 'FAIL: .github/workflows/ci.yml does not call check-commit-provenance.sh, and no pending patch adds it\n' >&2
	exit 1
fi

printf 'commit provenance guard: wired\n'
