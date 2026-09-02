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

# An ordinary co-authored commit: a second person, at an address they write
# from. This is the half of the trailer rule that has to keep passing, because
# crediting a colleague is the reason the trailer exists.
add coauthored.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: A Colleague <colleague@example.com>' >/dev/null
accepts 'a human co-author trailer' "${base}..HEAD"
human_coauthor="$(git -C "${test_repo}" rev-parse HEAD)"

# --- the trailers ------------------------------------------------------------
#
# The gap this closes. Every commit on the branch that introduced this check
# carried the trailer below, written by the tool rather than by anyone, and
# every one of them passed a guard that read the four ident fields and stopped.
# The headers were right; the trailer credited an account alias to a person who
# had not typed it. These cases are that exact string and its relatives.
add machine-coauthor.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: Kaj Kowalski <6353477+kjanat@users.noreply.github.com>' >/dev/null
refuses 'a co-author credited by a GitHub account alias' \
	'account alias a tool fills in' "${human_coauthor}..HEAD"
refuses 'a co-author credited by a GitHub account alias' \
	'6353477+kjanat@users.noreply.github.com' "${human_coauthor}..HEAD"
machine_coauthor="$(git -C "${test_repo}" rev-parse HEAD)"

# The escape hatch has to reach the trailers too, or a repository that means it
# has nowhere to go but deleting the rule.
accepts_with_allow() {
	local description="$1" allow="$2" range="$3" output
	if ! output="$(cd "${test_repo}" && PROVENANCE_ALLOW="${allow}" "${check_script}" "${range}" 2>&1)"; then
		printf 'expected PROVENANCE_ALLOW to admit: %s\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
}
accepts_with_allow 'an explicitly allowed co-author address' \
	'6353477+kjanat@users.noreply.github.com' "${human_coauthor}..HEAD"

add bot-coauthor.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: claude[bot] <209825114+claude[bot]@users.noreply.github.com>' >/dev/null
refuses 'a bot co-author' 'not a co-author of the change' "${machine_coauthor}..HEAD"
bot_coauthor="$(git -C "${test_repo}" rev-parse HEAD)"

# A bot at an ordinary address: caught by the name, not by the domain, so the
# two halves of the trailer rule are each load-bearing on their own.
add bot-coauthor-own-domain.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: renovate[bot] <renovate@example.com>' >/dev/null
refuses 'a bot co-author at its own domain' 'not a co-author of the change' "${bot_coauthor}..HEAD"
bot_coauthor="$(git -C "${test_repo}" rev-parse HEAD)"

# The same bot, spelled the way a display name is allowed to be spelled. The
# `[bot]` suffix is a convention GitHub renders, not one it enforces on the
# name field, so a case-sensitive test refuses `renovate[bot]` and waves
# `Renovate[Bot]` through — at an ordinary address, where the domain rule is
# not there to catch it either. This is that exact bypass.
add bot-coauthor-mixed-case.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: Renovate[Bot] <renovate@example.com>' >/dev/null
refuses 'a bot co-author spelled [Bot]' 'not a co-author of the change' "${bot_coauthor}..HEAD"
refuses 'a bot co-author spelled [Bot]' 'Renovate[Bot]' "${bot_coauthor}..HEAD"
bot_coauthor="$(git -C "${test_repo}" rev-parse HEAD)"

# And the human it must not take with it, immediately after, at the same
# address shape. The case fold widens the rule; this is what stops it widening
# past a person who happens to write from a domain a bot also uses.
add human-beside-mixed-case.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: A Colleague <colleague@example.com>' >/dev/null
accepts 'a human co-author beside the mixed-case bot rule' "${bot_coauthor}..HEAD"
bot_coauthor="$(git -C "${test_repo}" rev-parse HEAD)"

add gh-coauthor.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Co-authored-by: GitHub <noreply@github.com>' >/dev/null
refuses 'a co-author credited to the merge machinery' \
	'account alias a tool fills in' "${bot_coauthor}..HEAD"
gh_coauthor="$(git -C "${test_repo}" rev-parse HEAD)"

# The rule is Co-authored-by and nothing else. A sign-off is a different claim
# with a different meaning, and prose that talks about the rule is prose.
add signed-off.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'Signed-off-by: Kaj Kowalski <6353477+kjanat@users.noreply.github.com>' >/dev/null
accepts 'a Signed-off-by at the same address' "${gh_coauthor}..HEAD"
signed_off="$(git -C "${test_repo}" rev-parse HEAD)"

add prose.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl \
	'The guard now refuses a Co-authored-by: claude[bot] <x@users.noreply.github.com> trailer.' >/dev/null
accepts 'prose that quotes a trailer without being one' "${signed_off}..HEAD"
prose="$(git -C "${test_repo}" rev-parse HEAD)"

# --- the headers -------------------------------------------------------------
#
# The incident itself, header by header.
add squashed.txt 'claude[bot]' '209825114+claude[bot]@users.noreply.github.com' 'GitHub' noreply@github.com >/dev/null
refuses 'the REST squash identity' 'identity GitHub stamps on a commit it built itself' "${prose}..HEAD"
refuses 'a bot author' 'not the author of the change' "${prose}..HEAD"
squashed="$(git -C "${test_repo}" rev-parse HEAD)"

add web-merge.txt 'Kaj Kowalski' info@kajkowalski.nl 'GitHub' noreply@github.com >/dev/null
refuses 'a machine committer under a real author' 'GitHub <noreply@github.com>' "${squashed}..HEAD"
web="$(git -C "${test_repo}" rev-parse HEAD)"

add bot-committer.txt 'Kaj Kowalski' info@kajkowalski.nl 'dependabot[bot]' 'support@github.com' >/dev/null
refuses 'a bot committer' 'not the committer of the change' "${web}..HEAD"
bot_committer="$(git -C "${test_repo}" rev-parse HEAD)"

# The same hatch over the headers, or a repository that genuinely wants a bot
# identity has no way through other than deleting the guard.
output="$(cd "${test_repo}" && PROVENANCE_ALLOW='support@github.com' "${check_script}" "${web}..HEAD" 2>&1)"
grep -Fq '1 commit(s)' <<<"${output}"

# The header checks fold case for the same reason the trailer one does, so the
# mixed-case spelling is refused there too. At an ordinary address, again:
# `support@github.com` in the case above is caught by neither domain rule, so
# it is the name doing the work in both.
add bot-author-mixed-case.txt 'Renovate[Bot]' 'renovate@example.com' 'Kaj Kowalski' info@kajkowalski.nl >/dev/null
refuses 'a bot author spelled [Bot]' 'not the author of the change' "${bot_committer}..HEAD"
bot_committer="$(git -C "${test_repo}" rev-parse HEAD)"

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
	job_source="${patch}"
	job_name='the pending patch'
else
	job_source="${ci_workflow}"
	job_name='.github/workflows/ci.yml'
fi

# All three assertions below are about the provenance JOB, and a job is a
# structure rather than a set of lines: its condition may be folded over three
# lines, its `uses:` key may be quoted, and in the pending form every line of
# it carries a `+`. So the job is read from a real parse of the workflow this
# lands as, which for the pending form means applying the patch first.
#
# `git apply` outside a repository is a plain patch applier, so a scratch
# directory holding one copy of ci.yml is enough to build the post-image — and
# building it is strictly better than reading the patch, because the post-image
# is what CI will actually run.
#
# shellcheck source=.github/scripts/workflow-steps.sh
source "${repo_root}/.github/scripts/workflow-steps.sh"

if [[ "${job_source}" == "${patch}" ]]; then
	applied="${tmp_dir}/applied"
	mkdir -p "${applied}/.github/workflows"
	cp "${ci_workflow}" "${applied}/.github/workflows/ci.yml"
	if ! (cd "${applied}" && git apply "${patch}"); then
		printf 'FAIL: %s does not apply to a copy of .github/workflows/ci.yml\n' \
			'.github/workflows-pending/ci-provenance-job.patch' >&2
		exit 1
	fi
	job_workflow="${applied}/.github/workflows/ci.yml"
else
	job_workflow="${ci_workflow}"
fi

# A guard nothing calls is not a guard, and `grep -Fq` cannot tell a job that
# calls it from the comment above the job describing what it calls. The `run:`
# steps are read instead, so the assertion is that some step's command word is
# this script.
guard='.github/scripts/check-commit-provenance.sh'
guard_step="$(workflow_runs_script "${job_workflow}" --job provenance "${guard}")" || exit 1
if [[ "${guard_step}" != "${guard}" ]]; then
	printf 'FAIL: no step in the provenance job in %s runs %s\n' "${job_name}" "${guard}" >&2
	printf '      A step that names the path without running it is not the wiring.\n' >&2
	exit 1
fi

# The actions the job runs, pinned to commits. This job is the guard itself,
# runs on the default branch, and checks out the repository before reading it:
# an action resolved through a tag is a step someone else can repoint into that
# position. Scoped to the provenance job rather than the whole of ci.yml, which
# is not this change's to re-pin. `--expect-uses` is what keeps the scoping
# honest: a job that has stopped having any actions in it, or a job name that
# no longer exists, fails here rather than reporting nothing unpinned.
mutable="$(workflow_mutable_uses "${job_workflow}" --job provenance --expect-uses)" || exit 1
if [[ -n "${mutable}" ]]; then
	printf 'FAIL: the provenance job in %s resolves an external action through a mutable ref:\n' \
		"${job_name}" >&2
	printf '        %s\n' "${mutable}" >&2
	printf '      Pin it to the full commit SHA, with the version as a trailing comment.\n' >&2
	exit 1
fi

# The job's own trigger condition, asserted rather than trusted. The range it
# checks is `before..after`, and on a branch-deletion push `after` is the
# default branch's tip — a range spanning commits the deletion never touched,
# attributed to whoever deleted the branch. `github.event.deleted == false` is
# what keeps that off, and it is one word away from being dropped by anyone
# tidying the condition.
#
# Asserted as a CONJUNCTION, not as two substrings that both appear. Those two
# checks are satisfied by
#
#   github.event_name == 'push' || github.event.deleted == false
#
# which contains both terms and runs the job on exactly the deleted-ref push
# the second term exists to keep it off — and, on every non-push event, on
# nothing this repository can reason about either. One character turns the gate
# inside out while every substring the guard looks for is still there.
#
# So the expression is taken apart instead. A GitHub expression is whitespace
# insignificant outside its string literals, so `if:` written on one line, over
# three folded lines, or with no spaces around its operators reaches this as the
# same set of terms. Anything the split cannot account for — a disjunction
# anywhere, a parenthesis, `!` — is REFUSED rather than interpreted: this is not
# an expression evaluator, and an expression it cannot take apart must not read
# as a safe one.
#
# Extra conjuncts are allowed. `A && B && C` is at least as strict as `A && B`,
# and a repository narrowing the gate further should not have to edit this.

# gate_is_conjunction <expression> <required-term>...
gate_is_conjunction() {
	local expression="$1" term
	shift

	expression="$(tr '\n' ' ' <<<"${expression}")"
	expression="${expression#"${expression%%[![:space:]]*}"}"
	expression="${expression%"${expression##*[![:space:]]}"}"
	# `${{ ... }}` is optional in a job-level `if:` and means the same thing.
	# shellcheck disable=SC2016  # `${{` is GitHub expression syntax being
	# matched as text; expanding it here is the opposite of what is wanted.
	if [[ "${expression}" == '${{'*'}}' ]]; then
		expression="${expression#'${{'}"
		expression="${expression%'}}'}"
	fi

	case "${expression}" in
		*'||'* | *'('* | *')'* | *'!'*) return 1 ;;
	esac

	# Whitespace out, so a term is compared by what it says rather than how it
	# was laid out. Safe to remove entirely here because no required term
	# contains a quoted string with a space in it, so no two distinct literals
	# can be folded into one.
	local -A present=()
	local rest="${expression}"
	while [[ "${rest}" == *'&&'* ]]; do
		present["$(tr -d '[:space:]' <<<"${rest%%&&*}")"]=1
		rest="${rest#*&&}"
	done
	present["$(tr -d '[:space:]' <<<"${rest}")"]=1

	for term in "$@"; do
		[[ -n "${present["$(tr -d '[:space:]' <<<"${term}")"]-}" ]] || return 1
	done
	return 0
}

# The mutants, asserted before the real file is judged by this — including the
# OR that two substring checks accept, which is the finding this closes.
# gate_case <expected: accepted|refused> <expression>
gate_case() {
	local expected="$1" expression="$2" verdict=accepted
	gate_is_conjunction "${expression}" \
		"github.event_name == 'push'" 'github.event.deleted == false' || verdict=refused
	if [[ "${verdict}" != "${expected}" ]]; then
		printf 'FAIL: the provenance gate check %s %q, expected it %s\n' \
			"${verdict}" "${expression}" "${expected}" >&2
		exit 1
	fi
}

# Benign spellings of the intended gate. Whitespace, operand order, folding and
# the optional `${{ }}` are all layout rather than meaning.
gate_case accepted "github.event_name == 'push' && github.event.deleted == false"
gate_case accepted "github.event.deleted == false && github.event_name == 'push'"
gate_case accepted "github.event_name=='push'&&github.event.deleted==false"
gate_case accepted "github.event_name == 'push'   &&
  github.event.deleted == false"
gate_case accepted "\${{ github.event_name == 'push' && github.event.deleted == false }}"
# A further conjunct only narrows the gate.
gate_case accepted "github.event_name == 'push' && github.event.deleted == false && github.ref_name == 'master'"

# The finding: both terms appear, and the job runs on the deleted ref anyway.
gate_case refused "github.event_name == 'push' || github.event.deleted == false"
# `&&` binds tighter than `||`, so this is `(A && B && C) || D` — a gate that
# opens on D alone, with both required terms present and untouched inside the
# part that no longer has to hold. Splitting on `&&` finds A and B here and
# would accept; refusing a disjunction outright is what catches it, which is
# why that arm is a refusal rather than a tidiness rule.
gate_case refused "github.event_name == 'push' && github.event.deleted == false && github.ref_name == 'master' || github.actor == 'dependabot[bot]'"
gate_case refused "github.event_name == 'push'"
gate_case refused 'github.event.deleted == false'
gate_case refused "github.event_name == 'push' && github.event.deleted != true"
gate_case refused "github.event_name == 'push' && !github.event.deleted"
gate_case refused "(github.event_name == 'push' || github.event_name == 'schedule') && github.event.deleted == false"

job_condition="$(workflow_job_field "${job_workflow}" provenance if)" || exit 1
if ! gate_is_conjunction "${job_condition}" \
	"github.event_name == 'push'" 'github.event.deleted == false'; then
	printf 'FAIL: %s does not gate the provenance job on a push that is not a deletion (if: %s)\n' \
		"${job_name}" "${job_condition}" >&2
	printf '      Both terms have to hold, joined by &&. Deleting a branch reports the\n' >&2
	printf '      default branch tip as github.sha, so before..after spans commits the\n' >&2
	printf '      push never added. Restore:\n' >&2
	printf "        if: github.event_name == 'push' && github.event.deleted == false\n" >&2
	exit 1
fi

printf 'commit provenance guard: wired, and not on deleted refs\n'
