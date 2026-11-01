#!/usr/bin/env bash
# Drive .github/scripts/check-commit-provenance.sh over AI agent credits and the
# ordinary commits, bots and merges that must keep passing.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
check_script="${repo_root}/.github/scripts/check-commit-provenance.sh"

# GIT_DIR and GIT_WORK_TREE would aim the fixture at the caller's repository,
# and GIT_AUTHOR_*/GIT_COMMITTER_* (which GitHub Actions exports) would
# overwrite the identities under test.
unset "${!GIT_@}" PROVENANCE_ALLOW
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

test_repo="${tmp_dir}/repo"
mkdir -p "${test_repo}"
git -C "${test_repo}" init --quiet --initial-branch=master
git -C "${test_repo}" config commit.gpgsign false

# add <file> <author name> <author email> <committer name> <committer email> [body]
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

# human <file> [body]
human() {
	add "$1" 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl "${2-}"
}

# accepts <description> <sha> [ENV=value ...]
accepts() {
	local description="$1" sha="$2" output
	shift 2
	if ! output="$(cd "${test_repo}" && env "$@" "${check_script}" "${sha}^..${sha}" 2>&1)"; then
		printf 'expected the guard to accept: %s\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
}

# refuses <description> <needle> <sha>
refuses() {
	local description="$1" needle="$2" sha="$3" output
	if output="$(cd "${test_repo}" && "${check_script}" "${sha}^..${sha}" 2>&1)"; then
		printf 'expected the guard to refuse: %s\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
	if ! grep -Fq -- "${needle}" <<<"${output}"; then
		printf 'the refusal for %s does not mention %q:\n%s\n' "${description}" "${needle}" "${output}" >&2
		exit 1
	fi
}

base="$(human base.txt)"

# --- what passes ---------------------------------------------------------------
accepts 'an ordinary person-authored commit' "$(human ordinary.txt)"
accepts 'a human co-author' "$(human coauthor.txt 'Co-authored-by: A Colleague <colleague@example.com>')"
accepts 'a GitHub account alias co-author' \
	"$(human alias.txt 'Co-authored-by: Kaj Kowalski <6353477+kjanat@users.noreply.github.com>')"
accepts 'the #167 squash of a Renovate PR' \
	"$(add renovate.txt 'renovate[bot]' '29139614+renovate[bot]@users.noreply.github.com' GitHub noreply@github.com \
		'Co-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>')"
accepts 'an autofix.ci commit pushed to master' \
	"$(add autofix.txt 'autofix-ci[bot]' '114827586+autofix-ci[bot]@users.noreply.github.com' GitHub noreply@github.com)"
accepts 'a web editor commit' "$(add web.txt 'Kaj Kowalski' info@kajkowalski.nl GitHub noreply@github.com)"
accepts 'a dependabot committer' "$(add dependabot.txt 'Kaj Kowalski' info@kajkowalski.nl 'dependabot[bot]' support@github.com)"
accepts 'a body that talks about Claude and Codex' \
	"$(human talk.txt $'Skip the Claude review step when the OAuth token is unavailable.\n\nThe codex config moved.')"
accepts 'prose that quotes a trailer without being one' \
	"$(human prose.txt 'The guard now refuses a Co-authored-by: claude[bot] <x@users.noreply.github.com> trailer.')"
accepts 'a conventional-commit line parsed as a trailer' \
	"$(human ci-line.txt 'ci: skip Claude review step when the OAuth token is unavailable')"
accepts 'a Signed-off-by from a person' "$(human signed.txt 'Signed-off-by: Kaj Kowalski <info@kajkowalski.nl>')"
accepts 'Jean-Claude as author and committer' \
	"$(add jcvd.txt 'Jean-Claude Van Damme' jcvd@example.com 'Jean-Claude Van Damme' jcvd@example.com)"
accepts 'a name that contains grok' "$(add grokhovsky.txt 'Anna Grokhovsky' anna@example.com 'Kaj Kowalski' info@kajkowalski.nl)"
accepts 'an address that contains codex' "$(add codex-team.txt 'Kaj Kowalski' codex-team@corp.example 'Kaj Kowalski' info@kajkowalski.nl)"

# --- AI agents as author or committer --------------------------------------------
refuses 'claude[bot] as author' 'is authored by claude[bot]' \
	"$(add a1.txt 'claude[bot]' '209825114+claude[bot]@users.noreply.github.com' 'Kaj Kowalski' info@kajkowalski.nl)"
refuses 'claude[bot] behind a human address' 'is authored by claude[bot] <info@kajkowalski.nl>' \
	"$(add a2.txt 'claude[bot]' info@kajkowalski.nl 'Kaj Kowalski' info@kajkowalski.nl)"
refuses 'Claude at anthropic.com as author' 'is authored by Claude <noreply@anthropic.com>' \
	"$(add a3.txt Claude noreply@anthropic.com 'Kaj Kowalski' info@kajkowalski.nl)"
refuses 'a Codex committer' 'is committed by chatgpt-codex-connector[bot]' \
	"$(add a4.txt 'Kaj Kowalski' info@kajkowalski.nl 'chatgpt-codex-connector[bot]' '199175422+chatgpt-codex-connector[bot]@users.noreply.github.com')"
refuses 'Grok in any case' 'is authored by GROK' \
	"$(add a5.txt GROK agent@example.com 'Kaj Kowalski' info@kajkowalski.nl)"
refuses 'an agent address under a human name' 'is authored by Kaj Kowalski <bot@openai.com>' \
	"$(add a6.txt 'Kaj Kowalski' bot@openai.com 'Kaj Kowalski' info@kajkowalski.nl)"
refuses 'an x.ai subdomain address' 'is committed by Kaj Kowalski <bot@mail.x.ai>' \
	"$(add a7.txt 'Kaj Kowalski' info@kajkowalski.nl 'Kaj Kowalski' bot@mail.x.ai)"
refuses 'the squash of a PR the Claude app opened (fa4f06e)' \
	'is authored by claude[bot] <209825114+claude[bot]@users.noreply.github.com>' \
	"$(add a8.txt 'claude[bot]' '209825114+claude[bot]@users.noreply.github.com' GitHub noreply@github.com \
		'Co-authored-by: Kaj Kowalski <info@kajkowalski.nl>')"

# --- AI agents in the message ------------------------------------------------------
refuses 'Claude Code as co-author' 'credits Claude <noreply@anthropic.com> as a co-author' \
	"$(human t1.txt 'Co-Authored-By: Claude <noreply@anthropic.com>')"
refuses 'claude[bot] as co-author' 'credits claude[bot]' \
	"$(human t2.txt 'Co-authored-by: claude[bot] <209825114+claude[bot]@users.noreply.github.com>')"
refuses 'Codex as co-author' 'credits Codex <codex@openai.com>' \
	"$(human t3.txt 'Co-authored-by: Codex <codex@openai.com>')"
refuses 'a co-author above a later trailer paragraph' 'credits Claude Sonnet <claude@example.com>' \
	"$(human t5.txt $'Co-authored-by: Claude Sonnet <claude@example.com>\n\nSigned-off-by: Kaj Kowalski <info@kajkowalski.nl>')"
refuses 'a lowercase co-authored-by line' 'credits Codex' \
	"$(human t6.txt 'co-authored-by: Codex <codex@openai.com>')"
refuses 'Grok as co-author among humans' 'credits Grok' \
	"$(human t4.txt $'Co-authored-by: A Colleague <colleague@example.com>\nCo-authored-by: Grok <grok@x.ai>')"
refuses 'a Claude Code generated line' 'links an AI agent session' \
	"$(human s1.txt $'Generated with [Claude Code](https://claude.com/claude-code)\n\nCo-authored-by: A Colleague <colleague@example.com>')"
refuses 'a Claude Code web session link' 'links an AI agent session: https://claude.ai/code/session_011abc' \
	"$(human s2.txt 'https://claude.ai/code/session_011abc')"
refuses 'a Codex task link' 'links an AI agent session' \
	"$(human s3.txt 'Task: https://chatgpt.com/codex/tasks/task_e_123')"
refuses 'a Grok share link' 'links an AI agent session' \
	"$(human s4.txt 'See https://grok.com/share/abc')"
refuses 'a trailer named after an agent' 'carries the AI agent trailer Claude-Session-Id: 0123' \
	"$(human s5.txt 'Claude-Session-Id: 0123')"
refuses 'a session trailer naming an agent' 'carries the AI agent trailer Session: codex-0123' \
	"$(human s6.txt 'Session: codex-0123')"
refuses 'an assisted-by trailer naming an agent' 'carries the AI agent trailer Assisted-by: Claude' \
	"$(human s7.txt 'Assisted-by: Claude')"

# --- the escape hatch --------------------------------------------------------------
monet="$(add monet.txt 'Claude Monet' claude@monet.example 'Kaj Kowalski' info@kajkowalski.nl)"
refuses 'a person named Claude without an allowance' 'is authored by Claude Monet' "${monet}"
accepts 'a person named Claude with an allowance' "${monet}" 'PROVENANCE_ALLOW=CLAUDE@monet.example'
accepts 'an allowed co-author address' \
	"$(human monet-co.txt 'Co-authored-by: Claude Monet <claude@monet.example>')" 'PROVENANCE_ALLOW=claude@monet.example'

# --- ranges ------------------------------------------------------------------------
output="$(cd "${test_repo}" && "${check_script}" "${base}..HEAD" 2>&1)" && {
	printf 'a range holding agent commits was accepted:\n%s\n' "${output}" >&2
	exit 1
}
grep -Fq "AI agent credit(s) in ${base}..HEAD" <<<"${output}" || {
	printf 'the range summary is missing:\n%s\n' "${output}" >&2
	exit 1
}
head_sha="$(git -C "${test_repo}" rev-parse HEAD)"
output="$(cd "${test_repo}" && "${check_script}" "${head_sha}..${head_sha}" 2>&1)" || {
	printf 'an empty range was refused:\n%s\n' "${output}" >&2
	exit 1
}
output="$(cd "${test_repo}" && "${check_script}" '' 2>&1)" && {
	echo 'a missing range was accepted' >&2
	exit 1
}
grep -Fq 'usage:' <<<"${output}"
output="$(cd "${test_repo}" && "${check_script}" 'refs/heads/never-existed..HEAD' 2>&1)" && {
	echo 'a range git cannot resolve was accepted' >&2
	exit 1
}
grep -Fq 'could not resolve the revision range' <<<"${output}"

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
