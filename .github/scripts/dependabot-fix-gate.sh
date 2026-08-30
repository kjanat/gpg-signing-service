#!/usr/bin/env bash
# Decide whether a `workflow_run` completion is allowed to reach the privileged
# half of the Dependabot fix path — and refuse by default.
#
# Called by .github/workflows/claude-dependabot-fix.yml, twice: once to gate the
# unprivileged job that produces a patch, and again inside the job that holds
# the write token. Running it twice is not belt-and-braces for its own sake. The
# two jobs are minutes apart, and in between the branch can be force-pushed, the
# pull request closed, or its author changed by a rebase from someone else. The
# second call is the one whose answer the push depends on.
#
# WHY THIS SCRIPT EXISTS AT ALL
#
# A workflow triggered by Dependabot from `pull_request` is treated by GitHub as
# if it came from a fork: read-only GITHUB_TOKEN, and `secrets.*` resolving from
# the Dependabot store rather than the Actions store. Nothing declared in that
# workflow's `permissions:` block changes either fact. So the review workflow
# cannot push to a Dependabot branch, and adding `contents: write` to it would
# only make the file lie about what the run can do.
#
# `workflow_run` is the escape, and it is a better one than the
# `pull_request_target` that GitHub's own Dependabot page suggests:
#
#   - it gets the Actions secrets and a writable token ("The workflow started by
#     the workflow_run event is able to access secrets and write tokens, even if
#     the previous workflow was not");
#   - GITHUB_SHA and GITHUB_REF are the default branch, so a checkout with no
#     `ref:` is master and cannot be anything else;
#   - the workflow only runs if the file exists on the default branch, so a
#     contributor cannot introduce a privileged workflow in their own branch;
#   - and it fires after CI, so the privileged path opens only when there is
#     something broken to fix.
#
# What `workflow_run` does NOT do is tell the truth about who it is acting for.
# The event is attacker-influenced: any pull request in the repository can make
# CI fail and produce a `workflow_run` completion. Everything below exists to
# turn that into a decision, and every unrecognised shape is a refusal.
#
#   usage:  dependabot-fix-gate.sh
#
#   env:    GITHUB_REPOSITORY  owner/repo this workflow belongs to
#           RUN_EVENT          github.event.workflow_run.event
#           RUN_ACTOR          github.event.workflow_run.actor.login
#           RUN_HEAD_REPO      github.event.workflow_run.head_repository.full_name
#           RUN_HEAD_BRANCH    github.event.workflow_run.head_branch
#           RUN_HEAD_SHA       github.event.workflow_run.head_sha
#           GH_TOKEN           read-only token; `gh` reads it from the environment
#           GITHUB_OUTPUT      where the decision is written
#           GITHUB_STEP_SUMMARY  optional; the refusal reason is repeated here
#
#   out:    eligible=true|false, and on true: pr-number, head-ref, head-sha
#
#   exit:   0  a decision was reached, either way
#           1  the script cannot run (missing GITHUB_OUTPUT, GITHUB_REPOSITORY,
#              or an API call that failed rather than answered)
#
# `eligible=false` is exit 0 on purpose: refusing is the common case and the
# correct one, and a red check on every unrelated CI failure in the repository
# would teach everyone to ignore this workflow.
set -Eeuo pipefail

readonly BOT='dependabot[bot]'

readonly this_repo="${GITHUB_REPOSITORY-}"
readonly run_event="${RUN_EVENT-}"
readonly run_actor="${RUN_ACTOR-}"
readonly run_head_repo="${RUN_HEAD_REPO-}"
readonly run_head_branch="${RUN_HEAD_BRANCH-}"
readonly run_head_sha="${RUN_HEAD_SHA-}"
readonly github_output="${GITHUB_OUTPUT-}"

die() {
	printf '::error title=Dependabot fix gate::%s\n' "$1"
	exit 1
}

[[ -n "${github_output}" ]] || die 'GITHUB_OUTPUT is not set; this script only runs inside a job step'
[[ -n "${this_repo}" ]] || die 'GITHUB_REPOSITORY is not set'

# refuse REASON — the only way this script says no. One shape for every
# rejection, so a new check cannot accidentally invent a quieter one.
refuse() {
	printf 'eligible=false\n' >>"${github_output}"
	printf '::notice title=Dependabot fix path declined::%s\n' "$1"
	if [[ -n "${GITHUB_STEP_SUMMARY-}" ]]; then
		{
			printf '### :lock: Dependabot fix path declined\n\n'
			printf '%s\n' "$1"
		} >>"${GITHUB_STEP_SUMMARY}" || true
	fi
	exit 0
}

# --- the event, before anything is asked of the API --------------------------
#
# These are cheap and they are the checks that keep an ordinary contributor's
# pull request from ever reaching the API calls below, let alone the write job.
# The API is the authority on all of it, but a check that can be made without a
# network round trip should be.

[[ "${run_event}" == 'pull_request' ]] \
	|| refuse "The triggering run came from '${run_event:-<unset>}', not a pull request."

# Compared to the literal login rather than to a `*[bot]` pattern: "dependabot"
# is a reserved account, but "dependabot-preview[bot]", "renovate[bot]" and any
# user who names a branch dependabot/... are not this path's business.
[[ "${run_actor}" == "${BOT}" ]] \
	|| refuse "The triggering run was for '${run_actor:-<unset>}', not ${BOT}."

# A pull request from a fork has a head repository that is not this one, and
# nothing in this workflow may push to a repository it does not own.
[[ "${run_head_repo}" == "${this_repo}" ]] \
	|| refuse "The head repository is '${run_head_repo:-<unset>}', not ${this_repo}."

# Dependabot only ever pushes to branches under this prefix. A same-repo branch
# outside it, even one Dependabot somehow authored, is not a version bump.
[[ "${run_head_branch}" == dependabot/* ]] \
	|| refuse "The head branch '${run_head_branch:-<unset>}' is not under dependabot/."

# Pinned to a full object name because everything downstream fetches exactly
# this commit and refuses to work on anything else. An abbreviated or symbolic
# ref would leave room for it to resolve to something later.
[[ "${run_head_sha}" =~ ^[0-9a-f]{40}$ ]] \
	|| refuse "The head SHA '${run_head_sha:-<unset>}' is not a full commit id."

# --- the API, which is the authority -----------------------------------------
#
# The event payload was assembled when the triggering run started and describes
# the world as it was then. Only an open pull request may be written to, and
# only the API knows whether one still is.

# The answer goes to a file rather than to stdout. `pulls="$(api ...)"` would
# capture the ::error annotation that a failure prints, and GitHub only reads
# workflow commands off a step's stdout — so the one message that says the gate
# could not reach a decision would be the one message nobody ever saw.
api_body="$(mktemp)"
api_error="$(mktemp)"
trap 'rm -f "${api_body}" "${api_error}"' EXIT

api() {
	local path="$1"
	if ! gh api -H 'Accept: application/vnd.github+json' "${path}" >"${api_body}" 2>"${api_error}"; then
		# Distinguished from a refusal: the gate did not decide "no", it failed
		# to ask. Treating an outage as ineligible would make the whole path
		# fail open the day the answer stopped arriving, and silence is exactly
		# what that failure would look like.
		cat "${api_error}" >&2
		die "GitHub API request failed: ${path}"
	fi
}

readonly owner="${this_repo%%/*}"
api "repos/${this_repo}/pulls?state=open&per_page=100&head=${owner}:${run_head_branch}"
pulls="$(cat "${api_body}")"

count="$(jq 'length' <<<"${pulls}")"
[[ "${count}" == '1' ]] \
	|| refuse "Expected exactly one open pull request for ${run_head_branch}, found ${count}."

# Every field is re-read from the API answer rather than trusted from the event,
# and each is compared to what the event claimed. Agreement between the two is
# the point: a mismatch means the branch moved under the run, and the patch the
# other job produced was computed against a tree that is no longer there.
pr_number="$(jq -r '.[0].number' <<<"${pulls}")"
pr_author="$(jq -r '.[0].user.login' <<<"${pulls}")"
pr_state="$(jq -r '.[0].state' <<<"${pulls}")"
pr_head_repo="$(jq -r '.[0].head.repo.full_name' <<<"${pulls}")"
pr_base_repo="$(jq -r '.[0].base.repo.full_name' <<<"${pulls}")"
pr_head_ref="$(jq -r '.[0].head.ref' <<<"${pulls}")"
pr_head_sha="$(jq -r '.[0].head.sha' <<<"${pulls}")"

[[ "${pr_number}" =~ ^[1-9][0-9]*$ ]] \
	|| refuse "The API returned a pull request number that is not a positive integer: '${pr_number}'."

[[ "${pr_state}" == 'open' ]] \
	|| refuse "Pull request #${pr_number} is '${pr_state}', not open."

[[ "${pr_author}" == "${BOT}" ]] \
	|| refuse "Pull request #${pr_number} is authored by '${pr_author}', not ${BOT}."

[[ "${pr_head_repo}" == "${this_repo}" ]] \
	|| refuse "Pull request #${pr_number} has head repository '${pr_head_repo}', not ${this_repo}."

[[ "${pr_base_repo}" == "${this_repo}" ]] \
	|| refuse "Pull request #${pr_number} targets '${pr_base_repo}', not ${this_repo}."

[[ "${pr_head_ref}" == "${run_head_branch}" ]] \
	|| refuse "Pull request #${pr_number} has head ref '${pr_head_ref}', not '${run_head_branch}'."

[[ "${pr_head_sha}" == "${run_head_sha}" ]] \
	|| refuse "Pull request #${pr_number} has moved to ${pr_head_sha:0:12}; the run describes ${run_head_sha:0:12}."

{
	printf 'eligible=true\n'
	printf 'pr-number=%s\n' "${pr_number}"
	printf 'head-ref=%s\n' "${pr_head_ref}"
	printf 'head-sha=%s\n' "${pr_head_sha}"
} >>"${github_output}"

printf '::notice title=Dependabot fix path authorized::Pull request #%s (%s at %s) is eligible.\n' \
	"${pr_number}" "${pr_head_ref}" "${pr_head_sha:0:12}"
