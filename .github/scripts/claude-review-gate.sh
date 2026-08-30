#!/usr/bin/env bash
# Decide, in the first step of the Claude review job, whether this run is going
# to run Claude at all — and say why when it is not.
#
# Called by .github/workflows/claude-code-review.yml. It exists because the
# answer is needed by two steps, not one. The review job signs the commits it
# pushes (.github/actions/setup-claude-signing), and that setup is fail-closed
# by design: a job that means to sign and cannot must not proceed to make
# unsigned commits. On a pull request from a fork there is no
# CLAUDE_CODE_OAUTH_TOKEN and no id-token: write, so signing setup failed the
# whole workflow on a run whose only intended outcome was to do nothing.
#
# So `HAS_CLAUDE_TOKEN` gates the signing setup and the review step together.
# The invariant is that the two never disagree: signing is configured on exactly
# the runs that are going to sign something, and every other run is a clean
# no-op rather than a red check. Nothing here weakens the fail-closed path — a
# run that *does* have the token still fails if the service or the OIDC
# configuration is not there, which is #107's behaviour untouched.
#
#   usage:  claude-review-gate.sh
#
#   env:    CLAUDE_CODE_OAUTH_TOKEN  the secret; read for presence only
#           PR_HEAD_REPO             github.event.pull_request.head.repo.full_name
#           GITHUB_REPOSITORY        the repo the workflow belongs to
#           GITHUB_ACTOR             who the run is for; distinguishes Dependabot
#           GITHUB_ENV               where HAS_CLAUDE_TOKEN is written
#           GITHUB_STEP_SUMMARY      optional; the skip reason is repeated here
#
#   exit:   0  always — the decision is HAS_CLAUDE_TOKEN, never the status.
#
# Exit 0 even when there is no token, on purpose. This step is the thing that
# decides a run is a deliberate no-op; failing here would be the exact outcome
# it exists to prevent.
set -Eeuo pipefail

readonly DEPENDABOT='dependabot[bot]'

readonly token="${CLAUDE_CODE_OAUTH_TOKEN-}"
readonly head_repo="${PR_HEAD_REPO-}"
readonly this_repo="${GITHUB_REPOSITORY-}"
readonly actor="${GITHUB_ACTOR-}"
readonly github_env="${GITHUB_ENV-}"

if [[ -z "${github_env}" ]]; then
	printf '%s\n' '::error title=Claude review gate::GITHUB_ENV is not set; this script only runs inside a job step'
	exit 1
fi

if [[ -n "${token}" ]]; then
	printf 'HAS_CLAUDE_TOKEN=true\n' >>"${github_env}"
	exit 0
fi

# Written as the empty value rather than "false" so it matches what the inline
# `${CLAUDE_TOKEN:+true}` in the workflow used to write, and so the `if:`
# conditions stay a single equality against 'true'.
printf 'HAS_CLAUDE_TOKEN=\n' >>"${github_env}"

# A fork PR is the expected case: secrets are withheld from it by GitHub, which
# is the platform working correctly. Anything else is worth an operator's
# attention — the repository is meant to have this secret, and a same-repo pull
# request that silently skips its review is a review nobody notices is missing.
#
# The distinction only changes the annotation level; both paths skip. Failing
# the same-repo case would trade a missing review for a red check on every pull
# request until the secret is restored, which is worse, and the warning is
# already visible on the run.
if [[ -n "${head_repo}" && -n "${this_repo}" && "${head_repo}" != "${this_repo}" ]]; then
	level='notice'
	title='Claude review skipped (fork pull request)'
	detail=(
		"This pull request comes from ${head_repo}, so GitHub withholds"
		'CLAUDE_CODE_OAUTH_TOKEN and id-token: write from the run. The review'
		'step and the commit-signing setup are both skipped; nothing here is'
		'broken and nothing needs to be re-run.'
	)
elif [[ "${actor}" == "${DEPENDABOT}" ]]; then
	# A Dependabot pull request is same-repo, so the fork test above does not
	# catch it, and without this branch it lands in the "misconfigured
	# repository" case below and tells the operator to set a secret that is
	# already set. It is a third thing.
	#
	# GitHub treats a run triggered by Dependabot from `push`, `pull_request`,
	# `pull_request_review` or `pull_request_review_comment` as if it came from
	# a fork, and resolves `secrets.*` from the *Dependabot* secrets store
	# rather than the Actions store. A CLAUDE_CODE_OAUTH_TOKEN that exists as
	# an Actions secret is therefore simply not visible here. The only fix is
	# to add it to the Dependabot store as well — no workflow file can do it,
	# and this script deliberately does not pretend otherwise.
	#
	# Notice rather than warning, because skipping is the correct outcome until
	# an operator makes that choice, and this is the platform behaving as
	# designed. Note what is NOT affected: pushing a mechanical fix to the
	# branch never depended on this run at all. That happens on the separate
	# trusted `workflow_run` path, which reads the ordinary Actions secrets —
	# see docs/dependabot-fix-path.md.
	level='notice'
	title='Claude review skipped (Dependabot secrets store)'
	detail=(
		'Dependabot-triggered runs resolve secrets from the Dependabot store, not'
		'the Actions store, so CLAUDE_CODE_OAUTH_TOKEN is not visible to this run'
		'even when it exists as an Actions secret. Add it under Settings >'
		'Secrets and variables > Dependabot to have Dependabot pull requests'
		'reviewed. Pushing mechanical fixes does not need this: that runs on the'
		'trusted workflow_run path (.github/workflows/claude-dependabot-fix.yml).'
	)
else
	level='warning'
	title='Claude review skipped (no CLAUDE_CODE_OAUTH_TOKEN)'
	detail=(
		'This run is not from a fork, so the secret was expected to be present.'
		'Set the CLAUDE_CODE_OAUTH_TOKEN repository secret to restore automated'
		'review. Commit signing is skipped too, because this job now has nothing'
		'left to sign.'
	)
fi

printf '::%s title=%s::%s\n' "${level}" "${title}" "${detail[0]}"
printf '  %s\n' "${detail[@]:1}"

if [[ -n "${GITHUB_STEP_SUMMARY-}" ]]; then
	{
		printf '### :zzz: %s\n\n' "${title}"
		printf '%s\n' "${detail[@]}"
	} >>"${GITHUB_STEP_SUMMARY}" || true
fi

exit 0
