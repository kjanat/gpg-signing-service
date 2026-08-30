#!/usr/bin/env bash
# The two checks the agent-mode harness runs *during* a session, before it
# publishes anything.
#
# Agent mode hands the whole finish-the-job sequence to Claude: commit, push,
# `gh pr create`, one comment. Two things about that sequence are policy rather
# than judgement, so they are a script the prompt is told to run rather than a
# rule the prompt merely states.
#
#   attribution FILE...   Refuse text that carries AI/vendor attribution.
#
#     Tag mode used to append "Generated with Claude Code" to pull request
#     bodies (src/entrypoints/update-comment-link.ts) and to instruct the model
#     to sign its own output the same way (src/create-prompt/index.ts). Agent
#     mode does neither — `updateCommentLink` is guarded on a tracking comment
#     id that agent mode never creates — but the model has seen a great deal of
#     text that ends that way, and "please do not" is not a control. This is.
#
#   commits BASE_REF      The same scan over the commit messages in a range.
#
#   pr-token              Refuse to open a pull request with GITHUB_TOKEN.
#
#     GitHub does not raise workflow events for actions taken with a workflow's
#     own GITHUB_TOKEN. A pull request opened with it therefore arrives with no
#     CI at all: no checks, nothing for branch protection to require, and the
#     only fix is to close and reopen it by hand. claude-code-action normally
#     avoids this by exchanging its OIDC token for a Claude App installation
#     token and exporting that as GH_TOKEN before it starts the session
#     (src/entrypoints/run.ts), which is a *different* app identity and so does
#     raise events. That is a property of the action's internals, not of
#     anything we configure, so it is checked rather than assumed.
#
#   usage:  claude-agent-guard.sh attribution FILE...
#           claude-agent-guard.sh commits BASE_REF
#           claude-agent-guard.sh pr-token
#
#   env:    CLAUDE_HARNESS_DIR   optional; defaults to $RUNNER_TEMP/claude-harness
#           RUNNER_TEMP          used to locate the harness directory
#           GH_TOKEN             the session's token; hashed, never printed
#           CLAUDE_HARNESS_GH    optional; the gh binary, overridable in tests
#
#   exit:   0  the check passed
#           1  the check failed; stdout says which rule and where
#           2  the check could not be made (bad usage, missing inputs)
set -Eeuo pipefail

readonly gh_bin="${CLAUDE_HARNESS_GH:-gh}"
readonly harness_dir="${CLAUDE_HARNESS_DIR:-${RUNNER_TEMP:-/tmp}/claude-harness}"

# Extended regular expressions, matched case-insensitively. Deliberately about
# *attribution*, not about the word "Claude": a pull request body may need to
# say "claude-code-action" or link to Anthropic's docs, and a rule that made
# that impossible would be worked around rather than followed.
#
# ${decor} is what may sit between the phrase and the vendor name once the
# footer is dressed up: markdown emphasis, a link, a code span, an emoji, an
# HTML tag, punctuation, whitespace. It exists because the first cut of this
# list matched `Generated with Claude Code` and not
# `Generated with **Claude Code**`, and the second is what a markdown pull
# request body actually looks like.
#
# Two properties keep it from swallowing prose. Alphanumerics are excluded
# except inside an HTML tag, so "generated with the claude-code-action" is
# still a sentence and still allowed; and the run is bounded, so "generated"
# and "claude" at opposite ends of a line are not each other's footer.
readonly decor='([^[:alnum:]]|<[a-z/]{1,8}>){0,12}'

readonly -a BANNED_PATTERNS=(
	"generated${decor}(with|by)${decor}(claude|anthropic)"
	"created${decor}(with|by)${decor}claude"
	"(co-authored|signed-off)-by:?${decor}(claude|anthropic)"
	'claude\.(ai|com)/(code|session|chat|share)'
	"🤖${decor}generated"
	"(powered|assisted|written)${decor}by:?${decor}claude"
	"via${decor}claude code action"
)

readonly -a BANNED_NAMES=(
	'"Generated with/by Claude/Anthropic" footer'
	'"Created with Claude" footer'
	'Co-Authored-By / Signed-off-by: Claude/Anthropic trailer'
	'claude.ai session/code link'
	'robot-emoji generated-by sign-off'
	'"powered/assisted/written by Claude" attribution'
	'"via Claude Code Action" attribution'
)

# The two arrays are indexed together, so a pattern added without its name
# would report the wrong rule — or nothing at all — on the refusal it causes.
if ((${#BANNED_PATTERNS[@]} != ${#BANNED_NAMES[@]})); then
	printf '::error title=Claude harness: usage::BANNED_PATTERNS (%d) and BANNED_NAMES (%d) are out of step\n' \
		"${#BANNED_PATTERNS[@]}" "${#BANNED_NAMES[@]}"
	exit 2
fi

fail() {
	printf '::error title=Claude harness: %s::%s\n' "$1" "$2"
	shift 2
	if (($# > 0)); then printf '  %s\n' "$@"; fi
	exit 1
}

# scan_stream LABEL — read stdin, refuse on the first banned pattern.
scan_stream() {
	local label="$1" text index pattern hit
	text="$(cat)"

	for index in "${!BANNED_PATTERNS[@]}"; do
		pattern="${BANNED_PATTERNS[index]}"
		if hit="$(grep -inE -m1 -- "${pattern}" <<<"${text}")"; then
			fail 'attribution policy' \
				"${label} contains ${BANNED_NAMES[index]}." \
				"Offending line: ${hit}" \
				'Pull request titles, pull request bodies and status comments in this' \
				'repository are the maintainer'"'"'s own words. Remove the attribution and' \
				're-run this check. See docs/claude-agent-harness.md.'
		fi
	done

	printf 'ok: %s carries no AI attribution\n' "${label}"
}

case "${1-}" in
	attribution)
		shift
		if (($# == 0)); then
			printf '::error title=Claude harness: usage::attribution needs at least one file\n'
			exit 2
		fi
		for file in "$@"; do
			if [[ ! -r "${file}" ]]; then
				printf '::error title=Claude harness: usage::%s is not readable\n' "${file}"
				exit 2
			fi
			# shellcheck disable=SC2094  # the redirect only reads; scan_stream writes nothing
			scan_stream "${file}" <"${file}"
		done
		;;

	commits)
		base="${2-}"
		if [[ -z "${base}" ]]; then
			printf '::error title=Claude harness: usage::commits needs a base ref\n'
			exit 2
		fi
		if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
			printf '::error title=Claude harness: usage::%s is not a commit this repository knows\n' "${base}"
			exit 2
		fi
		# %B is the whole message, subject and body, for every commit that is on
		# HEAD and not on the base. A trailer added by a tool lands here.
		git log --format='%h %B' "${base}..HEAD" | scan_stream "commit messages in ${base}..HEAD"
		;;

	pr-token)
		token="${GH_TOKEN:-${GITHUB_TOKEN-}}"
		if [[ -z "${token}" ]]; then
			printf '::error title=Claude harness: usage::GH_TOKEN is not set; nothing to check\n'
			exit 2
		fi

		digest_file="${harness_dir}/workflow-token.sha256"
		if [[ ! -r "${digest_file}" ]]; then
			printf '::error title=Claude harness: usage::%s is missing; claude-agent-harness.sh did not run\n' "${digest_file}"
			exit 2
		fi

		workflow_digest="$(tr -d '[:space:]' <"${digest_file}")"
		session_digest="$(printf '%s' "${token}" | sha256sum | cut -d' ' -f1)"

		if [[ "${session_digest}" == "${workflow_digest}" ]]; then
			fail 'pull request would arrive with no CI' \
				'This session is authenticated as the workflow GITHUB_TOKEN.' \
				'GitHub raises no workflow events for actions taken with a workflow'"'"'s own' \
				'token, so a pull request opened now would have zero checks and branch' \
				'protection would have nothing to require. Do not open it.' \
				'Expected the Claude App installation token that claude-code-action exports' \
				'as GH_TOKEN before starting the session. If GH_TOKEN is being overridden in' \
				'the workflow step env, remove that override.'
		fi

		# Best-effort corroboration: an installation token can enumerate the
		# installation's repositories. A failure here is not proof of anything —
		# the endpoint can be unreachable — so it warns rather than refuses. The
		# digest comparison above is the actual gate.
		if ! "${gh_bin}" api /installation/repositories --jq '.total_count' >/dev/null 2>&1; then
			printf '::warning title=Claude harness::Could not confirm the session token is an App installation token; the GITHUB_TOKEN check still passed\n'
		fi

		printf 'ok: session token is not the workflow GITHUB_TOKEN; a pull request opened now will trigger normal CI\n'
		;;

	*)
		printf 'usage: %s attribution FILE...\n' "${0##*/}"
		printf '       %s commits BASE_REF\n' "${0##*/}"
		printf '       %s pr-token\n' "${0##*/}"
		exit 2
		;;
esac
