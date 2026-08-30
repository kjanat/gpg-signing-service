#!/usr/bin/env bash
# Decide, once per job and before any file has been edited, whether this run
# signs its commits — and if it cannot, say why in terms an operator can act on.
#
# Called by .github/actions/setup-claude-signing. The problem it exists for is
# ordering: git only invokes the signing shim when `git commit` runs, which in a
# Claude job is after the agent has already done its work. A service outage, a
# rotated key or an empty quota then surfaces as `git commit` exit 128 at the
# end of a run that cannot be salvaged. Asking the service one bounded question
# up front turns that into a setup-step failure with a named class.
#
#   usage:  signing-preflight.sh <service-url>
#
#   env:    GPG_SIGN_DISABLE               the escape hatch (see below)
#           ACTIONS_ID_TOKEN_REQUEST_URL   } checked for presence only;
#           ACTIONS_ID_TOKEN_REQUEST_TOKEN } never read, printed or forwarded
#           GPG_SIGN_PREFLIGHT_TIMEOUT     health-check budget, default 10s
#
#   exit:   0  sign — configuration is complete and the service answered healthy
#           3  do not sign — signing was deliberately disabled for this run
#           1  do not sign, and fail the job — the class is on the annotation
#
# 3 rather than 0 for the disabled case on purpose: a caller that forgets to
# check the status gets a failure, not a job that silently believes signing is
# configured when nothing was configured at all.
#
# Everything it prints goes to stdout, including the `::error` and `::warning`
# annotations, so the decision is never mixed into the channel the caller reads.
# The caller reads the exit status and nothing else.
set -Eeuo pipefail

readonly EXIT_SIGN=0
readonly EXIT_FAIL=1
readonly EXIT_DISABLED=3

readonly service_url="${1-}"
readonly disable="${GPG_SIGN_DISABLE-}"
readonly budget="${GPG_SIGN_PREFLIGHT_TIMEOUT:-10}"

# fail <class> <line>...
#
# One annotation naming the class, then the detail underneath it. The class is
# in the title as well as the body because GitHub's job summary shows titles
# only, and "Commit signing unavailable" alone is the exit 128 problem again
# one step earlier.
fail() {
	local class="$1"
	shift
	printf '::error title=Commit signing unavailable (%s)::%s\n' "${class}" "$1"
	shift
	local line
	for line in "$@"; do
		printf '  %s\n' "${line}"
	done
	exit "${EXIT_FAIL}"
}

# --- the escape hatch --------------------------------------------------------
#
# Checked before anything else, including the configuration guards. The hatch
# exists for the case where the service cannot sign, and an operator reaching
# for it during an outage should not also have to satisfy the configuration
# that only signing needs.
#
# An unrecognised value is a hard failure rather than a fall-through to "keep
# signing". Fail-closed would be the safe reading, but it is also the silent
# one: an operator who typed the value wrong during an incident would watch the
# run fail exactly as it did before, with nothing saying the hatch was ignored.
case "${disable,,}" in
	'' | 0 | false | no | off)
		;;
	1 | true | yes | on)
		printf '::warning title=Commit signing disabled::GPG_SIGN_DISABLE=%s — commits made by this run will NOT be signed by the signing service.\n' "${disable}"
		printf '  %s\n' \
			'This is the deliberate escape hatch, not a fallback: nothing in this job' \
			'pretends a signature was made. commit.gpgsign is left off, so commits' \
			'succeed and land unsigned, and any branch protection requiring signed' \
			'commits will reject them.' \
			'Clear the GPG_SIGN_DISABLE repository variable to restore signing.'
		# The annotation is easy to scroll past in a long log; the summary is not,
		# and an unsigned run is exactly the thing someone should notice later
		# without having been watching at the time.
		if [[ -n "${GITHUB_STEP_SUMMARY-}" ]]; then
			{
				printf '### :unlock: Commit signing disabled\n\n'
				# shellcheck disable=SC2016  # backticks are markdown here, not a subshell
				printf '`GPG_SIGN_DISABLE=%s` was set, so commits from this run are **unsigned**.\n' "${disable}"
			} >>"${GITHUB_STEP_SUMMARY}" || true
		fi
		exit "${EXIT_DISABLED}"
		;;
	*)
		fail CONFIG_DISABLE_VALUE \
			"GPG_SIGN_DISABLE is set to an unrecognised value: ${disable}" \
			'Use 1/true/yes/on to disable signing for this run, or 0/false/no/off' \
			'(or leave it unset) to sign. It is refused rather than ignored so a' \
			'typo cannot look like a service failure during an incident.'
		;;
esac

# --- configuration guards ----------------------------------------------------
#
# These ran in the action before the preflight existed and still have to run
# before it: an empty URL or a job without id-token: write is a failure the
# service cannot be asked about, and asking anyway would report it as an
# outage. They are here rather than in the action so that one shell suite
# covers every path into "signing is not configured".

if [[ -z "${service_url}" ]]; then
	fail CONFIG_SERVICE_URL \
		'service-url is empty' \
		'Set the SIGNING_SERVICE_URL repository variable, or pass service-url' \
		'to .github/actions/setup-claude-signing explicitly.'
fi

if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL-}" || -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN-}" ]]; then
	fail CONFIG_OIDC \
		'The job must grant id-token: write' \
		'The shim mints a fresh OIDC token per signature, so the request' \
		'variables have to be present in the job that configures signing.'
fi

# --- the bounded health check ------------------------------------------------
#
# `gpg-sign health` rather than curl: the Go client already owns the request
# semantics this needs — the timeout, the bounded retry, Retry-After, and the
# mapping from status and envelope onto a named code. A hand-rolled curl here
# would be a second, worse implementation of all four, and it would classify a
# 503 by status alone, which docs/troubleshooting.md is explicit does not
# separate SERVICE_DEGRADED from the two other things that wear one.
#
# So a missing binary is a preflight failure in its own right rather than a
# reason to fall back: the shim needs the same binary a few minutes later, and
# an install that did not happen is better named here than at `git commit`.
if ! command -v gpg-sign >/dev/null 2>&1; then
	fail CLIENT_MISSING \
		'gpg-sign is not on PATH' \
		'The signing shim runs the same binary for every commit, so this job' \
		'could not sign even if the service were healthy. Check the installer' \
		'step (uses: kjanat/gpg-signing-service) ran and succeeded.'
fi

# /health is unauthenticated, so the preflight sends no credential at all and
# has nothing to leak. `--token ''` is not needed — the client sends whatever
# GPG_SIGN_TOKEN holds — but the request that matters is the one the shim makes
# later, and proving the service is up is a strictly separate question from
# proving this job may use it. Authorization failures stay the shim's to report.
#
# Two bounds, because they fail differently: --timeout is the client's own
# deadline over the whole call including its retries, and `timeout` is the outer
# one for a client that never honours it. A setup step that hangs is the worst
# outcome here — it burns the job's minutes and reports nothing.
# Whole seconds, checked before anything does arithmetic with it. `$(( ))`
# evaluates its argument, so an unvalidated value here is a command substitution
# waiting to happen — the same hole .github/scripts/test-sign-commit-example.sh
# pins MAX_RETRY_WAIT against. A leading zero, a float or a suffix would also
# reach `timeout` and the client's flag parser as something neither accepts.
#
# Down here rather than at the top so the escape hatch keeps outranking every
# configuration check: an operator disabling signing during an incident should
# not be stopped by a setting only the health check reads.
if [[ ! "${budget}" =~ ^[1-9][0-9]*$ ]]; then
	fail CONFIG_PREFLIGHT_TIMEOUT \
		"GPG_SIGN_PREFLIGHT_TIMEOUT must be a whole number of seconds, got: ${budget}" \
		"It is fed to timeout(1) and to the client's --timeout flag, and it is" \
		'evaluated arithmetically, so it is refused rather than coerced.'
fi

if command -v timeout >/dev/null 2>&1; then
	# A margin over the client's own deadline, so the client wins the race in
	# the ordinary case and reports a classifiable error rather than being
	# killed and reporting nothing.
	hard_budget=$((budget + 5))
	bounded=(timeout "${hard_budget}")
else
	bounded=()
fi

health_output=''
health_rc=0
health_output="$(
	"${bounded[@]}" gpg-sign health \
		--url "${service_url}" \
		--timeout "${budget}s" 2>&1
)" || health_rc=$?

if [[ "${health_rc}" -eq 0 ]]; then
	printf '::notice title=Commit signing enabled::%s answered healthy; commits from this run will be signed by the service.\n' "${service_url}"
	exit "${EXIT_SIGN}"
fi

# shellcheck source-path=SCRIPTDIR source=gpg-sign-error-class.sh
. "${BASH_SOURCE[0]%/*}/gpg-sign-error-class.sh"

# 124 is what `timeout` exits with when it had to kill the command, and it is
# the one case with no diagnostic to classify: the client was still waiting.
if [[ "${health_rc}" -eq 124 && ${#bounded[@]} -gt 0 ]]; then
	class='SERVICE_UNREACHABLE'
else
	class="$(gpg_sign_error_class "${health_output}")"
fi

# The service's own words first, then ours. reportFailure in
# client/cmd/gpg-sign/explain.go already prints the subject, hint, docs link and
# request id one per line; re-summarising them would only lose detail.
mapfile -t health_lines <<<"${health_output}"
fail "${class}" \
	"gpg-sign health failed against ${service_url} (exit ${health_rc})" \
	"${health_lines[@]}" \
	"${class}: $(gpg_sign_error_summary "${class}")" \
	'To run this job without signing, set the GPG_SIGN_DISABLE repository' \
	'variable to 1 and re-run it; its commits will be unsigned. See' \
	'docs/troubleshooting.md#ci-commit-signing.'
