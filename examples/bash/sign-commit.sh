#!/usr/bin/env bash

set -euo pipefail

# Configuration
BASE_URL="${BASE_URL:-https://gpg.kajkowalski.nl}"
OIDC_TOKEN="${OIDC_TOKEN:-}"
MAX_RETRIES="${MAX_RETRIES:-3}"
# Ceiling on a wait the *server* chose. Both retry branches below take an
# interval off the response — `Retry-After` on either status, `retryAfter` in a
# 429's body — and neither value is this script's. An unbounded one parks a CI
# job for as long as whatever answered feels like: a misconfigured origin, an
# intermediary with its own idea of a maintenance window, or simply a typo'd
# variable. The Go client clamps the same two hints to its own retryWaitMax for
# this reason; this is the shell equivalent.
MAX_RETRY_WAIT="${MAX_RETRY_WAIT:-120}"

# The wait taken when a retryable response names none this script can use.
DEFAULT_RETRY_WAIT=30

# Bounds on a single attempt. Not configurable, and deliberately: they are
# arguments to `curl`, not knobs, and every value read from the environment here
# is one more thing validate_config has to defend.
#
# curl's own defaults are a 300-second connect timeout and no ceiling at all on
# a transfer that connected and then stalled, so a black-holed TCP connect — a
# security group that drops rather than rejects, a proxy that accepts and never
# answers — parks the job indefinitely. That is the same CI time MAX_RETRY_WAIT
# exists to bound, arriving by the one route the clamp cannot see, and until
# curl gives up the transport-failure branch below never runs.
CONNECT_TIMEOUT_SECONDS=10
REQUEST_TIMEOUT_SECONDS=60

# Functions
log_info() {
	echo "[INFO] $*" >&2
}

log_error() {
	echo "[ERROR] $*" >&2
}

# Print a refusal the way it is meant to be read.
#
# The service answers with four separate things — what happened, which subject
# it was about, what to change, and where to read more — and dumping the raw
# envelope into the log buries all four in one wrapped line. So each goes on its
# own line, and only the ones that are present.
#
# `docs` is a short redirect (`<service>/e/<CODE>`) that lands on the section
# for that exact code.
log_service_error() {
	local http_code="$1" body="$2" field value

	log_error "HTTP ${http_code}: $(jq -r '.error // "no message"' <<<"${body}" 2>/dev/null || echo "${body}")"

	for field in code subject hint docs requestId; do
		value=$(jq -r --arg f "${field}" '.[$f] // empty' <<<"${body}" 2>/dev/null) || continue
		# `if` rather than `[[ ... ]] && ...`: the loop body's status becomes the
		# function's, and under `set -e` a missing *last* field — requestId, which
		# several refusal bodies legitimately omit — made the caller exit on the
		# spot instead of reaching its own `return 1`.
		if [[ -n ${value} ]]; then
			log_error "  ${field}: ${value}"
		fi
	done
}

# Reject an operator-supplied wait or attempt count before it reaches
# arithmetic.
#
# Both are read from the environment and both end up inside `(( ))` — and one
# inside `sleep`. `((wait > MAX_RETRY_WAIT))` with `MAX_RETRY_WAIT=abc` does not
# fail loudly: bash resolves a bare word as a *variable name*, finds it unset,
# and evaluates it as 0, so every server hint would silently clamp to zero and
# the retry loop would spin. `MAX_RETRY_WAIT='a[$(rm -rf x)]'` is worse — array
# subscripts inside an arithmetic context are evaluated. The check is a
# whitelist for that reason, not a blacklist.
#
# Nine digits is the cap because a wait is measured in seconds and anything
# longer is a typo, not a policy; it also keeps the arithmetic below well clear
# of the point where bash's intmax_t wraps.
validate_config() {
	local name value

	for name in MAX_RETRY_WAIT MAX_RETRIES; do
		value="${!name}"
		if [[ ! ${value} =~ ^[0-9]{1,9}$ ]] || ((10#${value} == 0)); then
			log_error "${name} must be a positive whole number, got: '${value}'"
			return 1
		fi
		# `10#` so a padded value like 030 is thirty seconds and not an octal
		# twenty-four, and so the normalised form is what every later `(( ))`
		# and `sleep` sees.
		printf -v "${name}" '%d' "$((10#${value}))"
	done
}

# The last `Retry-After` on the response, verbatim.
#
# Header names are case-insensitive and HTTP/1.1 line endings are CRLF, neither
# of which a naive `grep '^Retry-After: '` survives. The value is returned
# unparsed because both forms RFC 9110 §10.2.3 permits are legal here and only
# the reader below decides which one this is.
retry_after_header() {
	sed -n 's/^[Rr][Ee][Tt][Rr][Yy]-[Aa][Ff][Tt][Ee][Rr]:[[:space:]]*\(.*\)$/\1/p' <<<"${1-}" \
		| tr -d '\r' \
		| tail -1
}

# Convert a `Retry-After` value to whole seconds, or to nothing at all.
#
# RFC 9110 §10.2.3 permits delay-seconds *and* an absolute HTTP-date, and the
# date form is not hypothetical: intermediaries and CDNs emit IMF-fixdate
# freely, and the throttle most likely to answer a 429 in front of this service
# is exactly such an intermediary. Reading only integers turned every one of
# those into "no hint".
#
# Empty output means "no hint" rather than "no wait" — a date already in the
# past says nothing about how long to wait now, and neither does a value that
# parses as neither form. Callers fall back to their own default. This mirrors
# the Go client's parseRetryAfter.
retry_after_seconds() {
	local value deadline now
	value="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}")"
	[[ -n ${value} ]] || return 0

	if [[ ${value} =~ ^[0-9]+$ ]]; then
		# Zero is "no hint", not "immediately" — the reading the Go client's
		# retryAfterSeconds takes. Reported as nothing at all so a `Retry-After: 0`
		# lets the body value, and then the caller's default, answer instead of
		# turning the retry loop into a tight one against a dependency that has
		# just failed.
		[[ ${value} =~ ^0+$ ]] || printf '%s\n' "${value}"
		return 0
	fi

	# Only the three formats RFC 9110 §5.6.7 permits reach `date`, and the shape
	# is checked here rather than left to it. `date -d` is not a date parser but a
	# natural-language one: it reads `tomorrow` as +86400 and `5 seconds` as +5,
	# and neither is a `Retry-After`. Left ungated that leniency has teeth now
	# that the header outranks the body — a header of `tomorrow` beside a
	# perfectly good `retryAfter: 5` was read as a hint of a day, clamped to
	# MAX_RETRY_WAIT, and the body never consulted. The Go client's
	# `http.ParseTime` accepts these three and nothing else; so does this.
	local imf_fixdate rfc850 asctime
	imf_fixdate='^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Za-z]+$'
	rfc850='^[A-Za-z]{6,9}, [0-9]{2}-[A-Za-z]{3}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Za-z]+$'
	asctime='^[A-Za-z]{3} [A-Za-z]{3} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}$'
	[[ ${value} =~ ${imf_fixdate} || ${value} =~ ${rfc850} || ${value} =~ ${asctime} ]] || return 0

	# GNU date first, then the BSD/macOS spelling of each accepted form, so this
	# reads a date on a developer's laptop and not only on a Linux runner.
	deadline="$(date -u -d "${value}" +%s 2>/dev/null)" \
		|| deadline="$(date -u -j -f '%a, %d %b %Y %T %Z' "${value}" +%s 2>/dev/null)" \
		|| deadline="$(date -u -j -f '%A, %d-%b-%y %T %Z' "${value}" +%s 2>/dev/null)" \
		|| deadline="$(date -u -j -f '%a %b %e %T %Y' "${value}" +%s 2>/dev/null)" \
		|| return 0
	[[ ${deadline} =~ ^-?[0-9]+$ ]] || return 0

	now="$(date -u +%s)"
	if ((deadline > now)); then
		printf '%s\n' "$((deadline - now))"
	fi
}

# Clamp a server-chosen wait to MAX_RETRY_WAIT, and reject anything that is not
# a plain number of seconds.
#
# Everything reaching here came off a response, so "not a number" is a real
# case: an intermediary's malformed header, a JSON `retryAfter` of `null`, a
# date `retry_after_seconds` declined to read. Each lands on the caller's
# fallback instead of reaching `sleep` as a word it would refuse.
clamp_wait() {
	local wait="$1" fallback="$2" digits

	if [[ ! ${wait} =~ ^[0-9]+$ ]]; then
		wait="${fallback}"
	else
		# Leading zeros are padding, not magnitude. The length test below stands in
		# for "too large for bash's intmax_t", and measuring the *unpadded* form is
		# what makes it one: `Retry-After: 0000000005` is five seconds, and counting
		# its ten characters sent it to the ceiling instead. `strconv.Atoi` in the Go
		# client reads the same value as 5.
		digits="${wait#"${wait%%[!0]*}"}"
		if [[ -z ${digits} ]]; then
			# Zero is "no hint", not "immediately" — the same reading the Go client's
			# retryAfterSeconds takes. Sleeping 0 turns the retry loop into a tight one
			# against a dependency that has just failed.
			wait="${fallback}"
		elif ((${#digits} > 9)); then
			# Longer than any wait this script will honour anyway, and long enough
			# that `10#` below would overflow bash's intmax_t and arrive negative —
			# a wait that reads as one already past. The ceiling is the answer.
			wait="${MAX_RETRY_WAIT}"
		else
			wait="$((10#${digits}))"
		fi
	fi

	if ((wait > MAX_RETRY_WAIT)); then
		wait="${MAX_RETRY_WAIT}"
	fi
	echo "${wait}"
}

# How long a 429 asks the caller to wait, header first.
#
# The header is the HTTP-level authority and it is the one an intermediary can
# set, so it outranks the envelope: a throttle in front of this service answers
# with a page and a `Retry-After`, and a stale or optimistic `retryAfter` in a
# body underneath it would otherwise send the next attempt in before the thing
# doing the throttling permits one.
#
# The body is the fallback because this service's own limiter always writes
# `retryAfter` when it writes a body at all. `|| true`, and `empty` rather than
# a jq-side default: jq exits non-zero on an HTML error page, and under `set -e`
# an assignment taking its status ended the whole script right here — before the
# clamp, before `last_body` was recorded, and so before anything at all was
# printed about the refusal.
rate_limit_wait() {
	local headers="$1" body="$2" wait

	wait="$(retry_after_seconds "$(retry_after_header "${headers}")")"
	if [[ -z ${wait} ]]; then
		wait="$(jq -r '.retryAfter // empty' <<<"${body}" 2>/dev/null)" || wait=""
	fi

	clamp_wait "${wait}" "${DEFAULT_RETRY_WAIT}"
}

# How long a 503 asks the caller to wait.
#
# Retry-After is a header here and only a header: ErrorResponse declares no
# `retryAfter`, so there is no body value to prefer or fall back to.
degraded_wait() {
	clamp_wait "$(retry_after_seconds "$(retry_after_header "$1")")" "${DEFAULT_RETRY_WAIT}"
}

# Wait between two signing attempts — but only when another one is coming.
#
# `attempts_made` is the count *after* the attempt just refused, so once it
# reaches MAX_RETRIES the loop is over and this sleep would be paid for a retry
# that is never made. On a 503 with a ten-minute hint that is ten minutes of CI
# time spent to reach a failure the script already knows about.
sleep_before_retry() {
	local attempts_made="$1" wait_seconds="$2" reason="$3"

	if ((attempts_made >= MAX_RETRIES)); then
		log_info "${reason}; no attempt remains, not waiting ${wait_seconds}s"
		return 0
	fi

	log_info "${reason}, waiting ${wait_seconds}s..."
	sleep "${wait_seconds}"
}

check_requirements() {
	local required_tools=("curl" "jq" "git" "gpg" "uuidgen")
	for tool in "${required_tools[@]}"; do
		if ! command -v "${tool}" &>/dev/null; then
			log_error "Required tool not found: ${tool}"
			return 1
		fi
	done
}

get_oidc_token() {
	if [[ -z ${OIDC_TOKEN} ]]; then
		if [[ -z ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-} ]]; then
			log_error "OIDC token not provided and not in GitHub Actions"
			return 1
		fi

		log_info "Fetching OIDC token from GitHub Actions..."
		OIDC_TOKEN=$(curl -s -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
			"${ACTIONS_ID_TOKEN_REQUEST_URL:-}&audience=gpg-signing-service" | jq -r '.value')
	fi

	if [[ -z ${OIDC_TOKEN} || ${OIDC_TOKEN} == "null" ]]; then
		log_error "Failed to get OIDC token"
		return 1
	fi
}

import_public_key() {
	log_info "Importing public key from signing service..."

	local public_key
	public_key=$(curl -sf "${BASE_URL}/public-key")

	if [[ -z ${public_key} ]]; then
		log_error "Failed to retrieve public key"
		return 1
	fi

	echo "${public_key}" | gpg --import --quiet
	log_info "Public key imported successfully"
}

sign_commit() {
	local commit_ref="${1:-HEAD}"
	local keyid="${2:-}"
	local retry_count=0
	# The last refusal the retry loop swallowed. A 429 and a 503 both carry the
	# same actionable fields every other refusal does, and both are printed at
	# most once — after the retries run out — rather than on every attempt.
	local last_code="" last_body=""

	log_info "Signing commit: ${commit_ref}"

	# Get commit data
	local commit_data
	commit_data=$(git cat-file commit "${commit_ref}")

	# Build request URL
	local request_url="${BASE_URL}/sign"
	if [[ -n ${keyid} ]]; then
		request_url="${request_url}?keyId=${keyid}"
	fi

	# Retry logic
	while ((retry_count < MAX_RETRIES)); do
		log_info "Signing attempt $((retry_count + 1))/${MAX_RETRIES}..."

		local response http_code body request_id headers headers_file curl_status
		request_id=$(uuidgen) || true
		# Headers to a file, not just the body: `Retry-After` is a header on both
		# retryable statuses and has no field in the 503's envelope, so a body-only
		# read cannot see the one thing that response is telling the caller.
		headers_file=$(mktemp)
		curl_status=0
		response=$(curl -sw "\n%{http_code}" -D "${headers_file}" -X POST \
			--connect-timeout "${CONNECT_TIMEOUT_SECONDS}" \
			--max-time "${REQUEST_TIMEOUT_SECONDS}" \
			-H "Authorization: Bearer ${OIDC_TOKEN}" \
			-H "X-Request-ID: ${request_id}" \
			--data-raw "${commit_data}" \
			"${request_url}") || curl_status=$?
		headers=$(cat "${headers_file}" 2>/dev/null || true)
		rm -f "${headers_file}"

		# A non-zero curl exit means no response existed to have a status: DNS did
		# not resolve, TLS did not verify, the connection was refused or timed out.
		# Left unhandled it is not a quiet nothing — `set -e` ends the run on the
		# assignment above, with no line saying why, and the status the case below
		# would otherwise sort on is curl's `%{http_code}` of `000`, which is not a
		# refusal from this service and must not be reported as one.
		if ((curl_status != 0)); then
			log_error "No HTTP response from ${request_url}: curl exited ${curl_status}" \
				"(transport failure — DNS, TLS, connection or timeout; nothing was signed)"
			log_error "  requestId: ${request_id:-unavailable}"
			return 1
		fi

		# `sed '$d'` rather than `head -n -1`: a negative line count is a GNU
		# extension and BSD/macOS head refuses it outright, which would strand the
		# body on the same laptop the date fallback above exists to support. `<<<`
		# rather than `echo` for the same reason it is used elsewhere here — a body
		# that happens to start with `-n` is an argument to some echos, not output.
		http_code="$(tail -1 <<<"${response}")"
		body="$(sed '$d' <<<"${response}")"

		case "${http_code}" in
			200)
				log_info "Commit signed successfully"
				echo "${body}"
				return 0
				;;
			429)
				local retry_after
				retry_after="$(rate_limit_wait "${headers}" "${body}")"
				last_code="${http_code}" last_body="${body}"
				retry_count=$((retry_count + 1))
				sleep_before_retry "${retry_count}" "${retry_after}" "Rate limited"
				;;
			503)
				# SERVICE_DEGRADED: the service could not reach something it needs
				# — the issuer's JWKS, its authorization store — so nothing about
				# this request was judged. It is the one refusal the service invites
				# a caller to repeat, and the only one where waiting is the whole
				# fix.
				#
				# Every 503 from this service is that one, and every 503 carries a
				# Retry-After. The permanent fault — a deployment whose own
				# configuration stopped the request, which answers identically until
				# an operator changes it — is SERVICE_MISCONFIGURED and arrives as a
				# 500, so it never reaches this branch to be sorted out of it.
				local wait_seconds
				wait_seconds="$(degraded_wait "${headers}")"
				last_code="${http_code}" last_body="${body}"
				retry_count=$((retry_count + 1))
				sleep_before_retry "${retry_count}" "${wait_seconds}" "Service degraded"
				;;
			401)
				# AUTH_MISSING and AUTH_INVALID are the credential's problem;
				# AUTH_SUBJECT_UNTRUSTED means the credential was fine and the
				# identity is not authorized, which no amount of re-minting fixes.
				# The `code` field is what separates them; the `hint` says what to
				# do about it.
				log_service_error "${http_code}" "${body}"
				return 1
				;;
			*)
				# Everything else, 500 included, is reported once and not repeated.
				#
				# 500 is where SERVICE_MISCONFIGURED lands, and stopping is the
				# whole point of it having its own status: the service is telling
				# the caller that retrying gets this same answer every time. Adding
				# a generic 5xx retry above this would undo that — if you do, read
				# `.code` first and let SERVICE_MISCONFIGURED fall through to here.
				log_service_error "${http_code}" "${body}"
				return 1
				;;
		esac
	done

	log_error "Signing failed after ${MAX_RETRIES} attempts"
	# Without this the run ends on that one line and everything the service sent
	# — which code it was, what to change, where to read about it — is discarded
	# by the loop that was supposed to be handling it.
	if [[ -n ${last_body} ]]; then
		log_service_error "${last_code}" "${last_body}"
	fi
	return 1
}

main() {
	log_info "GPG Signing Service - Commit Signing"

	# Before anything reaches `(( ))` or `sleep`, and before the run spends a
	# token fetch and a key import on a configuration it will fail on later.
	validate_config
	check_requirements
	get_oidc_token
	import_public_key

	local signature
	signature=$(sign_commit "$@")

	log_info "Signature:"
	echo "${signature}"
}

# Only a direct run signs anything. The shell regression suite in
# .github/scripts/test-sign-commit-example.sh sources this file to exercise the
# retry and transport paths against stubbed responses, and must not sign a
# commit or reach the network to do it.
if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
	main "$@"
fi
