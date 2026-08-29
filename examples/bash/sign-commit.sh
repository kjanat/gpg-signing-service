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
#
# Every request the script makes takes them, not only the signing one: the token
# fetch and the key import are the same hang for the same reason, and bounding
# one call in a script that makes three bounds nothing.
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
# Two outcomes, and they are not the same statement:
#
#   - Nothing at all — "no hint". The value was absent, or is not one of the
#     forms the grammar admits: `soon-ish`, `tomorrow`, or a `-30` that
#     delay-seconds (1*DIGIT) does not cover. The caller goes on to its next
#     source.
#   - A number, which may be `0` — a hint of zero. `Retry-After: 0` is a valid
#     delay-seconds value and a date already past has a remaining delay of
#     zero; in both, the responder is saying the wait is already over, which is
#     not the same as saying nothing. Every value that parses is reported as
#     max(0, delay) for that reason.
#
# Keeping those apart is what lets a header outrank a body that disagrees with
# it even when the header says zero. The Go client's parseRetryAfter cannot
# draw the same line — it returns a time.Duration whose zero value *is* its "no
# hint" — so this is the one place the two read a header differently. The
# immediate retries that result are still bounded by MAX_RETRIES.
retry_after_seconds() {
	local value deadline now
	value="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}")"
	[[ -n ${value} ]] || return 0

	if [[ ${value} =~ ^[0-9]+$ ]]; then
		printf '%s\n' "${value}"
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
	#
	# `GMT` is matched literally, not as a zone abbreviation, because §5.6.7
	# spells it that way and `date -d` does not: it reads `CEST` as +0200 and
	# `EST` as -0500. A `Retry-After` five minutes out labelled `CEST` came back
	# as a moment two hours *past* — a hint of zero, which then outranked a
	# `retryAfter: 60` in the body and sent every remaining attempt in at once,
	# at a throttle that had just asked for a wait. `http.TimeFormat` has the
	# same literal for the same reason.
	local imf_fixdate rfc850 asctime
	imf_fixdate='^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$'
	rfc850='^[A-Za-z]{6,9}, [0-9]{2}-[A-Za-z]{3}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$'
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
	else
		# The date read, and it has already come round: the remaining delay is
		# zero, not unknown. Reported as `0` so the responder that named a moment
		# now passed still gets the last word over a body value written before it.
		printf '0\n'
	fi
}

# Clamp a server-chosen wait to MAX_RETRY_WAIT, and reject anything that is not
# a plain number of seconds.
#
# Everything reaching here came off a response, so "not a number" is a real
# case: an intermediary's malformed header, a JSON `retryAfter` of `null`, a
# date `retry_after_seconds` declined to read. Each lands on the caller's
# fallback instead of reaching `sleep` as a word it would refuse.
#
# The output is therefore always a whole number of seconds in 0..MAX_RETRY_WAIT
# — bounded and nonnegative — whatever the response said.
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
			# All padding and no magnitude: a hint of zero, honoured as itself rather
			# than swapped for the fallback. It can only have come from a value that
			# parsed — a `Retry-After: 0`, a date already past, a `retryAfter` of 0 —
			# and each of those is the responder saying the wait is over. The fallback
			# belongs to the values that said nothing at all.
			wait=0
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
# A header of `0` keeps that precedence. It parses, so it is a hint, and
# `retry_after_seconds` reports it as `0` rather than as nothing — which is the
# whole reason that function separates the two. A throttle saying the window has
# just cleared is not overruled by a `retryAfter: 60` written underneath it
# before the window elapsed.
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
#
# A wait of zero is the other case where nothing is waited on: the response
# named a moment that has already arrived. `sleep 0` is a process spawned to
# accomplish nothing, and "waiting 0s..." in the log reads as a bug in the
# script rather than as what the responder asked for.
sleep_before_retry() {
	local attempts_made="$1" wait_seconds="$2" reason="$3"

	if ((attempts_made >= MAX_RETRIES)); then
		log_info "${reason}; no attempt remains, not waiting ${wait_seconds}s"
		return 0
	fi

	if ((wait_seconds == 0)); then
		log_info "${reason}; the response says the wait is over, retrying now"
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

# A curl that fails here has to say so for the same reason the signing one does.
#
# `OIDC_TOKEN=$(curl ... | jq ...)` takes the pipeline's status, and under
# `set -euo pipefail` a refused connect or an expired --max-time ended the whole
# run on that assignment — before the `[[ -z ${OIDC_TOKEN} ]]` check below,
# which is what was supposed to report it. The run stopped after "Fetching OIDC
# token..." with no [ERROR] line and curl's exit status as the script's own.
# Bounding the request without saying what happened when the bound is hit only
# turns a hang into a silent stop.
#
# Both request variables are checked, not just the token: Actions sets them
# together, and an empty URL made the curl above fetch the literal
# `&audience=...`.
get_oidc_token() {
	local token_response curl_status

	if [[ -z ${OIDC_TOKEN} ]]; then
		if [[ -z ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-} || -z ${ACTIONS_ID_TOKEN_REQUEST_URL:-} ]]; then
			log_error "OIDC token not provided and not in GitHub Actions"
			return 1
		fi

		log_info "Fetching OIDC token from GitHub Actions..."
		curl_status=0
		token_response=$(curl -s \
			--connect-timeout "${CONNECT_TIMEOUT_SECONDS}" \
			--max-time "${REQUEST_TIMEOUT_SECONDS}" \
			-H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
			"${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=gpg-signing-service") || curl_status=$?

		if ((curl_status != 0)); then
			log_error "No response from the Actions token endpoint: curl exited ${curl_status}" \
				"(transport failure — DNS, TLS, connection or timeout; nothing was signed)"
			return 1
		fi

		# `empty` and a fallback, not a bare `.value`: the endpoint answers a
		# refusal with a JSON object jq reads fine and with no `.value` in it,
		# and it answers a proxy's interception with HTML that jq refuses
		# outright. Both are "no token", and the check below is what says so.
		OIDC_TOKEN=$(jq -r '.value // empty' <<<"${token_response}" 2>/dev/null) || OIDC_TOKEN=""
	fi

	if [[ -z ${OIDC_TOKEN} || ${OIDC_TOKEN} == "null" ]]; then
		log_error "Failed to get OIDC token"
		return 1
	fi
}

import_public_key() {
	log_info "Importing public key from signing service..."

	local public_key curl_status=0

	# `-sf` makes curl exit non-zero on a 4xx or 5xx as well as on a transport
	# fault, and the assignment takes that status: unhandled, `set -e` ended the
	# run right here and the `[[ -z ${public_key} ]]` check below — the line that
	# names the failure — was unreachable for every way of failing except a 200
	# with an empty body.
	public_key=$(curl -sf \
		--connect-timeout "${CONNECT_TIMEOUT_SECONDS}" \
		--max-time "${REQUEST_TIMEOUT_SECONDS}" \
		"${BASE_URL}/public-key") || curl_status=$?

	if ((curl_status != 0)) || [[ -z ${public_key} ]]; then
		log_error "Failed to retrieve public key from ${BASE_URL}/public-key (curl exited ${curl_status})"
		return 1
	fi

	# Piped, so `pipefail` gives the pipeline gpg's status; without the guard a
	# key gpg refuses stops the run as wordlessly as the curl above did.
	if ! gpg --import --quiet <<<"${public_key}"; then
		log_error "gpg refused the public key served by ${BASE_URL}/public-key"
		return 1
	fi
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
				# this request was judged. Waiting is the whole fix, and it is the
				# one refusal that says how long: a Retry-After, which degraded_wait
				# prefers over the default.
				#
				# It is not the only 503 that reaches here, though. RATE_LIMIT_ERROR
				# is the other one — the limiter itself was unreachable or answered
				# with an error, so the request went unjudged for a different reason —
				# and it is worth repeating for the same reason. It carries no
				# Retry-After: the limiter never answered, so there is no interval to
				# quote. degraded_wait already handles that, falling back to
				# DEFAULT_RETRY_WAIT, and this branch wants it to: a missing hint is
				# not a stop signal, only an absent one.
				#
				# The permanent fault — a deployment whose own configuration stopped
				# the request, which answers identically until an operator changes it
				# — is SERVICE_MISCONFIGURED and arrives as a 500, so it never reaches
				# this branch to be sorted out of it.
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
