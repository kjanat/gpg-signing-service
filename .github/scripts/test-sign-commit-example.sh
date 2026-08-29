#!/usr/bin/env bash

# Regression coverage for examples/bash/sign-commit.sh.
#
# The example is the only client in this repository with no unit test runner of
# its own, and the parts of it that are easiest to get wrong are the ones that
# only run against a response nobody has locally: a `Retry-After` header from an
# intermediary, a 429 whose body disagrees with that header, a curl that never
# reached the service at all. So this suite sources the example — which is why
# it guards its `main` — and drives those functions against canned responses.
#
# Nothing here reaches the network, signs a commit, or waits: `curl`, `sleep`,
# `uuidgen` and `git cat-file` are shadowed by shell functions inside a subshell
# per scenario, and the recorded sleeps are what several of the assertions are
# about.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
example="${repo_root}/examples/bash/sign-commit.sh"

stub_dir="$(mktemp -d)"
cleanup() { rm -rf "${stub_dir}"; }
trap cleanup EXIT

failures=0
checks=0

ok() {
	checks=$((checks + 1))
	printf '[ok] %s\n' "$1"
}

fail() {
	checks=$((checks + 1))
	failures=$((failures + 1))
	printf '[FAIL] %s\n' "$1" >&2
}

expect_eq() {
	local name="$1" want="$2" got="$3"
	if [[ ${want} == "${got}" ]]; then
		ok "${name}"
	else
		fail "${name}: want '${want}', got '${got}'"
	fi
}

expect_contains() {
	local name="$1" needle="$2" haystack="$3"
	if [[ ${haystack} == *"${needle}"* ]]; then
		ok "${name}"
	else
		fail "${name}: expected output to contain '${needle}', got: ${haystack}"
	fi
}

expect_between() {
	local name="$1" low="$2" high="$3" got="$4"
	if [[ ${got} =~ ^[0-9]+$ ]] && ((got >= low && got <= high)); then
		ok "${name}"
	else
		fail "${name}: want ${low}..${high}, got '${got}'"
	fi
}

# `source`, not run: the example's trailing guard keeps main() for a direct
# invocation only.
# shellcheck source=../../examples/bash/sign-commit.sh disable=SC1091
source "${example}"

http_date() { date -u -d "$1" '+%a, %d %b %Y %H:%M:%S GMT'; }
# The two obsolete forms RFC 9110 §5.6.7 still requires a recipient to accept.
rfc850_date() { date -u -d "$1" '+%A, %d-%b-%y %H:%M:%S GMT'; }
asctime_date() { date -u -d "$1" '+%a %b %e %H:%M:%S %Y'; }

crlf_headers() {
	# What curl -D actually writes: a status line, CRLF endings, and header
	# names in whatever case the responder chose.
	printf 'HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/html\r\n'
	local header
	for header in "$@"; do
		printf '%s\r\n' "${header}"
	done
	printf '\r\n'
}

### Header reading -----------------------------------------------------------

expect_eq "retry_after_header reads a CRLF header" \
	"7" "$(retry_after_header "$(crlf_headers 'Retry-After: 7')")"

expect_eq "retry_after_header is case-insensitive" \
	"7" "$(retry_after_header "$(crlf_headers 'retry-after: 7')")"

expect_eq "retry_after_header takes the last of a repeated header" \
	"9" "$(retry_after_header "$(crlf_headers 'Retry-After: 4' 'Retry-After: 9')")"

expect_eq "retry_after_header reports nothing when the header is absent" \
	"" "$(retry_after_header "$(crlf_headers 'X-Other: 1')")"

### Retry-After value forms --------------------------------------------------

expect_eq "delta-seconds are read as seconds" "12" "$(retry_after_seconds "12")"
expect_eq "surrounding whitespace does not defeat the parse" "12" "$(retry_after_seconds "  12  ")"
expect_eq "a value that is neither form is no hint" "" "$(retry_after_seconds "soon-ish")"
expect_eq "an empty value is no hint" "" "$(retry_after_seconds "")"
# Not delay-seconds at all: the grammar is 1*DIGIT, so this is malformed rather
# than a wait to be floored at zero, and the caller's next source answers.
expect_eq "a negative delta is no hint" "" "$(retry_after_seconds "-30")"

expect_between "an HTTP-date is the remaining wait" 5 10 \
	"$(retry_after_seconds "$(http_date '+8 seconds')")"

# The two zero-delay forms. Both are the responder saying the wait is already
# over, which is a hint of zero and not the absence of one — the distinction the
# precedence assertions below rest on.
expect_eq "a zero delta is a hint of zero, not an absent one" "0" "$(retry_after_seconds "0")"
expect_eq "a padded zero delta is still a hint" "00" "$(retry_after_seconds "00")"
expect_eq "an HTTP-date already past has no remaining delay" "0" \
	"$(retry_after_seconds "$(http_date '-60 seconds')")"
expect_eq "an HTTP-date of this second has no remaining delay" "0" \
	"$(retry_after_seconds "$(http_date 'now')")"

expect_between "an RFC 850 date is read" 295 300 \
	"$(retry_after_seconds "$(rfc850_date '+300 seconds')")"

expect_between "an asctime date is read" 295 300 \
	"$(retry_after_seconds "$(asctime_date '+300 seconds')")"

# `date -d` is a natural-language parser, not a date parser: ungated it reads
# `tomorrow` as +86400 and `5 seconds` as +5. Neither is a `Retry-After`, and
# accepting them lets a malformed header outrank a good body value below.
expect_eq "a relative expression is not an HTTP-date" "" "$(retry_after_seconds "tomorrow")"
expect_eq "a bare duration is not an HTTP-date" "" "$(retry_after_seconds "5 seconds")"
expect_eq "a weekday name alone is not an HTTP-date" "" "$(retry_after_seconds "next friday")"
expect_eq "an epoch spelling is not an HTTP-date" "" "$(retry_after_seconds "@1735689600")"

### Clamping -----------------------------------------------------------------

MAX_RETRY_WAIT=120

expect_eq "a server hint under the ceiling is honoured" "45" "$(clamp_wait 45 30)"
expect_eq "a server hint over the ceiling is clamped" "120" "$(clamp_wait 99999 30)"
expect_eq "a non-numeric hint falls back" "30" "$(clamp_wait "tomorrow" 30)"
expect_eq "an empty hint falls back" "30" "$(clamp_wait "" 30)"
expect_eq "a zero hint is honoured, not replaced by the fallback" "0" "$(clamp_wait 0 30)"
expect_eq "a padded hint is decimal, not octal" "30" "$(clamp_wait 030 30)"
expect_eq "a negative hint is not a number and falls back" "30" "$(clamp_wait -5 30)"
expect_eq "a hint too large for the arithmetic is clamped, not wrapped" "120" \
	"$(clamp_wait 99999999999999999999 30)"
# The length test is a stand-in for "too large for the arithmetic", so it has to
# measure magnitude and not padding: ten characters of `0000000005` are still
# five seconds.
expect_eq "a long but small padded hint is its value, not the ceiling" "5" \
	"$(clamp_wait 0000000005 30)"
expect_eq "a padded zero is a zero hint, not the fallback" "0" "$(clamp_wait 0000000000 30)"

### Header precedence over the body ------------------------------------------

rate_limited_body='{"error":"Rate limit exceeded","code":"RATE_LIMITED","retryAfter":60}'

expect_eq "a valid header outranks the body's retryAfter" "5" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 5')" "${rate_limited_body}")"

expect_eq "an HTTP-date header still outranks the body" "5" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 5')" '{"retryAfter":1}')"

expect_between "an HTTP-date header is used in place of the body" 5 10 \
	"$(rate_limit_wait "$(crlf_headers "Retry-After: $(http_date '+8 seconds')")" "${rate_limited_body}")"

expect_eq "the body answers when there is no header" "60" \
	"$(rate_limit_wait "$(crlf_headers)" "${rate_limited_body}")"

expect_eq "the body answers when the header is unreadable" "60" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: whenever')" "${rate_limited_body}")"

# The header outranking the body is only safe if "unreadable" is decided
# strictly. `tomorrow` is a value `date -d` accepts and RFC 9110 does not, and
# taking it as a hint clamped every such response to MAX_RETRY_WAIT while the
# body's real interval sat unread.
expect_eq "a header date-ish enough for date(1) does not outrank the body" "5" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: tomorrow')" '{"retryAfter":5}')"

expect_eq "a padded header hint is its value, not the ceiling" "5" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 0000000005')" "${rate_limited_body}")"

# The two zero-delay headers keep their precedence over a body that disagrees.
# The responder that set the header is the one doing the throttling; a
# `retryAfter: 60` written underneath it was written before the window elapsed.
expect_eq "a zero header outranks a body that disagrees" "0" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 0')" "${rate_limited_body}")"

expect_eq "a padded zero header outranks the body too" "0" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 00')" "${rate_limited_body}")"

expect_eq "a header date already past outranks the body" "0" \
	"$(rate_limit_wait "$(crlf_headers "Retry-After: $(http_date '-60 seconds')")" "${rate_limited_body}")"

# A value the grammar does not admit is not a zero-delay one: it is no hint at
# all, and the body is what answers.
expect_eq "a negative header is malformed, so the body answers" "60" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: -30')" "${rate_limited_body}")"

expect_eq "a zero header with no body value is still zero" "0" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 0')" '<html><body>429</body></html>')"

expect_eq "a header hint over the ceiling is clamped, not taken from the body" "120" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 9000')" "${rate_limited_body}")"

expect_eq "an HTML page from an edge throttle does not defeat the header" "5" \
	"$(rate_limit_wait "$(crlf_headers 'Retry-After: 5')" '<html><body>429</body></html>')"

expect_eq "an HTML page with no header falls back to the default" "30" \
	"$(rate_limit_wait "$(crlf_headers)" '<html><body>429</body></html>')"

expect_eq "a 503 reads its wait off the header" "15" \
	"$(degraded_wait "$(crlf_headers 'Retry-After: 15')")"

expect_eq "a 503 with no readable header falls back to the default" "30" \
	"$(degraded_wait "$(crlf_headers)")"

# The 503 has no body field to fall back to, so an invented default here would
# be this script overruling the only thing the response said.
expect_eq "a 503 zero header is a zero wait, not the default" "0" \
	"$(degraded_wait "$(crlf_headers 'Retry-After: 0')")"

expect_eq "a 503 header date already past is a zero wait, not the default" "0" \
	"$(degraded_wait "$(crlf_headers "Retry-After: $(http_date '-60 seconds')")")"

### The retry loop -----------------------------------------------------------

# Drive sign_commit against canned responses. Every external command it reaches
# is shadowed here, and the subshell keeps the shadowing out of the assertions
# above and below.
#
#   STUB_CODES       status per attempt, space separated; the last repeats
#   STUB_HEADERS     header block returned for every attempt
#   STUB_BODY        response body returned for every attempt
#   STUB_CURL_EXIT   curl's exit status, for the transport-failure case
#   STUB_TRACE_ARGS  file the last curl argv is written to, when set
run_sign_commit() (
	local codes attempt_file
	read -ra codes <<<"${STUB_CODES}"
	attempt_file="${stub_dir}/attempts"
	printf '0\n' >"${attempt_file}"
	: >"${stub_dir}/sleeps"

	# shellcheck disable=SC2329  # reached through the sourced sign_commit
	curl() {
		local arg prev="" dump="" attempt code
		for arg in "$@"; do
			[[ ${prev} == "-D" ]] && dump="${arg}"
			prev="${arg}"
		done

		attempt=$(($(cat "${attempt_file}") + 1))
		printf '%s\n' "${attempt}" >"${attempt_file}"

		[[ -n ${STUB_TRACE_ARGS:-} ]] && printf '%s\n' "$*" >"${STUB_TRACE_ARGS}"

		if ((${STUB_CURL_EXIT:-0} != 0)); then
			# curl writes nothing usable when the connection never happened.
			return "${STUB_CURL_EXIT}"
		fi

		if ((attempt <= ${#codes[@]})); then
			code="${codes[attempt - 1]}"
		else
			code="${codes[-1]}"
		fi

		[[ -n ${dump} ]] && printf '%s' "${STUB_HEADERS}" >"${dump}"
		# The shape `-sw "\n%{http_code}"` produces: body, then the status.
		printf '%s\n%s\n' "${STUB_BODY}" "${code}"
	}

	# shellcheck disable=SC2329  # reached through the sourced sign_commit
	sleep() { printf '%s\n' "$1" >>"${stub_dir}/sleeps"; }
	# shellcheck disable=SC2329  # reached through the sourced sign_commit
	uuidgen() { printf 'stub-request-id\n'; }
	# shellcheck disable=SC2329  # reached through the sourced sign_commit
	git() {
		if [[ ${1-} == "cat-file" ]]; then
			printf 'tree 0000000000000000000000000000000000000000\n'
			return 0
		fi
		command git "$@"
	}

	sign_commit HEAD
)

sleeps() { cat "${stub_dir}/sleeps"; }
sleep_count() { grep -c . "${stub_dir}/sleeps" || true; }
attempts() { cat "${stub_dir}/attempts"; }

MAX_RETRIES=3
MAX_RETRY_WAIT=120
# Read by the sourced sign_commit, not by anything in this file.
# shellcheck disable=SC2034
OIDC_TOKEN=stub-token
# shellcheck disable=SC2034
BASE_URL=https://signing.example.test

# Every attempt refused, header and body disagreeing: the header's wait is the
# one slept, and the third refusal — after which no attempt remains — is not
# slept on at all.
status=0
STUB_CODES="429" \
	STUB_HEADERS="$(crlf_headers 'Retry-After: 5')" \
	STUB_BODY="${rate_limited_body}" \
	output="$(run_sign_commit 2>&1)" || status=$?

expect_eq "an exhausted 429 retry fails" "1" "${status}"
expect_eq "every allowed attempt is made" "3" "$(attempts)"
expect_eq "the last allowed 429 is not slept on" "2" "$(sleep_count)"
expect_eq "each sleep used the header's wait, not the body's" "5
5" "$(sleeps)"
expect_contains "the swallowed refusal is reported once the retries run out" \
	"code: RATE_LIMITED" "${output}"
expect_contains "the final response says no attempt remains" \
	"no attempt remains" "${output}"

# The 503 path: Retry-After is a header and only a header there.
status=0
STUB_CODES="503" \
	STUB_HEADERS="$(crlf_headers 'Retry-After: 4')" \
	STUB_BODY='{"error":"Service temporarily unavailable","code":"SERVICE_DEGRADED"}' \
	output="$(run_sign_commit 2>&1)" || status=$?

expect_eq "an exhausted 503 retry fails" "1" "${status}"
expect_eq "the last allowed 503 is not slept on" "2" "$(sleep_count)"
expect_eq "the 503 slept on its header's wait" "4
4" "$(sleeps)"
expect_contains "the swallowed 503 is reported" "SERVICE_DEGRADED" "${output}"

# A `Retry-After: 0` against a body that disagrees: the header wins all the way
# through the loop, so every allowed attempt is made and none of them is slept
# on — not the body's sixty seconds, and not `sleep 0` either. MAX_RETRIES is
# what bounds the immediate retries.
status=0
STUB_CODES="429" \
	STUB_HEADERS="$(crlf_headers 'Retry-After: 0')" \
	STUB_BODY="${rate_limited_body}" \
	output="$(run_sign_commit 2>&1)" || status=$?

expect_eq "a zero-wait 429 loop still exhausts and fails" "1" "${status}"
expect_eq "a zero-wait 429 loop makes every allowed attempt" "3" "$(attempts)"
expect_eq "a zero-wait 429 loop never sleeps, and never on the body's wait" "0" "$(sleep_count)"
expect_contains "a zero wait is reported as an immediate retry" \
	"the wait is over, retrying now" "${output}"

# The same on a 503, where the header is the only source there is: a date that
# has already come round is a zero wait, not the invented default.
status=0
STUB_CODES="503" \
	STUB_HEADERS="$(crlf_headers "Retry-After: $(http_date '-60 seconds')")" \
	STUB_BODY='{"error":"Service temporarily unavailable","code":"SERVICE_DEGRADED"}' \
	output="$(run_sign_commit 2>&1)" || status=$?

expect_eq "a 503 with a past date still exhausts and fails" "1" "${status}"
expect_eq "a 503 with a past date makes every allowed attempt" "3" "$(attempts)"
expect_eq "a 503 with a past date does not sleep the default" "0" "$(sleep_count)"

# A single retryable response followed by success: one sleep, and the signature
# on stdout.
status=0
STUB_CODES="429 200" \
	STUB_HEADERS="$(crlf_headers 'Retry-After: 3')" \
	STUB_BODY='{"signature":"-----BEGIN PGP SIGNATURE-----"}' \
	output="$(run_sign_commit 2>/dev/null)" || status=$?

expect_eq "a retried request that succeeds returns success" "0" "${status}"
expect_eq "only the refusal that had a retry left was slept on" "3" "$(sleeps)"
expect_contains "the signature is written to stdout" "BEGIN PGP SIGNATURE" "${output}"

# A single allowed attempt: the one 429 it gets is the last one, so nothing is
# slept on at all.
status=0
MAX_RETRIES=1
STUB_CODES="429" \
	STUB_HEADERS="$(crlf_headers 'Retry-After: 45')" \
	STUB_BODY="${rate_limited_body}" \
	output="$(run_sign_commit 2>&1)" || status=$?
MAX_RETRIES=3

expect_eq "a single-attempt run fails without waiting" "1" "${status}"
expect_eq "a single-attempt run never sleeps" "0" "$(sleep_count)"

# A permanent refusal is not retried and not slept on.
status=0
STUB_CODES="401" \
	STUB_HEADERS="$(crlf_headers 'Retry-After: 5')" \
	STUB_BODY='{"error":"Subject not authorized","code":"AUTH_SUBJECT_UNTRUSTED","hint":"add the subject"}' \
	output="$(run_sign_commit 2>&1)" || status=$?

expect_eq "a 401 fails immediately" "1" "${status}"
expect_eq "a 401 is attempted once" "1" "$(attempts)"
expect_eq "a 401 is not slept on" "0" "$(sleep_count)"
expect_contains "a 401 prints its actionable hint" "hint: add the subject" "${output}"

### Transport failure --------------------------------------------------------

status=0
STUB_CODES="200" \
	STUB_CURL_EXIT=7 \
	STUB_HEADERS="" \
	STUB_BODY="" \
	output="$(run_sign_commit 2>&1)" || status=$?

expect_eq "a curl that never connected fails the signing" "1" "${status}"
expect_eq "a transport failure is not retried into a sleep" "0" "$(sleep_count)"
expect_contains "a transport failure says no response was received" \
	"No HTTP response" "${output}"
expect_contains "a transport failure reports curl's exit status" \
	"curl exited 7" "${output}"
expect_contains "a transport failure names itself as one" "transport failure" "${output}"

# A connect that is dropped rather than refused produces no response and no
# failure, so the bound has to be on the request. Without it MAX_RETRY_WAIT
# bounds only the waits it can see and the job hangs on the attempt itself.
status=0
STUB_CODES="200" \
	STUB_TRACE_ARGS="${stub_dir}/curl-args" \
	STUB_HEADERS="$(crlf_headers)" \
	STUB_BODY='{"signature":"-----BEGIN PGP SIGNATURE-----"}' \
	output="$(run_sign_commit 2>/dev/null)" || status=$?

curl_args="$(cat "${stub_dir}/curl-args" 2>/dev/null || true)"
expect_contains "the signing request bounds its connect" "--connect-timeout" "${curl_args}"
expect_contains "the signing request bounds its total time" "--max-time" "${curl_args}"
if [[ ${output} == *"HTTP 000"* ]]; then
	fail "a transport failure must not be reported as an HTTP status"
else
	ok "a transport failure is not dressed up as an HTTP status"
fi

### MAX_RETRY_WAIT validation ------------------------------------------------

MAX_RETRY_WAIT=60
MAX_RETRIES=3
if validate_config; then
	ok "a valid ceiling passes validation"
else
	fail "a valid ceiling passes validation"
fi

# The shipped defaults are values the guard accepts — otherwise every run out of
# the box would stop on the check.
MAX_RETRY_WAIT=120
MAX_RETRIES=3
if validate_config; then
	ok "the shipped defaults pass validation"
else
	fail "the shipped defaults pass validation"
fi

# A padded value is normalised to decimal rather than read as octal, before any
# `(( ))` sees it.
MAX_RETRY_WAIT=030
# shellcheck disable=SC2034  # read by validate_config
MAX_RETRIES=3
validate_config
expect_eq "a padded ceiling is normalised to decimal" "30" "${MAX_RETRY_WAIT}"
MAX_RETRY_WAIT=120

# The invalid ones are rejected by a *run* of the script, not by calling the
# function, so the assertion covers what the issue asks: the value cannot reach
# arithmetic or `sleep`. Both are stubbed on PATH and record any invocation.
mkdir -p "${stub_dir}/bin"
cat >"${stub_dir}/bin/sleep" <<'STUB'
#!/usr/bin/env bash
printf 'sleep %s\n' "$*" >>"${STUB_TRACE}"
STUB
cat >"${stub_dir}/bin/curl" <<'STUB'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"${STUB_TRACE}"
exit 1
STUB
chmod +x "${stub_dir}/bin/sleep" "${stub_dir}/bin/curl"

# The last value is an arithmetic-injection attempt; the single quotes around it
# are deliberate, and ${stub_dir} is concatenated in rather than expanded there.
# shellcheck disable=SC2016
for bad in "abc" "0" "-5" "12.5" " 30" "1e3" "9999999999999999999999" 'x[$(printf pwned >"'"${stub_dir}"'/pwned")]'; do
	trace="${stub_dir}/trace"
	: >"${trace}"
	rm -f "${stub_dir}/pwned"

	status=0
	output="$(
		PATH="${stub_dir}/bin:${PATH}" \
			STUB_TRACE="${trace}" \
			MAX_RETRY_WAIT="${bad}" \
			OIDC_TOKEN=stub-token \
			bash "${example}" HEAD 2>&1
	)" || status=$?

	if ((status == 0)); then
		fail "MAX_RETRY_WAIT='${bad}' was accepted"
	else
		ok "MAX_RETRY_WAIT='${bad}' is rejected"
	fi

	expect_contains "MAX_RETRY_WAIT='${bad}' is named in the error" \
		"MAX_RETRY_WAIT must be a positive whole number" "${output}"

	if [[ -s ${trace} ]]; then
		fail "MAX_RETRY_WAIT='${bad}' reached a command: $(tr '\n' ' ' <"${trace}")"
	else
		ok "MAX_RETRY_WAIT='${bad}' reaches neither curl nor sleep"
	fi

	if [[ -e "${stub_dir}/pwned" ]]; then
		fail "MAX_RETRY_WAIT='${bad}' was evaluated as an arithmetic expression"
	else
		ok "MAX_RETRY_WAIT='${bad}' is not evaluated as an arithmetic expression"
	fi
done

# An empty value is an unset one: `${MAX_RETRY_WAIT:-120}` at the top of the
# example substitutes the default, so this is a configured run and not a
# rejected one. The assertion is that it gets *past* validation — the curl stub
# then fails the run for its own reason.
: >"${stub_dir}/trace"
status=0
output="$(
	PATH="${stub_dir}/bin:${PATH}" \
		STUB_TRACE="${stub_dir}/trace" \
		MAX_RETRY_WAIT="" \
		OIDC_TOKEN=stub-token \
		bash "${example}" HEAD 2>&1
)" || status=$?

if [[ ${output} == *"MAX_RETRY_WAIT must be"* ]]; then
	fail "an empty MAX_RETRY_WAIT should take the default, not be rejected"
else
	ok "an empty MAX_RETRY_WAIT takes the default"
fi

# MAX_RETRIES shares the arithmetic and the same guard.
status=0
output="$(
	PATH="${stub_dir}/bin:${PATH}" \
		STUB_TRACE="${stub_dir}/trace" \
		MAX_RETRIES="never" \
		OIDC_TOKEN=stub-token \
		bash "${example}" HEAD 2>&1
)" || status=$?
expect_eq "an invalid MAX_RETRIES is rejected too" "1" "${status}"
expect_contains "an invalid MAX_RETRIES is named in the error" \
	"MAX_RETRIES must be a positive whole number" "${output}"

### ---------------------------------------------------------------------------

printf '\n%d checks, %d failures\n' "${checks}" "${failures}"
((failures == 0))
