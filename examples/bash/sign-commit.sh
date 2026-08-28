#!/usr/bin/env bash

set -euo pipefail

# Configuration
BASE_URL="${BASE_URL:-https://gpg.kajkowalski.nl}"
OIDC_TOKEN="${OIDC_TOKEN:-}"
MAX_RETRIES="${MAX_RETRIES:-3}"
# Ceiling on a wait the *server* chose. Both retry branches below take an
# interval off the response — `retryAfter` in a 429's body, `Retry-After` on a
# 503 — and neither value is this script's. An unbounded one parks a CI job for
# as long as whatever answered feels like: a misconfigured origin, an
# intermediary with its own idea of a maintenance window, or simply a typo'd
# variable. The Go client clamps the same two hints to its own retryWaitMax for
# this reason; this is the shell equivalent.
MAX_RETRY_WAIT="${MAX_RETRY_WAIT:-120}"

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

# Clamp a server-chosen wait to MAX_RETRY_WAIT, and reject anything that is not
# a plain number of seconds.
#
# `Retry-After` also has an HTTP-date form that intermediaries emit freely, and
# the reader below yields an empty string for one rather than trying to parse a
# date in portable shell — so a non-numeric value lands on the default here
# instead of reaching `sleep` as a word it would refuse.
clamp_wait() {
	local wait="$1" fallback="$2"

	# Zero is "no hint", not "immediately" — the same reading the Go client's
	# retryAfterSeconds takes. Sleeping 0 turns the retry loop into a tight one
	# against a dependency that has just failed.
	[[ ${wait} =~ ^[0-9]+$ && ${wait} -gt 0 ]] || wait="${fallback}"
	if ((wait > MAX_RETRY_WAIT)); then
		wait="${MAX_RETRY_WAIT}"
	fi
	echo "${wait}"
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
	while [[ ${retry_count} -lt ${MAX_RETRIES} ]]; do
		log_info "Signing attempt $((retry_count + 1))/${MAX_RETRIES}..."

		local response http_code body request_id headers headers_file
		request_id=$(uuidgen) || true
		# Headers to a file, not just the body: `Retry-After` on a 503 is a header
		# and has no field in the envelope, so a body-only read cannot see the one
		# thing that response is telling the caller.
		headers_file=$(mktemp)
		response=$(curl -sw "\n%{http_code}" -D "${headers_file}" -X POST \
			-H "Authorization: Bearer ${OIDC_TOKEN}" \
			-H "X-Request-ID: ${request_id}" \
			--data-raw "${commit_data}" \
			"${request_url}")
		headers=$(cat "${headers_file}")
		rm -f "${headers_file}"

		http_code="$(echo "${response}" | tail -1)"
		body="$(echo "${response}" | head -n -1)"

		case "${http_code}" in
			200)
				log_info "Commit signed successfully"
				echo "${body}"
				return 0
				;;
			429)
				# `|| true`, and `empty` rather than a jq-side default: a 429 is the
				# one refusal that needs no envelope to be understood, and the
				# responder most likely to answer one is an edge throttle in front
				# of this service, which sends an HTML page and a `Retry-After`
				# header. jq exits non-zero on that body, and under `set -e` an
				# assignment taking its status ended the whole script right here —
				# before the clamp, before `last_body` was recorded, and so before
				# anything at all was printed about the refusal. Same failure the
				# `if` in log_service_error exists to prevent.
				#
				# The header is the fallback for exactly that responder, read the
				# same way the 503 branch reads its own.
				local retry_after
				retry_after=$(jq -r '.retryAfter // empty' <<<"${body}" 2>/dev/null) || retry_after=""
				if [[ -z ${retry_after} ]]; then
					retry_after=$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' <<<"${headers}" | tail -1)
				fi
				retry_after=$(clamp_wait "${retry_after:-30}" 30)
				log_info "Rate limited, waiting ${retry_after}s..."
				last_code="${http_code}" last_body="${body}"
				sleep "${retry_after}"
				retry_count=$((retry_count + 1))
				;;
			503)
				# SERVICE_DEGRADED: the service could not reach something it needs
				# — the issuer's JWKS, its authorization store — so nothing about
				# this request was judged. It is the one refusal the service invites
				# a caller to repeat, and the only one where waiting is the whole
				# fix. Retry-After is a header here, not a body field: ErrorResponse
				# declares no `retryAfter`.
				#
				# Every 503 from this service is that one, and every 503 carries a
				# Retry-After. The permanent fault — a deployment whose own
				# configuration stopped the request, which answers identically until
				# an operator changes it — is SERVICE_MISCONFIGURED and arrives as a
				# 500, so it never reaches this branch to be sorted out of it.
				local degraded_wait
				degraded_wait=$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' <<<"${headers}" | tail -1)
				degraded_wait=$(clamp_wait "${degraded_wait:-30}" 30)
				log_info "Service degraded, waiting ${degraded_wait}s..."
				last_code="${http_code}" last_body="${body}"
				sleep "${degraded_wait}"
				retry_count=$((retry_count + 1))
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

	log_error "Signing failed after ${MAX_RETRIES} retries"
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

	check_requirements
	get_oidc_token
	import_public_key

	local signature
	signature=$(sign_commit "$@")

	log_info "Signature:"
	echo "${signature}"
}

main "$@"
