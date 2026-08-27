#!/usr/bin/env bash

set -euo pipefail

# Configuration
BASE_URL="${BASE_URL:-https://gpg.kajkowalski.nl}"
OIDC_TOKEN="${OIDC_TOKEN:-}"
MAX_RETRIES="${MAX_RETRIES:-3}"

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
				local retry_after
				retry_after=$(echo "${body}" | jq -r '.retryAfter // 30')
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
				local degraded_wait
				degraded_wait=$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' <<<"${headers}" | tail -1)
				degraded_wait="${degraded_wait:-30}"
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
