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
			"${ACTIONS_ID_TOKEN_REQUEST_URL:-}" | jq -r '.token')
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

		local response http_code body request_id
		request_id=$(uuidgen) || true
		response=$(curl -sw "\n%{http_code}" -X POST \
			-H "Authorization: Bearer ${OIDC_TOKEN}" \
			-H "X-Request-ID: ${request_id}" \
			--data-raw "${commit_data}" \
			"${request_url}")

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
				sleep "${retry_after}"
				retry_count=$((retry_count + 1))
				;;
			401)
				local error_msg
				error_msg=$(echo "${body}" | jq -r .error) || true
				log_error "Authentication failed: ${error_msg}"
				return 1
				;;
			*)
				local error_msg
				error_msg=$(echo "${body}" | jq -r '.error // .') || true
				log_error "Signing failed (HTTP ${http_code}): ${error_msg}"
				return 1
				;;
		esac
	done

	log_error "Signing failed after ${MAX_RETRIES} retries"
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
