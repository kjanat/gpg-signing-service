#!/usr/bin/env bash

# Query audit logs with filtering and formatting

BASE_URL="${BASE_URL:-'https://gpg.kajkowalski.nl'}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

if [[ -z $ADMIN_TOKEN ]]; then
	echo "Error: ADMIN_TOKEN not set"
	exit 1
fi

# Helper functions
query_logs() {
	local query_params="$1"
	curl -s "${BASE_URL}/admin/audit?${query_params}" \
		-H "Authorization: Bearer ${ADMIN_TOKEN}"
}

format_logs() {
	jq -r '.logs[] | "\(.timestamp | split("T")[0]) \(.timestamp | split("T")[1]
) | \(.action:12) | \(.subject:20) | \(if .success then "✓" else "✗" end)"'
}

# Different query types
case "${1:-all}" in
	all)
		echo "Recent audit logs:"
		query_logs "limit=50" | format_logs
		;;

	signing)
		echo "Signing operations:"
		query_logs "action=sign&limit=100" | format_logs
		;;

	keys)
		echo "Key management operations:"
		query_logs "action=key_upload,key_rotate&limit=100" | format_logs
		;;

	failures)
		echo "Failed operations:"
		query_logs "limit=100" | jq '.logs[] | select(.success == false) |
      "\(.timestamp) | \(.action) | \(.errorCode // "unknown")"'
		;;

	by-repo)
		repo="$2"
		if [[ -z $repo ]]; then
			echo "Usage: $0 by-repo <subject>"
			exit 1
		fi
		echo "Operations for subject: $repo"
		query_logs "subject=$repo&limit=100" | format_logs
		;;

	*)
		echo "Usage: $0 {all|signing|keys|failures|by-repo <subject>}"
		exit 1
		;;
esac
