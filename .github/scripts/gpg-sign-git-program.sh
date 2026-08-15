#!/usr/bin/env bash
# git gpg.program shim that signs commits via this repo's own signing service.
#
# git invokes the configured gpg.program as:  <program> --status-fd=2 -bsau <key>
# with the commit object on stdin, and accepts the signature iff:
#   - the armored detached signature is written to stdout
#   - a "[GNUPG:] SIG_CREATED " status line is written to the status fd (2)
#   - exit code is 0
# (see gpg-interface.c in git's source)
#
# `gpg-sign sign` prints exactly the armored detached signature (fmt.Print in
# client/cmd/gpg-sign/main.go), so we pipe stdin straight through.
#
# A fresh OIDC token is fetched per invocation: minted identity tokens expire
# quickly, while the job-scoped request credential remains usable throughout a
# long Claude session. setup-claude-signing forwards that credential through
# Claude settings under GPG_OIDC_REQUEST_* because Claude Bash tools do not
# inherit the runner's ACTIONS_ID_TOKEN_REQUEST_* variables directly.
set -euo pipefail

signing=false
for arg in "$@"; do
	case "${arg}" in
		-bsau | -bsa | --detach-sign) signing=true ;;
		*) ;;
	esac
done
if [[ "${signing}" != true ]]; then
	# git also calls gpg.program with --verify when showing signatures; we only
	# sign. Fail loudly rather than pretending to verify.
	printf 'gpg-sign-git-program: unsupported invocation (sign-only shim): %s\n' "$*" >&2
	exit 1
fi

: "${GPG_SIGN_URL:?GPG_SIGN_URL must point at the signing service}"

oidc_url="${GPG_OIDC_REQUEST_URL:-${ACTIONS_ID_TOKEN_REQUEST_URL:-}}"
oidc_token="${GPG_OIDC_REQUEST_TOKEN:-${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}}"
if [[ -z "${oidc_url}" || -z "${oidc_token}" ]]; then
	printf '%s\n' 'gpg-sign-git-program: OIDC request credentials are unavailable.' >&2
	printf '  %s\n' "Grant id-token: write and use setup-claude-signing's settings-file output." >&2
	exit 1
fi

GPG_SIGN_TOKEN="$(
	curl -sSf \
		--header "Authorization: bearer ${oidc_token}" \
		"${oidc_url}&audience=gpg-signing-service" \
		| jq -r '.value'
)"
export GPG_SIGN_TOKEN

gpg-sign sign

printf '\n[GNUPG:] SIG_CREATED \n' >&2
