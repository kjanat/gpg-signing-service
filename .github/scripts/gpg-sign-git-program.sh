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
# A fresh OIDC token is fetched per invocation: GitHub's job-level OIDC tokens
# expire after ~5 minutes, while a Claude session can run much longer. The
# ACTIONS_ID_TOKEN_REQUEST_* vars are present in the environment of any job
# with `id-token: write`, and are inherited by every child process, including
# Claude's Bash tool.
set -euo pipefail

signing=false
for arg in "$@"; do
	case "$arg" in
		-bsau | -bsa | --detach-sign) signing=true ;;
	esac
done
if ! "$signing"; then
	# git also calls gpg.program with --verify when showing signatures; we only
	# sign. Fail loudly rather than pretending to verify.
	echo "gpg-sign-git-program: unsupported invocation (sign-only shim): $*" >&2
	exit 1
fi

: "${GPG_SIGN_URL:?GPG_SIGN_URL must point at the signing service}"

# Two auth modes, so the same shim works in CI and in environments with no OIDC
# issuer (Claude Code cloud sessions, a laptop). A pre-set GPG_SIGN_TOKEN — a
# `gst_` service token — wins; otherwise mint a short-lived OIDC token, which
# requires running inside a job with `id-token: write`.
# See docs/cloud-session-signing.md.
if [ -z "${GPG_SIGN_TOKEN:-}" ]; then
	: "${ACTIONS_ID_TOKEN_REQUEST_URL:?no GPG_SIGN_TOKEN set and no OIDC issuer available}"
	: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?no GPG_SIGN_TOKEN set and no OIDC issuer available}"

	GPG_SIGN_TOKEN="$(
		curl -sSf \
			-H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
			"${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=gpg-signing-service" \
			| jq -r '.value'
	)"
fi
export GPG_SIGN_TOKEN

gpg-sign sign

printf '\n[GNUPG:] SIG_CREATED \n' >&2
