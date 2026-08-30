#!/usr/bin/env bash
# Orchestrate a routine signing run: turn workflow inputs into `gpg-sign
# sign-commit` flags, then publish what it rewrote.
#
# The signing itself lives in the Go CLI. This is the part that does not: flag
# assembly from dispatch inputs, and the force push the CLI deliberately
# refuses to perform.
#
#   env:  BASE_REF        exclusive lower bound; blank resolves one
#         DEFAULT_BRANCH  branch that gets the last-signed-commit scan
#         ALLOW_RESIGN    "true" permits rewriting already-signed commits
#         SIGN_OTHERS     "true" signs commits by identities the key omits
#         SCAN_LIMIT      bound on the last-signed-commit scan; blank is unbounded
#         GPG_SIGN_TOKEN  OIDC token, read by gpg-sign
#         GPG_SIGN_URL    service base URL, read by gpg-sign
set -Eeuo pipefail

# Written as `if` blocks rather than `[[ ... ]] && flags+=(...)`: under errexit
# a one-liner whose test is false makes the whole list fail, and a blank
# optional input would end the run before anything was signed.
flags=(--default-branch="${DEFAULT_BRANCH:-master}")
if [[ -n "${BASE_REF-}" ]]; then
	flags+=(--base="${BASE_REF}")
fi
if [[ "${ALLOW_RESIGN-}" == "true" ]]; then
	flags+=(--allow-resign)
fi
if [[ "${SIGN_OTHERS-}" == "true" ]]; then
	flags+=(--sign-others)
fi
if [[ -n "${SCAN_LIMIT-}" ]]; then
	flags+=(--scan-limit="${SCAN_LIMIT}")
fi

gpg-sign sign-commit "${flags[@]}"

# sign-commit stops at `git update-ref HEAD`, so HEAD is already the rewritten
# tip here and the lease is the remote's own tracked value.
git push origin HEAD --force-with-lease
