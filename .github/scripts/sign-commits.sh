#!/usr/bin/env bash
# Orchestrate a routine signing run: turn workflow inputs into `gpg-sign
# sign-commit` flags, and name the binary that has to carry the command.
#
# The signing itself — resolving the base, deciding which commits are stale,
# rewriting each one with an embedded signature, verifying it and moving the
# local HEAD — belongs to `gpg-sign sign-commit` and lives in Go, with tests.
# This script is the part that does not: flag assembly from dispatch inputs.
#
# It publishes nothing. sign-commit stops at `git update-ref HEAD`, so the
# workflow's own push step is what makes the rewrite real, and this script
# failing leaves the branch exactly where it was.
#
#   env:  BASE_REF        exclusive lower bound; blank resolves one
#         DEFAULT_BRANCH  branch that gets the last-signed-commit scan
#         ALLOW_RESIGN    "true" permits rewriting already-signed commits
#         SIGN_OTHERS     "true" signs commits by identities the key omits
#         SCAN_LIMIT      bound on the last-signed-commit scan; blank is unbounded
#         GPG_SIGN_BIN    the gpg-sign to run; defaults to PATH's
#         GPG_SIGN_TOKEN  OIDC token, read by gpg-sign
#         GPG_SIGN_URL    service base URL, read by gpg-sign
set -Eeuo pipefail

# Which gpg-sign, said out loud — the same seam repair-history.sh names. The
# signing action installs a release, and `sign-commit` is newer than some of
# them, so a run that takes the name from PATH can reach a build that has never
# heard of the command. GPG_SIGN_BIN points at the one you mean.
readonly gpg_sign="${GPG_SIGN_BIN:-gpg-sign}"

die() {
	printf '::error::%s\n' "$1"
	exit 1
}

command -v "${gpg_sign}" >/dev/null 2>&1 || die "${gpg_sign} is not executable; set GPG_SIGN_BIN to the gpg-sign to run"

# Ask before signing anything. Without this, a binary that predates the
# subcommand fails inside cobra's usage text, which reads like a flag typo
# rather than like an install that needs upgrading.
"${gpg_sign}" sign-commit --help >/dev/null 2>&1 \
	|| die "${gpg_sign} has no sign-commit command; it predates it. Install a release that has it, or build the checked-out client (task c:b) and set GPG_SIGN_BIN to it"

# Trimmed the way the dispatch inputs arrive: a `type: number` input that was
# left blank is the empty string, and one that was filled in can carry the
# whitespace a copy-paste brought with it.
trim() {
	local value="$1"
	value="${value#"${value%%[![:space:]]*}"}"
	printf '%s' "${value%"${value##*[![:space:]]}"}"
}

base="$(trim "${BASE_REF-}")"
scan_limit="$(trim "${SCAN_LIMIT-}")"

# Written as `if` blocks rather than `[[ ... ]] && flags+=(...)`: under errexit
# a one-liner whose test is false makes the whole list fail, and a blank
# optional input would end the run before anything was signed.
flags=(--default-branch="${DEFAULT_BRANCH:-master}")
if [[ -n "${base}" ]]; then
	flags+=(--base="${base}")
fi
if [[ "${ALLOW_RESIGN-}" == "true" ]]; then
	flags+=(--allow-resign)
fi
if [[ "${SIGN_OTHERS-}" == "true" ]]; then
	flags+=(--sign-others)
fi
if [[ -n "${scan_limit}" ]]; then
	flags+=(--scan-limit="${scan_limit}")
fi

"${gpg_sign}" sign-commit "${flags[@]}"
