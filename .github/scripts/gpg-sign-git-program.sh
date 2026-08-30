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
# gpg.program is not sign-only from git's side: the same program is run with
# --verify for `git log --show-signature`, `git tag -v`, `git merge
# --verify-signatures` and friends. Only the detached-sign invocation is ours;
# every other invocation is exec'd against the real gpg unchanged, so
# gpg.program stays a drop-in GnuPG for anything that is not signing.
#
# A fresh OIDC token is fetched per invocation: GitHub's job-level OIDC tokens
# expire after ~5 minutes, while a Claude session can run much longer, so a
# pre-minted token would go stale mid-run.
#
# ACTIONS_ID_TOKEN_REQUEST_* are present in ordinary steps of a job with
# `id-token: write`, but NOT in a Claude session: claude-code-action deletes
# both from the child environment on purpose (base-action/src/parse-sdk-options.ts,
# "Remove OIDC token request variables so Claude cannot mint new tokens").
# Hence the GPG_OIDC_REQUEST_* fallback below — see the precedence comment.
set -euo pipefail

# The first executable named `gpg` on PATH that is not this script, or whatever
# GPG_SIGN_REAL_GPG names. The override exists so the choice is testable
# without rewriting PATH, and so an installation that keeps GnuPG off PATH can
# still verify.
#
# The self-check is what keeps `gpg.program` safe to install *as* `gpg`: -ef
# compares device and inode through symlinks, so a `gpg -> this script` symlink
# on PATH is skipped rather than re-entered. A byte copy has its own inode and
# survives that check, which is what the re-entry guard in delegate() is for.
find_real_gpg() {
	local candidate

	if [[ -n "${GPG_SIGN_REAL_GPG:-}" ]]; then
		# -f as well as -x: -x alone is true for any searchable directory, so
		# GPG_SIGN_REAL_GPG=/usr/bin would pass here and fail at exec with
		# bash's own "Is a directory" and status 126, instead of the named
		# error this branch exists to produce.
		if [[ ! -f "${GPG_SIGN_REAL_GPG}" || ! -x "${GPG_SIGN_REAL_GPG}" ]]; then
			printf '%s\n' \
				"gpg-sign-git-program: GPG_SIGN_REAL_GPG is not an executable file: ${GPG_SIGN_REAL_GPG}" >&2
			return 1
		fi
		# The override skips the PATH search, so it also skips its self-check.
		# Without this, GPG_SIGN_REAL_GPG=<this script> is caught one exec later
		# by the re-entry guard, which then blames PATH for a bad override.
		if [[ "${GPG_SIGN_REAL_GPG}" -ef "${BASH_SOURCE[0]}" ]]; then
			printf '%s\n' \
				"gpg-sign-git-program: GPG_SIGN_REAL_GPG points at this script: ${GPG_SIGN_REAL_GPG}" >&2
			return 1
		fi
		printf '%s\n' "${GPG_SIGN_REAL_GPG}"
		return 0
	fi

	while IFS= read -r candidate; do
		if [[ ! -f "${candidate}" || ! -x "${candidate}" ]]; then
			continue
		fi
		if [[ "${candidate}" -ef "${BASH_SOURCE[0]}" ]]; then
			continue
		fi
		printf '%s\n' "${candidate}"
		return 0
	done < <(type -aP gpg 2>/dev/null || true)

	return 1
}

# Hand the invocation to GnuPG with argv, stdin, stdout, stderr and exit status
# untouched. exec, not a subshell: git reads the status fd of this very process
# and propagates whatever it exits with.
delegate() {
	local real_gpg

	# Set across the exec below. Seeing it on entry means the "real gpg" we
	# picked last time was this script again — a copy on PATH under the name
	# gpg, which -ef cannot detect. Refuse instead of exec'ing forever.
	if [[ -n "${GPG_SIGN_GIT_PROGRAM_DELEGATED:-}" ]]; then
		printf '%s\n' \
			'gpg-sign-git-program: refusing to delegate to itself.' >&2
		printf '  %s\n' \
			'The gpg it resolved to is a byte copy of this script, which -ef cannot see.' >&2
		printf '  %s\n' \
			'Point GPG_SIGN_REAL_GPG at the real GnuPG binary.' >&2
		exit 1
	fi

	if ! real_gpg="$(find_real_gpg)"; then
		# A rejected GPG_SIGN_REAL_GPG has already said why; saying "no gpg
		# found" on top of it would point at the wrong problem.
		if [[ -z "${GPG_SIGN_REAL_GPG:-}" ]]; then
			printf '%s\n' \
				'gpg-sign-git-program: no gpg executable found for a non-signing invocation.' >&2
			printf '  %s\n' \
				'Only signing goes to the service; git uses gpg.program to verify too.' >&2
			printf '  %s\n' \
				'Install GnuPG, or point GPG_SIGN_REAL_GPG at it.' >&2
		fi
		# 127 is the conventional "command not found", and is what git would
		# have seen had gpg.program itself been missing.
		exit 127
	fi

	export GPG_SIGN_GIT_PROGRAM_DELEGATED=1
	exec "${real_gpg}" "$@"
}

signing=false
for arg in "$@"; do
	case "${arg}" in
		-bsau | -bsa | --detach-sign) signing=true ;;
		*) ;;
	esac
done
if [[ "${signing}" != true ]]; then
	delegate "$@"
fi

: "${GPG_SIGN_URL:?GPG_SIGN_URL must point at the signing service}"

# Credentials, in precedence order:
#
#   1. GPG_SIGN_TOKEN — a `gst_` service token, for environments with no OIDC
#      issuer at all (Claude Code cloud sessions, a laptop).
#      See docs/cloud-session-signing.md.
#   2. GPG_OIDC_REQUEST_* — copies of the OIDC request variables re-exported by
#      .github/actions/setup-claude-signing.
#   3. ACTIONS_ID_TOKEN_REQUEST_* — the native variables, present in ordinary
#      workflow steps of a job with `id-token: write`.
#
# (2) exists because an agent does not run this shim directly. It is not process
# depth: claude-code-action deletes both native variables from the child
# environment on purpose (base-action/src/parse-sdk-options.ts, "Remove OIDC
# token request variables so Claude cannot mint new tokens"). Copies under our
# own names are not caught by that name-based removal.
if [[ -z "${GPG_SIGN_TOKEN:-}" ]]; then
	oidc_url="${GPG_OIDC_REQUEST_URL:-${ACTIONS_ID_TOKEN_REQUEST_URL:-}}"
	oidc_token="${GPG_OIDC_REQUEST_TOKEN:-${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}}"
	if [[ -z "${oidc_url}" || -z "${oidc_token}" ]]; then
		printf '%s\n' 'gpg-sign-git-program: no credential available.' >&2
		printf '  %s\n' 'Set GPG_SIGN_TOKEN (service token), or run in a job with' >&2
		printf '  %s\n' "'id-token: write' that uses .github/actions/setup-claude-signing." >&2
		exit 1
	fi

	GPG_SIGN_TOKEN="$(
		curl -sSf \
			--header "Authorization: bearer ${oidc_token}" \
			"${oidc_url}&audience=gpg-signing-service" \
			| jq -r '.value'
	)"

	# pipefail catches curl failing, but not a well-formed response without a
	# .value — jq prints the literal string "null" and the shim would go on to
	# send it as a bearer token, surfacing as a 401 that looks like a bad
	# credential rather than a bad response.
	if [[ -z "${GPG_SIGN_TOKEN}" || "${GPG_SIGN_TOKEN}" == "null" ]]; then
		printf '%s\n' 'gpg-sign-git-program: OIDC endpoint returned no token value.' >&2
		exit 1
	fi
fi
export GPG_SIGN_TOKEN

# git captures this process's stderr and prints it back under "gpg failed to
# sign the data", so stderr is the only channel a failure has to explain itself
# on — and it is the same fd git scans for SIG_CREATED. Holding gpg-sign's
# diagnostic in a file until its exit status is known lets it be read and
# classified before it is forwarded, without ever reordering it against the
# status line.
#
# stdout is untouched: gpg-sign writes the armored signature straight through to
# git, and writes nothing there when it fails.
sign_stderr="$(mktemp)"
trap 'rm -f "${sign_stderr}"' EXIT

sign_rc=0
gpg-sign sign 2>"${sign_stderr}" || sign_rc=$?

if [[ "${sign_rc}" -ne 0 ]]; then
	# Reached only once signing has already failed, which is why the classifier
	# is sourced here and not at the top: a missing or broken
	# gpg-sign-error-class.sh cannot cost a signature that would otherwise have
	# been made, and the diagnostic below is forwarded either way. Only the
	# class name degrades, to UNKNOWN.
	class=UNKNOWN
	class_lib="${BASH_SOURCE[0]%/*}/gpg-sign-error-class.sh"
	if [[ -r "${class_lib}" ]]; then
		# shellcheck source-path=SCRIPTDIR source=gpg-sign-error-class.sh
		. "${class_lib}"
		class="$(gpg_sign_error_class "$(<"${sign_stderr}")")"
	fi

	# The class first and on its own line. Everything git shows an operator is
	# this stderr wrapped in its own sentence, and without a leading token the
	# whole of it reads as "the commit failed" — a 429 indistinguishable from a
	# rotated key, which is what made every one of these an exit 128 with no
	# further information.
	printf 'gpg-sign-git-program: signing failed [%s] (gpg-sign exit %d)\n' \
		"${class}" "${sign_rc}" >&2

	# Verbatim, unindented, unfiltered. gpg-sign already prints the service's
	# message, the subject it refused, its hint, the docs link and the request
	# id one field per line (client/cmd/gpg-sign/explain.go); re-wording any of
	# it here would only lose detail an operator is asked to quote.
	cat "${sign_stderr}" >&2

	if declare -F gpg_sign_error_summary >/dev/null; then
		printf '  %s\n' "$(gpg_sign_error_summary "${class}")" >&2
	fi
	printf '  %s\n' \
		'The commit was not made: signing fails closed on purpose.' \
		'To run one CI job without the service, set the GPG_SIGN_DISABLE' \
		'repository variable to 1 and re-run it; its commits land unsigned.' \
		'See docs/troubleshooting.md#ci-commit-signing.' >&2

	# gpg-sign's own status, not a flattened 1: `git commit` reports any
	# non-zero identically, but a human or a wrapper reading this script
	# directly should see what the client actually exited with.
	exit "${sign_rc}"
fi

# gpg-sign is silent on success, but forward anything it did say: this used to
# go straight to git's status fd, and swallowing a warning is not this change's
# business.
cat "${sign_stderr}" >&2

printf '\n[GNUPG:] SIG_CREATED \n' >&2
