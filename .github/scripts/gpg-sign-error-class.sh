#!/usr/bin/env bash
# Shared classifier: name the service failure class behind a failed `gpg-sign`
# invocation, and say what that class means for the caller.
#
# Sourced by two callers that ask the same question of the same output:
#
#   - .github/scripts/gpg-sign-git-program.sh, after `gpg-sign sign` failed
#     during `git commit`;
#   - .github/scripts/signing-preflight.sh, after `gpg-sign health` failed
#     during job setup.
#
# It lives in one file because the code list has to track
# client/pkg/client/errors.go, and a second copy of it would drift silently:
# nothing fails when a classifier stops recognising a code, it just falls back
# to UNKNOWN and the operator reads a worse message.
#
# Pure: reads its argument, writes to stdout, touches no files, makes no network
# call and never exits the shell. Both callers reach it only on a path that has
# already failed.
#
# shellcheck shell=bash

# gpg_sign_error_class <text>
#
# Prints exactly one token naming the failure class.
#
# The service's refusal codes are the first choice, because they are what
# docs/errors.md and docs/troubleshooting.md are indexed by. A failure carries
# its code in at least one of three shapes, so one search over the whole text
# finds it wherever this particular error happened to keep it:
#
#   ServiceError   "SERVICE_DEGRADED: <msg> (status 503, retry after 5s, ...)"
#   AuthError      "authentication failed: AUTH_INVALID: <msg> (request ...)"
#   reportFailure  "  docs:    https://<host>/e/RATE_LIMITED"
#
# -w rather than \b: BSD grep spells the word boundary differently, and this
# runs on laptops as well as on runners.
gpg_sign_error_class() {
	local text="${1-}" code

	code="$(
		{
			grep -owE \
				'AUTH_MISSING|AUTH_INVALID|AUTH_SUBJECT_UNTRUSTED|SERVICE_DEGRADED|SERVICE_MISCONFIGURED|RATE_LIMIT_ERROR|RATE_LIMITED|KEY_NOT_FOUND|KEY_NOT_ALLOWED|INVALID_REQUEST|INTERNAL_ERROR' \
				<<<"${text}" || true
		} | head -n 1
	)"
	if [[ -n "${code}" ]]; then
		printf '%s\n' "${code}"
		return 0
	fi

	# No code means no envelope: either the client never got an HTTP response, or
	# it built the error itself. Match the wording it uses — these strings are
	# pinned by client/pkg/client/errors_test.go, so they are as stable as the
	# codes are.
	case "${text}" in
		*'rate limit'* | *'Rate limit'*)
			printf 'RATE_LIMITED\n'
			;;
		*'authentication failed'*)
			printf 'AUTH_FAILED\n'
			;;
		*'validation error'*)
			printf 'INVALID_REQUEST\n'
			;;
		# Go's net/http phrasings for "the request never reached a server, or
		# reached it and got nothing back". SERVICE_UNREACHABLE is ours, not the
		# service's: by definition the service said nothing to be quoted.
		*'no such host'* | *'connection refused'* | *'dial tcp'* | \
			*'i/o timeout'* | *'context deadline exceeded'* | \
			*'Client.Timeout'* | *'TLS handshake'* | *'EOF'*)
			printf 'SERVICE_UNREACHABLE\n'
			;;
		*)
			printf 'UNKNOWN\n'
			;;
	esac
}

# gpg_sign_error_summary <class>
#
# Prints one line saying what the class means for whoever is reading the log:
# specifically, whether waiting fixes it, whether re-running fixes it, and whose
# problem it is. The `gpg-sign` diagnostic underneath it already carries the
# service's own hint and docs link; this is the part that is about *this*
# caller's next move, and it is why a 429 no longer reads the same as a 401.
gpg_sign_error_summary() {
	case "${1-}" in
		RATE_LIMITED)
			printf 'Quota: the caller was metered. The client already retried and honoured Retry-After, so the limit is standing — wait for the bucket to refill rather than re-running now.\n'
			;;
		RATE_LIMIT_ERROR)
			printf 'The service could not reach its rate limiter and refused rather than sign unmetered. Retryable, but it quotes no interval — check the Durable Object.\n'
			;;
		SERVICE_DEGRADED)
			printf 'The service could not reach a dependency, so the request was never judged. Nothing about the credential is implicated; waiting is the whole fix.\n'
			;;
		SERVICE_MISCONFIGURED)
			printf 'A deployment setting is wrong. This answers identically until an operator changes it, so re-running will not help.\n'
			;;
		AUTH_MISSING)
			printf 'No usable credential reached the service. In CI that is the job losing id-token: write, or the setup action not having run.\n'
			;;
		AUTH_INVALID | AUTH_FAILED)
			printf 'The credential itself was refused — unlisted issuer, wrong audience, or expired. The issuer was reached, so this is not a service outage.\n'
			;;
		AUTH_SUBJECT_UNTRUSTED)
			printf 'The token verified and the identity is not authorized. Add a trust rule; no OIDC change will fix it.\n'
			;;
		KEY_NOT_FOUND | KEY_NOT_ALLOWED)
			printf 'The credential was accepted and the key was not. Check the key id and the grant on the calling subject.\n'
			;;
		INVALID_REQUEST)
			printf 'The service rejected the request itself. This is a bug in the caller, not an outage.\n'
			;;
		INTERNAL_ERROR)
			printf 'The service faulted. Quote the request id below when reporting it.\n'
			;;
		SERVICE_UNREACHABLE)
			printf 'No HTTP response at all: DNS, TLS, connection or timeout. Check the configured URL and the runner network before suspecting the service.\n'
			;;
		*)
			printf 'Unrecognised failure. The diagnostic above is the whole of what gpg-sign reported.\n'
			;;
	esac
}
