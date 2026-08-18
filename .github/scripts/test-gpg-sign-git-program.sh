#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
shim="${repo_root}/.github/scripts/gpg-sign-git-program.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

mkdir "${tmp_dir}/bin"

cat >"${tmp_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

header=''
url=''
while (($#)); do
	case "$1" in
		--header | -H)
			header="$2"
			shift 2
			;;
		-sSf)
			shift
			;;
		*)
			url="$1"
			shift
			;;
	esac
done

test "${header}" = "Authorization: bearer ${EXPECTED_OIDC_TOKEN}"
test "${url}" = "${EXPECTED_OIDC_URL}&audience=gpg-signing-service"
printf '{"value":"minted-token"}\n'
EOF

cat >"${tmp_dir}/bin/jq" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

test "$1" = '-r'
test "$2" = '.value'
cat >/dev/null
printf 'minted-token\n'
EOF

cat >"${tmp_dir}/bin/gpg-sign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

test "$1" = 'sign'
test "${GPG_SIGN_TOKEN}" = 'minted-token'
test "$(cat)" = 'commit object'
printf '%s\n' '-----BEGIN PGP SIGNATURE-----' 'test' '-----END PGP SIGNATURE-----'
EOF

chmod +x "${tmp_dir}/bin/curl" "${tmp_dir}/bin/jq" "${tmp_dir}/bin/gpg-sign"

# The shim is sign-only, and git calls gpg.program with --verify whenever it
# shows a signature. That rejection is load-bearing: if it ever regressed into a
# silent success, `git log --show-signature` would report commits as verified
# without anything having verified them. Nothing below covers it, because every
# other case invokes the shim the way git invokes it to sign.
#
# GPG_SIGN_TOKEN is set deliberately, so a pass proves the guard fires on the
# arguments rather than on a missing credential.
if printf 'commit object' | env \
	PATH="${tmp_dir}/bin:${PATH}" \
	GPG_SIGN_URL='https://sign.example.test' \
	GPG_SIGN_TOKEN='minted-token' \
	"${shim}" --status-fd=2 --verify /dev/null - \
	>"${tmp_dir}/verify-output" 2>"${tmp_dir}/verify-error"; then
	echo 'expected --verify to be rejected by the sign-only shim' >&2
	exit 1
fi

grep -q 'unsupported invocation (sign-only shim)' "${tmp_dir}/verify-error"

# GPG_SIGN_URL is required, and the message has to name it: git reports any
# non-zero exit from gpg.program as "gpg failed to sign the data", so an
# unnamed failure is indistinguishable from a rejected credential.
#
# -u GPG_SIGN_URL is not decoration — setup-claude-signing exports it through
# GITHUB_ENV, so in CI this case inherits a real one and asserts nothing.
if printf 'commit object' | env \
	-u GPG_SIGN_URL \
	PATH="${tmp_dir}/bin:${PATH}" \
	GPG_SIGN_TOKEN='minted-token' \
	"${shim}" --status-fd=2 -bsau test-key \
	>"${tmp_dir}/no-url-output" 2>"${tmp_dir}/no-url-error"; then
	echo 'expected a missing GPG_SIGN_URL to fail' >&2
	exit 1
fi

grep -q 'GPG_SIGN_URL must point at the signing service' "${tmp_dir}/no-url-error"

run_signing_case() {
	local output_file="$1"
	local status_file="$2"
	shift 2

	# Clear every credential variable first, then let the case set only the ones
	# it exercises. Without this the ambient environment leaks in: any job that
	# ran setup-claude-signing exports GPG_OIDC_REQUEST_*, which outranks the
	# native variables and makes the native case assert against the wrong URL.
	printf 'commit object' | env \
		-u GPG_SIGN_TOKEN \
		-u GPG_OIDC_REQUEST_URL \
		-u GPG_OIDC_REQUEST_TOKEN \
		-u ACTIONS_ID_TOKEN_REQUEST_URL \
		-u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
		PATH="${tmp_dir}/bin:${PATH}" \
		GPG_SIGN_URL='https://sign.example.test' \
		"$@" \
		"${shim}" --status-fd=2 -bsau test-key \
		>"${output_file}" 2>"${status_file}"

	grep -q '^-----BEGIN PGP SIGNATURE-----$' "${output_file}"
	grep -q '^\[GNUPG:\] SIG_CREATED $' "${status_file}"
}

run_signing_case "${tmp_dir}/alias-output" "${tmp_dir}/alias-status" \
	EXPECTED_OIDC_URL='https://oidc.example.test/token?api-version=2.0' \
	EXPECTED_OIDC_TOKEN='aliased-request-token' \
	GPG_OIDC_REQUEST_URL='https://oidc.example.test/token?api-version=2.0' \
	GPG_OIDC_REQUEST_TOKEN='aliased-request-token' \
	ACTIONS_ID_TOKEN_REQUEST_URL='https://wrong.example.test' \
	ACTIONS_ID_TOKEN_REQUEST_TOKEN='wrong-token'

run_signing_case "${tmp_dir}/native-output" "${tmp_dir}/native-status" \
	EXPECTED_OIDC_URL='https://native.example.test/token?api-version=2.0' \
	EXPECTED_OIDC_TOKEN='native-request-token' \
	ACTIONS_ID_TOKEN_REQUEST_URL='https://native.example.test/token?api-version=2.0' \
	ACTIONS_ID_TOKEN_REQUEST_TOKEN='native-request-token'

if printf 'commit object' | env \
	-u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
	-u ACTIONS_ID_TOKEN_REQUEST_URL \
	-u GPG_OIDC_REQUEST_TOKEN \
	-u GPG_OIDC_REQUEST_URL \
	-u GPG_SIGN_TOKEN \
	PATH="${tmp_dir}/bin:${PATH}" \
	GPG_SIGN_URL='https://sign.example.test' \
	"${shim}" --status-fd=2 -bsau test-key \
	>"${tmp_dir}/missing-output" 2>"${tmp_dir}/missing-error"; then
	echo 'expected missing OIDC credentials to fail' >&2
	exit 1
fi

grep -q 'no credential available' "${tmp_dir}/missing-error"

# Precedence 1: a pre-set GPG_SIGN_TOKEN is used as-is and the OIDC endpoint is
# never contacted. Swap in a curl that always fails, so "never contacted" is what
# the case actually proves rather than a side effect of which variables happen to
# be unset. Everything after this point supplies its own mocks.
cat >"${tmp_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo 'curl must not be called when GPG_SIGN_TOKEN is set' >&2
exit 1
EOF
chmod +x "${tmp_dir}/bin/curl"

printf 'commit object' | env \
	-u GPG_OIDC_REQUEST_URL \
	-u GPG_OIDC_REQUEST_TOKEN \
	-u ACTIONS_ID_TOKEN_REQUEST_URL \
	-u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
	-u EXPECTED_OIDC_URL \
	-u EXPECTED_OIDC_TOKEN \
	PATH="${tmp_dir}/bin:${PATH}" \
	GPG_SIGN_URL='https://sign.example.test' \
	GPG_SIGN_TOKEN='minted-token' \
	"${shim}" --status-fd=2 -bsau test-key \
	>"${tmp_dir}/service-token-output" 2>"${tmp_dir}/service-token-status"

grep -q '^-----BEGIN PGP SIGNATURE-----$' "${tmp_dir}/service-token-output"
grep -q '^\[GNUPG:\] SIG_CREATED $' "${tmp_dir}/service-token-status"

# A well-formed response with no .value must not be forwarded as a bearer token:
# curl succeeds, jq prints the literal string "null".
cat >"${tmp_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

cat >/dev/null 2>&1 || true
printf '{"value":null}\n'
EOF
cat >"${tmp_dir}/bin/jq" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

cat >/dev/null
printf 'null\n'
EOF
chmod +x "${tmp_dir}/bin/curl" "${tmp_dir}/bin/jq"

if printf 'commit object' | env \
	-u GPG_SIGN_TOKEN \
	-u GPG_OIDC_REQUEST_URL \
	-u GPG_OIDC_REQUEST_TOKEN \
	PATH="${tmp_dir}/bin:${PATH}" \
	GPG_SIGN_URL='https://sign.example.test' \
	EXPECTED_OIDC_URL='https://native.example.test/token?api-version=2.0' \
	EXPECTED_OIDC_TOKEN='native-request-token' \
	ACTIONS_ID_TOKEN_REQUEST_URL='https://native.example.test/token?api-version=2.0' \
	ACTIONS_ID_TOKEN_REQUEST_TOKEN='native-request-token' \
	"${shim}" --status-fd=2 -bsau test-key \
	>"${tmp_dir}/null-output" 2>"${tmp_dir}/null-error"; then
	echo 'expected a null token value to fail' >&2
	exit 1
fi

grep -q 'returned no token value' "${tmp_dir}/null-error"
printf 'signing shim tests passed\n'
