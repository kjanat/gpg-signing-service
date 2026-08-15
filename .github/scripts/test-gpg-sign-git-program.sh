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

run_signing_case() {
	local output_file="$1"
	local status_file="$2"
	shift 2

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

grep -q 'OIDC request credentials are unavailable' "${tmp_dir}/missing-error"
printf 'signing shim tests passed\n'
