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
fail_on_http_error=false
while (($#)); do
	case "$1" in
		--header | -H)
			header="$2"
			shift 2
			;;
		-sSf)
			fail_on_http_error=true
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
# -f is load-bearing: without it curl exits 0 on an HTTP 4xx/5xx and pipes the
# error body to jq, leaving the null-value guard as the only thing between a
# failed token request and a bearer header built from an error page.
test "${fail_on_http_error}" = true
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

# --- delegation to the real gpg ---------------------------------------------
#
# git uses gpg.program to verify as well as to sign: `git log --show-signature`,
# `git tag -v` and `--verify-signatures` all run it with --verify. Only the
# detached-sign invocation belongs to the service, so everything else has to
# reach GnuPG with argv, stdin, stdout, stderr and exit status untouched.

mkdir "${tmp_dir}/delegate"

cat >"${tmp_dir}/delegate/gpg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$@" >"${STUB_ARGV_FILE}"
cat >"${STUB_STDIN_FILE}"
printf 'stub gpg stdout\n'
printf 'stub gpg stderr\n' >&2
exit "${STUB_EXIT}"
EOF

# Routing is by argv, not by credential. A checkout with signing fully
# configured must still delegate --verify, so a gpg-sign that fails on sight
# sits next to the gpg stub for the whole section.
cat >"${tmp_dir}/delegate/gpg-sign" <<'EOF'
#!/usr/bin/env bash
echo 'gpg-sign must not be called for a non-signing invocation' >&2
exit 1
EOF

chmod +x "${tmp_dir}/delegate/gpg" "${tmp_dir}/delegate/gpg-sign"

# The exit status matters as much as the output: git reads it to decide whether
# a signature is good, so a shim that swallowed gpg's non-zero exit would report
# a BADSIG commit as verified.
for stub_exit in 0 1; do
	rm -f "${tmp_dir}/delegate-argv" "${tmp_dir}/delegate-stdin"

	set +e
	printf 'signed payload' | env \
		-u GPG_SIGN_REAL_GPG \
		-u GPG_OIDC_REQUEST_URL \
		-u GPG_OIDC_REQUEST_TOKEN \
		-u ACTIONS_ID_TOKEN_REQUEST_URL \
		-u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
		PATH="${tmp_dir}/delegate:${PATH}" \
		GPG_SIGN_URL='https://sign.example.test' \
		GPG_SIGN_TOKEN='minted-token' \
		STUB_ARGV_FILE="${tmp_dir}/delegate-argv" \
		STUB_STDIN_FILE="${tmp_dir}/delegate-stdin" \
		STUB_EXIT="${stub_exit}" \
		"${shim}" --status-fd=2 --keyid-format=long --verify /dev/null - \
		>"${tmp_dir}/delegate-output" 2>"${tmp_dir}/delegate-error"
	delegate_rc=$?
	set -e

	if [[ "${delegate_rc}" -ne "${stub_exit}" ]]; then
		echo "expected the shim to exit ${stub_exit} from gpg, got ${delegate_rc}" >&2
		exit 1
	fi

	# Byte-for-byte argv, in order. git's verify invocations carry options this
	# shim knows nothing about, so anything less than a full passthrough is a
	# shim that only works for the arguments someone thought to enumerate.
	diff - "${tmp_dir}/delegate-argv" <<'EOF'
--status-fd=2
--keyid-format=long
--verify
/dev/null
-
EOF

	# git feeds the signed payload on stdin and reads the verdict from the
	# status fd, so both directions have to survive the exec.
	test "$(cat "${tmp_dir}/delegate-stdin")" = 'signed payload'
	diff - "${tmp_dir}/delegate-output" <<'EOF'
stub gpg stdout
EOF
	diff - "${tmp_dir}/delegate-error" <<'EOF'
stub gpg stderr
EOF
done

# Verification must work in a checkout that has no signing credential at all —
# it is the everyday case for anyone who cloned this repo. env -i also proves
# the delegation path reads nothing from the environment beyond PATH.
printf 'signed payload' | env -i \
	PATH="${tmp_dir}/delegate:/usr/bin:/bin" \
	STUB_ARGV_FILE="${tmp_dir}/bare-argv" \
	STUB_STDIN_FILE="${tmp_dir}/bare-stdin" \
	STUB_EXIT=0 \
	"${shim}" --verify /dev/null - \
	>"${tmp_dir}/bare-output" 2>"${tmp_dir}/bare-error"

grep -qx 'stub gpg stdout' "${tmp_dir}/bare-output"

# GPG_SIGN_REAL_GPG names the binary outright, for a host that keeps GnuPG off
# PATH — and it has to outrank PATH, or the override cannot rescue a PATH whose
# `gpg` is the wrong one.
cat >"${tmp_dir}/override-gpg" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
printf 'override gpg ran\n'
EOF
chmod +x "${tmp_dir}/override-gpg"

printf 'signed payload' | env \
	PATH="${tmp_dir}/delegate:${PATH}" \
	GPG_SIGN_REAL_GPG="${tmp_dir}/override-gpg" \
	STUB_ARGV_FILE="${tmp_dir}/unused-argv" \
	STUB_STDIN_FILE="${tmp_dir}/unused-stdin" \
	STUB_EXIT=0 \
	"${shim}" --verify /dev/null - \
	>"${tmp_dir}/override-output" 2>"${tmp_dir}/override-error"

grep -qx 'override gpg ran' "${tmp_dir}/override-output"

# An override that cannot be executed must say so rather than quietly falling
# back to PATH: a typo'd path would otherwise verify against some other gpg
# while looking like it honoured the setting.
rm -f "${tmp_dir}/delegate-argv"
if printf 'signed payload' | env \
	PATH="${tmp_dir}/delegate:${PATH}" \
	GPG_SIGN_REAL_GPG="${tmp_dir}/does-not-exist" \
	STUB_ARGV_FILE="${tmp_dir}/delegate-argv" \
	STUB_STDIN_FILE="${tmp_dir}/delegate-stdin" \
	STUB_EXIT=0 \
	"${shim}" --verify /dev/null - \
	>"${tmp_dir}/bad-override-output" 2>"${tmp_dir}/bad-override-error"; then
	echo 'expected an unusable GPG_SIGN_REAL_GPG to fail' >&2
	exit 1
fi

grep -q 'GPG_SIGN_REAL_GPG is not an executable file' "${tmp_dir}/bad-override-error"
if grep -q 'no gpg executable found' "${tmp_dir}/bad-override-error"; then
	echo 'expected the override error alone, not the generic missing-gpg hint' >&2
	exit 1
fi
if [[ -e "${tmp_dir}/delegate-argv" ]]; then
	echo 'expected an unusable GPG_SIGN_REAL_GPG not to fall back to PATH' >&2
	exit 1
fi

# A regression in either self-reference guard does not fail, it hangs: the shim
# execs itself until the runner dies. Cap every case that could loop.
if command -v timeout >/dev/null 2>&1; then
	guard_self=(timeout 20)
else
	guard_self=()
fi

# A directory is -x whenever it is searchable, so an override that names one
# reaches exec and dies there with bash's own "Is a directory" and status 126 --
# the shape of a broken shim rather than of a misconfigured variable. Reject it
# on the same branch as a missing path.
if printf 'signed payload' | env \
	PATH="${tmp_dir}/delegate:${PATH}" \
	GPG_SIGN_REAL_GPG="${tmp_dir}/delegate" \
	STUB_ARGV_FILE="${tmp_dir}/unused-argv" \
	STUB_STDIN_FILE="${tmp_dir}/unused-stdin" \
	STUB_EXIT=0 \
	"${shim}" --verify /dev/null - \
	>"${tmp_dir}/dir-override-output" 2>"${tmp_dir}/dir-override-error"; then
	echo 'expected a directory GPG_SIGN_REAL_GPG to fail' >&2
	exit 1
fi

grep -q 'GPG_SIGN_REAL_GPG is not an executable file' "${tmp_dir}/dir-override-error"

# The override bypasses the PATH search, so it bypasses that search's self
# check. Pointed at this script it would otherwise exec once and be caught by
# the re-entry guard, whose message blames a copy of the shim on PATH -- the
# wrong thing to go looking at when the variable is what is wrong.
if printf 'signed payload' | env \
	-u GPG_SIGN_GIT_PROGRAM_DELEGATED \
	PATH="${tmp_dir}/delegate:${PATH}" \
	GPG_SIGN_REAL_GPG="${shim}" \
	"${guard_self[@]}" "${shim}" --verify /dev/null - \
	>"${tmp_dir}/self-override-output" 2>"${tmp_dir}/self-override-error"; then
	echo 'expected GPG_SIGN_REAL_GPG pointing at the shim to fail' >&2
	exit 1
fi

grep -q 'GPG_SIGN_REAL_GPG points at this script' "${tmp_dir}/self-override-error"
if grep -q 'refusing to delegate to itself' "${tmp_dir}/self-override-error"; then
	echo 'expected the override to be rejected before any exec' >&2
	exit 1
fi

# Installing the shim under the name `gpg` is a supported thing to do, and the
# obvious implementation of "run gpg" would then run the shim again. A symlink
# is the ordinary way to do it, and -ef sees through it, so the search has to
# walk past this entry and find the next one.
mkdir "${tmp_dir}/self-link"
ln -s "${shim}" "${tmp_dir}/self-link/gpg"

rm -f "${tmp_dir}/delegate-argv"
printf 'signed payload' | env \
	-u GPG_SIGN_REAL_GPG \
	PATH="${tmp_dir}/self-link:${tmp_dir}/delegate:${PATH}" \
	STUB_ARGV_FILE="${tmp_dir}/delegate-argv" \
	STUB_STDIN_FILE="${tmp_dir}/delegate-stdin" \
	STUB_EXIT=0 \
	"${shim}" --verify /dev/null - \
	>"${tmp_dir}/self-link-output" 2>"${tmp_dir}/self-link-error"

grep -qx 'stub gpg stdout' "${tmp_dir}/self-link-output"
test -e "${tmp_dir}/delegate-argv"

# A byte copy under the name `gpg` has its own inode, so -ef cannot see it and
# the shim does exec itself. The re-entry marker is the only thing between that
# and a runner forking until it dies, so this case asserts it terminates —
# under `timeout`, because a regression here does not fail, it hangs.
mkdir "${tmp_dir}/self-copy"
cp "${shim}" "${tmp_dir}/self-copy/gpg"
chmod +x "${tmp_dir}/self-copy/gpg"

if printf 'signed payload' | env \
	-u GPG_SIGN_REAL_GPG \
	-u GPG_SIGN_GIT_PROGRAM_DELEGATED \
	PATH="${tmp_dir}/self-copy:${PATH}" \
	"${guard_self[@]}" "${shim}" --verify /dev/null - \
	>"${tmp_dir}/self-copy-output" 2>"${tmp_dir}/self-copy-error"; then
	echo 'expected a self-copy on PATH to be refused' >&2
	exit 1
fi

grep -q 'refusing to delegate to itself' "${tmp_dir}/self-copy-error"

# No gpg anywhere: say what is missing. git turns any non-zero exit into its own
# message, so an unnamed failure here reads as a broken signature rather than a
# host without GnuPG. bash is symlinked in because the shebang needs it; gpg
# deliberately is not.
mkdir "${tmp_dir}/no-gpg"
ln -s "$(command -v bash)" "${tmp_dir}/no-gpg/bash"

if printf 'signed payload' | env \
	-u GPG_SIGN_REAL_GPG \
	PATH="${tmp_dir}/no-gpg" \
	"${shim}" --verify /dev/null - \
	>"${tmp_dir}/no-gpg-output" 2>"${tmp_dir}/no-gpg-error"; then
	echo 'expected a missing gpg to fail' >&2
	exit 1
fi

grep -q 'no gpg executable found' "${tmp_dir}/no-gpg-error"

# GPG_SIGN_URL is required, and the message has to name it: git reports any
# non-zero exit from gpg.program as "gpg failed to sign the data", so an
# unnamed failure is indistinguishable from a rejected credential.
#
# -u GPG_SIGN_URL is not decoration — setup-claude-signing exports it through
# GITHUB_ENV, so in CI this case inherits a real one and asserts nothing.
#
# Unset and empty both have to fail: the guard is ${GPG_SIGN_URL:?...}, and
# covering only the unset case cannot tell that apart from a plain ${...?...},
# which fires on unset but not on null. What an empty value would reach is
# `gpg-sign sign`, not curl — the OIDC request URL is built from oidc_url, and
# GPG_SIGN_URL is never part of it. getBaseURL() in client/cmd/gpg-sign/main.go
# treats empty as unset and falls back to the hardcoded
# https://gpg.kajkowalski.nl, so a weakened guard does not fail loudly: it sends
# the commit object and the bearer token to the upstream default host instead of
# whichever deployment the caller configured.
for url_case in unset empty; do
	if [ "${url_case}" = unset ]; then
		url_env=(-u GPG_SIGN_URL)
	else
		url_env=(GPG_SIGN_URL=)
	fi

	if printf 'commit object' | env \
		"${url_env[@]}" \
		PATH="${tmp_dir}/bin:${PATH}" \
		GPG_SIGN_TOKEN='minted-token' \
		"${shim}" --status-fd=2 -bsau test-key \
		>"${tmp_dir}/no-url-output" 2>"${tmp_dir}/no-url-error"; then
		echo "expected GPG_SIGN_URL (${url_case}) to fail" >&2
		exit 1
	fi

	grep -q 'GPG_SIGN_URL must point at the signing service' "${tmp_dir}/no-url-error"
done

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

# git passes -bsau <key>, but the shim also advertises -bsa and --detach-sign.
# Every case above uses -bsau, so dropping the other two aliases leaves the
# suite green while breaking any caller that uses them.
for signing_arg in -bsa --detach-sign; do
	printf 'commit object' | env \
		-u GPG_OIDC_REQUEST_URL \
		-u GPG_OIDC_REQUEST_TOKEN \
		-u ACTIONS_ID_TOKEN_REQUEST_URL \
		-u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
		PATH="${tmp_dir}/bin:${PATH}" \
		GPG_SIGN_URL='https://sign.example.test' \
		GPG_SIGN_TOKEN='minted-token' \
		"${shim}" --status-fd=2 "${signing_arg}" \
		>"${tmp_dir}/alias-arg-output" 2>"${tmp_dir}/alias-arg-status"

	grep -q '^-----BEGIN PGP SIGNATURE-----$' "${tmp_dir}/alias-arg-output"
	grep -q '^\[GNUPG:\] SIG_CREATED $' "${tmp_dir}/alias-arg-status"
done

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

# --- end to end, against real git and real GnuPG -----------------------------
#
# Everything above stubs gpg, so it proves the shim hands over an invocation but
# not that git is satisfied by what comes back. This signs with real gpg, then
# verifies through the shim: `git log --show-signature`, `git verify-commit` and
# `git tag -v` are exactly the three commands issue #72 reported as broken.
if ! command -v gpg >/dev/null 2>&1; then
	printf 'skipping the end-to-end verification case: no gpg on PATH\n' >&2
else
	gnupg_home="${tmp_dir}/gnupg"
	mkdir -m 700 "${gnupg_home}"
	# gpg-agent outlives the command that started it and holds the socket in
	# the temp dir the EXIT trap is about to remove.
	trap 'gpgconf --homedir "${gnupg_home}" --kill all >/dev/null 2>&1 || true; rm -rf "${tmp_dir}"' EXIT

	GNUPGHOME="${gnupg_home}" gpg --batch --quiet --passphrase '' \
		--quick-generate-key 'Shim Test <shim@example.test>' ed25519 sign never

	signing_key="$(
		GNUPGHOME="${gnupg_home}" gpg --batch --with-colons --list-secret-keys \
			| awk -F: '/^fpr:/ { print $10; exit }'
	)"
	test -n "${signing_key}"

	e2e_repo="${tmp_dir}/e2e-repo"
	git init -q "${e2e_repo}"
	git -C "${e2e_repo}" config user.name 'Shim Test'
	git -C "${e2e_repo}" config user.email 'shim@example.test'
	git -C "${e2e_repo}" config gpg.format openpgp
	git -C "${e2e_repo}" config user.signingkey "${signing_key}"
	: >"${e2e_repo}/file"
	git -C "${e2e_repo}" add file

	# Signed by gpg directly. The service path has no key in this keyring, and
	# what is under test is verification, not signing.
	GNUPGHOME="${gnupg_home}" git -C "${e2e_repo}" \
		-c gpg.program=gpg -c commit.gpgsign=true \
		commit -q -m 'signed by real gpg'
	GNUPGHOME="${gnupg_home}" git -C "${e2e_repo}" \
		-c gpg.program=gpg tag -s -m 'signed tag' e2e-tag

	# From here on gpg.program is the shim, and no credential is in scope: a
	# clone that never configured the service still has to be able to verify.
	e2e_git() {
		env \
			-u GPG_SIGN_URL \
			-u GPG_SIGN_TOKEN \
			-u GPG_SIGN_REAL_GPG \
			-u GPG_OIDC_REQUEST_URL \
			-u GPG_OIDC_REQUEST_TOKEN \
			-u ACTIONS_ID_TOKEN_REQUEST_URL \
			-u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
			GNUPGHOME="${gnupg_home}" \
			git -C "${e2e_repo}" -c gpg.program="${shim}" -c gpg.format=openpgp "$@"
	}

	e2e_git log --show-signature -1 >"${tmp_dir}/e2e-log" 2>&1
	grep -q 'Good signature from "Shim Test <shim@example.test>"' "${tmp_dir}/e2e-log"

	e2e_git verify-commit HEAD >"${tmp_dir}/e2e-verify" 2>&1
	grep -q 'Good signature' "${tmp_dir}/e2e-verify"

	e2e_git tag -v e2e-tag >"${tmp_dir}/e2e-tag" 2>&1
	grep -q 'Good signature' "${tmp_dir}/e2e-tag"

	# A tampered signature has to come back bad. Without this, a shim that
	# exited 0 unconditionally would pass every case above.
	git -C "${e2e_repo}" cat-file commit HEAD \
		| sed 's/signed by real gpg/tampered payload!!/' \
		| git -C "${e2e_repo}" hash-object -t commit -w --stdin \
			>"${tmp_dir}/tampered-commit"

	if e2e_git verify-commit "$(cat "${tmp_dir}/tampered-commit")" \
		>"${tmp_dir}/e2e-bad" 2>&1; then
		echo 'expected a tampered commit to fail verification through the shim' >&2
		exit 1
	fi

	# The verdict, not just the exit code: a shim that mangled the payload would
	# also exit non-zero, but for the wrong reason.
	grep -q 'BAD signature' "${tmp_dir}/e2e-bad"
fi

printf 'signing shim tests passed\n'
