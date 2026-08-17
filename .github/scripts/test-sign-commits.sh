#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
sign_script="${repo_root}/.github/scripts/sign-commits.py"

# The fixture must inherit no GIT_* state at all; unsetting just the identity
# vars left the rest of the namespace reachable. Worst first:
#   GIT_DIR / GIT_WORK_TREE  aim `git -C "${test_repo}"` back at the caller's
#     repository, so `init` re-inits it and the fixture's commits and its
#     `config user.email` land on the real repo. `reset --hard` does not undo
#     the config half. Git does not export these to hooks, but anything that
#     exports them by hand (bare-repo tooling, wrapper scripts) gets this.
#   GIT_INDEX_FILE  fails the run outright ("error: Error building trees"), and
#     git *does* export it to pre-commit / commit-msg hooks.
#   GIT_CONFIG_COUNT / GIT_CONFIG_KEY_*  inject config that outranks the
#     GIT_CONFIG_GLOBAL pin below, including the commit.gpgsign case it names.
#   GIT_AUTHOR_* / GIT_COMMITTER_*  outrank the fixture's local config and
#     silently rewrite the "foreign" committer (GitHub Actions exports these).
# Quoted "${!GIT_@}" expands per-name like "$@", so an environment with no
# GIT_* variables yields a bare, successful `unset`.
unset "${!GIT_@}"

# Keep the fixture repo away from the caller's git config: a global
# commit.gpgsign would sign (or block on pinentry for) the base commit.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

tmp_dir="$(mktemp -d)"

cleanup() {
	local home
	# sign-commits.py leaves a keyring per invocation; TMPDIR keeps them here.
	for home in "${tmp_dir}"/sign-commits-* "${tmp_dir}"/*-gnupg; do
		[[ -d "${home}" ]] || continue
		gpgconf --homedir "${home}" --kill all >/dev/null 2>&1 || true
	done
	rm -rf "${tmp_dir}"
}
trap cleanup EXIT

service_home="${tmp_dir}/service-gnupg"
foreign_home="${tmp_dir}/foreign-gnupg"
test_repo="${tmp_dir}/repo"
mkdir -m 700 "${service_home}" "${foreign_home}"

generate_key() {
	local home="$1"
	local identity="$2"
	local key

	if ! gpg --homedir "${home}" --batch --quiet --pinentry-mode loopback \
		--passphrase '' --quick-generate-key "${identity}" ed25519 sign 0; then
		return 1
	fi
	key="$(gpg --homedir "${home}" --batch --with-colons --list-secret-keys \
		| awk -F: '$1 == "sec" { print $5; exit }')"
	[[ -n "${key}" ]]
	printf '%s\n' "${key}"
}

service_key="$(generate_key "${service_home}" 'Service signer <service@example.com>')"
foreign_key="$(generate_key "${foreign_home}" 'Foreign signer <foreign@example.com>')"

mkdir -p "${tmp_dir}/bin" "${test_repo}"

cat >"${tmp_dir}/bin/gpg-sign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
	public-key)
		gpg --homedir "${SERVICE_GNUPGHOME}" --batch --quiet --armor --export "${SERVICE_KEY}"
		;;
	sign)
		gpg --homedir "${SERVICE_GNUPGHOME}" --batch --quiet --yes --armor \
			--pinentry-mode loopback --passphrase '' --detach-sign --local-user "${SERVICE_KEY}"
		;;
	*)
		printf 'unexpected gpg-sign command: %s\n' "${1:-}" >&2
		exit 1
		;;
esac
EOF
chmod +x "${tmp_dir}/bin/gpg-sign"

git -C "${test_repo}" init --quiet --initial-branch=master
git -C "${test_repo}" config user.name 'Foreign signer'
git -C "${test_repo}" config user.email 'foreign@example.com'
printf 'base\n' >"${test_repo}/fixture.txt"
git -C "${test_repo}" add fixture.txt
git -C "${test_repo}" commit --quiet -m base
base="$(git -C "${test_repo}" rev-parse HEAD)"

git -C "${test_repo}" config user.signingkey "${foreign_key}"
git -C "${test_repo}" config commit.gpgsign true
printf 'foreign signature\n' >>"${test_repo}/fixture.txt"
git -C "${test_repo}" add fixture.txt
GNUPGHOME="${foreign_home}" git -C "${test_repo}" commit --quiet -m foreign
foreign="$(git -C "${test_repo}" rev-parse HEAD)"
GNUPGHOME="${foreign_home}" git -C "${test_repo}" verify-commit "${foreign}" \
	>/dev/null 2>&1

common_env=(
	PATH="${tmp_dir}/bin:${PATH}"
	TMPDIR="${tmp_dir}"
	SERVICE_GNUPGHOME="${service_home}"
	SERVICE_KEY="${service_key}"
	GPG_SIGN_TOKEN=test-token
	GPG_SIGN_URL=https://sign.example.test
	BASE_REF="${base}"
	DEFAULT_BRANCH=master
	SIGN_OTHERS=true
	SCAN_LIMIT=
)

if blocked="$(cd "${test_repo}" && env "${common_env[@]}" ALLOW_RESIGN=false python3 "${sign_script}" 2>&1)"; then
	printf 'expected an already-signed foreign commit to require allow_resign\n' >&2
	exit 1
fi
grep -Fq 'dispatch with allow_resign' <<<"${blocked}"
grep -Fq 'signed by a key this service does not carry' <<<"${blocked}"
current="$(git -C "${test_repo}" rev-parse HEAD)"
[[ "${current}" == "${foreign}" ]]
committer="$(git -C "${test_repo}" log -1 --format='%ce' "${foreign}")"
[[ "${committer}" == foreign@example.com ]]

(cd "${test_repo}" && env "${common_env[@]}" ALLOW_RESIGN=true python3 "${sign_script}")
resigned="$(git -C "${test_repo}" rev-parse HEAD)"
[[ "${resigned}" != "${foreign}" ]]
GNUPGHOME="${service_home}" git -C "${test_repo}" verify-commit "${resigned}" \
	>/dev/null 2>&1

rerun="$(cd "${test_repo}" && env "${common_env[@]}" ALLOW_RESIGN=true python3 "${sign_script}")"
current="$(git -C "${test_repo}" rev-parse HEAD)"
[[ "${current}" == "${resigned}" ]]
grep -Fq 'Nothing to sign' <<<"${rerun}"

printf 'foreign signature re-signing test passed\n'
