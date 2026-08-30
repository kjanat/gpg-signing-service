#!/usr/bin/env bash
# Drive .github/scripts/assert-repaired-range.sh against a repaired range and
# against every way a repair can look finished and still be wrong.
#
# The Go tests cover the rewrite. This covers the gate in front of the force
# push, which is the half that has to hold even if the rewrite is wrong — the
# Aug 30 chain was rewritten, signed, and still carried `author claude[bot]`
# and `committer GitHub`, and nothing looked at that before publishing it.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
assert_script="${repo_root}/.github/scripts/assert-repaired-range.sh"

# The fixture must inherit no GIT_* state at all. Worst first: GIT_DIR and
# GIT_WORK_TREE aim the fixture's commands back at the caller's own repository,
# so `init` re-inits it and the fixture's commits land there; GIT_INDEX_FILE,
# which git exports to hooks, fails the run outright; GIT_CONFIG_COUNT injects
# config outranking the pin below; and GIT_AUTHOR_*/GIT_COMMITTER_* — which
# GitHub Actions exports — would silently overwrite the very identities this
# suite is asserting on.
unset "${!GIT_@}"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

if ! command -v gpg >/dev/null 2>&1; then
	printf 'gpg is not installed; skipping the repaired-range assertion suite\n'
	exit 0
fi

tmp_dir="$(mktemp -d)"
cleanup() {
	local home
	for home in "${tmp_dir}"/*-gnupg; do
		[[ -d "${home}" ]] || continue
		gpgconf --homedir "${home}" --kill all >/dev/null 2>&1 || true
	done
	rm -rf "${tmp_dir}"
}
trap cleanup EXIT

service_home="${tmp_dir}/service-gnupg"
test_repo="${tmp_dir}/repo"
mkdir -m 700 "${service_home}"
mkdir -p "${tmp_dir}/bin" "${test_repo}"

gpg --homedir "${service_home}" --batch --quiet --pinentry-mode loopback \
	--passphrase '' --quick-generate-key 'Kaj Kowalski <info@kajkowalski.nl>' ed25519 sign 0
service_key="$(gpg --homedir "${service_home}" --batch --with-colons --list-secret-keys \
	| awk -F: '$1 == "sec" { print $5; exit }')"
[[ -n "${service_key}" ]]

# The assertion script builds its keyring from `gpg-sign public-key` and
# nothing else, so the stub only has to answer that.
cat >"${tmp_dir}/bin/gpg-sign" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
	public-key) gpg --homedir "${SERVICE_GNUPGHOME}" --batch --quiet --armor --export "${SERVICE_KEY}" ;;
	*)
		printf 'unexpected gpg-sign command: %s\n' "${1:-}" >&2
		exit 1
		;;
esac
STUB
chmod +x "${tmp_dir}/bin/gpg-sign"

export PATH="${tmp_dir}/bin:${PATH}"
export SERVICE_GNUPGHOME="${service_home}"
export SERVICE_KEY="${service_key}"

readonly identity='Kaj Kowalski <info@kajkowalski.nl>'
readonly bot='claude[bot] <209825114+claude[bot]@users.noreply.github.com>'

git -C "${test_repo}" init --quiet --initial-branch=master
git -C "${test_repo}" config user.signingkey "${service_key}"
git -C "${test_repo}" config commit.gpgsign true

# add <file> <author> <committer> [--no-gpg-sign]
#
# The author and committer are set independently, because the failure this
# guards against had a different wrong identity in each header.
add() {
	local file="$1" author="$2" committer="$3"
	shift 3
	local author_email="${author##*<}" committer_email="${committer##*<}"
	printf '%s\n' "${file}" >"${test_repo}/${file}"
	git -C "${test_repo}" add "${file}"
	GNUPGHOME="${service_home}" \
		GIT_AUTHOR_NAME="${author%% <*}" GIT_AUTHOR_EMAIL="${author_email%>}" \
		GIT_COMMITTER_NAME="${committer%% <*}" GIT_COMMITTER_EMAIL="${committer_email%>}" \
		git -C "${test_repo}" commit --quiet -m "add ${file}" "$@"
}

add base.txt "${identity}" "${identity}"
base="$(git -C "${test_repo}" rev-parse HEAD)"

add one.txt "${identity}" "${identity}"
add two.txt "${identity}" "${identity}"
good_tip="$(git -C "${test_repo}" rev-parse HEAD)"
good_tree="$(git -C "${test_repo}" rev-parse "${good_tip}^{tree}")"

# A correctly repaired range passes, or none of the refusals below prove
# anything.
output="$(cd "${test_repo}" && "${assert_script}" "${base}" "${good_tip}" "${good_tree}" "${identity}")"
grep -Fq '2 commit(s)' <<<"${output}"

# refuses <description> <needle> <base> <tip> <tree> <identity>
refuses() {
	local description="$1" needle="$2"
	shift 2
	local output
	if output="$(cd "${test_repo}" && "${assert_script}" "$@" 2>&1)"; then
		printf 'expected the assertions to refuse: %s\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
	if ! grep -Fq "${needle}" <<<"${output}"; then
		printf 'the refusal for %s does not mention %q:\n%s\n' "${description}" "${needle}" "${output}" >&2
		exit 1
	fi
}

# The exact regression. A commit that is signed, and rewritten, and still says
# the bot wrote it, must not reach a push.
add bot-author.txt "${bot}" "${identity}"
bot_author_tip="$(git -C "${test_repo}" rev-parse HEAD)"
refuses 'an author left as the bot' 'author is claude[bot]' \
	"${base}" "${bot_author_tip}" "$(git -C "${test_repo}" rev-parse "${bot_author_tip}^{tree}")" "${identity}"

add github-committer.txt "${identity}" 'GitHub <noreply@github.com>'
github_tip="$(git -C "${test_repo}" rev-parse HEAD)"
refuses 'a committer left as GitHub' 'committer is GitHub' \
	"${base}" "${github_tip}" "$(git -C "${test_repo}" rev-parse "${github_tip}^{tree}")" "${identity}"

# Right identity, no signature: the other half of what "repaired" has to mean.
add unsigned.txt "${identity}" "${identity}" --no-gpg-sign
unsigned_tip="$(git -C "${test_repo}" rev-parse HEAD)"
refuses 'an unsigned commit' 'carries no signature the service key verifies' \
	"${base}" "${unsigned_tip}" "$(git -C "${test_repo}" rev-parse "${unsigned_tip}^{tree}")" "${identity}"

# A repair is not allowed to change what the branch contains, whatever it does
# to who is named on it.
refuses 'a tip whose tree moved' 'changed the content of the branch' \
	"${base}" "${good_tip}" "$(git -C "${test_repo}" rev-parse "${base}^{tree}")" "${identity}"

refuses 'an empty range' 'nothing to assert about' \
	"${good_tip}" "${good_tip}" "${good_tree}" "${identity}"

refuses 'a missing identity' 'usage:' "${base}" "${good_tip}" "${good_tree}"

printf 'repaired-range assertions: all cases passed\n'
