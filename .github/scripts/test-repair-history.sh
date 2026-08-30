#!/usr/bin/env bash
# Drive .github/scripts/repair-history.sh and assert-repaired-range.sh against a
# repaired range and against every way a repair can look finished and still be
# wrong.
#
# The Go tests cover the rewrite. This covers the gate in front of the force
# push, which is the half that has to hold even if the rewrite is wrong — the
# Aug 30 chain was rewritten, signed, and still carried `author claude[bot]`
# and `committer GitHub`, and nothing looked at that before publishing it.
#
# Nothing here resolves `gpg-sign` from PATH. Both scripts take the binary to
# run from GPG_SIGN_BIN, and this suite points it at a recording stub or at a
# build of the checked-out command — never at whatever release happens to be
# installed, which predates `repair-history` and would make a run that should
# fail look like it passed.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
assert_script="${repo_root}/.github/scripts/assert-repaired-range.sh"
repair_script="${repo_root}/.github/scripts/repair-history.sh"

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

# The stub stands in for the CLI: the assertion script builds its keyring from
# `gpg-sign public-key`, and the orchestration script asks for `repair-history
# --help` and then reads a JSON report. The rewrite itself is the Go code's job
# and has its own tests; the stub only has to answer in the shape the shell
# reads, and to record what it was asked so the flag assembly can be checked.
cat >"${tmp_dir}/bin/gpg-sign" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${STUB_ARGV-}" ]] || printf '%s\n' "$@" >>"${STUB_ARGV}"

args=("$@")
[[ "${args[0]-}" != "--json" ]] || args=("${args[@]:1}")

case "${args[0]-}" in
	public-key) gpg --homedir "${SERVICE_GNUPGHOME}" --batch --quiet --armor --export "${SERVICE_KEY}" ;;
	repair-history)
		if [[ " ${args[*]} " == *" --help "* ]]; then
			printf 'Rewrite a range of commits to claim one identity, then sign them\n'
			exit 0
		fi
		printf '{"tip":"%s","mapping":[]}\n' "${STUB_TIP-}"
		;;
	*)
		printf 'unexpected gpg-sign command: %s\n' "${args[0]-}" >&2
		exit 1
		;;
esac
STUB
chmod +x "${tmp_dir}/bin/gpg-sign"

# A gpg-sign that predates repair-history, which is exactly what the released
# binary the signing action installs is today.
cat >"${tmp_dir}/bin/gpg-sign-old" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf 'Error: unknown command "%s" for "gpg-sign"\n' "${1:-}" >&2
exit 1
STUB
chmod +x "${tmp_dir}/bin/gpg-sign-old"

# Deliberately not on PATH. If either script ever stops honouring the seam and
# falls back to the bare name, these runs fail rather than silently reaching a
# gpg-sign this suite did not build.
export GPG_SIGN_BIN="${tmp_dir}/bin/gpg-sign"
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

# --- the orchestration in front of the force push -----------------------------
#
# repair-history.sh is the only thing here that can publish, so what it refuses
# is the point. Every run below drives it against the recording stub: the flags
# it assembles are read back out of the recording, and no run is allowed to
# reach a real signing service or a real remote.

if ! command -v jq >/dev/null 2>&1; then
	printf 'jq is not installed; skipping the repair orchestration suite\n'
	exit 0
fi

export STUB_ARGV="${tmp_dir}/argv"
export STUB_TIP="${good_tip}"

# The fixture's later commits exist to be refused; the orchestration runs
# against the range that passes.
git -C "${test_repo}" checkout --quiet --detach "${good_tip}"

# run_repair [VAR=VALUE ...] — the four required inputs, plus any overrides.
#
# IDENTITY is deliberately padded: the CLI writes the trimmed form, so a script
# that passed the raw string through would sign the whole range and only then
# fail its own assertions comparing against the untrimmed one.
run_repair() {
	: >"${STUB_ARGV}"
	(
		cd "${test_repo}" || exit 1
		env BASE_REF="${base}" EXPECTED_TIP="${good_tip}" \
			IDENTITY="  ${identity}  " BRANCH=master \
			EXPECT_IDENTITIES=$'info@kajkowalski.nl\nnoreply@github.com' \
			"$@" "${repair_script}" 2>&1
	)
}

# refuses_repair <description> <needle> [VAR=VALUE ...]
refuses_repair() {
	local description="$1" needle="$2"
	shift 2
	local output
	if output="$(run_repair "$@")"; then
		printf 'expected repair-history.sh to refuse: %s\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
	if ! grep -Fq "${needle}" <<<"${output}"; then
		printf 'the refusal for %s does not mention %q:\n%s\n' "${description}" "${needle}" "${output}" >&2
		exit 1
	fi
}

# Publishing is opt-in. The four required inputs and nothing else must leave the
# branch where it was — and the fixture has no remote, so a run that tried to
# push would fail here rather than pass quietly.
if ! output="$(run_repair)"; then
	printf 'a run with the four required inputs and nothing else failed — it should have stopped short of publishing, not tried:\n%s\n' "${output}" >&2
	exit 1
fi
if ! grep -Fq 'was not published (PUSH=false)' <<<"${output}"; then
	printf 'a run without PUSH=true did not stop short of publishing:\n%s\n' "${output}" >&2
	exit 1
fi

# The flags the stub was actually given: the trimmed identity, the bounds, and
# one --expect-identity per line of EXPECT_IDENTITIES.
grep -Fqx -- "--identity=${identity}" "${STUB_ARGV}" \
	|| {
		printf 'the identity was not trimmed before it reached the CLI:\n%s\n' "$(cat "${STUB_ARGV}")" >&2
		exit 1
	}
grep -Fqx -- "--base=${base}" "${STUB_ARGV}"
grep -Fqx -- "--expected-tip=${good_tip}" "${STUB_ARGV}"
grep -Fqx -- '--expect-identity=info@kajkowalski.nl' "${STUB_ARGV}"
grep -Fqx -- '--expect-identity=noreply@github.com' "${STUB_ARGV}"
if grep -Fqx -- '--dry-run' "${STUB_ARGV}"; then
	printf 'a plain run passed --dry-run\n' >&2
	exit 1
fi

# A dry run stops before the assertions and before any push, and says so.
if ! output="$(run_repair DRY_RUN=true)"; then
	printf 'a dry run failed:\n%s\n' "${output}" >&2
	exit 1
fi
grep -Fq 'Nothing was signed, written or pushed.' <<<"${output}"
grep -Fqx -- '--dry-run' "${STUB_ARGV}" \
	|| {
		printf 'DRY_RUN=true did not reach the CLI:\n%s\n' "$(cat "${STUB_ARGV}")" >&2
		exit 1
	}

# The seam, stated as a refusal. A released gpg-sign that predates the command
# has to be named as such, not discovered halfway through a rewrite.
refuses_repair 'a gpg-sign without repair-history' 'has no repair-history command' \
	GPG_SIGN_BIN="${tmp_dir}/bin/gpg-sign-old"
refuses_repair 'a gpg-sign that does not exist' 'is not executable' \
	GPG_SIGN_BIN="${tmp_dir}/bin/gpg-sign-missing"

# Every bound is required, by design: there is no default for any of them.
refuses_repair 'a missing base' 'base is required' BASE_REF=
refuses_repair 'a missing expected tip' 'expected_tip is required' EXPECTED_TIP=
refuses_repair 'a missing identity' 'identity is required' IDENTITY=
refuses_repair 'a missing branch' 'branch is required' BRANCH=
refuses_repair 'no expected identities' 'EXPECT_IDENTITIES is empty' EXPECT_IDENTITIES=

# The lease is only as good as the tip it names.
refuses_repair 'a tip HEAD is not on' 're-read the branch before dispatching' \
	EXPECTED_TIP="${base}"

printf 'repair orchestration: all cases passed\n'

# --- the command this all orchestrates ----------------------------------------
#
# Built from the checkout, on purpose. `gpg-sign repair-history` does not exist
# in any release yet, so a suite that took the name from PATH would be testing
# whatever the signing action installed.

if ! command -v go >/dev/null 2>&1; then
	printf 'go is not installed; skipping the checked-out CLI build\n'
	exit 0
fi

built="${tmp_dir}/bin/gpg-sign-built"
(cd "${repo_root}/client" && go build -o "${built}" ./cmd/gpg-sign)

"${built}" repair-history --help >/dev/null \
	|| {
		printf 'the checked-out gpg-sign has no repair-history command\n' >&2
		exit 1
	}

# The same probe repair-history.sh makes, against the binary it would run in
# production once a release carries the command. The run itself goes no further
# than the probe — there is no signing service here — but it must not be the
# probe that stops it.
output="$(run_repair GPG_SIGN_BIN="${built}" DRY_RUN=true || true)"
if grep -Fq 'has no repair-history command' <<<"${output}"; then
	printf 'the orchestration rejected the checked-out CLI:\n%s\n' "${output}" >&2
	exit 1
fi

printf 'checked-out gpg-sign: repair-history is present\n'
