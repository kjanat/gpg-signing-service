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

# --- the wiring ---------------------------------------------------------------
#
# A repair nothing can dispatch is a repair that gets run by hand. The workflow
# arrives the way the other workflow files this repository's bot writes do: in
# .github/workflows-pending/, because a GitHub App token has no `workflows`
# permission, activated by a human with one `git mv`.
#
# Resolved PENDING-first, and checked before the gpg/jq/go skips below so the
# wiring is asserted on every machine. Once the file is moved into place this
# follows it and becomes a standing guard.
pending_workflow="${repo_root}/.github/workflows-pending/repair-history.yml"
live_workflow="${repo_root}/.github/workflows/repair-history.yml"

if [[ -f "${pending_workflow}" ]]; then
	workflow="${pending_workflow}"
	printf '  note: the repair workflow is still pending activation (git mv %s .github/workflows/repair-history.yml)\n' \
		'.github/workflows-pending/repair-history.yml'
elif [[ -f "${live_workflow}" ]]; then
	workflow="${live_workflow}"
else
	echo 'FAIL: repair-history.yml is in neither .github/workflows/ nor .github/workflows-pending/' >&2
	exit 1
fi

# What the workflow runs, not what it mentions. `grep -F '<path>'` cannot tell
# the step that dispatches the repair from a comment describing it or a line
# that prints the path, and the whole value of this assertion is that it fails
# when the workflow stops calling the script this suite goes on to exercise.
# The script's own `run:` block is several lines of setup with the call last,
# so the block form has to be read as well as the inline one.
#
# shellcheck source=.github/scripts/workflow-steps.sh
source "${repo_root}/.github/scripts/workflow-steps.sh"

# The shapes that must not read as wiring, asserted before the workflow is
# judged by them.
fixture_dir="$(mktemp -d)"
trap 'rm -rf "${fixture_dir}"' EXIT

# matcher_case <description> <expected> <workflow body>
matcher_case() {
	local description="$1" expected="$2" got
	printf '%s\n' "$3" >"${fixture_dir}/workflow.yml"
	# `|| exit 1` because "" is a real answer here — no step runs the script —
	# so a parse that could not happen must not read as that same answer.
	got="$(workflow_runs_script "${fixture_dir}/workflow.yml" .github/scripts/repair-history.sh)" || exit 1
	if [[ "${got}" != "${expected}" ]]; then
		printf 'FAIL: the wiring matcher read %s as %q, expected %q\n' \
			"${description}" "${got}" "${expected}" >&2
		exit 1
	fi
}

matcher_case 'a step that runs the script' .github/scripts/repair-history.sh \
	'jobs:
  repair:
    steps:
      - run: .github/scripts/repair-history.sh'
# shellcheck disable=SC2016  # the fixture is YAML the matcher parses, so
# `${GPG_SIGN_BIN}` is meant to stay unexpanded.
matcher_case 'a step that runs it on the last line of a block' .github/scripts/repair-history.sh \
	'jobs:
  repair:
    steps:
      - run: |
          [[ -n "${GPG_SIGN_BIN}" ]] || unset GPG_SIGN_BIN
          .github/scripts/repair-history.sh'
matcher_case 'a comment describing the step' '' \
	'jobs:
  repair:
    steps:
      # .github/scripts/repair-history.sh rewrites and signs, then asserts.
      - run: git push'
matcher_case 'a step that only prints the path' '' \
	'jobs:
  repair:
    steps:
      - run: echo .github/scripts/repair-history.sh'
matcher_case 'a shell comment inside a run block' '' \
	'jobs:
  repair:
    steps:
      - run: |
          # .github/scripts/repair-history.sh is dispatched from elsewhere
          task client:build'
matcher_case 'an env value naming the path' '' \
	'jobs:
  repair:
    steps:
      - env:
          SCRIPT: .github/scripts/repair-history.sh
        run: git push'
# The folded pair: YAML joins a `>` block into one command, so the first of
# these passes the path to `echo` and the second runs it. The full matrix is
# .github/scripts/test-workflow-steps.sh.
matcher_case 'a folded block where the path is an argument' '' \
	'jobs:
  repair:
    steps:
      - run: >
          echo dispatching
          .github/scripts/repair-history.sh'
matcher_case 'a folded block that runs the script' .github/scripts/repair-history.sh \
	'jobs:
  repair:
    steps:
      - run: >-
          .github/scripts/repair-history.sh
          --dry-run'

rm -rf "${fixture_dir}"
trap - EXIT

repair_step="$(workflow_runs_script "${workflow}" .github/scripts/repair-history.sh)" || exit 1
if [[ "${repair_step}" != .github/scripts/repair-history.sh ]]; then
	printf 'FAIL: no step in %s runs .github/scripts/repair-history.sh\n' "${workflow}" >&2
	printf '      A step that names the path without running it is not the wiring.\n' >&2
	exit 1
fi
[[ -x "${repair_script}" ]] || {
	printf 'FAIL: %s is not an executable file in this tree\n' "${repair_script}" >&2
	exit 1
}

# Every external action this job runs, pinned. The steps before the signing
# one hold `contents: write` and an OIDC token that mints real signatures, so
# an action resolved through a tag is a step someone else can repoint into a
# job with all of that. Asserted rather than reviewed once, because a tag and a
# SHA look equally fine in a diff.
mutable="$(workflow_mutable_uses "${workflow}" --expect-uses)" || exit 1
if [[ -n "${mutable}" ]]; then
	printf 'FAIL: %s resolves an external action through a mutable ref:\n' "${workflow}" >&2
	printf '        %s\n' "${mutable}" >&2
	printf '      Pin it to the full commit SHA, with the version as a trailing comment.\n' >&2
	exit 1
fi

# The two defaults that decide what an operator gets when they fill in the
# bounds and press the button. A dispatch that plans is recoverable; one that
# rewrites and publishes twenty commits is the thing this whole command exists
# to clean up after. Both are asserted here because a YAML default is one
# character away from its opposite and nothing else would notice.
#
# Read from the input's own mapping, not by scanning forward from its name. The
# scan this replaces —
#
#   awk '/^      dry_run:/ { found = 1 } found && /default:/ { print $2; exit }'
#
# — does not stop at the end of the input it started in. An input that has lost
# its own `default:` inherits the next input's, so the guard reports a value
# nothing set: delete `push`'s default here and the scan reads
# `build_from_source`'s `false` and passes, having checked nothing. That is the
# whole assertion going quiet on the one edit it exists to catch.
#
# `workflow_input_field` fails rather than answering when the key is absent, so
# the two cases below are told apart: a default that is wrong, and a default
# that is not there.
# The mutants, asserted before the real file is judged by this. Both are the
# same edit — an input losing its own `default:` — and the fixture puts a LATER
# input with the opposite default underneath, which is the shape the scan this
# replaces would have read. `dispatch_fixture` writes them; nothing here
# touches the workflow under test.
dispatch_fixture() {
	printf '%s\n' "$1" >"${fixture_dir}/dispatch.yml"
}

# default_case <description> <input> <expected>, where "" means "declares none"
default_case() {
	local description="$1" input="$2" expected="$3" got='' status=0
	got="$(workflow_input_field "${fixture_dir}/dispatch.yml" "${input}" default 2>/dev/null)" || status=$?
	if [[ -n "${expected}" ]]; then
		if ((status != 0)); then
			printf 'FAIL: reading %s default in %s failed (exit %d), expected %q\n' \
				"${input}" "${description}" "${status}" "${expected}" >&2
			exit 1
		fi
		if [[ "${got}" != "${expected}" ]]; then
			printf 'FAIL: %s default in %s read as %q, expected %q\n' \
				"${input}" "${description}" "${got}" "${expected}" >&2
			exit 1
		fi
		return 0
	fi
	if ((status == 0)); then
		printf 'FAIL: %s declares no default in %s, but the query answered %q — that value\n' \
			"${input}" "${description}" "${got}" >&2
		printf '      belongs to another input, and a guard reading it would pass on nothing.\n' >&2
		exit 1
	fi
}

mkdir -p "${fixture_dir}"
trap 'rm -rf "${fixture_dir}"' EXIT

dispatch_fixture 'on:
  workflow_dispatch:
    inputs:
      dry_run:
        type: boolean
        required: false
      push:
        type: boolean
        required: false
        default: true
      build_from_source:
        type: boolean
        required: false
        default: true
jobs:
  repair:
    steps:
      - run: .github/scripts/repair-history.sh'
default_case 'a workflow where dry_run lost its default' dry_run ''
default_case 'a workflow where dry_run lost its default' push true

dispatch_fixture 'on:
  workflow_dispatch:
    inputs:
      dry_run:
        type: boolean
        required: false
        default: true
      push:
        type: boolean
        required: false
      build_from_source:
        type: boolean
        required: false
        default: false
jobs:
  repair:
    steps:
      - run: .github/scripts/repair-history.sh'
default_case 'a workflow where push lost its default' push ''
default_case 'a workflow where push lost its default' dry_run true

rm -rf "${fixture_dir}"
trap - EXIT

input_default() {
	local input="$1" default status=0
	default="$(workflow_input_field "${workflow}" "${input}" default 2>/dev/null)" || status=$?
	if ((status != 0)); then
		printf 'FAIL: %s gives %s no default of its own; an unset boolean input dispatches\n' \
			"${workflow}" "${input}" >&2
		printf '      as false, and a scan would have reported a later input default instead.\n' >&2
		exit 1
	fi
	printf '%s' "${default}"
}

dry_run_default="$(input_default dry_run)"
push_default="$(input_default push)"
if [[ "${dry_run_default}" != "true" ]]; then
	printf 'FAIL: %s does not default dry_run to true (got %q)\n' "${workflow}" "${dry_run_default}" >&2
	exit 1
fi
if [[ "${push_default}" != "false" ]]; then
	printf 'FAIL: %s does not default push to false (got %q)\n' "${workflow}" "${push_default}" >&2
	exit 1
fi

# The bounds that make a repair explicit rather than guessed. `expected_tip` is
# the one that turns the publish into a claim about which object is being
# replaced — repair-history.sh spends it on
# `--force-with-lease=refs/heads/<branch>:<expected_tip>`, so a dispatch that
# could leave it blank would degrade that into an unconditional force push.
# `required: true` with no `default:` is what forces the operator to re-read the
# branch immediately before dispatching. Asserted per input, from that input's
# own keys — the absence of a default is a fact about which keys the mapping
# has, which is what `workflow_input_fields` answers.
for bound in base expected_tip expect_identities; do
	required="$(workflow_input_field "${workflow}" "${bound}" required 2>/dev/null || true)"
	if [[ "${required}" != "true" ]]; then
		printf 'FAIL: %s does not mark %s required (got %q)\n' "${workflow}" "${bound}" "${required}" >&2
		exit 1
	fi
	fields="$(workflow_input_fields "${workflow}" "${bound}")" || exit 1
	if grep -qx 'default' <<<"${fields}"; then
		printf 'FAIL: %s gives %s a default; a repair bound must be typed out, not inherited\n' \
			"${workflow}" "${bound}" >&2
		exit 1
	fi
done

# And the expected tip has to reach the lease, not just the dispatch form. The
# script is what spends it; this asserts the two stay wired together.
#
# shellcheck disable=SC2016  # the needle is repair-history.sh's source text,
# so `${branch}` and `${expected_tip}` are meant to stay unexpanded.
grep -Fq -- '--force-with-lease="refs/heads/${branch}:${expected_tip}"' "${repair_script}" || {
	printf 'FAIL: %s no longer leases the push against the expected tip\n' "${repair_script}" >&2
	exit 1
}

printf 'repair workflow: wired, dry by default, bounds required\n'

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
