#!/usr/bin/env bash
# Assert the two properties that decide whether a release publishes what it
# claims: every external action in the release workflow is pinned to an
# immutable ref, and the tag it publishes under is the commit it built.
#
#   task test:release-workflow
#
# Why this suite exists at all. `action.yml` resolves `version: latest` to an
# asset from a GitHub Release of this repository, so every consumer installs
# whatever this one job produced. The job holds `contents: write`. Until this
# branch it ran three external actions from tags — `actions/checkout@v7`,
# `jdx/mise-action@v4`, `softprops/action-gh-release@v3` — each a mutable
# pointer in a repository nobody here controls, any of which could be repointed
# upstream into a job that both builds the binaries and publishes them.
#
# Pinning is a one-line change and staying pinned is the hard part, which is why
# it is asserted. A tag and a SHA look equally fine in a diff.
#
# Nothing here greps the workflow. `uses` is a mapping key and a mapping key may
# be quoted, so `"uses": actions/checkout@v7` is the same step to GitHub that an
# anchored `uses:` pattern does not see; a `#` comment and a folded `run: >`
# block mislead a line scanner in the other direction. The questions are
# answered by .github/scripts/workflow-steps.ts, a real parse, and the fixtures
# under "the shapes a line scanner gets wrong" below prove that is what is
# answering them.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
validate_script="${repo_root}/.github/scripts/validate-release-tag.sh"

failures=0

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	shift
	local line
	for line in "$@"; do printf '      %s\n' "${line}" >&2; done
	failures=$((failures + 1))
}

pass() { printf '  ok: %s\n' "$1"; }

# --- which release workflow ---------------------------------------------------
#
# PENDING-first: a GitHub App token has no `workflows` permission, so the pinned
# file arrives in .github/workflows-pending/ and a human activates it with one
# `git mv`. Once it is moved this follows it and becomes a standing guard on the
# live file.
#
# While both exist the live file is NOT covered, and it is the one that publishes
# today. .github/scripts/dependabot-activation.sh is the shape that closes this:
# it treats activation as a rename and refuses the state where a workflow is live
# and a copy is still pending.
pending_workflow="${repo_root}/.github/workflows-pending/release.yml"
live_workflow="${repo_root}/.github/workflows/release.yml"

if [[ -f "${pending_workflow}" ]]; then
	workflow="${pending_workflow}"
	printf 'note: the pinned release workflow is still pending activation\n'
	printf '      git mv -f .github/workflows-pending/release.yml .github/workflows/release.yml\n'
elif [[ -f "${live_workflow}" ]]; then
	workflow="${live_workflow}"
else
	printf 'FAIL: release.yml is in neither .github/workflows/ nor .github/workflows-pending/\n' >&2
	exit 1
fi

printf 'asserting on %s\n' "${workflow#"${repo_root}/"}"

# shellcheck source=.github/scripts/workflow-steps.sh
source "${repo_root}/.github/scripts/workflow-steps.sh"

# --- the shapes a line scanner gets wrong -------------------------------------
#
# Asserted BEFORE the workflow is judged by them, so a guard that had quietly
# stopped seeing anything cannot report the workflow clean. Each fixture is a
# workflow GitHub accepts, and each is checked against the grep it replaces so
# the case is demonstrably a bypass rather than a strawman.
fixture_dir="$(mktemp -d)"
trap 'rm -rf "${fixture_dir}"' EXIT

pin_case() {
	local name="$1" expected="$2" source="$3"
	local file="${fixture_dir}/pin.yml"
	printf '%s\n' "${source}" >"${file}"

	local got
	if ! got="$(workflow_mutable_uses "${file}")"; then
		fail "${name}: the parser could not read the fixture"
		return
	fi
	if [[ "${got}" != "${expected}" ]]; then
		fail "${name}" "expected: ${expected:-<nothing>}" "got:      ${got:-<nothing>}"
		return
	fi
	pass "${name}"
}

# The bypass the pin guard exists to survive. `grep -E '^\s*-?\s*uses:'` reports
# this file clean while a tag-resolved action runs in a job holding
# contents: write.
pin_case 'a quoted uses: key is still a uses:' 'actions/checkout@v7' \
	'jobs:
  release:
    steps:
      - "uses": actions/checkout@v7'
if grep -Eq '^\s*-?\s*uses:' "${fixture_dir}/pin.yml"; then
	fail 'the quoted-key fixture is not a bypass of the pattern it replaces'
else
	pass 'the quoted-key fixture is a real bypass of an anchored uses: pattern'
fi

pin_case 'a commented-out uses: is not an action this job runs' '' \
	'jobs:
  release:
    steps:
      # - uses: actions/checkout@v7
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
pin_case 'a trailing version comment does not become part of the ref' '' \
	'jobs:
  release:
    steps:
      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 }'
pin_case 'a local action has nothing to pin' '' \
	'jobs:
  release:
    steps:
      - uses: ./.github/actions/setup-bun'
pin_case 'a branch that looks like a sha but is short is not a pin' 'foo/bar@3d3c42e' \
	'jobs:
  release:
    steps:
      - uses: foo/bar@3d3c42e'
pin_case 'a reusable-workflow call is resolved the same way' 'foo/bar/.github/workflows/w.yml@v1' \
	'jobs:
  release:
    uses: foo/bar/.github/workflows/w.yml@v1'

# The wiring counterpart: a folded block joins its lines into one command, so
# the script path is an argument to `echo` and nothing runs it.
runs_case() {
	local name="$1" expected="$2" source="$3"
	local file="${fixture_dir}/runs.yml"
	printf '%s\n' "${source}" >"${file}"

	local got
	if ! got="$(workflow_runs_script "${file}" .github/scripts/validate-release-tag.sh)"; then
		fail "${name}: the parser could not read the fixture"
		return
	fi
	[[ "${got}" == "${expected}" ]] && {
		pass "${name}"
		return
	}
	fail "${name}" "expected: ${expected:-<nothing>}" "got:      ${got:-<nothing>}"
}

runs_case 'a folded block where the path is an argument is not wiring' '' \
	'jobs:
  release:
    steps:
      - run: >
          echo validating
          .github/scripts/validate-release-tag.sh'
runs_case 'a step that runs the script is wiring' .github/scripts/validate-release-tag.sh \
	'jobs:
  release:
    steps:
      - run: .github/scripts/validate-release-tag.sh'

rm -rf "${fixture_dir}"
trap - EXIT

# --- the release workflow itself ----------------------------------------------

mutable="$(workflow_mutable_uses "${workflow}" --expect-uses)" || exit 1
if [[ -n "${mutable}" ]]; then
	while IFS= read -r reference; do
		fail "${workflow#"${repo_root}/"} resolves ${reference} through a mutable ref" \
			'Pin it to the full commit SHA, with the version as a trailing comment.'
	done <<<"${mutable}"
else
	pass 'every external action in the release workflow is pinned to a commit SHA'
fi

wired="$(workflow_runs_script "${workflow}" .github/scripts/validate-release-tag.sh)" || exit 1
if [[ "${wired}" != .github/scripts/validate-release-tag.sh ]]; then
	fail 'no step in the release workflow runs .github/scripts/validate-release-tag.sh' \
		'A step that names the path without running it is not the wiring.'
else
	pass 'the release job runs the tag check before publishing'
fi

if [[ ! -x "${validate_script}" ]]; then
	fail "${validate_script#"${repo_root}/"} is not an executable file in this tree"
fi

# Both entry points, still there. The dispatch path is what publishes an
# already-existing tag; the push path is what a maintainer's `git push origin
# v1.2.0` fires. Losing either is a silent change in how releases happen.
#
# Read here rather than through workflow-steps.sh because that parser is scoped
# to a workflow's STEPS by design, and `on:` is not one. It is the same `yaml`
# package underneath, for the same reason: `on` is a YAML 1.1 boolean, so a
# document that spells the key `on:` parses to the key `true`, and a scanner
# looking for the literal string would be answering a different question than
# the runner does.
triggers="$(
	bun --eval '
		const { parseDocument } = require("yaml");
		const doc = parseDocument(require("node:fs").readFileSync(process.argv[1], "utf8"));
		if (doc.errors.length > 0) { process.exit(1); }
		const root = doc.toJS();
		const on = root.on ?? root[true];
		process.stdout.write(JSON.stringify({
			push: on?.push?.tags ?? null,
			dispatch: on?.workflow_dispatch?.inputs?.tag ?? null,
		}));
	' "${workflow}"
)" || {
	printf 'FAIL: could not parse the release workflow triggers\n' >&2
	exit 1
}

if [[ "$(jq -r '.push | @json' <<<"${triggers}")" != '["v*.*.*"]' ]]; then
	fail 'the release workflow no longer publishes on a v*.*.* tag push' "got: ${triggers}"
else
	pass 'the tag-push path is preserved'
fi
if [[ "$(jq -r '.dispatch.required' <<<"${triggers}")" != true ]]; then
	fail 'the release workflow dispatch no longer requires an existing tag' "got: ${triggers}"
else
	pass 'the guarded workflow_dispatch(tag=...) path is preserved and required'
fi

# --- the tag check, driven ----------------------------------------------------
#
# The structural assertions above say the step is there. These say it refuses
# the things it exists to refuse, on real objects, which is the half a workflow
# file cannot tell you.
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

git_env=(
	env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_OBJECT_DIRECTORY
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
	GIT_AUTHOR_NAME=Fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
	GIT_COMMITTER_NAME=Fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
	GIT_AUTHOR_DATE='2026-01-01T00:00:00+00:00'
	GIT_COMMITTER_DATE='2026-01-01T00:00:00+00:00'
)
g() { (cd "${work}" && "${git_env[@]}" git "$@"); }

g init --quiet --initial-branch=master .
printf 'one\n' >"${work}/file"
g add file
g commit --quiet -m 'chore: one'
first="$(g rev-parse HEAD)"
printf 'two\n' >"${work}/file"
g add file
g commit --quiet -m 'chore: two'
second="$(g rev-parse HEAD)"

g tag -a v1.2.0 -m 'v1.2.0' "${second}"
g tag v1.3.0 "${second}"    # lightweight, to prove the peel is not what matches
g tag v9.9.9 "${first}"     # a real tag naming a different commit
g branch v4.0.0 "${second}" # a branch whose name would resolve without refs/tags/

# Read before anything runs against this repository. It is the one object name
# in the expected set that is not known up front, and reading it after the
# checks would compare the state to itself: a check that re-pointed
# refs/tags/v1.2.0 would supply both sides of the comparison meant to catch it.
annotated_tag="$(g rev-parse refs/tags/v1.2.0)"

# check <name> <expected-status> <RELEASE_TAG> [expected-substring]
check() {
	local name="$1" want="$2" tag="$3" needle="${4-}"
	local out status=0
	out="$(cd "${work}" && "${git_env[@]}" RELEASE_TAG="${tag}" "${validate_script}" 2>&1)" || status=$?

	if [[ "${status}" -ne "${want}" ]]; then
		fail "${name}: expected exit ${want}, got ${status}" "${out}"
		return
	fi
	if [[ -n "${needle}" && "${out}" != *"${needle}"* ]]; then
		fail "${name}: output did not mention ${needle}" "${out}"
		return
	fi
	pass "${name}"
}

check 'an annotated tag at HEAD publishes' 0 v1.2.0 "Publishing v1.2.0 at ${second}"
check 'a lightweight tag at HEAD publishes' 0 v1.3.0 "Publishing v1.3.0 at ${second}"
check 'a tag naming another commit is refused' 1 v9.9.9 "resolves to ${first}"
check 'an empty tag is refused' 1 '' 'RELEASE_TAG is empty'
check 'a two-part version is refused' 1 v1.2 'must match vX.Y.Z'
check 'a prerelease suffix is refused' 1 v1.2.0-rc1 'must match vX.Y.Z'
check 'a fully qualified ref is refused' 1 refs/tags/v1.2.0 'must match vX.Y.Z'
check 'a tag that is not in the checkout is refused' 1 v5.5.5 'No tag v5.5.5'
check 'a branch with a version name is not a tag' 1 v4.0.0 'No tag v4.0.0'

# The refusals must not have created, moved or fetched anything: this step runs
# before the publish and is allowed to read the object store, nothing else.
refs_after="$(g for-each-ref --format='%(refname) %(objectname)')"
expected_refs="$(
	printf 'refs/heads/master %s\nrefs/heads/v4.0.0 %s\nrefs/tags/v1.2.0 %s\nrefs/tags/v1.3.0 %s\nrefs/tags/v9.9.9 %s\n' \
		"${second}" "${second}" "${annotated_tag}" "${second}" "${first}"
)"
if [[ "${refs_after}" != "${expected_refs}" ]]; then
	fail 'the tag check mutated the repository' "${refs_after}"
else
	pass 'the tag check reads objects and writes none'
fi

# An annotated tag object is not the commit, so a check that compared
# `rev-parse <tag>` with HEAD would refuse the release this workflow exists to
# publish. Asserted directly, because the passing case above cannot tell a
# correct peel from a repository where the two happen to be equal.
if [[ "$(g rev-parse refs/tags/v1.2.0)" == "$(g rev-parse 'refs/tags/v1.2.0^{commit}')" ]]; then
	fail 'the annotated-tag fixture is not annotated, so the peel is untested'
else
	pass 'the passing case peels a real annotated tag object to its commit'
fi

rm -rf "${work}"
trap - EXIT

if [[ "${failures}" -ne 0 ]]; then
	printf '\nrelease workflow: %d case(s) failed\n' "${failures}" >&2
	exit 1
fi
printf '\nrelease workflow: all cases passed\n'
