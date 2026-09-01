#!/usr/bin/env bash
# Assert the properties that decide whether a release publishes what it claims:
# every external action in the release workflow is pinned to an immutable ref,
# the job holds exactly one permission, the tag it publishes under is the tag it
# validated, and that tag is the commit it built.
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
# answered by .github/scripts/workflow-steps.ts and
# .github/scripts/release-workflow-shape.ts, real parses, and the fixtures under
# "the shapes a line scanner gets wrong" below prove that is what is answering
# them.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
validate_script="${repo_root}/.github/scripts/validate-release-tag.sh"

# The one job in the release workflow, and the exact set of expressions and
# permissions it is held to. Written out here rather than derived, because a
# contract derived from the file it judges is a contract the file can move.
readonly RELEASE_JOB=release
readonly RELEASE_PERMISSIONS='{"contents":"write"}'
readonly VALIDATOR_RUN='.github/scripts/validate-release-tag.sh'
# shellcheck disable=SC2016  # GitHub expressions, literal on purpose: they are the strings being compared
readonly REQUESTED_TAG='${{ inputs.tag || github.ref_name }}' \
	REQUESTED_REF='${{ inputs.tag || github.ref }}'

failures=0

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	shift
	local line
	for line in "$@"; do printf '      %s\n' "${line}" >&2; done
	failures=$((failures + 1))
}

pass() { printf '  ok: %s\n' "$1"; }

# shellcheck source=.github/scripts/workflow-steps.sh
source "${repo_root}/.github/scripts/workflow-steps.sh"

# The privilege and tag-identity reader. Its interpreter selection mirrors
# workflow_steps_run in workflow-steps.sh deliberately: a machine with no bun
# has to fail loudly here rather than quietly reducing every assertion below to
# "clean".
release_shape() {
	local script="${repo_root}/.github/scripts/release-workflow-shape.ts"

	if command -v bun >/dev/null 2>&1; then
		bun "${script}" "$@"
	elif command -v mise >/dev/null 2>&1; then
		mise exec -- bun "${script}" "$@"
	else
		printf 'test-release-workflow.sh: bun is not on PATH, so the workflow parser cannot run.\n' >&2
		printf '                          Install it (see .github/actions/setup-bun) rather than skipping these checks.\n' >&2
		return 127
	fi
}

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

# --- the release security contract --------------------------------------------
#
# One function, applied to every copy of the release workflow that exists in a
# tree. Prints one line per way the file falls short; empty output means it
# satisfies the contract. It never fails the suite by itself, so the same code
# can judge the repository and be judged by the fixtures below it.
release_contract_violations() {
	local file="$1" label="$2"
	local out shape

	# Every job, not just the release job: a second job in this workflow would
	# run in the same repository with the same secrets. `--expect-uses` is the
	# difference between "everything is pinned" and "nothing was looked at".
	if ! out="$(workflow_mutable_uses "${file}" --expect-uses 2>&1)"; then
		printf '%s: the pin check could not read it — %s\n' "${label}" "${out//$'\n'/ }"
	elif [[ -n "${out}" ]]; then
		local reference
		while IFS= read -r reference; do
			printf '%s: resolves %s through a mutable ref, not a full commit SHA\n' "${label}" "${reference}"
		done <<<"${out}"
	fi

	if ! out="$(workflow_runs_script "${file}" --job "${RELEASE_JOB}" .github/scripts/validate-release-tag.sh 2>&1)"; then
		printf '%s: the wiring check could not read it — %s\n' "${label}" "${out//$'\n'/ }"
	elif [[ "${out}" != .github/scripts/validate-release-tag.sh ]]; then
		printf '%s: no step in job %s runs .github/scripts/validate-release-tag.sh\n' "${label}" "${RELEASE_JOB}"
	fi

	if ! shape="$(release_shape "${file}" "${RELEASE_JOB}" 2>&1)"; then
		printf '%s: its %s job could not be read — %s\n' "${label}" "${RELEASE_JOB}" "${shape//$'\n'/ }"
		return 0
	fi

	# Privilege. The job mints the artifacts every consumer installs; anything
	# past `contents: write` — `id-token:` for an OIDC token, `packages:` for the
	# registry — is a capability the publish step inherits for free.
	local permissions granted_by
	permissions="$(jq -cS '.permissions' <<<"${shape}")"
	granted_by="$(jq -r '.permissionsSource' <<<"${shape}")"
	if [[ "${permissions}" != "${RELEASE_PERMISSIONS}" ]]; then
		printf '%s: job %s runs with %s (from the %s permissions:), not exactly %s\n' \
			"${label}" "${RELEASE_JOB}" "${permissions}" "${granted_by}" "${RELEASE_PERMISSIONS}"
	fi

	# Tag identity. Nothing in the job re-reads the object after the checkout, so
	# the requested tag selecting the checkout, being validated, and being
	# published under are three readings of ONE expression. A job that validated
	# v1.2.0 and published v9.9.9 would satisfy every pin and wiring assertion
	# above this line.
	local ref release_tag tag_name
	ref="$(jq -r '.checkout.ref // ""' <<<"${shape}")"
	release_tag="$(jq -r '.validator.releaseTag // ""' <<<"${shape}")"
	tag_name="$(jq -r '.publisher.tagName // ""' <<<"${shape}")"

	local kind expected got
	for kind in checkout validator publisher; do
		case "${kind}" in
			checkout) expected="${REQUESTED_REF}" got="${ref}" ;;
			validator) expected="${REQUESTED_TAG}" got="${release_tag}" ;;
			publisher) expected="${REQUESTED_TAG}" got="${tag_name}" ;;
		esac
		local count
		count="$(jq -r ".${kind}.count" <<<"${shape}")"
		if [[ "${count}" != 1 ]]; then
			printf '%s: job %s has %s %s steps, expected exactly 1\n' "${label}" "${RELEASE_JOB}" "${count}" "${kind}"
			continue
		fi
		if [[ "${got}" != "${expected}" ]]; then
			printf '%s: the %s takes %s, not the requested tag %s\n' \
				"${label}" "${kind}" "${got:-<nothing>}" "${expected}"
		fi
	done

	# Present is not the same as effective. `if:` and `continue-on-error:` both
	# leave a step that parses exactly like one that runs, and the wiring check
	# above cannot tell the difference: `if: false` skips the tag check outright,
	# and `continue-on-error: true` turns it into an annotation the publish step
	# below it ignores.
	if [[ "$(jq -r '.validator.guarded' <<<"${shape}")" != false ]]; then
		printf '%s: the tag check carries an if:, so it is conditional on something other than publishing\n' "${label}"
	fi
	local advisory
	advisory="$(jq -r '.validator.advisory' <<<"${shape}")"
	if [[ "${advisory}" != null && "${advisory}" != false ]]; then
		printf '%s: the tag check is continue-on-error: %s, so failing it does not stop the publish\n' "${label}" "${advisory}"
	fi

	# The step given RELEASE_TAG has to be the step that spends it. Otherwise a
	# decoy step carrying the right expression satisfies the identity assertion
	# while the script itself reads RELEASE_TAG from a job-level env: nobody
	# looked at.
	local validator_run
	validator_run="$(jq -r '.validator.run // ""' <<<"${shape}")"
	if [[ "${validator_run}" != "${VALIDATOR_RUN}" ]]; then
		printf '%s: the step given RELEASE_TAG runs %s, not %s\n' \
			"${label}" "${validator_run:-<nothing>}" "${VALIDATOR_RUN}"
	fi

	# Order. `action-gh-release` creates the Release; a step that fails after it
	# does not take one back. A validated tag is only a precondition if it is
	# checked first.
	local validator_index publisher_index
	validator_index="$(jq -r '.validator.index // -1' <<<"${shape}")"
	publisher_index="$(jq -r '.publisher.index // -1' <<<"${shape}")"
	if [[ "${validator_index}" -lt 0 || "${publisher_index}" -lt 0 || "${validator_index}" -ge "${publisher_index}" ]]; then
		printf '%s: the tag check is step %s and the publish is step %s — the release is created before the tag is validated\n' \
			"${label}" "${validator_index}" "${publisher_index}"
	fi

	# The credential the checkout leaves behind. Nothing after it talks to git
	# over the network, so a write-capable token in .git/config is inherited by
	# the toolchain install, six `go build`s and the publisher for nothing.
	if [[ "$(jq -r '.checkout.persistCredentials' <<<"${shape}")" != false ]]; then
		printf '%s: the checkout does not set persist-credentials: false, so every later step inherits a write-capable token\n' "${label}"
	fi

	# Both entry points, still there. The dispatch path is what publishes an
	# already-existing tag; the push path is what a maintainer's `git push origin
	# v1.2.0` fires. Losing either is a silent change in how releases happen.
	if [[ "$(jq -cS '.push' <<<"${shape}")" != '["v*.*.*"]' ]]; then
		printf '%s: no longer publishes on a v*.*.* tag push (push: %s)\n' \
			"${label}" "$(jq -c '.push' <<<"${shape}")"
	fi
	if [[ "$(jq -r '.dispatchTagRequired' <<<"${shape}")" != true ]]; then
		printf '%s: its workflow_dispatch no longer requires an existing tag\n' "${label}"
	fi
}

# --- which release workflow ---------------------------------------------------
#
# EVERY copy, not the first one found.
#
# A GitHub App token has no `workflows` permission, so a hardened file arrives in
# .github/workflows-pending/ and a human activates it with one `git mv`.
# Activation is that RENAME — .github/scripts/dependabot-activation.sh already
# refuses the state where a workflow is live and a copy is still pending, for the
# reason this function exists: while both files are on disk, only one of them
# runs, and both look authoritative in review.
#
# A guard that picked the pending copy would report the release path clean while
# the live publisher — the file that runs if anyone pushes v1.2.1 tomorrow —
# still resolved three external actions through tags. So the contract is applied
# to both, and coexistence is only survivable while both independently satisfy
# it. Until the rename lands, this suite is red, and that is the true state of
# the repository rather than a defect in the assertion.
release_tree_violations() {
	local root="$1" found=0 path
	for path in .github/workflows/release.yml .github/workflows-pending/release.yml; do
		[[ -f "${root}/${path}" ]] || continue
		found=$((found + 1))
		release_contract_violations "${root}/${path}" "${path}"
	done
	if [[ "${found}" -eq 0 ]]; then
		printf 'release.yml is in neither .github/workflows/ nor .github/workflows-pending/\n'
	fi
}

# --- the contract, judged ------------------------------------------------------
#
# Every case here is a tree of release workflows built from the hardened file, so
# the clean pair is a positive control: the mutations below it are the only
# difference between passing and failing, which is what makes each one evidence
# that the assertion it names is load-bearing.
guard_dir="$(mktemp -d)"
trap 'rm -rf "${guard_dir}"' EXIT

# The file every fixture is built from: the hardened copy, wherever it currently
# lives. Before activation that is the pending one; after the `git mv` it is the
# live one and the pending one is gone. Anchoring the fixtures to a fixed path
# would make them all collapse the moment the rename they exist to demand
# actually happens.
for hardened_workflow in \
	"${repo_root}/.github/workflows-pending/release.yml" \
	"${repo_root}/.github/workflows/release.yml"; do
	[[ -f "${hardened_workflow}" ]] && break
done
if [[ ! -f "${hardened_workflow}" ]]; then
	printf 'FAIL: no release.yml to build the guard fixtures from\n' >&2
	exit 1
fi

# install_copy <from> <to> [awk-program] — a copy of the hardened workflow,
# optionally rewritten. awk rather than an editor for the YAML, because a
# mutation is a fixture being constructed, not a workflow being interpreted.
install_copy() {
	local from="$1" to="$2" mutation="${3-}"
	if [[ -z "${mutation}" ]]; then
		cp "${from}" "${to}"
	else
		awk "${mutation}" "${from}" >"${to}"
	fi
}

# release_tree [live-mutation] [pending-mutation] — a root holding a live and a
# pending copy of the hardened workflow, each optionally mutated.
release_tree() {
	local live_mutation="${1-}" pending_mutation="${2-}"
	local root
	root="$(mktemp -d "${guard_dir}/tree-XXXXXX")"
	mkdir -p "${root}/.github/workflows" "${root}/.github/workflows-pending"

	install_copy "${hardened_workflow}" "${root}/.github/workflows/release.yml" "${live_mutation}"
	install_copy "${hardened_workflow}" "${root}/.github/workflows-pending/release.yml" "${pending_mutation}"
	printf '%s\n' "${root}"
}

# tree_case <name> <root> <needle> — <needle> empty asserts the tree is clean.
tree_case() {
	local name="$1" root="$2" needle="${3-}"
	local got
	got="$(release_tree_violations "${root}")"

	if [[ -z "${needle}" ]]; then
		if [[ -n "${got}" ]]; then
			fail "${name}" "expected no violations, got:" "${got}"
		else
			pass "${name}"
		fi
		return
	fi
	if [[ "${got}" != *"${needle}"* ]]; then
		fail "${name}" "expected a violation mentioning: ${needle}" "got: ${got:-<none>}"
		return
	fi
	pass "${name}"
}

# The positive control. Everything below differs from this by exactly one
# mutation, so this failing means the fixtures are being built from a workflow
# that is itself short of the contract and none of the cases under it are
# evidence of anything.
tree_case 'the workflow the mutations are built from satisfies the contract on both paths' "$(release_tree)" ''

# The maintainer blocker this file was reopened for. The pending copy is the
# hardened one, untouched; the live copy — the one that actually publishes —
# resolves checkout through a tag again, behind a trailing comment that still
# reads like a pin.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a mutable action in the LIVE copy fails even while the pending copy is clean' \
	"$(release_tree '{ sub(/actions\/checkout@[0-9a-f]+/, "actions/checkout@v7"); print }')" \
	'.github/workflows/release.yml: resolves actions/checkout@v7 through a mutable ref'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a mutable action in the PENDING copy fails too' \
	"$(release_tree '' '{ sub(/actions\/checkout@[0-9a-f]+/, "actions/checkout@v7"); print }')" \
	'.github/workflows-pending/release.yml: resolves actions/checkout@v7 through a mutable ref'

# Tag identity. Each of these publishes, or builds, or validates something other
# than the requested tag, and every one of them is green on pins and wiring.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'publishing under a tag other than the one validated fails' \
	"$(release_tree '' '/^ +tag_name:/ { $0 = "          tag_name: v9.9.9" } { print }')" \
	'the publisher takes v9.9.9, not the requested tag'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a divergent checkout ref fails' \
	"$(release_tree '' '/^ +ref: / { $0 = "          ref: master" } { print }')" \
	'the checkout takes master, not the requested tag'

# shellcheck disable=SC2016  # awk's $0, and a GitHub expression the mutation must write literally
tree_case 'validating a different tag than the one built fails' \
	"$(release_tree '' '/^ +RELEASE_TAG:/ { $0 = "          RELEASE_TAG: ${{ github.event.inputs.other }}" } { print }')" \
	'the validator takes ${{ github.event.inputs.other }}, not the requested tag'

# Privilege.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'extra write permissions fail' \
	"$(release_tree '' '/^permissions:/ { $0 = "permissions: { contents: write, id-token: write, packages: write }" } { print }')" \
	'"id-token":"write"'

tree_case 'a job-level permissions: that widens the workflow-level one fails' \
	"$(release_tree '' '{ print } /^ +runs-on:/ { print "    permissions: { contents: write, packages: write }" }')" \
	'from the job permissions:'

tree_case 'dropping permissions: entirely fails rather than inheriting the default token' \
	"$(release_tree '' '/^permissions:/ { next } { print }')" \
	'runs with null (from the none permissions:)'

# Wiring and triggers, per copy.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a copy that only names the tag check fails' \
	"$(release_tree '' '/run: \.github\/scripts\/validate-release-tag\.sh/ { $0 = "        run: echo .github/scripts/validate-release-tag.sh" } { print }')" \
	'no step in job release runs .github/scripts/validate-release-tag.sh'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'losing the tag-push trigger fails' \
	"$(release_tree '' '/^ +tags: /  { $0 = "    branches: [master]" } { print }')" \
	'no longer publishes on a v*.*.* tag push'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a dispatch that no longer requires a tag fails' \
	"$(release_tree '' '/^ +required: true/ { $0 = "        required: false" } { print }')" \
	'workflow_dispatch no longer requires an existing tag'

# Effectiveness. Each of these leaves a step that PARSES as the tag check and is
# green on wiring, identity, pins and permissions — and none of them validates
# anything before the release is created.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tag check behind an if: fails' \
	"$(release_tree '' '/^ +- name: Validate release tag/ { print; print "        if: false"; next } { print }')" \
	'the tag check carries an if:'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'an advisory tag check fails' \
	"$(release_tree '' '/^ +- name: Validate release tag/ { print; print "        continue-on-error: true"; next } { print }')" \
	'failing it does not stop the publish'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'RELEASE_TAG on a step other than the one that spends it fails' \
	"$(release_tree '' '/^ +run: \.github\/scripts\/validate-release-tag\.sh/ { $0 = "        run: echo decoy" } { print }')" \
	'runs echo decoy, not .github/scripts/validate-release-tag.sh'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'dropping persist-credentials: false fails' \
	"$(release_tree '' '/^ +persist-credentials: false/ { next } { print }')" \
	'so every later step inherits a write-capable token'

# The same step, still wired, still given the right expression — moved to the
# end of the job. `action-gh-release` has already created the Release by the
# time it refuses.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tag check that runs after the publish fails' \
	"$(release_tree '' '/^ +- name: Validate release tag/, /^ +run: \.github\/scripts\/validate-release-tag\.sh/ { next }
	                    { print }
	                    END { print "      - name: Validate release tag"
	                          print "        env:"
	                          print "          RELEASE_TAG: ${{ inputs.tag || github.ref_name }}"
	                          print "        run: .github/scripts/validate-release-tag.sh" }')" \
	'the release is created before the tag is validated'

tree_case 'a tree with no release workflow at all fails' \
	"$(mktemp -d "${guard_dir}/empty-XXXXXX")" \
	'release.yml is in neither'

rm -rf "${guard_dir}"
trap - EXIT

# --- the repository itself -----------------------------------------------------

tree_violations="$(release_tree_violations "${repo_root}")"
if [[ -n "${tree_violations}" ]]; then
	while IFS= read -r violation; do
		fail "${violation}"
	done <<<"${tree_violations}"
	if [[ -f "${repo_root}/.github/workflows/release.yml" && -f "${repo_root}/.github/workflows-pending/release.yml" ]]; then
		printf '\nnote: two files claim to be the release workflow. Activation is a RENAME,\n' >&2
		printf '      and the live one is what publishes until it happens:\n' >&2
		printf '        git mv -f .github/workflows-pending/release.yml .github/workflows/release.yml\n\n' >&2
	fi
else
	pass 'every release workflow in this tree satisfies the release security contract'
fi

if [[ ! -x "${validate_script}" ]]; then
	fail "${validate_script#"${repo_root}/"} is not an executable file in this tree"
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
