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
# The tag check runs from the TOOLING checkout, not from the tree the requested
# tag supplies. `run:` executes in $GITHUB_WORKSPACE and the release checkout
# replaced $GITHUB_WORKSPACE with the tag's tree, so `.github/scripts/...` there
# names a file the published tag has to carry -- and every tag this repository
# cut before this branch, v1.2.0 included, carries none. That made the one path
# that can publish an already-signed tag unable to run its own gate, and it put
# the code deciding whether a ref is safe inside the ref being decided on.
readonly TOOLING_PATH='.release-tooling'
readonly VALIDATOR_RUN='.release-tooling/.github/scripts/validate-release-tag.sh'
# The ENTIRE argument mapping of each checkout, not the three arguments the
# assertions below name. `actions/checkout` defaults `repository:` to
# `github.repository` and `submodules:` to false, and both are absent here --
# so both are settable in one added line that leaves `ref:`, `path:` and
# `persist-credentials:` exactly as reviewed. `repository: <fork>` on the
# release checkout builds and publishes another repository's `client/` under
# this repository's tag, with the fork's own `v1.2.0` making the tag check
# agree; `submodules:` lets the published tag's `.gitmodules` supply code to the
# build. Naming the arguments to object to can only refuse the ones somebody
# thought of, so the reviewed set is pinned whole and an addition is a violation
# until it is reviewed and written here.
# shellcheck disable=SC2016  # GitHub expressions, literal on purpose
readonly RELEASE_CHECKOUT_WITH='{"fetch-depth":0,"persist-credentials":false,"ref":"${{ inputs.tag || github.ref }}"}'
# shellcheck disable=SC2016  # GitHub expressions, literal on purpose
readonly TOOLING_CHECKOUT_WITH='{"path":".release-tooling","persist-credentials":false,"ref":"${{ github.workflow_sha }}","sparse-checkout":".github/scripts"}'
# The job set is part of the contract because every assertion past the pin check
# is scoped to RELEASE_JOB. A second job is a second publisher -- its own
# `permissions:`, its own `tag_name:`, its own checkout -- that a reading scoped
# to one job id is structurally unable to see, and it needs no unpinned action to
# get there. One job is the cheapest way to say nothing else publishes from here.
readonly RELEASE_JOBS='["release"]'
# shellcheck disable=SC2016  # GitHub expressions, literal on purpose: they are the strings being compared
readonly REQUESTED_TAG='${{ inputs.tag || github.ref_name }}' \
	REQUESTED_REF='${{ inputs.tag || github.ref }}' \
	TOOLING_REF='${{ github.workflow_sha }}'

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
	if ! got="$(workflow_runs_script "${file}" "${VALIDATOR_RUN}")"; then
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
          .release-tooling/.github/scripts/validate-release-tag.sh'
runs_case 'a step that runs the script is wiring' "${VALIDATOR_RUN}" \
	'jobs:
  release:
    steps:
      - run: .release-tooling/.github/scripts/validate-release-tag.sh'
# The bootstrap defect itself, as a parser question: the tag check spelled
# against the workspace is a DIFFERENT command from the one spelled against the
# tooling checkout, and the wiring check has to tell them apart.
runs_case 'the tag check run out of the published tag is not the wiring asked for' '' \
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

	if ! out="$(workflow_runs_script "${file}" --job "${RELEASE_JOB}" "${VALIDATOR_RUN}" 2>&1)"; then
		printf '%s: the wiring check could not read it — %s\n' "${label}" "${out//$'\n'/ }"
	elif [[ "${out}" != "${VALIDATOR_RUN}" ]]; then
		printf '%s: no step in job %s runs %s\n' "${label}" "${RELEASE_JOB}" "${VALIDATOR_RUN}"
	fi

	if ! shape="$(release_shape "${file}" "${RELEASE_JOB}" 2>&1)"; then
		printf '%s: its %s job could not be read — %s\n' "${label}" "${RELEASE_JOB}" "${shape//$'\n'/ }"
		return 0
	fi

	# Scope, before anything scoped to RELEASE_JOB runs. `workflow_mutable_uses`
	# above reads every job; everything from here down reads one. A second job --
	# pinned to these same reviewed SHAs, so green on the only whole-file check --
	# carrying `permissions: { contents: write, id-token: write }` and its own
	# `softprops/action-gh-release` publishes on its own terms, and every
	# assertion below answers about `release` while it does.
	local jobs
	jobs="$(jq -c '.jobs | sort' <<<"${shape}")"
	if [[ "${jobs}" != "${RELEASE_JOBS}" ]]; then
		printf '%s: has jobs %s, not exactly %s — anything past %s publishes unasserted\n' \
			"${label}" "${jobs}" "${RELEASE_JOBS}" "${RELEASE_JOB}"
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
	local release_tag tag_name
	release_tag="$(jq -r '.validator.releaseTag // ""' <<<"${shape}")"
	tag_name="$(jq -r '.publisher.tagName // ""' <<<"${shape}")"

	local kind expected got
	for kind in validator publisher; do
		case "${kind}" in
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

	# --- the two checkouts, and which is which ---------------------------------
	#
	# The release job checks out twice and the two are not interchangeable. One
	# replaces $GITHUB_WORKSPACE with the requested tag's tree, which is what gets
	# built and where every `run:` executes; the other lands the tag check under
	# its own `path:` from the commit that supplied the workflow. Collapse them --
	# drop the second, or give it no `path:` so it overwrites the first -- and the
	# gate is loaded out of the ref it is deciding on, which for every tag cut
	# before this branch means it is not loaded at all.
	local checkout_count
	checkout_count="$(jq -r '.checkout.count' <<<"${shape}")"
	if [[ "${checkout_count}" != 2 ]]; then
		printf '%s: job %s has %s checkout steps, expected exactly 2 — the release tree and the trusted tooling\n' \
			"${label}" "${RELEASE_JOB}" "${checkout_count}"
	fi

	local release_index=-1 tooling_index=-1
	if [[ "$(jq -r '.checkout.release' <<<"${shape}")" == null ]]; then
		printf '%s: job %s has no single checkout without a path:, so which checkout is the release workspace — the tree that gets built, and the cwd of every run: — is undecidable\n' \
			"${label}" "${RELEASE_JOB}"
	else
		release_index="$(jq -r '.checkout.release.index' <<<"${shape}")"
		local ref release_with
		ref="$(jq -r '.checkout.release.ref // ""' <<<"${shape}")"
		if [[ "${ref}" != "${REQUESTED_REF}" ]]; then
			printf '%s: the checkout takes %s, not the requested tag %s\n' \
				"${label}" "${ref:-<nothing>}" "${REQUESTED_REF}"
		fi
		release_with="$(jq -cS '.checkout.release.with' <<<"${shape}")"
		if [[ "${release_with}" != "${RELEASE_CHECKOUT_WITH}" ]]; then
			printf '%s: the release checkout takes %s, not exactly %s — an unreviewed argument decides what lands in the workspace that gets built and published\n' \
				"${label}" "${release_with}" "${RELEASE_CHECKOUT_WITH}"
		fi
	fi

	if [[ "$(jq -r '.checkout.tooling' <<<"${shape}")" == null ]]; then
		printf '%s: job %s has no single checkout with its own path:, so the tag check can only come from the tree the requested tag supplies\n' \
			"${label}" "${RELEASE_JOB}"
	else
		tooling_index="$(jq -r '.checkout.tooling.index' <<<"${shape}")"
		local tooling_ref tooling_path
		tooling_ref="$(jq -r '.checkout.tooling.ref // ""' <<<"${shape}")"
		tooling_path="$(jq -r '.checkout.tooling.path // ""' <<<"${shape}")"
		if [[ "${tooling_ref}" != "${TOOLING_REF}" ]]; then
			printf '%s: the tooling checkout takes %s, not the commit that supplied this workflow %s\n' \
				"${label}" "${tooling_ref:-<nothing>}" "${TOOLING_REF}"
		fi
		if [[ "${tooling_path}" != "${TOOLING_PATH}" ]]; then
			printf '%s: the tooling checkout lands in %s, not %s, so the validator the wiring check names is not the one that runs\n' \
				"${label}" "${tooling_path:-<nothing>}" "${TOOLING_PATH}"
		fi
		local tooling_with
		tooling_with="$(jq -cS '.checkout.tooling.with' <<<"${shape}")"
		if [[ "${tooling_with}" != "${TOOLING_CHECKOUT_WITH}" ]]; then
			printf '%s: the tooling checkout takes %s, not exactly %s — an unreviewed argument decides which repository supplies the tag check\n' \
				"${label}" "${tooling_with}" "${TOOLING_CHECKOUT_WITH}"
		fi
	fi

	# A root checkout cleans the workspace it lands in. Tooling first would be
	# discarded by the release checkout that follows it.
	if [[ "${release_index}" -lt 0 || "${tooling_index}" -lt 0 || "${release_index}" -ge "${tooling_index}" ]]; then
		printf '%s: the release checkout is step %s and the tooling checkout is step %s — the release checkout cleans the workspace, so the tooling has to arrive after it\n' \
			"${label}" "${release_index}" "${tooling_index}"
	fi

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
	if [[ "${validator_index}" -lt 0 || "${tooling_index}" -lt 0 || "${tooling_index}" -ge "${validator_index}" ]]; then
		printf '%s: the tag check is step %s and the tooling it runs from arrives at step %s\n' \
			"${label}" "${validator_index}" "${tooling_index}"
	fi

	# The credential the checkout leaves behind. Nothing after it talks to git
	# over the network, so a write-capable token in .git/config is inherited by
	# the toolchain install, six `go build`s and the publisher for nothing.
	# Every checkout, not the first. Two checkouts are two chances to leave a
	# write-capable token in a .git/config that the toolchain install, six
	# `go build`s and the publisher all inherit.
	local persisting
	while IFS= read -r persisting; do
		[[ -n "${persisting}" ]] || continue
		printf '%s: checkout step %s does not set persist-credentials: false, so every later step inherits a write-capable token\n' \
			"${label}" "${persisting}"
	done < <(jq -r '.checkout.persisting[]' <<<"${shape}")

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
	"$(release_tree '' '/^ +ref: .*inputs\.tag/ { $0 = "          ref: master" } { print }')" \
	'the checkout takes master, not the requested tag'

# --- the trust boundary the tag check is loaded across -------------------------
#
# `run:` executes in $GITHUB_WORKSPACE, and the release checkout replaced
# $GITHUB_WORKSPACE with the requested tag's tree. Every one of these mutations
# puts the tag check back inside the ref it is deciding on: the validator becomes
# a file the published tag has to supply, and no tag this repository cut before
# this branch supplies one. Each is green on pins, permissions, tag identity,
# triggers, `if:`/`continue-on-error:` and ordering.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'no tooling checkout fails' \
	"$(release_tree '' '/^ +- name: Checkout release tooling/, /^ +persist-credentials: false/ { next } { print }')" \
	'no single checkout with its own path:'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tooling checkout taken from anything but the workflow commit fails' \
	"$(release_tree '' '/^ +ref: .*github\.workflow_sha/ { $0 = "          ref: master" } { print }')" \
	'the tooling checkout takes master, not the commit that supplied this workflow'

# Without a `path:` the second checkout lands at the root, which cleans the
# workspace: the release tree the job is about to build is replaced by the
# workflow commit's, and there is no longer one checkout that is the release.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tooling checkout that overwrites the release workspace fails' \
	"$(release_tree '' '/^ +path: \.release-tooling/ { next } { print }')" \
	'no single checkout without a path:'

# The tooling checkout before the release checkout: the release checkout cleans
# the workspace and takes the tag check with it.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'tooling checked out before the release tree fails' \
	"$(release_tree '' 'BEGIN { hold = "" }
	                    /^ +- name: Checkout release tooling/, /^ +persist-credentials: false/ { hold = hold $0 "\n"; next }
	                    /^ +- name: Checkout release tag/ { printf "%s\n", hold; hold = "" }
	                    { print }')" \
	'the tooling has to arrive after it'

# --- what the checkouts are allowed to be told ---------------------------------
#
# `ref:`, `path:` and `persist-credentials:` are the arguments the assertions
# above name, and `actions/checkout` takes more than those. Each of these leaves
# all three exactly as reviewed and is green on pins, permissions, tag identity,
# triggers, effectiveness, ordering and the trust boundary -- one added line in a
# `with:` block that reads like housekeeping.
#
# `repository:` is the sharpest. It defaults to `github.repository`, so writing
# it at all is invisible in review, and a fork resolves this repository's commits
# through the shared fork network. On the release checkout the workspace becomes
# the fork's tree at the fork's OWN `v1.2.0` -- so `<tag>^{commit}` equals `HEAD`
# and the tag check agrees -- `client/` is built from it, and
# `action-gh-release` publishes the result as a Release of THIS repository under
# the requested tag. On the tooling checkout it is the trust boundary itself: the
# code deciding whether a ref is safe to publish comes from a repository nobody
# reviewed, in a job holding contents: write.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a release checkout from another repository fails' \
	"$(release_tree '' '/^ +ref: .*inputs\.tag/ { print "          repository: attacker/gpg-signing-service" } { print }')" \
	'the release checkout takes'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tooling checkout from another repository fails' \
	"$(release_tree '' '/^ +ref: .*github\.workflow_sha/ { print "          repository: attacker/gpg-signing-service" } { print }')" \
	'the tooling checkout takes'

# The published tag's own `.gitmodules` deciding what the build compiles.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a release checkout that fetches submodules fails' \
	"$(release_tree '' '/^ +ref: .*inputs\.tag/ { print "          submodules: recursive" } { print }')" \
	'the release checkout takes'

# The defect this boundary exists to fix, written back in: the step still runs a
# validator, is still handed the right expression, and is still ahead of the
# publish -- out of the tree the tag supplies.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tag check run out of the published tag tree fails' \
	"$(release_tree '' '/^ +run: \.release-tooling\// { $0 = "        run: .github/scripts/validate-release-tag.sh" } { print }')" \
	'runs .github/scripts/validate-release-tag.sh, not .release-tooling/.github/scripts/validate-release-tag.sh'

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

# The scoped-reading bypass. This second job is pinned to the reviewed SHAs, so
# the one whole-file assertion passes it; everything that would object to
# `id-token: write` or to publishing v9.9.9 is looking at job `release`.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a second job that publishes on its own terms fails' \
	"$(release_tree '' '{ print }
	  END {
	    print "";
	    print "  publish-extra:";
	    print "    runs-on: ubuntu-latest";
	    print "    permissions: { contents: write, id-token: write, packages: write }";
	    print "    steps:";
	    print "      - uses: softprops/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64 # v3.0.3";
	    print "        with: { tag_name: v9.9.9 }";
	  }')" \
	'has jobs ["publish-extra","release"], not exactly ["release"]'

tree_case 'dropping permissions: entirely fails rather than inheriting the default token' \
	"$(release_tree '' '/^permissions:/ { next } { print }')" \
	'runs with null (from the none permissions:)'

# Wiring and triggers, per copy.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a copy that only names the tag check fails' \
	"$(release_tree '' '/run: \.release-tooling\// { $0 = "        run: echo .release-tooling/.github/scripts/validate-release-tag.sh" } { print }')" \
	'no step in job release runs .release-tooling/.github/scripts/validate-release-tag.sh'

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
	"$(release_tree '' '/^ +run: \.release-tooling\// { $0 = "        run: echo decoy" } { print }')" \
	'runs echo decoy, not .release-tooling/.github/scripts/validate-release-tag.sh'

# Both checkouts, one at a time. The second one is the one a `checkout[0]`
# reading cannot see, and its credential is inherited by exactly the same later
# steps as the first one's.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a release checkout that persists credentials fails' \
	"$(release_tree '' '!dropped && /^ +persist-credentials: false/ { dropped = 1; next } { print }')" \
	'checkout step 1 does not set persist-credentials: false'

# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tooling checkout that persists credentials fails' \
	"$(release_tree '' '/^ +- name: Checkout release tooling/ { seen = 1 }
	                    seen && /^ +persist-credentials: false/ { seen = 0; next }
	                    { print }')" \
	'checkout step 2 does not set persist-credentials: false'

# The same step, still wired, still given the right expression — moved to the
# end of the job. `action-gh-release` has already created the Release by the
# time it refuses.
# shellcheck disable=SC2016  # $0 is awk's whole line, not a shell parameter
tree_case 'a tag check that runs after the publish fails' \
	"$(release_tree '' '/^ +- name: Validate release tag/, /^ +run: \.release-tooling\// { next }
	                    { print }
	                    END { print "      - name: Validate release tag"
	                          print "        env:"
	                          print "          RELEASE_TAG: ${{ inputs.tag || github.ref_name }}"
	                          print "        run: .release-tooling/.github/scripts/validate-release-tag.sh" }')" \
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

# --- the bootstrap: a tag cut before the validator existed ----------------------
#
# The structural assertions above say the workflow loads the tag check from the
# tooling checkout rather than from the tag. This is the half that cannot be read
# off a workflow file: that the arrangement actually validates and publishes a tag
# whose own tree has never heard of the check.
#
# `${work}` is exactly that tag. Its tree is one file; there is no
# .github/scripts/ in it, the same way v1.0.0 through v1.2.0 of this repository
# have none. `run:` executes in $GITHUB_WORKSPACE, which after the release
# checkout IS this tree, so the two invocations below are the two spellings of
# the tag check the workflow could carry — one loaded out of the ref it is
# deciding on, one loaded across the boundary.
if [[ -e "${work}/.github/scripts/validate-release-tag.sh" ]]; then
	fail 'the release fixture already carries a validator, so the bootstrap case proves nothing'
else
	pass 'the tag being published carries no validator of its own'
fi

# What the workflow did before the tooling checkout. Fail-closed, so not an
# exploit — but the dispatch path is the only path that can publish an
# already-signed tag, and on it the gate was unreachable for every tag this
# repository has.
bootstrap_status=0
(
	cd "${work}" && "${git_env[@]}" RELEASE_TAG=v1.2.0 bash -c '.github/scripts/validate-release-tag.sh'
) >/dev/null 2>&1 || bootstrap_status=$?
if [[ "${bootstrap_status}" -eq 0 ]]; then
	fail 'a tag tree with no validator appeared to validate itself'
else
	pass 'a tag check loaded out of the published tag cannot run on a tag cut before it existed'
fi

# What it does now. The script comes from the workflow commit, checked out under
# its own path; the objects come from the release workspace, which is still the
# working directory. Nothing in the script resolves a path relative to itself, so
# this is the same reading the workflow performs.
tooling="${work}/.release-tooling/.github/scripts"
mkdir -p "${tooling}"
cp "${validate_script}" "${tooling}/validate-release-tag.sh"
tooling_run="${TOOLING_PATH}/.github/scripts/validate-release-tag.sh"

bootstrap_check() {
	local name="$1" want="$2" tag="$3" needle="${4-}"
	local out status=0
	out="$(cd "${work}" && "${git_env[@]}" RELEASE_TAG="${tag}" "${tooling_run}" 2>&1)" || status=$?

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

bootstrap_check 'a tag with no validator in its tree is validated from the tooling checkout' \
	0 v1.2.0 "Publishing v1.2.0 at ${second}"
# And the boundary buys nothing if crossing it also relaxed the check.
bootstrap_check 'the tooling checkout still refuses a tag naming another commit' \
	1 v9.9.9 "resolves to ${first}"
bootstrap_check 'the tooling checkout still refuses a tag that is not in the release workspace' \
	1 v5.5.5 'No tag v5.5.5'

# The tooling checkout is a separate git dir inside the workspace. If the script
# had read through it instead of through the release workspace, every answer
# above would be about the wrong repository.
if [[ ! -d "${work}/.release-tooling" ]]; then
	fail 'the tooling fixture is not a distinct path, so nothing about the boundary was exercised'
else
	pass 'the tag check read the release workspace while running from a distinct tooling path'
fi

rm -rf "${work}"
trap - EXIT

if [[ "${failures}" -ne 0 ]]; then
	printf '\nrelease workflow: %d case(s) failed\n' "${failures}" >&2
	exit 1
fi
printf '\nrelease workflow: all cases passed\n'
