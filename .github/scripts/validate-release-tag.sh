#!/usr/bin/env bash
# Refuse to publish a release unless the checkout is exactly the commit the
# named tag already resolves to.
#
# Called by .github/workflows/release.yml as its first step after checkout, on
# both of that workflow's paths:
#
#   push:              RELEASE_TAG is github.ref_name  — the tag that fired the run
#   workflow_dispatch: RELEASE_TAG is inputs.tag       — a tag that already exists
#
#   usage:  validate-release-tag.sh            # reads RELEASE_TAG from the environment
#   env:    RELEASE_TAG   the vX.Y.Z tag being published
#   exit:   0  publish — the tag names this checkout
#           1  do not publish, and fail the job — the reason is on the annotation
#
# The dispatch path is the one this guards. `.github/workflows/release.yml`
# checks out `ref: ${{ inputs.tag || github.ref }}`, so the operator's string
# decides what gets built, and `softprops/action-gh-release` is then handed that
# same string as `tag_name:`. Nothing in that chain re-reads the object. A typo,
# a branch name that happens to parse, or a tag moved between the dispatch and
# the checkout would each publish assets built from one commit under a tag
# naming another — which is the provenance failure class this repository has
# spent #111 on, one layer up from commit headers.
#
# So the check is the one question that cannot be answered by the string: does
# `<tag>^{commit}` equal `HEAD`. Both sides come from the object store of the
# checkout that is about to be built, and a peel through `^{commit}` means an
# annotated tag answers about the commit it points at rather than about the tag
# object.
#
# It deliberately does not create, move or fetch anything. A tag that is not
# present in the checkout is a refusal, not something to go and get: the run is
# meant to publish a tag that was reviewed and pushed by a human beforehand.
set -Eeuo pipefail

readonly release_tag="${RELEASE_TAG-}"

# fail <line>...
#
# One `::error` annotation on the first line so the failure is readable from the
# job list, with any detail under it. Annotations go to stdout, matching
# .github/scripts/signing-preflight.sh, so a caller reading stderr never has to
# separate them from a git diagnostic.
fail() {
	printf '::error::%s\n' "$1"
	shift
	local line
	for line in "$@"; do
		printf '  %s\n' "${line}"
	done
	exit 1
}

if [[ -z "${release_tag}" ]]; then
	fail 'RELEASE_TAG is empty, so there is no tag to publish' \
		'On a dispatch this is inputs.tag; on a tag push it is github.ref_name.'
fi

# The name is checked before the object is looked up, because the name is what
# `action-gh-release` publishes under. `refs/tags/v1.2.0` and `v1.2.0-rc1` both
# resolve to real objects and neither is a release this repository publishes.
if [[ ! "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	fail "Release tag must match vX.Y.Z, got '${release_tag}'" \
		'A release is published under this exact string; it is not normalised anywhere downstream.'
fi

# `refs/tags/` rather than the bare name: a bare name is resolved through git's
# ref search order, so a branch called v1.2.0 would answer for a tag that does
# not exist. This run publishes tags.
if ! tag_commit="$(git rev-parse --verify --quiet "refs/tags/${release_tag}^{commit}")"; then
	fail "No tag ${release_tag} in this checkout" \
		'Release tags are created and pushed by a maintainer before the workflow runs.' \
		'This step does not fetch or create one.'
fi
readonly tag_commit

if ! head_commit="$(git rev-parse --verify --quiet 'HEAD^{commit}')"; then
	fail 'HEAD does not resolve to a commit' \
		'The checkout step did not leave a usable working tree.'
fi
readonly head_commit

if [[ "${tag_commit}" != "${head_commit}" ]]; then
	fail "Checked out ${head_commit}, but ${release_tag} resolves to ${tag_commit}" \
		'The assets would be built from one commit and published under a tag naming another.' \
		'Re-read the tag and dispatch again rather than moving the tag.'
fi

printf 'Publishing %s at %s\n' "${release_tag}" "${head_commit}"
