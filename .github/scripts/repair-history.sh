#!/usr/bin/env bash
# Orchestrate one history repair: run the CLI, check its work independently,
# and publish the result under a lease.
#
# The repair itself — reading the range, rewriting identity headers, stripping
# and replacing signatures, writing objects — belongs to `gpg-sign
# repair-history` and lives in Go, with tests. This script is the part that
# cannot: turning workflow inputs into flags, refusing to push a plan, and
# performing the single force-with-lease that makes the rewrite real.
#
#   env:  BASE_REF           exclusive lower bound of the range   (required)
#         EXPECTED_TIP       commit the branch must be at now     (required)
#         IDENTITY           "Name <address>" to write            (required)
#         EXPECT_IDENTITIES  addresses the range may carry, one per line
#                                                                 (required)
#         BRANCH             branch to publish to                 (required)
#         DRY_RUN            "true" plans and stops before signing anything
#         PUSH               "false" repairs and asserts but does not publish
#         GPG_SIGN_TOKEN     OIDC token, read by gpg-sign
#         GPG_SIGN_URL       service base URL, read by gpg-sign
#
# Nothing here rewrites a commit. If this script is wrong, the worst it does is
# refuse to push.
set -Eeuo pipefail

# The assertion script sits beside this one, and both are called by path from
# the workflow rather than from PATH.
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly here
readonly base="${BASE_REF-}"
readonly expected_tip="${EXPECTED_TIP-}"
readonly identity="${IDENTITY-}"
readonly branch="${BRANCH-}"
readonly dry_run="${DRY_RUN:-false}"
readonly push="${PUSH:-true}"

die() {
	printf '::error::%s\n' "$1"
	exit 1
}

for required in base expected_tip identity branch; do
	[[ -n "${!required}" ]] || die "${required} is required; this command has no defaults by design"
done

# One --expect-identity per line. Every address the range carries has to be
# named: the CLI refuses any it was not told to expect, which is what stops a
# widened range from quietly reattributing a commit nobody looked at.
expect=()
while read -r address; do
	[[ -n "${address}" ]] || continue
	expect+=("--expect-identity=${address}")
done <<<"${EXPECT_IDENTITIES-}"
((${#expect[@]} > 0)) || die 'EXPECT_IDENTITIES is empty; name every address the range is allowed to carry'

# The lease is taken against the tip the operator named, and the tip that is
# there now must be it. Checking here as well as in the CLI keeps the failure
# on the workflow's own terms.
head="$(git rev-parse HEAD)"
[[ "${head}" == "$(git rev-parse --verify "${expected_tip}^{commit}")" ]] \
	|| die "HEAD is ${head}, not the expected tip ${expected_tip}; re-read the branch before dispatching"
tree="$(git rev-parse --verify "${expected_tip}^{tree}")"

if [[ "${dry_run}" == "true" ]]; then
	gpg-sign repair-history --dry-run \
		--base="${base}" --expected-tip="${expected_tip}" \
		--identity="${identity}" "${expect[@]}"
	printf 'Dry run only. Nothing was signed, written or pushed.\n'
	exit 0
fi

# --json puts the machine-readable half on stdout and the progress lines on
# stderr, so the tip can be read without scraping prose.
report="$(gpg-sign --json repair-history \
	--base="${base}" --expected-tip="${expected_tip}" \
	--identity="${identity}" "${expect[@]}")"

tip="$(jq -r '.tip // ""' <<<"${report}")"
[[ -n "${tip}" ]] || die 'the repair produced no tip; nothing was pushed'
jq -r '.mapping[] | "  \(.commit) -> \(.newCommit)"' <<<"${report}"

# The independent check. It runs against the objects git stored, with git and
# gpg rather than the CLI's own code, and it is the last thing between here and
# a force push.
"${here}/assert-repaired-range.sh" "${base}" "${tip}" "${tree}" "${identity}"

if [[ "${push}" != "true" ]]; then
	printf 'Repaired tip %s was not published (PUSH=%s). Publish it with:\n' "${tip}" "${push}"
	printf '  git push origin %s:refs/heads/%s --force-with-lease=refs/heads/%s:%s\n' \
		"${tip}" "${branch}" "${branch}" "${expected_tip}"
	exit 0
fi

# One push, of one commit, under a lease naming the exact object it replaces.
# The local HEAD is deliberately still on the old chain: the CLI moves no ref,
# so a failed lease leaves this checkout and the branch both untouched.
git push origin "${tip}:refs/heads/${branch}" \
	--force-with-lease="refs/heads/${branch}:${expected_tip}"
printf 'Published %s to %s, replacing %s.\n' "${tip}" "${branch}" "${expected_tip}"
