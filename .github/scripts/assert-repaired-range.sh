#!/usr/bin/env bash
# Prove a repaired range is safe to publish, before anything force-pushes it.
#
#   usage:  assert-repaired-range.sh <base> <tip> <expected-tree> "<identity>"
#
#   env:    GNUPGHOME  optional; a keyring already holding the service key.
#                      When unset, one is built from `gpg-sign public-key`.
#
#   exit:   0  every commit in <base>..<tip> claims <identity> as both its
#              author and its committer, carries a signature the service key
#              verifies, and <tip> points at <expected-tree>
#           1  one of those does not hold; the offenders are named
#
# This repeats checks `gpg-sign repair-history` already made, on purpose. The
# CLI checks its own work with its own code and its own OpenPGP implementation;
# this checks the same objects with git and gpg, which are the tools GitHub's
# own verification agrees with, and it is the last thing to run before a
# force-with-lease that cannot be undone. A repair that satisfies one and not
# the other is exactly the state the Aug 30 chain was left in: rewritten,
# signed, and reported Unverified.
set -Eeuo pipefail

readonly base="${1-}"
readonly tip="${2-}"
readonly expected_tree="${3-}"
readonly identity="${4-}"

die() {
	printf '::error::%s\n' "$1"
	exit 1
}

[[ -n "${base}" && -n "${tip}" && -n "${expected_tree}" && -n "${identity}" ]] \
	|| die 'usage: assert-repaired-range.sh <base> <tip> <expected-tree> "<identity>"'

# The keyring is built from the service's own published key and nothing else.
# Verifying against the caller's keyring would answer "does some key we trust
# cover this commit", which is not the question.
if [[ -z "${GNUPGHOME-}" ]]; then
	GNUPGHOME="$(mktemp -d)"
	export GNUPGHOME
	chmod 700 "${GNUPGHOME}"
	trap 'gpgconf --homedir "${GNUPGHOME}" --kill all >/dev/null 2>&1 || true; rm -rf "${GNUPGHOME}"' EXIT
	gpg-sign public-key | gpg --batch --quiet --import \
		|| die 'could not import the service public key'
fi

commits="$(git rev-list --reverse "${base}..${tip}")"
[[ -n "${commits}" ]] || die "no commits in ${base}..${tip}; there is nothing to assert about"

failures=0
count=0
while read -r commit; do
	count=$((count + 1))

	# %an <%ae> is the author line's identity half, %cn <%ce> the committer's.
	# Both must be the one identity the repair was told to write; anything else
	# is the provenance failure surviving the repair.
	author="$(git log -1 --format='%an <%ae>' "${commit}")"
	committer="$(git log -1 --format='%cn <%ce>' "${commit}")"
	if [[ "${author}" != "${identity}" ]]; then
		printf '::error::%s author is %s, want %s\n' "${commit}" "${author}" "${identity}"
		failures=$((failures + 1))
	fi
	if [[ "${committer}" != "${identity}" ]]; then
		printf '::error::%s committer is %s, want %s\n' "${commit}" "${committer}" "${identity}"
		failures=$((failures + 1))
	fi

	# The verifier is pinned the same way the keyring is. A checkout that ran
	# setup-claude-signing has gpg.program aimed at our shim, and minTrustLevel
	# above the default rejects a good signature from a key carrying no
	# ownertrust — which is every key imported this way.
	if ! git -c gpg.program=gpg -c gpg.format=openpgp -c gpg.minTrustLevel=undefined \
		verify-commit "${commit}" >/dev/null 2>&1; then
		printf '::error::%s carries no signature the service key verifies\n' "${commit}"
		failures=$((failures + 1))
	fi
done <<<"${commits}"

tree="$(git rev-parse --verify "${tip}^{tree}")"
if [[ "${tree}" != "${expected_tree}" ]]; then
	printf '::error::the repaired tip %s carries tree %s, want %s: the repair changed the content of the branch\n' \
		"${tip}" "${tree}" "${expected_tree}"
	failures=$((failures + 1))
fi

((failures == 0)) \
	|| die "${failures} assertion(s) failed over ${count} commit(s); nothing was pushed"

printf '%d commit(s) in %s..%s claim %s, verify against the service key, and leave tree %s unchanged.\n' \
	"${count}" "${base}" "${tip}" "${identity}" "${tree}"
