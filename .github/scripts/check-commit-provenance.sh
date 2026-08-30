#!/usr/bin/env bash
# Refuse commits whose identity headers were manufactured by a merge path
# rather than written by whoever wrote the code.
#
#   usage:  check-commit-provenance.sh <revision-range>
#
#   env:    PROVENANCE_ALLOW  addresses to permit anyway, one per line
#
#   exit:   0  every commit in the range names a real author and committer
#           1  at least one does not; each offender is named
#
# This exists because of one incident and to stop its exact repeat. Merging a
# bot's pull request through the REST squash endpoint writes commits whose
# author is the bot and whose committer is "GitHub <noreply@github.com>" — two
# identities that describe the mechanism, not the person. Nothing noticed until
# the branch was signed, at which point the signature was correct and the
# provenance underneath it was not, and the only way out was rewriting twenty
# commits of published history.
#
# The signature check that runs alongside this one cannot catch it: a
# manufactured commit signs perfectly well. What it says is the problem.
set -Eeuo pipefail

readonly range="${1-}"

die() {
	printf '::error::%s\n' "$1"
	exit 1
}

[[ -n "${range}" ]] || die 'usage: check-commit-provenance.sh <revision-range>'

# The committer address the web and REST merge paths stamp on a commit they
# built themselves. A person never has it.
readonly machine_committer='noreply@github.com'

allow=()
while read -r address; do
	[[ -n "${address}" ]] || continue
	allow+=("${address,,}")
done <<<"${PROVENANCE_ALLOW-}"

allowed() {
	local candidate="${1,,}" address
	for address in ${allow[@]+"${allow[@]}"}; do
		[[ "${candidate}" == "${address}" ]] && return 0
	done
	return 1
}

# One `git log -1` per commit rather than one delimited record per line. A
# display name is free text, so no printable delimiter is safe, and NUL is not
# an option either: bash strips it from a command substitution and cannot hold
# it in IFS, so a NUL-delimited record silently reads back as one field. git
# does forbid a newline inside an ident, which makes %n the one separator that
# cannot be forged from inside a name.
#
# The rev-list is run on its own rather than inside the process substitution
# `mapfile` would otherwise read from: errexit does not reach into one, so a
# range git cannot resolve — a typo, a ref a shallow clone never fetched —
# would read back as zero commits and this guard would report that history it
# never looked at is clean.
listed="$(git rev-list --reverse "${range}")" \
	|| die "could not resolve the revision range ${range}"

commits=()
if [[ -n "${listed}" ]]; then
	mapfile -t commits <<<"${listed}"
fi

failures=0
for commit in ${commits[@]+"${commits[@]}"}; do
	mapfile -t fields < <(git log -1 --format='%an%n%ae%n%cn%n%ce' "${commit}")
	author_name="${fields[0]-}"
	author_email="${fields[1]-}"
	committer_name="${fields[2]-}"
	committer_email="${fields[3]-}"

	if [[ "${committer_email,,}" == "${machine_committer}" ]] && ! allowed "${committer_email}"; then
		printf '::error::%s was committed by %s <%s>, which is the identity GitHub stamps on a commit it built itself; the person who wrote it is not recorded\n' \
			"${commit}" "${committer_name}" "${committer_email}"
		failures=$((failures + 1))
	fi

	# A bot as *author* is the other half of the same failure: the squash path
	# copies the pull request author onto the commit, so a bot-opened PR
	# carrying a person's work lands attributed to the bot.
	if [[ "${author_name}" == *'[bot]' ]] && ! allowed "${author_email}"; then
		printf '::error::%s is authored by %s <%s>; a bot is the mechanism that opened the pull request, not the author of the change\n' \
			"${commit}" "${author_name}" "${author_email}"
		failures=$((failures + 1))
	fi
	if [[ "${committer_name}" == *'[bot]' ]] && ! allowed "${committer_email}"; then
		printf '::error::%s is committed by %s <%s>; a bot is the mechanism that opened the pull request, not the committer of the change\n' \
			"${commit}" "${committer_name}" "${committer_email}"
		failures=$((failures + 1))
	fi
done

if ((failures > 0)); then
	printf '::error::%d commit(s) in %s carry manufactured provenance. Merge with a squash that keeps the real author, or repair the range with gpg-sign repair-history before publishing.\n' \
		"${failures}" "${range}"
	exit 1
fi

printf '%d commit(s) in %s name a real author and committer.\n' "${#commits[@]}" "${range}"
