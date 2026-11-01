#!/usr/bin/env bash
# Refuse commits that credit an AI agent: Claude, Codex or Grok as author,
# committer or co-author, or a session link or trailer an agent left behind.
#
#   usage:  check-commit-provenance.sh <revision-range>
#
#   env:    PROVENANCE_ALLOW  addresses to permit anyway, one per line
#
#   exit:   0  no commit in the range credits an AI agent
#           1  at least one does; each offender is named
set -Eeuo pipefail

readonly range="${1-}"

die() {
	printf '::error::%s\n' "$1"
	exit 1
}

[[ -n "${range}" ]] || die 'usage: check-commit-provenance.sh <revision-range>'

readonly agent_word='claude|codex|grok'
readonly agent_name='(^|[^a-z0-9-])(claude|codex|grok)([^a-z0-9-]|$)'
readonly agent_domain='(^|[.@])(anthropic\.com|openai\.com|x\.ai)$'
readonly agent_key='session|generated|assisted|agent|model'
readonly session_link='claude\.ai/code|claude\.com/claude-code|chatgpt\.com/codex|grok\.com'

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

# agent <name> <email>
agent() {
	local name="${1,,}" email="${2,,}"
	allowed "${email}" && return 1
	[[ "${name}" =~ ${agent_name} || "${email}" =~ ${agent_name} || "${email}" =~ ${agent_domain} ]] && return 0
	[[ "${name}${email}" == *'[bot]'* && "${name}${email}" =~ ${agent_word} ]]
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
# range git cannot resolve would read back as zero commits and pass.
listed="$(git rev-list --reverse "${range}")" \
	|| die "could not resolve the revision range ${range}"

commits=()
if [[ -n "${listed}" ]]; then
	mapfile -t commits <<<"${listed}"
fi

failures=0
finding() {
	printf '::error::%s\n' "$1"
	failures=$((failures + 1))
}

for commit in ${commits[@]+"${commits[@]}"}; do
	mapfile -t fields < <(git log -1 --format='%an%n%ae%n%cn%n%ce' "${commit}")
	if agent "${fields[0]-}" "${fields[1]-}"; then
		finding "${commit} is authored by ${fields[0]-} <${fields[1]-}>, an AI agent"
	fi
	if agent "${fields[2]-}" "${fields[3]-}"; then
		finding "${commit} is committed by ${fields[2]-} <${fields[3]-}>, an AI agent"
	fi

	body="$(git log -1 --format='%B' "${commit}")" \
		|| die "could not read the message of ${commit}"

	while IFS= read -r line || [[ -n "${line}" ]]; do
		if [[ "${line,,}" =~ ${session_link} ]]; then
			finding "${commit} links an AI agent session: ${line}"
		fi
		[[ "${line,,}" == 'co-authored-by:'* ]] || continue
		value="${line#*:}"
		value="${value#"${value%%[![:space:]]*}"}"
		email=''
		name="${value}"
		if [[ "${value}" == *'<'*'>'* ]]; then
			email="${value##*<}"
			email="${email%%>*}"
			name="${value%<*}"
			name="${name%"${name##*[![:space:]]}"}"
		fi
		if agent "${name}" "${email}"; then
			finding "${commit} credits ${name} <${email}> as a co-author, an AI agent"
		fi
	done <<<"${body}"

	trailers="$(git interpret-trailers --parse <<<"${body}")" \
		|| die "could not parse the trailers of ${commit}"
	while IFS= read -r line; do
		[[ -n "${line}" ]] || continue
		key="${line%%:*}"
		value="${line#*:}"
		value="${value#"${value%%[![:space:]]*}"}"
		[[ "${key,,}" != 'co-authored-by' ]] || continue
		if [[ "${key,,}" =~ ${agent_word} ]] \
			|| [[ "${key,,}" =~ ${agent_key} && "${value,,}" =~ ${agent_word} ]]; then
			finding "${commit} carries the AI agent trailer ${line}"
		fi
	done <<<"${trailers}"
done

if ((failures > 0)); then
	printf '::error::%d AI agent credit(s) in %s. Drop the trailer or link, or repair the range with gpg-sign repair-history before publishing.\n' \
		"${failures}" "${range}"
	exit 1
fi

printf '%d commit(s) in %s credit no AI agent.\n' "${#commits[@]}" "${range}"
