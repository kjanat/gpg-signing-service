#!/usr/bin/env bash

# This script checks if the code is formatted correctly
# If not, it prints the diff and exits with 1
# If yes, it prints "All files are correctly formatted" and exits with 0

# Print markdown formatted output to the summary
function print_markdown() {
	local language=$1
	local content=$2

	printf '```%s\n' "$language"
	printf '%s\n' "$content"
	printf '```\n'
}

# Get the root of the git repository
function get_git_root() {
	git rev-parse --show-toplevel
}

cd "$(get_git_root)" || exit 1

if ! task format:check &>/dev/null; then
	{
		echo "### Different files

$(print_markdown 'files' "$(task format:check -- --list-different 2>&1 | head -n -1)")

### Diff

$(print_markdown 'diff' "$(task format:check 2>&1)")
"
	} |& tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

	exit 1
else
	echo "All files are correctly formatted" |& tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
	exit 0
fi
