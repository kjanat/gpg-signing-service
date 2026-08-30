#!/usr/bin/env bash
# Where the trusted Dependabot fix path is in its activation, and what a human
# has to type to finish it.
#
# .github/workflows/claude-dependabot-fix.yml cannot be created by the
# automation that wrote it: a GitHub App token has no `workflows` permission, so
# a push touching that directory is rejected outright — and the rejection kills
# the whole push, not just that one file. The activation is therefore checked in
# as a patch beside the pending workflow, applied once by a human holding an
# ordinary credential.
#
# A patch in an issue comment would not be reviewed with the pull request, would
# not be covered by branch protection, and could change afterwards with no
# signal here. In the tree it is a reviewable artifact, and the two test suites
# that depend on it can prove it still applies.
#
# Sourced by test-dependabot-fix.sh and test-claude-review-gate.sh. Not a
# program: it defines paths and functions and does nothing on its own.

activation_root="$(git rev-parse --show-toplevel)"
ACTIVATION_WORKFLOW="${activation_root}/.github/workflows/claude-dependabot-fix.yml"
ACTIVATION_PENDING="${activation_root}/.github/workflows-pending/claude-dependabot-fix.yml"
ACTIVATION_PATCH="${activation_root}/.github/workflows-pending/activate.patch"
ACTIVATION_REVIEW="${activation_root}/.github/workflows/claude-code-review.yml"
readonly activation_root ACTIVATION_WORKFLOW ACTIVATION_PENDING ACTIVATION_PATCH ACTIVATION_REVIEW

# activation_state — one word on stdout:
#
#   active    the workflow is at the live path and nothing is left behind
#   pending   it is still in .github/workflows-pending/, awaiting the patch
#   both      it is in both places: two files claiming to be this workflow
#   absent    it is in neither, which is not a state the patch can repair
#
# Callers treat everything but `active` as a failure. This function only reports.
activation_state() {
	if [[ -f "${ACTIVATION_WORKFLOW}" && -f "${ACTIVATION_PENDING}" ]]; then
		printf 'both'
	elif [[ -f "${ACTIVATION_WORKFLOW}" ]]; then
		printf 'active'
	elif [[ -f "${ACTIVATION_PENDING}" ]]; then
		printf 'pending'
	else
		printf 'absent'
	fi
}

# activation_apply DEST — reproduce the activated tree in DEST from the
# checked-in patch, so a suite that has to run before activation can still run
# against the bytes activation will produce. Non-zero, with a diagnosis on
# stderr, if the patch is gone or no longer applies to the files it targets.
#
# DEST is a scratch directory and never the repository: this reads the tree, it
# does not activate anything.
activation_apply() {
	local dest="$1"
	if [[ ! -f "${ACTIVATION_PATCH}" ]]; then
		echo "      the activation patch is missing: ${ACTIVATION_PATCH}" >&2
		echo '      without it there is no checked-in way to activate this path' >&2
		return 1
	fi
	if [[ ! -f "${ACTIVATION_PENDING}" ]]; then
		echo "      nothing to activate: ${ACTIVATION_PENDING} is missing" >&2
		return 1
	fi
	mkdir -p "${dest}/.github/workflows" "${dest}/.github/workflows-pending"
	cp "${ACTIVATION_REVIEW}" "${dest}/.github/workflows/claude-code-review.yml"
	cp "${ACTIVATION_PENDING}" "${dest}/.github/workflows-pending/claude-dependabot-fix.yml"
	if ! (cd "${dest}" && git apply --whitespace=nowarn "${ACTIVATION_PATCH}") 2>"${dest}/apply.err"; then
		echo '      the checked-in activation patch NO LONGER APPLIES:' >&2
		sed 's/^/        /' "${dest}/apply.err" >&2
		echo "      regenerate ${ACTIVATION_PATCH#"${activation_root}/"} against the current files" >&2
		return 1
	fi
	# The patch is a rename plus a prompt edit; if either half stopped landing
	# where it claims to, everything read off this tree would be read off the
	# wrong file.
	if [[ ! -f "${dest}/.github/workflows/claude-dependabot-fix.yml" ]]; then
		echo '      the activation patch applied but did not produce' >&2
		echo '      .github/workflows/claude-dependabot-fix.yml' >&2
		return 1
	fi
	if [[ -e "${dest}/.github/workflows-pending/claude-dependabot-fix.yml" ]]; then
		echo '      the activation patch applied but left a copy in' >&2
		echo '      .github/workflows-pending/ — it is a rename, not a copy' >&2
		return 1
	fi
}

# activation_unusable STATE — the diagnosis for a state neither suite can assert
# against, on stderr. Shared, so `both` and `absent` cannot be described one way
# by test-dependabot-fix.sh and another by test-claude-review-gate.sh.
#
# `both` in particular must NOT be answered with activation_procedure. Once
# .github/workflows/claude-dependabot-fix.yml exists, `git apply` refuses the
# patch outright — "already exists in working directory" — so pointing a human
# at it there sends them at a command that cannot run. It is also the state a
# half-finished activation lands in, which makes it the one most likely to be
# read under pressure.
activation_unusable() {
	case "$1" in
		both)
			echo 'FAIL: the workflow is active AND a copy is still in .github/workflows-pending/.' >&2
			echo '      Two files claim to be this workflow; only one of them runs, and both' >&2
			echo '      look authoritative in review. This is a half-applied activation, so' >&2
			echo '      do NOT re-run git apply — the patch refuses once the live file exists.' >&2
			echo '      Finish it by hand:' >&2
			echo '        git rm .github/workflows-pending/claude-dependabot-fix.yml' >&2
			echo '        git rm .github/workflows-pending/activate.patch' >&2
			echo '      and confirm .github/workflows/claude-code-review.yml carries the' >&2
			echo '      prompt correction the patch makes; the rename alone is not the whole' >&2
			echo '      activation. See docs/dependabot-fix-path.md#activation.' >&2
			;;
		*)
			echo 'FAIL: claude-dependabot-fix.yml is in neither .github/workflows/ nor' >&2
			echo '      .github/workflows-pending/. The trusted Dependabot write path is' >&2
			echo '      gone, and no checked-in patch can bring it back.' >&2
			;;
	esac
}

# activation_procedure — the two commands, on stderr, under a failure. Only
# correct in the `pending` state; see activation_unusable for the others.
activation_procedure() {
	echo '      Activate it with a credential that can write .github/workflows/' >&2
	echo '      (a GitHub App token cannot: it has no workflows permission):' >&2
	echo >&2
	echo '        git apply .github/workflows-pending/activate.patch' >&2
	echo '        git rm .github/workflows-pending/activate.patch' >&2
	echo "        git commit -m 'ci: activate the trusted Dependabot fix path'" >&2
	echo >&2
	echo '      task test:dependabot-fix and task test:review-gate both fail' >&2
	echo '      until it lands, and both say this.' >&2
	echo '      See docs/dependabot-fix-path.md#activation.' >&2
}
