#!/usr/bin/env bash
# Covers the invariant that a pending Go modernization fails CI.
#
# The gate is three links long and every one of them is silent when it breaks:
#
#   * `.github/workflows/ci.yml` runs `task c:l` in the Go client job
#   * `client:lint` chains `client:modernize:check`
#   * `go fix -diff` exits non-zero on a non-empty fixer diff, and writes nothing
#
# Drop any link and the tree still lints green while a modernization sits in it
# unnoticed, which is precisely what happened in #115: `modernize` is not in
# .golangci.yml's enable list, so the drift only surfaced because someone ran
# the task by hand. Enabling it there would not be this check -- golangci-lint
# carries its own vendored x/tools copy of those analyzers, while `go fix` is by
# construction the fixer set shipped by the toolchain client/go.mod selects, and
# that is the invariant held down here. The last link is the one worth
# distrusting hardest -- the whole gate is an exit code from a flag whose
# contract is "print the diff", and a toolchain that started reporting success
# for a non-empty diff would disarm CI without changing a line in this repo.
#
# The fixture module takes its language version from client/go.mod so this adds
# no second Go pin: whichever toolchain the client is built with is the one
# whose fixers are exercised here.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

failures=0
case_name=""

new_case() {
	case_name="$1"
	printf '  case: %s\n' "${case_name}"
}

fail() {
	printf '    FAIL (%s): %s\n' "${case_name}" "$1" >&2
	failures=$((failures + 1))
}

if ! command -v go >/dev/null 2>&1; then
	printf 'go toolchain absent, skipping the modernize gate tests\n'
	exit 0
fi

go_directive="$(awk '$1 == "go" { print $2; exit }' "${repo_root}/client/go.mod")"
if [[ -z ${go_directive} ]]; then
	printf 'could not read the go directive from client/go.mod\n' >&2
	exit 1
fi

# GOTOOLCHAIN=auto rather than inherited: a pin in the environment beats go.mod,
# and a fixture running under some other toolchain would be asserting the fixer
# behaviour of a Go the client is never built with. GOWORK=off keeps the
# repository's workspace from adopting the fixture.
run_fixer() {
	local dir="$1"
	(cd "${dir}" && GOTOOLCHAIN=auto GOWORK=off GOFLAGS='' go fix -diff ./...)
}

# `for i := 0; i < N; i++` is the modernization the toolchain rewrites to a
# `range` loop. It is planted rather than borrowed from client/ because the
# client is supposed to be clean -- a fixture that went quiet the day the real
# tree got modernized would assert nothing.
write_fixture() {
	local dir="$1" body="$2"
	mkdir -p "${dir}"
	cat >"${dir}/go.mod" <<EOF
module modernizefixture

go ${go_directive}
EOF
	cat >"${dir}/main.go" <<EOF
package main

import "fmt"

func main() {
${body}
}
EOF
}

stale_loop=$'\tfor i := 0; i < 3; i++ {\n\t\tfmt.Println(i)\n\t}'
fresh_loop=$'\tfor i := range 3 {\n\t\tfmt.Println(i)\n\t}'

# --- a pending modernization has to be a CI failure ---------------------------
#
# Exit code and output are asserted separately: a run that printed a diff but
# exited 0 would leave `task c:l` green, and an exit code with no diff would be
# some other breakage wearing the same trousers.
new_case pending-modernization-fails
stale_dir="${tmp_dir}/stale"
write_fixture "${stale_dir}" "${stale_loop}"
before="$(cat "${stale_dir}/main.go")"

set +e
diff_out="$(run_fixer "${stale_dir}" 2>"${tmp_dir}/stale.err")"
rc=$?
set -e

if [[ ${rc} -eq 0 ]]; then
	fail "go fix -diff exited 0 on a pending modernization; CI can no longer fail on drift"
fi
if [[ -z ${diff_out} ]]; then
	fail "go fix -diff reported no diff for a loop the toolchain modernizes: $(cat "${tmp_dir}/stale.err")"
fi

# --- and it has to stay a dry run --------------------------------------------
#
# CI runs this on a checkout it then walks away from. A fixer that wrote would
# turn a red build into a mutated one, so the file is compared byte for byte.
new_case dry-run-does-not-write
if [[ "$(cat "${stale_dir}/main.go")" != "${before}" ]]; then
	fail "go fix -diff rewrote the source file; the CI check is no longer a dry run"
fi

# --- a clean tree has to pass -------------------------------------------------
#
# Without this the gate could be a permanently red command and the case above
# would still be satisfied.
new_case clean-tree-passes
fresh_dir="${tmp_dir}/fresh"
write_fixture "${fresh_dir}" "${fresh_loop}"

set +e
clean_out="$(run_fixer "${fresh_dir}" 2>"${tmp_dir}/fresh.err")"
rc=$?
set -e

if [[ ${rc} -ne 0 ]]; then
	fail "go fix -diff failed on an already-modernized tree: $(cat "${tmp_dir}/fresh.err")"
fi
if [[ -n ${clean_out} ]]; then
	fail "go fix -diff printed a diff for an already-modernized tree: ${clean_out}"
fi

# --- the dry run has to be reachable from what CI runs ------------------------
#
# Asserted against the resolved command list rather than the Taskfile text, so
# it follows a rename or a move between tasks and only goes red when the fixer
# genuinely stops running. `task c:l` is the command the Go client job invokes.
#
# Flag and package scope are asserted separately on the resolved `go fix` line.
# `-diff` alone is not the gate: narrowing the invocation to `./cmd/...` would
# leave a real `go fix ... -diff` in the plan while everything outside that one
# package stopped being checked, and this case would have gone on passing.
new_case lint-chains-the-dry-run
if command -v task >/dev/null 2>&1; then
	lint_plan="$(cd "${repo_root}" && task c:l --dry 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
	# `|| true` because no match is the failure this case exists to report: under
	# `set -e` a bare grep miss kills the script before the message is printed and
	# before the workflow case below ever runs.
	fixer_line="$(grep -E '(^|[[:space:]])go fix([[:space:]]|$)' <<<"${lint_plan}" | head -n 1 || true)"

	if [[ -z ${fixer_line} ]]; then
		fail "task c:l no longer reaches the modernization dry run:"$'\n'"${lint_plan}"
	elif ! grep -qE '(^|[[:space:]])-diff([[:space:]]|$)' <<<"${fixer_line}"; then
		fail "task c:l runs the fixer without -diff; CI would mutate the checkout: ${fixer_line}"
	elif ! grep -qE '(^|[[:space:]])\./\.\.\.([[:space:]]|$)' <<<"${fixer_line}"; then
		fail "task c:l narrowed the fixer off ./...; part of the client is unchecked: ${fixer_line}"
	fi
else
	printf '    task absent, skipping the lint wiring assertion\n'
fi

# --- and the Go client job has to keep invoking it ----------------------------
#
# The workflow is the one link this repository cannot express as a task, so it
# is read here. Losing `task c:l` from that job would take the modernization
# check out of CI with every assertion above still passing.
new_case workflow-runs-client-lint
workflow="${repo_root}/.github/workflows/ci.yml"

# Scoped to the client-test job rather than grepped file-wide: `task c:l` living
# in some other job would satisfy a whole-file match while the assertion's own
# failure message claims to be about this one.
client_job="$(awk '
	/^  client-test:/ { in_job = 1; next }
	in_job && /^  [^[:space:]]/ { exit }
	in_job { print }
' "${workflow}")"

if [[ -z ${client_job} ]]; then
	fail "no 'client-test' job in .github/workflows/ci.yml; the modernization check has no CI home"
# Every alias the include exposes, so renaming the invocation in the workflow is
# not mistaken for removing it -- but `lint` has to be terminated rather than
# left on a \b, which `lint:fix` also satisfies. `client:lint:fix` deliberately
# does not chain modernize:check, so a job that ran it would disarm the gate
# with this case still green.
elif ! grep -qE 'run:[[:space:]]*task (c|client|gpg-sign):(l|lint)([[:space:]]|,|}|$)' <<<"${client_job}"; then
	fail "the Go client job in .github/workflows/ci.yml no longer runs 'task c:l'"$'\n'"${client_job}"
fi

if [[ ${failures} -ne 0 ]]; then
	printf '%d modernize gate assertion(s) failed\n' "${failures}" >&2
	exit 1
fi

printf 'go modernize gate tests passed\n'
