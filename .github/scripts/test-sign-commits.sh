#!/usr/bin/env bash
# Drive .github/scripts/sign-commits.sh against a recording stub.
#
# The signing walk moved into `gpg-sign sign-commit` and is covered by the Go
# suite in client/pkg/gitsign — base resolution, the allow-resign refusals, the
# stripped-vs-reparent distinction, the pinned verifier. What is left here is
# the half that cannot live in Go: the flags this script builds out of dispatch
# inputs, and the binary it builds them for.
#
# Nothing here resolves `gpg-sign` from PATH. The script takes the binary from
# GPG_SIGN_BIN, and this suite points it at a stub or at a build of the
# checked-out command — never at whatever release happens to be installed,
# which is the thing the probe under test exists to catch.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
sign_script="${repo_root}/.github/scripts/sign-commits.sh"

# --- the wiring ---------------------------------------------------------------
#
# The workflow lives in one of two places, and this is not cosmetic. A GitHub
# App token has no `workflows` permission, so the branch that deleted
# sign-commits.py could not edit the job that invoked it — the push is rejected
# outright, and the rejection kills the whole push rather than just that file.
# The replacement is therefore committed to .github/workflows-pending/ and a
# human activates it with a one-line `git mv`, the same route
# .github/workflows-pending/claude.yml takes.
#
# Resolved PENDING-first: the pending file REPLACES a live workflow rather than
# adding a new one, so while both exist the pending one is the version under
# review. Once it is moved into place there is only one, and this follows it —
# and then the check below is a standing regression guard, because a workflow
# naming a script that is not in the tree is exactly the failure this whole
# change risks.
pending_workflow="${repo_root}/.github/workflows-pending/sign-commits.yml"
live_workflow="${repo_root}/.github/workflows/sign-commits.yml"

# The path the job actually runs, whichever of the two implementations it is.
# Scoped to the `run:` lines on purpose: the pending file's header quotes the
# line it replaces, and a sweep of the whole file would read that quotation as
# the wiring. Under pipefail a grep that matches nothing fails the pipeline, so
# an unwired workflow has to reach the check below rather than end the suite.
names_script() {
	grep -E '^[[:space:]]*run: ' "$1" \
		| grep -oE '\.github/scripts/sign-commits\.(sh|py)' | head -1 || true
}

if [[ -f "${pending_workflow}" ]]; then
	workflow="${pending_workflow}"
	printf '  note: the Sign Commits workflow is still pending activation (git mv -f %s .github/workflows/sign-commits.yml)\n' \
		'.github/workflows-pending/sign-commits.yml'
	# The live file still names whatever it named before the move, and that is
	# the whole hazard: a merge that takes the deletion without the move points
	# the live job at a file that is not there, and the failure surfaces the
	# next time someone dispatches a signing run rather than here. So this is an
	# assertion, not a note. It is red on the branch that removes the Python
	# script and stays red until the `git mv` above lands in the same tree —
	# which is exactly the atomicity the two-file split cannot otherwise
	# enforce, since the branch that writes one of them cannot write the other.
	live_names="$(names_script "${live_workflow}")"
	if [[ -n "${live_names}" && ! -x "${repo_root}/${live_names}" ]]; then
		printf 'FAIL: .github/workflows/sign-commits.yml still runs %s, which is not in this tree.\n' \
			"${live_names}" >&2
		printf '      The deletion and the activation have to land in the same merge. Activate with:\n' >&2
		printf '        git mv -f .github/workflows-pending/sign-commits.yml .github/workflows/sign-commits.yml\n' >&2
		exit 1
	fi
elif [[ -f "${live_workflow}" ]]; then
	workflow="${live_workflow}"
else
	echo 'FAIL: sign-commits.yml is in neither .github/workflows/ nor .github/workflows-pending/' >&2
	exit 1
fi

named="$(names_script "${workflow}")"
if [[ -z "${named}" ]]; then
	printf 'FAIL: %s runs no .github/scripts/sign-commits script at all\n' "${workflow}" >&2
	exit 1
fi
if [[ ! -x "${repo_root}/${named}" ]]; then
	printf 'FAIL: %s runs %s, which is not an executable file in this tree\n' "${workflow}" "${named}" >&2
	exit 1
fi
if [[ "${named}" != .github/scripts/sign-commits.sh ]]; then
	printf 'FAIL: %s still runs %s; the signing walk belongs to gpg-sign sign-commit\n' "${workflow}" "${named}" >&2
	exit 1
fi

# The push is the workflow's, not the script's — sign-commit stops at the local
# ref update, and nothing publishes it if this step is dropped.
grep -Fq 'git push origin HEAD --force-with-lease' "${workflow}" || {
	printf 'FAIL: %s no longer publishes the rewritten tip\n' "${workflow}" >&2
	exit 1
}

# The fixture must inherit no GIT_* state at all. Worst first: GIT_DIR and
# GIT_WORK_TREE aim the fixture's commands back at the caller's own repository,
# so `init` re-inits it and the fixture's commits land there; GIT_INDEX_FILE,
# which git exports to hooks, fails the run outright; GIT_CONFIG_COUNT injects
# config outranking the pin below; and GIT_AUTHOR_*/GIT_COMMITTER_* — which
# GitHub Actions exports — would silently overwrite the fixture's identities.
unset "${!GIT_@}"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

test_repo="${tmp_dir}/repo"
mkdir -p "${tmp_dir}/bin" "${test_repo}"

# The stub stands in for the CLI. The script asks it for `sign-commit --help`
# and then runs `sign-commit` with the flags it assembled; the stub only has to
# answer in that shape and record what it was asked, because what it does with
# the flags is the Go code's job and has its own tests.
cat >"${tmp_dir}/bin/gpg-sign" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1-}" == sign-commit ]] || {
	printf 'unexpected gpg-sign command: %s\n' "${1-}" >&2
	exit 1
}
[[ "${2-}" != --help ]] || exit 0
[[ -z "${STUB_ARGV-}" ]] || printf '%s\n' "$@" >"${STUB_ARGV}"
printf 'Signed 0 of 0 commit(s)\n'
STUB

# A release from before the subcommand existed: the binary is there and runs,
# and `sign-commit` is what it has never heard of. v1.1.2, the newest tag as
# this lands, is exactly this.
cat >"${tmp_dir}/bin/gpg-sign-old" <<'OLD'
#!/usr/bin/env bash
printf 'unknown command "%s" for "gpg-sign"\n' "${1-}" >&2
exit 1
OLD
chmod +x "${tmp_dir}/bin/gpg-sign" "${tmp_dir}/bin/gpg-sign-old"

git -C "${test_repo}" init --quiet --initial-branch=master
git -C "${test_repo}" config user.name 'Fixture'
git -C "${test_repo}" config user.email 'fixture@example.com'
printf 'base\n' >"${test_repo}/fixture.txt"
git -C "${test_repo}" add fixture.txt
git -C "${test_repo}" commit --quiet --no-gpg-sign -m base
head_before="$(git -C "${test_repo}" rev-parse HEAD)"

export STUB_ARGV="${tmp_dir}/argv"

# `env` applies assignments in order, so a caller's override wins over these.
common_env=(
	GPG_SIGN_BIN="${tmp_dir}/bin/gpg-sign"
	GPG_SIGN_TOKEN=test-token
	GPG_SIGN_URL=https://sign.example.test
	DEFAULT_BRANCH=master
)

run_sign() {
	(cd "${test_repo}" && env "${common_env[@]}" "$@" "${sign_script}" 2>&1)
}

# Every flag the dispatch inputs can produce, and the trimming that a
# copy-pasted value needs.
if ! output="$(run_sign BASE_REF=" ${head_before} " ALLOW_RESIGN=true SIGN_OTHERS=true SCAN_LIMIT=' 50 ')"; then
	printf 'a fully specified run failed:\n%s\n' "${output}" >&2
	exit 1
fi
grep -Fqx -- 'sign-commit' "${STUB_ARGV}"
grep -Fqx -- '--default-branch=master' "${STUB_ARGV}"
grep -Fqx -- "--base=${head_before}" "${STUB_ARGV}" \
	|| {
		printf 'the base was not trimmed before it reached the CLI:\n%s\n' "$(cat "${STUB_ARGV}")" >&2
		exit 1
	}
grep -Fqx -- '--allow-resign' "${STUB_ARGV}"
grep -Fqx -- '--sign-others' "${STUB_ARGV}"
grep -Fqx -- '--scan-limit=50' "${STUB_ARGV}" \
	|| {
		printf 'the scan limit was not trimmed before it reached the CLI:\n%s\n' "$(cat "${STUB_ARGV}")" >&2
		exit 1
	}

# The default dispatch: three blank inputs and two booleans left false. Under
# errexit a blank optional input has ended a run before now, so the run
# succeeding is half of what this asserts.
if ! output="$(run_sign BASE_REF= ALLOW_RESIGN=false SIGN_OTHERS=false SCAN_LIMIT=)"; then
	printf 'a run with the optional inputs left blank failed:\n%s\n' "${output}" >&2
	exit 1
fi
for absent in --base --allow-resign --sign-others --scan-limit; do
	if grep -Fq -- "${absent}" "${STUB_ARGV}"; then
		printf 'a blank or false input still produced %s:\n%s\n' "${absent}" "$(cat "${STUB_ARGV}")" >&2
		exit 1
	fi
done

# A boolean input arrives as the string "false", not as an empty value. Anything
# testing it for non-emptiness would sign a range the dispatcher declined.
if ! run_sign ALLOW_RESIGN=false SIGN_OTHERS=false >/dev/null; then
	printf 'a run with the booleans off failed\n' >&2
	exit 1
fi
if grep -Eq -- '^--(allow-resign|sign-others)$' "${STUB_ARGV}"; then
	printf 'a "false" boolean was treated as set:\n%s\n' "$(cat "${STUB_ARGV}")" >&2
	exit 1
fi

# The environment with nothing named at all still runs, and still names a
# default branch — the CLI's own default is `master` too, but the script is
# what the workflow's DEFAULT_BRANCH input reaches.
if ! run_sign >/dev/null; then
	printf 'a run with no inputs at all failed\n' >&2
	exit 1
fi
grep -Fqx -- '--default-branch=master' "${STUB_ARGV}"

refuses_sign() {
	local description="$1" needle="$2" output
	shift 2

	if output="$(run_sign "$@")"; then
		printf 'expected %s to be refused; it was not:\n%s\n' "${description}" "${output}" >&2
		exit 1
	fi
	if ! grep -Fq "${needle}" <<<"${output}"; then
		printf 'the refusal for %s does not mention %q:\n%s\n' "${description}" "${needle}" "${output}" >&2
		exit 1
	fi
}

# The landing-order seam, stated as a refusal. This script replaced a Python
# implementation that needed no CLI at all, so the release that carries
# `sign-commit` has to be a named prerequisite rather than a puzzle in the log.
refuses_sign 'a gpg-sign without sign-commit' 'has no sign-commit command' \
	GPG_SIGN_BIN="${tmp_dir}/bin/gpg-sign-old"
refuses_sign 'a gpg-sign that does not exist' 'is not executable' \
	GPG_SIGN_BIN="${tmp_dir}/bin/gpg-sign-missing"

# A failing CLI has to fail the run: the workflow pushes in the step after this
# one, and a swallowed error would publish whatever the rewrite left behind.
cat >"${tmp_dir}/bin/gpg-sign-failing" <<'FAILING'
#!/usr/bin/env bash
[[ "${2-}" != --help ]] || exit 0
printf 'sign-commit failed: the service refused the token\n' >&2
exit 1
FAILING
chmod +x "${tmp_dir}/bin/gpg-sign-failing"
refuses_sign 'a CLI that failed' 'the service refused the token' \
	GPG_SIGN_BIN="${tmp_dir}/bin/gpg-sign-failing"

# Nothing here moves a ref or publishes. The fixture has no remote, so a script
# that tried to push would have failed above rather than pass quietly, and HEAD
# is where the fixture left it.
[[ "$(git -C "${test_repo}" rev-parse HEAD)" == "${head_before}" ]] \
	|| {
		printf 'the orchestration moved HEAD; sign-commit owns that, and the push is the workflow step after it\n' >&2
		exit 1
	}

printf 'sign orchestration: all cases passed\n'

# --- the command this all orchestrates ----------------------------------------
#
# Built from the checkout, on purpose. `sign-commit` is not in every release, so
# a suite that took the name from PATH would be testing whatever the signing
# action installed.

if ! command -v go >/dev/null 2>&1; then
	printf 'go is not installed; skipping the checked-out CLI build\n'
	exit 0
fi

built="${tmp_dir}/bin/gpg-sign-built"
(cd "${repo_root}/client" && go build -o "${built}" ./cmd/gpg-sign)

"${built}" sign-commit --help >/dev/null \
	|| {
		printf 'the checked-out gpg-sign has no sign-commit command\n' >&2
		exit 1
	}

# The same probe the script makes, against the binary it would run in
# production once a release carries the command. The run goes no further than
# base resolution — there is no signing service here — but it must not be the
# probe that stops it.
output="$(run_sign GPG_SIGN_BIN="${built}" BASE_REF="${head_before}" || true)"
if grep -Fq 'has no sign-commit command' <<<"${output}"; then
	printf 'the orchestration rejected the checked-out CLI:\n%s\n' "${output}" >&2
	exit 1
fi

printf 'checked-out gpg-sign: sign-commit is present\n'
