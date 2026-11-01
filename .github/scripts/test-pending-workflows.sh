#!/usr/bin/env bash
# Pin the two staged workflows and the one maintainer commit that activates them.
#
# This repository's automation cannot write under .github/workflows/ (a GitHub
# App token has no `workflows` permission), so two workflow changes are staged
# in .github/workflows-pending/ and activated together:
#
#   autofix.yml   kjanat/actions@fmt shells out to `mise`, which nothing installed
#   security.yml  the OpenPGP.js licence exemption (pinned by its own suite)
#
# Passes in both states. While staged, each file may differ from the live one by
# exactly the delta named here; once activated, the live file must carry it.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
wf="${repo_root}/.github/workflows"
pend="${repo_root}/.github/workflows-pending"
doc="${repo_root}/docs/workflow-activation.md"

readonly activation_command='git mv -f .github/workflows-pending/autofix.yml .github/workflows/autofix.yml && git mv -f .github/workflows-pending/security.yml .github/workflows/security.yml && git commit -m "ci: activate staged workflows"'
readonly mise_sha='jdx/mise-action@2d8d4cafcbd33be2ea37d2b6f5ad595363d1f1ca'

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

# --- which workflows are staged -----------------------------------------------
staged=()
for name in autofix security; do
	[[ -f "${pend}/${name}.yml" ]] && staged+=("${name}")
done
if ((${#staged[@]} != 0 && ${#staged[@]} != 2)); then
	fail "staged workflows are activated together, but only ${staged[*]} remain in .github/workflows-pending/"
fi
state=active
((${#staged[@]} == 2)) && state=pending

# subject NAME — the file that is, or will be, live.
subject() {
	if [[ "${state}" == pending ]]; then echo "${pend}/$1.yml"; else echo "${wf}/$1.yml"; fi
}

# live_baseline NAME — what live is today, for the delta checks. autofix.yml
# lives on master; a checkout that predates it reads the default branch's copy.
live_baseline() {
	local name="$1" out="${tmp_dir}/live-$1.yml"
	if [[ -f "${wf}/${name}.yml" ]]; then
		echo "${wf}/${name}.yml"
	elif git -C "${repo_root}" show "origin/master:.github/workflows/${name}.yml" >"${out}" 2>/dev/null; then
		echo "${out}"
	else
		return 1
	fi
}

# --- static analysis ----------------------------------------------------------
if command -v actionlint >/dev/null 2>&1; then
	lint=(actionlint)
elif command -v mise >/dev/null 2>&1; then
	lint=(mise exec -- actionlint)
else
	fail 'actionlint is not available, so the workflows cannot be validated'
fi
"${lint[@]}" "$(subject autofix)" || fail "actionlint rejects $(subject autofix)"
[[ -z "$(tail -c1 "$(subject autofix)")" ]] || fail 'autofix.yml has no final newline, which the Format check refuses'

# --- autofix.yml: mise before fmt, nothing else -------------------------------
python3 - "${state}" "$(subject autofix)" "$(live_baseline autofix || true)" "${mise_sha}" <<'PY' || fail 'autofix.yml is not the live workflow plus mise set up before fmt'
import copy, sys, yaml

state, subject, live, mise = sys.argv[1:5]
load = lambda p: yaml.safe_load(open(p))
wf = load(subject)
steps = wf["jobs"]["autofix"]["steps"]
uses = [str(s.get("uses", "")) for s in steps]

mise_at = [i for i, u in enumerate(uses) if u.split("#")[0].strip().startswith("jdx/mise-action@")]
fmt_at = [i for i, u in enumerate(uses) if u.startswith("kjanat/actions@fmt")]
assert len(mise_at) == 1 and len(fmt_at) == 1, "need exactly one mise step and one fmt step"
assert mise_at[0] < fmt_at[0], "fmt runs before mise, which it shells out to"
assert uses[mise_at[0]] == mise, f"mise is not the repository pin {mise}"
assert steps[mise_at[0]]["with"] == {"version": "${{ vars.MISE_VERSION }}"}
assert uses[0].startswith("actions/checkout@") and mise_at[0] > 0, "checkout must come first"
assert uses[-1].startswith("autofix-ci/action@") and fmt_at[0] < len(uses) - 1

if state == "pending":
    assert live, "no live autofix.yml to compare against"
    base = copy.deepcopy(wf)
    del base["jobs"]["autofix"]["steps"][mise_at[0]]
    base["jobs"]["autofix"]["timeout-minutes"] = load(live)["jobs"]["autofix"]["timeout-minutes"]
    assert base == load(live), "pending autofix.yml differs from live by more than mise setup and its timeout"
    assert "jdx/mise-action" not in open(live).read(), "live autofix.yml already sets up mise"
PY

# --- the activation -----------------------------------------------------------
[[ -f "${doc}" ]] || fail 'docs/workflow-activation.md is missing'
grep -qF -- "${activation_command}" "${doc}" \
	|| fail "docs/workflow-activation.md does not carry the activation command: ${activation_command}"
grep -qF -- 'Dependency Review' "${doc}" \
	|| fail 'docs/workflow-activation.md does not account for the red Dependency Review check'

if [[ "${state}" == pending ]]; then
	# Run the documented command, verbatim, in a scratch repository that holds
	# copies of the workflow directories, and look at the one commit it makes.
	scratch="${tmp_dir}/activation"
	mkdir -p "${scratch}/.github"
	cp -R "${wf}" "${scratch}/.github/workflows"
	cp -R "${pend}" "${scratch}/.github/workflows-pending"
	if ! [[ -f "${scratch}/.github/workflows/autofix.yml" ]]; then
		live_baseline autofix >"${tmp_dir}/path" && cp "$(<"${tmp_dir}/path")" "${scratch}/.github/workflows/autofix.yml"
	fi
	(
		cd "${scratch}"
		unset "${!GIT_@}"
		export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
		git init --quiet --initial-branch=master
		git config user.name tester && git config user.email tester@example.com && git config commit.gpgsign false
		git add -A && git commit --quiet -m base
		bash -c "${activation_command}" >/dev/null
		[[ "$(git rev-list --count HEAD)" == 2 ]] || {
			echo 'the command did not make exactly one commit' >&2
			exit 1
		}
		changed="$(git diff --name-only HEAD~1 HEAD | LC_ALL=C sort | tr '\n' ' ')"
		expected=".github/workflows-pending/autofix.yml .github/workflows-pending/security.yml .github/workflows/autofix.yml .github/workflows/security.yml "
		[[ "${changed}" == "${expected}" ]] || {
			echo "the commit touches ${changed}" >&2
			exit 1
		}
		for name in autofix security; do
			cmp -s "${pend}/${name}.yml" ".github/workflows/${name}.yml" || {
				echo "${name}.yml is not the staged file" >&2
				exit 1
			}
		done
		[[ -f .github/workflows-pending/claude.yml ]] || {
			echo 'the command moved a workflow that is not part of it' >&2
			exit 1
		}
	) || fail 'the documented activation command does not do exactly one commit moving autofix and security'
	printf '  note: autofix.yml and security.yml are staged, not active (activation pending)\n'
fi

printf 'pending workflow tests passed (%s)\n' "${state}"
