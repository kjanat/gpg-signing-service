#!/usr/bin/env bash
# Pin the Security workflow's licence policy and its maintainer activation.
#
# Dependency review denies GPL and LGPL for what a pull request introduces, and
# openpgp (OpenPGP.js, LGPL-3.0-or-later) is the signing library already in the
# tree: bumping it reads as introducing an LGPL dependency and fails the check.
# The fix is a single named exemption (`allow-dependencies-licenses`), not a
# relaxed licence list. This repository's automation cannot write under
# .github/workflows/ (a GitHub App token has no `workflows` permission), so the
# replacement is staged as .github/workflows-pending/security.yml and a
# maintainer moves it into place with the one command asserted below.
#
# Passes in both states. While staged, the live workflow must still be the
# unexempted one; once activated, the live workflow must carry exactly the
# exemption. The only thing that is allowed to stay red until a maintainer acts
# is the dependency-review check of the OpenPGP.js bump itself.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
live="${repo_root}/.github/workflows/security.yml"
pending="${repo_root}/.github/workflows-pending/security.yml"
doc="${repo_root}/docs/security-license-policy.md"

readonly activation_command='git mv -f .github/workflows-pending/autofix.yml .github/workflows/autofix.yml && git mv -f .github/workflows-pending/security.yml .github/workflows/security.yml && git commit -m "ci: activate staged workflows"'
readonly denied='GPL-2.0, GPL-3.0, LGPL-2.0, LGPL-2.1, LGPL-3.0'
readonly exempt='pkg:npm/openpgp'

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[[ -f "${live}" ]] || fail '.github/workflows/security.yml is missing; staging replaces it, it does not stand in for it'
if [[ -f "${pending}" ]]; then
	state=pending
else
	state=active
fi

# What is asserted of the one workflow that is, or will be, live.
subject="${live}"
[[ "${state}" == pending ]] && subject="${pending}"

# policy FILE — print the dependency-review step's `with:` as sorted key=value
# lines, after proving there is exactly one such step and no other licence knob.
policy() {
	python3 - "$1" <<'PY'
import sys, yaml

wf = yaml.safe_load(open(sys.argv[1]))
steps = [
    s
    for job in wf["jobs"].values()
    for s in job.get("steps", [])
    if str(s.get("uses", "")).startswith("actions/dependency-review-action@")
]
assert len(steps) == 1, f"expected one dependency-review step, found {len(steps)}"
for key, value in sorted(steps[0].get("with", {}).items()):
    print(f"{key}={value}")
PY
}

policy_text="$(policy "${subject}")" || fail "${subject#"${repo_root}/"} has no single dependency-review step"

# Syntax and static analysis of whatever will run. lint:actions covers the
# directory too; this keeps the pending file failing here, with a name on it,
# when someone runs only this suite.
if command -v actionlint >/dev/null 2>&1; then
	actionlint "${subject}" || fail "actionlint rejects ${subject#"${repo_root}/"}"
elif command -v mise >/dev/null 2>&1; then
	mise exec -- actionlint "${subject}" || fail "actionlint rejects ${subject#"${repo_root}/"}"
else
	fail 'actionlint is not available, so the staged workflow cannot be validated'
fi

# The deny list is exactly what it was; the exemption is exactly OpenPGP.js;
# nothing else about the licence policy moved.
expected_keys=$'allow-dependencies-licenses\ndeny-licenses\nfail-on-severity'
actual_keys=''
while IFS= read -r line; do actual_keys+="${line%%=*}"$'\n'; done <<<"${policy_text}"
actual_keys="${actual_keys%$'\n'}"
[[ "${actual_keys}" == "${expected_keys}" ]] \
	|| fail "the dependency-review inputs are not exactly ${expected_keys//$'\n'/, }: ${actual_keys//$'\n'/, }"
grep -qxF "allow-dependencies-licenses=${exempt}" <<<"${policy_text}" \
	|| fail "the exemption is not exactly ${exempt}"
grep -qxF "deny-licenses=${denied}" <<<"${policy_text}" \
	|| fail "the deny list is not exactly: ${denied}"
grep -qxF 'fail-on-severity=high' <<<"${policy_text}" || fail 'fail-on-severity is not high'
for knob in allow-licenses license-check allow-ghsas config-file; do
	if grep -q "^${knob}=" <<<"${policy_text}"; then
		fail "${knob} is set on dependency review; the policy is the deny list plus one named package"
	fi
done

# The exemption is a package, never a licence and never a wildcard.
if [[ "${exempt}" == *'*'* || "${exempt}" == *LGPL* ]]; then fail 'the exemption is not a single package'; fi

# Active or pending, the rest of the workflow must be the live one: staging may
# change the dependency-review step's inputs and its comment, nothing else.
if [[ "${state}" == pending ]]; then
	python3 - "${live}" "${pending}" <<'PY' || fail 'the staged workflow differs from the live one by more than the exemption'
import sys, yaml

def load(path):
    wf = yaml.safe_load(open(path))
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/dependency-review-action@"):
                step["with"] = {
                    k: v for k, v in step["with"].items() if k != "allow-dependencies-licenses"
                }
    return wf

assert load(sys.argv[1]) == load(sys.argv[2])
PY
	live_policy="$(policy "${live}")"
	if grep -q '^allow-dependencies-licenses=' <<<"${live_policy}"; then
		fail 'the live workflow already carries the exemption but a staged copy remains'
	fi
	printf '  note: the OpenPGP.js licence exemption is staged, not active (activation pending)\n'
fi

# The activation is documented with the exact command, and only that command.
[[ -f "${doc}" ]] || fail 'docs/security-license-policy.md is missing'
grep -qF -- "${activation_command}" "${doc}" \
	|| fail "docs/security-license-policy.md does not carry the activation command: ${activation_command}"

printf 'security licence policy tests passed (%s)\n' "${state}"
