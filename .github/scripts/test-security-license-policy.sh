#!/usr/bin/env bash
# Pin the Security workflow's licence policy.
#
# Dependency review denies GPL and LGPL for what a pull request introduces, and
# openpgp (OpenPGP.js, LGPL-3.0-or-later) is the signing library already in the
# tree: bumping it reads as introducing an LGPL dependency and fails the check.
# The fix is a single named exemption (`allow-dependencies-licenses`), not a
# relaxed licence list.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
subject="${repo_root}/.github/workflows/security.yml"
readonly denied='GPL-2.0, GPL-3.0, LGPL-2.0, LGPL-2.1, LGPL-3.0'
readonly exempt='pkg:npm/openpgp'

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[[ -f "${subject}" ]] || fail '.github/workflows/security.yml is missing'

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

if command -v actionlint >/dev/null 2>&1; then
	actionlint "${subject}" || fail "actionlint rejects ${subject#"${repo_root}/"}"
elif command -v mise >/dev/null 2>&1; then
	mise exec -- actionlint "${subject}" || fail "actionlint rejects ${subject#"${repo_root}/"}"
else
	fail 'actionlint is not available, so the workflow cannot be validated'
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

printf 'security licence policy tests passed\n'
