#!/usr/bin/env bash
# Covers the retired-key-reference contract: no tracked file tells a reader to
# use the key #147 retired, and the files that are *about* that key still may.
#
# The two key gates own different failures, so neither is asked to cover the
# other:
#
#   test-key-material.sh      no tracked file carries key *material* -- a packet,
#                             under any encoding, secret or public
#   this file                 no tracked file carries a usable *instruction*
#                             naming the retired key id
#
# The second is not a secret-scanning problem. `62E75E54497815DD` is a public key
# id; it is on every signature that key ever made. What was wrong with master is
# that roughly thirty documentation and CLI examples still passed it, and
# production has answered `404 KEY_NOT_FOUND` for it since 2026-09-08 -- so each
# of those was a copy-paste that fails, pointing a new operator at the key the
# incident retired.
#
# Deleting every mention would break the containment record. ADR-004, the
# key-handoff runbook and its tooling, the key-material guard's retired set and
# fourteen unit suites all name the key on purpose. So the gate is scoped by path
# *and* by meaning, and both halves are mutated below: section 3 proves the path
# tier, section 4 proves that an operational example smuggled into an allowlisted
# file is still caught, and section 5 proves the allowlist cannot quietly grow to
# cover a live-facing guide.
#
# Run: task test:retired-key-refs
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
detector="${repo_root}/scripts/retired-key-refs.py"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

retired='62E75E54497815DD'
replacement='AFD5E3EC68371856'

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

# Run the detector against one path, from a root it treats as the repository.
# Paths are passed repo-relative because the tier is decided by path.
detect() {
	local root="$1" && shift
	if (cd "${root}" && python3 "${detector}" "$@" >"${tmp_dir}/report" 2>&1); then
		printf 'clean\n'
	else
		printf 'found\n'
	fi
}

report() { cat "${tmp_dir}/report"; }

# =============================================================================
# 1. The tree the gate is guarding
# =============================================================================

new_case 'no tracked file names the retired key outside the incident and fixture tiers'
if ! (cd "${repo_root}" && git ls-files -z | xargs -0 python3 "${detector}" >"${tmp_dir}/report" 2>&1); then
	fail "$(report | head -n 5)"
fi

# The other end of the same fact. A gate that reported nothing because it read
# nothing would pass the case above, so count the files whose bytes the detector
# actually got -- `--considered` reports `read` or `unread` per path, and
# echoing one line per argument would only restate the argument list.
# `-z`/`-0` because a tracked path containing a space would otherwise reach the
# detector as two paths that do not exist, and be skipped as unreadable.
new_case 'every tracked file is read, with nothing dropped'
tracked="$(cd "${repo_root}" && git ls-files | wc -l)"
were_read="$(cd "${repo_root}" && git ls-files -z | xargs -0 python3 "${detector}" --considered | grep -c "$(printf '\tread\t')")"
[[ ${tracked} -eq ${were_read} ]] \
	|| fail "git tracks ${tracked} files and the detector read ${were_read}"

# ...and that count is only meaningful if `unread` is reachable, or the case
# above is comparing an argument list against itself.
new_case 'a path the detector cannot open is reported as unread, not as clean'
[[ "$(cd "${repo_root}" && python3 "${detector}" --considered docs/does-not-exist.md)" == *$'\tunread\t'* ]] \
	|| fail 'a missing path was reported as read'

# A future rotation moves the deployment again. If it ever moves *onto* the key
# this gate hunts, every example in the tree is wrong in the opposite direction
# and the gate would be banning the live key. Two copies of one fact, so this
# fails rather than lets them drift.
new_case 'the gate hunts a key wrangler.toml does not deploy'
deployed="$(sed -nE 's/^KEY_ID[[:space:]]*=[[:space:]]*"([0-9A-Fa-f]{16})".*/\1/p' "${repo_root}/wrangler.toml" | head -n1)"
[[ -n ${deployed} ]] || fail 'no KEY_ID found in wrangler.toml, so this case cannot check anything'
if [[ ${deployed} == "${retired}" ]]; then
	fail "wrangler.toml deploys ${deployed}, which scripts/retired-key-refs.py treats as retired; the gate would reject every correct example in the tree"
fi

new_case 'the replacement key is not what the gate reports'
[[ ${deployed} == "${replacement}" ]] \
	|| fail "wrangler.toml deploys ${deployed}, not ${replacement}; the docs this gate steers people to would be steering them at the wrong key"

# =============================================================================
# 2. A scratch tree the mutants are built in
# =============================================================================

plant() {
	local rel="$1" && shift
	mkdir -p "${tmp_dir}/tree/$(dirname "${rel}")"
	cat >"${tmp_dir}/tree/${rel}"
}

mkdir -p "${tmp_dir}/tree"

# =============================================================================
# 3. The path tier: a live-facing file may not name the key at all
# =============================================================================

new_case 'mutant: a new documentation page naming the retired key is reported'
plant 'docs/new-guide.md' <<EOF
Request a signature:

    gpg-sign sign --key-id ${retired} > commit.sig
EOF
[[ "$(detect "${tmp_dir}/tree" docs/new-guide.md)" == "found" ]] \
	|| fail 'a retired key id in a new documentation page was not reported'

new_case 'mutant: a CLI help string naming the retired key is reported'
plant 'client/cmd/gpg-sign/example.go' <<EOF
package main

// Example:
//   gpg-sign sign-commit --key-id=${retired}
EOF
[[ "$(detect "${tmp_dir}/tree" client/cmd/gpg-sign/example.go)" == "found" ]] \
	|| fail 'a retired key id in a Go CLI example was not reported'

# `KeyIdSchema` normalises on the way in, so the lower-case spelling names the
# same key and reaches the same 404. The gate that only matched one spelling
# missed exactly this on docs/github-app.md.
new_case 'mutant: the lower-case spelling is reported'
plant 'docs/lower.md' <<EOF
An operator who pastes \`$(printf '%s' "${retired}" | tr '[:upper:]' '[:lower:]')\` gets a key.
EOF
[[ "$(detect "${tmp_dir}/tree" docs/lower.md)" == "found" ]] \
	|| fail 'the lower-case spelling of the retired key id was not reported'

new_case 'mutant: the full fingerprint is reported, since it ends in the key id'
plant 'docs/fingerprint.md' <<EOF
Verify against 806D3A1B9F957D6731950BCA${retired}.
EOF
[[ "$(detect "${tmp_dir}/tree" docs/fingerprint.md)" == "found" ]] \
	|| fail 'the retired key fingerprint was not reported'

new_case 'the replacement key is never reported'
plant 'docs/replacement.md' <<EOF
    gpg-sign sign --key-id ${replacement} > commit.sig
EOF
[[ "$(detect "${tmp_dir}/tree" docs/replacement.md)" == "clean" ]] \
	|| fail "the gate reported ${replacement}, which is the key the service deploys"

# A file that is not valid UTF-8 is still a file. Skipping by encoding is an
# exclusion with another name.
new_case 'a file that is not valid UTF-8 is still read'
mkdir -p "${tmp_dir}/tree/docs"
{
	printf '\xff\xfe\x00'
	printf -- '--key-id %s\n' "${retired}"
} >"${tmp_dir}/tree/docs/binary.md"
[[ "$(detect "${tmp_dir}/tree" docs/binary.md)" == "found" ]] \
	|| fail 'a retired key id in a file that is not valid UTF-8 was not reported'

# `splitlines()` breaks on \x85 among others, and \x85 is the third byte of a
# UTF-8 check mark. One emoji above the finding and every reported line number
# after it is wrong -- which is a gate nobody can act on.
new_case 'line numbers survive a multi-byte character earlier in the file'
plant 'docs/emoji.md' <<EOF
- ✅ a line with a check mark
- ❌ and a cross

    gpg-sign sign --key-id ${retired}
EOF
detect "${tmp_dir}/tree" docs/emoji.md >/dev/null
grep -q '^docs/emoji.md:4:' "${tmp_dir}/report" \
	|| fail "expected the finding on line 4, got: $(report | head -n 1)"

# =============================================================================
# 4. The semantic tier: an allowlisted file may describe the key, not deploy it
# =============================================================================

new_case 'an incident file may name the retired key in prose about its retirement'
plant 'docs/adr/ADR-004-retired-key-revocation.md' <<EOF
The retired key ${retired} keeps its public half so v1.2.0 still verifies.
EOF
[[ "$(detect "${tmp_dir}/tree" docs/adr/ADR-004-retired-key-revocation.md)" == "clean" ]] \
	|| fail "an incident file was reported for prose about the retirement: $(report | head -n 1)"

# The failure a path allowlist on its own cannot see: the runbook is exactly
# where a signing example would look at home.
new_case 'mutant: an unmarked example appended to an incident file is reported'
plant 'docs/key-handoff-runbook.md' <<EOF
The 2026-09-08 rotation retired ${retired}.

## Signing

    gpg-sign sign --key-id ${retired} > commit.sig

    gpg-sign public-key --key-id ${retired} > key.asc

    gpg-sign admin upload --key-id ${retired} --file key.asc
EOF
if [[ "$(detect "${tmp_dir}/tree" docs/key-handoff-runbook.md)" == "found" ]]; then
	grep -q 'docs/key-handoff-runbook.md:7:' "${tmp_dir}/report" \
		|| fail "the unmarked example on line 7 was not among the findings: $(report | head -n 3)"
else
	fail 'an operational example appended to an incident file was not reported'
fi

# ...and the first line of that same file must still pass, or the semantic rule
# is just the path rule inverted.
new_case 'the marked line of that same file is not reported'
if grep -q 'docs/key-handoff-runbook.md:1:' "${tmp_dir}/report"; then
	fail 'prose that says the key is retired was reported anyway'
fi

# The footer of every guide in this tree is a block of markdown link-reference
# definitions, and `[ADR-004]: adr/ADR-004-retired-key-revocation.md` matches
# three markers inside a file path while saying nothing about the line beneath
# it. An appended example lands in exactly that part of the file, so before this
# was excluded the runbook's own footer vouched for whatever was written under
# it -- the one failure the semantic tier exists to catch.
new_case 'mutant: a link-reference footer does not vouch for an example under it'
plant 'docs/key-handoff-runbook.md' <<EOF
The 2026-09-08 rotation retired ${retired}.

[#147]: https://github.com/kjanat/gpg-signing-service/issues/147
[ADR-004]: adr/ADR-004-retired-key-revocation.md

    gpg-sign sign --key-id ${retired} > commit.sig
EOF
if [[ "$(detect "${tmp_dir}/tree" docs/key-handoff-runbook.md)" == "found" ]]; then
	grep -q 'docs/key-handoff-runbook.md:6:' "${tmp_dir}/report" \
		|| fail "the example on line 6 was not among the findings: $(report | head -n 3)"
else
	fail 'a link-reference footer marked an operational example as retirement prose'
fi

# ...while a real sentence next to a link reference still marks the occurrence,
# so the exclusion is of the definition line only and not of the vocabulary.
new_case 'prose beside a link-reference footer still marks the occurrence'
plant 'docs/adr/ADR-004-retired-key-revocation.md' <<EOF
[#147]: https://github.com/kjanat/gpg-signing-service/issues/147

The 2026-09-08 rotation retired ${retired}; its public half stays.
EOF
[[ "$(detect "${tmp_dir}/tree" docs/adr/ADR-004-retired-key-revocation.md)" == "clean" ]] \
	|| fail "prose was reported because a link definition sat above it: $(report | head -n 1)"

# =============================================================================
# 5. The fixture tier, and the allowlist that decides all three
# =============================================================================

new_case 'the retired key id is deterministic test data under src/__tests__'
plant 'src/__tests__/service-tokens.test.ts' <<EOF
const policy = { keyIds: ["${retired}"] };
EOF
[[ "$(detect "${tmp_dir}/tree" src/__tests__/service-tokens.test.ts)" == "clean" ]] \
	|| fail 'a unit-test fixture was reported; the suites use this id as historical data on purpose'

new_case 'wrangler.test.toml keeps naming the retired key'
plant 'wrangler.test.toml' <<EOF
KEY_ID = "${retired}"
EOF
[[ "$(detect "${tmp_dir}/tree" wrangler.test.toml)" == "clean" ]] \
	|| fail 'the test worker config was reported'

# The fixture tier is one prefix, anchored. A live-facing file cannot buy itself
# out by being named like a test...
new_case 'mutant: a file merely named like a test is not in the fixture tier'
plant 'docs/__tests__-notes.md' <<EOF
    gpg-sign sign --key-id ${retired}
EOF
[[ "$(detect "${tmp_dir}/tree" docs/__tests__-notes.md)" == "found" ]] \
	|| fail 'a live-facing file with a test-shaped name was treated as a fixture'

# ...nor by carrying the prefix somewhere other than the start. The exemption is
# for the Worker's own suites, and `src/__tests__/` is a path that can exist
# again under any package in the workspace.
new_case 'mutant: the fixture prefix is anchored, not matched anywhere in the path'
plant 'client/src/__tests__/notes.md' <<EOF
    gpg-sign sign --key-id ${retired}
EOF
[[ "$(detect "${tmp_dir}/tree" client/src/__tests__/notes.md)" == "found" ]] \
	|| fail 'a path containing src/__tests__/ below another package was treated as a Worker test fixture'

# The allowlist is the whole gate, so it is the thing worth attacking. Under
# docs/, only the two files whose subject is the incident may be on it: anything
# else there is a guide somebody follows.
new_case 'the allowlist names no live-facing guide'
listed_docs="$(
	python3 - "${detector}" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
block = re.search(r"^INCIDENT = \{(.*?)^\}", src, re.S | re.M).group(1)
for path in re.findall(r'"([^"]+)"', block):
    if path.startswith("docs/"):
        print(path)
PY
)"
expected_docs=$'docs/adr/ADR-004-retired-key-revocation.md\ndocs/key-handoff-runbook.md'
[[ ${listed_docs} == "${expected_docs}" ]] \
	|| fail "the incident allowlist covers documentation beyond ADR-004 and the runbook: ${listed_docs//$'\n'/, }"

# ...and that assertion is only worth having if it goes red. Widen the allowlist
# in a copy and require that this case would have caught it.
new_case 'mutant: widening the allowlist to a live-facing guide is caught'
widened="${tmp_dir}/widened.py"
sed 's|^INCIDENT = {$|INCIDENT = {\n    "docs/cli.md",|' "${detector}" >"${widened}"
grep -q '"docs/cli.md"' "${widened}" || fail 'the mutant was not built'
widened_docs="$(
	python3 - "${widened}" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
block = re.search(r"^INCIDENT = \{(.*?)^\}", src, re.S | re.M).group(1)
for path in re.findall(r'"([^"]+)"', block):
    if path.startswith("docs/"):
        print(path)
PY
)"
[[ ${widened_docs} != "${expected_docs}" ]] \
	|| fail 'the allowlist assertion did not notice docs/cli.md being added'

# And the widened copy really would have let the plant through, so the allowlist
# is load-bearing rather than decorative.
new_case 'the allowlist is load-bearing'
plant 'docs/cli.md' <<EOF
    gpg-sign sign --key-id ${retired} > commit.sig
EOF
[[ "$(detect "${tmp_dir}/tree" docs/cli.md)" == "found" ]] \
	|| fail 'the shipped detector did not report a live example in docs/cli.md'
if (cd "${tmp_dir}/tree" && python3 "${widened}" docs/cli.md >/dev/null 2>&1); then
	fail 'the widened detector reported it too, so the allowlist decides nothing'
fi

# =============================================================================

if [[ ${failures} -gt 0 ]]; then
	printf '\n%s case(s) failed\n' "${failures}" >&2
	exit 1
fi

printf '\nretired-key-reference contract holds\n'
