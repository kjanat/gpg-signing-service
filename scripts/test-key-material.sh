#!/usr/bin/env bash
# Covers the key-material contract: no tracked file carries a private key, and
# no tracked file carries a retired production key even in public form.
#
# #147: `src/__tests__/` held the deployment's own encrypted signing key --
# 62E75E54497815DD, the `KEY_ID` wrangler.toml sets and the key the v1.2.0 tag
# is signed with -- in twelve places across four suites. Ten of them wore an
# earlier creation timestamp, which is a different fingerprint over an identical
# public point and an identical S2K-protected secret, so a check that compared
# fingerprints would have called those ten a different key and moved on.
#
# gitleaks cannot be the thing that holds this shut, and the reason is #146's
# fix. Its `private-key` rule keys on a literal armor header; `src/utils/armor.ts`
# composes every marker in this repository at run time precisely so that the
# rule stops firing on fixtures. That was the right call -- a header opens a
# 64-character-minimum match that swallows whatever is under it -- but it means a
# key committed without its header is a key gitleaks does not see. Header or no
# header, the base64 still decodes, so `scripts/key-material.py` decodes it.
#
# What the two gates own, so neither is asked to cover the other:
#
#   test-gitleaks-contract.sh   the allowlist cannot excuse a live credential
#   this file                   no private key is in the tree to excuse
#
# Every mutant below is built from a key generated during the run. A gate that
# ships a realistic secret in its own source is a gate that trips itself, which
# is the trap the corpus it replaces fell into -- and the trap the first version
# of this gate then walked into a second time, by excusing the one file that
# still spelled the packet out. There are no exclusions here now, and section 4
# is what keeps it that way.
#
# Run: task test:key-material
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
detector="${repo_root}/scripts/key-material.py"
tmp_dir="$(mktemp -d)"

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

# Deliberately not the `exit 0` skip the generated-file gates use. This is the
# only thing standing between the repository and a committed private key, and a
# gate that passes quietly when it cannot run is the failure it exists to
# prevent -- the same reasoning test-gitleaks-contract.sh gives for gitleaks.
for tool in python3 gpg; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		printf '%s is required to check for committed key material, and is not on PATH\n' "${tool}" >&2
		exit 1
	fi
done

export GNUPGHOME="${tmp_dir}/gnupg"
mkdir -p "${GNUPGHOME}"
chmod 700 "${GNUPGHOME}"
cleanup() {
	gpgconf --kill all >/dev/null 2>&1 || true
	rm -rf "${tmp_dir}"
}
trap cleanup EXIT

# `detect <path...>` -> `clean` or `found`, with the report left in
# ${tmp_dir}/report for whichever case wants to quote it. Printing every report
# would bury the case lines under the findings the mutants are supposed to
# produce, so only a failure says what it saw.
report="${tmp_dir}/report"
detect() {
	if python3 "${detector}" "$@" >"${report}" 2>&1; then
		printf 'clean\n'
	else
		printf 'found\n'
	fi
}

# The first line of the last report, for a failure message.
first_finding() { head -n1 "${report}" 2>/dev/null || printf 'no output'; }

# --- probe material ----------------------------------------------------------
#
# One Ed25519 key with a passphrase, exported both ways. Passphrase-protected on
# purpose: #147's whole point is that an encrypted private key is still a private
# key, so a gate that only saw unprotected ones would have missed the twelve.

probe_pass="$(head -c 24 /dev/urandom | base64 | tr -d '\n')"
gpg --batch --quiet --pinentry-mode loopback --passphrase "${probe_pass}" \
	--quick-generate-key 'gate probe <probe@example.invalid>' ed25519 sign never

probe_secret="${tmp_dir}/probe-secret.asc"
probe_public="${tmp_dir}/probe-public.asc"
gpg --batch --quiet --pinentry-mode loopback --passphrase "${probe_pass}" \
	--armor --export-secret-keys >"${probe_secret}"
gpg --batch --quiet --armor --export >"${probe_public}"

# The armored body without its markers, which is what a fixture holds once
# `src/utils/armor.ts` has stopped anyone from writing the markers down.
body_of() { sed '1d;$d' "$1" | sed '/^$/d;/^[A-Za-z]*:/d'; }

secret_body="${tmp_dir}/secret-body"
public_body="${tmp_dir}/public-body"
body_of "${probe_secret}" >"${secret_body}"
body_of "${probe_public}" >"${public_body}"

# =============================================================================
# 1. The tree the gate is guarding
# =============================================================================

new_case 'no tracked file carries key material'
tree_result="$(cd "${repo_root}" && git ls-files | xargs python3 "${detector}" >"${report}" 2>&1 && printf 'clean\n' || printf 'found\n')"
[[ ${tree_result} == "clean" ]] \
	|| fail "a tracked file carries an OpenPGP key packet: $(first_finding)"

# The retired set and the deployment have to name the same key, or the guard is
# watching for something the service stopped using years ago. wrangler.toml is
# the source of truth for what is live; when the operator cuts over to the
# replacement key, this case is what says the retired set was updated too.
new_case 'the retired set names the key wrangler.toml deploys'
deployed_key_id="$(sed -nE 's/^KEY_ID[[:space:]]*=[[:space:]]*"([0-9A-Fa-f]{16})".*/\1/p' "${repo_root}/wrangler.toml" | head -n1)"
if [[ -z ${deployed_key_id} ]]; then
	fail 'no KEY_ID found in wrangler.toml, so this case cannot check anything'
elif ! grep -qi -- "${deployed_key_id}" "${detector}"; then
	fail "wrangler.toml deploys ${deployed_key_id}, which scripts/key-material.py does not name; after a rotation, add the retired key's identity digest to RETIRED_IDENTITIES"
fi

# =============================================================================
# 2. A private key is reported however it is written down
# =============================================================================

armored="${tmp_dir}/armored"
mkdir -p "${armored}"
cp "${probe_secret}" "${armored}/fixture.test.ts"

new_case 'mutant: an armored private key in a fixture is reported'
[[ "$(detect "${armored}/fixture.test.ts")" == "found" ]] \
	|| fail 'a complete armored private key was not reported'

# The case that gitleaks cannot cover. `src/utils/armor.ts` is why no fixture in
# this repository writes an armor header, so a key pasted underneath one of them
# arrives with no header either -- and gitleaks' rule starts at the header.
headerless="${tmp_dir}/headerless"
mkdir -p "${headerless}"
{
	printf 'const marker = armorMarker("BEGIN", "PGP PRIVATE KEY BLOCK");\n'
	printf 'const fixture = [\n'
	sed 's/^/  "/; s/$/",/' "${secret_body}"
	printf '].join("\\n");\n'
} >"${headerless}/fixture.test.ts"

new_case 'mutant: the same key with no armor header at all is reported'
[[ "$(detect "${headerless}/fixture.test.ts")" == "found" ]] \
	|| fail 'a private key without its armor header was not reported; the check has regressed to matching headers, which is what gitleaks already does'

new_case 'mutant: folded onto one line with escaped newlines, still reported'
folded="${tmp_dir}/folded"
mkdir -p "${folded}"
printf 'const fixture = "%s";\n' "$(tr '\n' '\001' <"${secret_body}" | sed 's/\x01/\\n/g')" >"${folded}/fixture.test.ts"
[[ "$(detect "${folded}/fixture.test.ts")" == "found" ]] \
	|| fail 'a private key folded into a single string literal was not reported'

new_case 'mutant: regex-escaped, the way .gitleaks.toml holds one, still reported'
escaped="${tmp_dir}/escaped"
mkdir -p "${escaped}"
printf "regexes = ['''\\\\A%s\\\\z''']\n" \
	"$(tr '\n' '\001' <"${secret_body}" | sed 's/\x01/\\n/g; s/+/\\+/g')" >"${escaped}/config.toml"
[[ "$(detect "${escaped}/config.toml")" == "found" ]] \
	|| fail 'a regex-escaped private key was not reported, so escaping is a way to smuggle one past this gate'

# =============================================================================
# 3. The rule is about secrets, not about keys
# =============================================================================
#
# A public key is publication, not exposure: `docs/` and the check suites carry
# them on purpose. A gate that reported those would be turned off inside a week.

public_dir="${tmp_dir}/public"
mkdir -p "${public_dir}"
cp "${probe_public}" "${public_dir}/verify.test.ts"

new_case 'a freshly generated public key is not reported'
[[ "$(detect "${public_dir}/verify.test.ts")" == "clean" ]] \
	|| fail "a public key was reported as key material -- the secret rule has widened to every packet and will be disabled by the first person it inconveniences: $(first_finding)"

# ...unless it is a retired production key, which is the other half of #147: the
# public half of a compromised key showing up as a fixture is how it gets used
# as one again.
new_case 'mutant: the public half of a retired key IS reported'
probe_identity="$(python3 "${detector}" --identities "${public_dir}/verify.test.ts" | head -n1)"
if [[ -z ${probe_identity} ]]; then
	fail 'the probe key has no identity digest, so the retired rule cannot be exercised'
elif [[ "$(detect --retired "${probe_identity}" "${public_dir}/verify.test.ts")" != "found" ]]; then
	fail 'a public key in the retired set was not reported'
fi

# The property that hid ten of #147's twelve copies. Re-stamping a key's four
# creation-time bytes gives a new fingerprint over an unchanged secret; if the
# retired set were keyed on fingerprints, that alone would clear it.
new_case 'mutant: re-stamping a key does not change the identity it is known by'
restamped="${tmp_dir}/restamped"
mkdir -p "${restamped}"
python3 - "${public_body}" "${restamped}/verify.test.ts" <<'PY'
import base64
import sys

body, out = sys.argv[1], sys.argv[2]
raw = bytearray(base64.b64decode("".join(open(body).read().split())))
# Old-format tag 6, one-octet length: version, then the four creation bytes.
created = int.from_bytes(raw[3:7], "big")
raw[3:7] = (created - 86_400).to_bytes(4, "big")
encoded = base64.b64encode(bytes(raw)).decode()
print("\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64)), file=open(out, "w"))
PY
restamped_identity="$(python3 "${detector}" --identities "${restamped}/verify.test.ts" | head -n1)"
if [[ -z ${restamped_identity} ]]; then
	fail 'the re-stamped key did not parse, so this case measured nothing'
elif [[ ${restamped_identity} != "${probe_identity}" ]]; then
	fail "re-stamping changed the identity digest (${probe_identity:0:16}... became ${restamped_identity:0:16}...); the digest is covering the creation time and a re-stamped retired key would walk straight through"
fi

# =============================================================================
# 4. No file is excused, and .gitleaks.toml least of all
# =============================================================================
#
# The first version of this gate skipped `.gitleaks.toml` by name. Its historical
# allowlist matches pre-#147 findings by their exact text, and an exact-match
# regex cannot stop naming what it matches -- so the config spelled the
# deployment's own encrypted secret-key packet out, and the gate was told not to
# look. That is the worst possible place for an exception: gitleaks' *own*
# default allowlist drops every path ending `gitleaks.toml`
# (`scripts/test-gitleaks-contract.sh` measures this), so the config is already
# the one file the scanner will not read. Two gates skipping the same file is not
# defence in depth.
#
# The entries now write their long literal runs one `\xNN` per character, which
# accepts the same strings -- proved against the scanner in the contract suite --
# and is not a base64 run, so the config passes on its merits. What follows holds
# that shut from both sides: the file is scanned, and no mechanism exists to stop
# scanning it.

new_case '.gitleaks.toml is scanned like any other tracked file and is clean'
[[ "$(detect "${repo_root}/.gitleaks.toml")" == "clean" ]] \
	|| fail "the shipped config carries key material: $(first_finding)"

new_case 'mutant: a real secret packet in .gitleaks.toml is caught, as anywhere else'
planted_config="${tmp_dir}/planted-config"
mkdir -p "${planted_config}"
{
	cat "${repo_root}/.gitleaks.toml"
	printf '\n# planted by the key-material gate\n'
	cat "${probe_secret}"
} >"${planted_config}/.gitleaks.toml"
[[ "$(detect "${planted_config}/.gitleaks.toml")" == "found" ]] \
	|| fail 'a generated private key appended to .gitleaks.toml was not reported; the config is excused again and #147 is back'

# The same bytes under a name with no special meaning, so the case above is
# measuring the key and not the filename.
cp "${planted_config}/.gitleaks.toml" "${tmp_dir}/planted-plain.toml"
new_case 'the same planted key is reported under an ordinary filename too'
[[ "$(detect "${tmp_dir}/planted-plain.toml")" == "found" ]] \
	|| fail 'the planted key was reported only under one name, so the detector is name-sensitive after all'

# Structural, because a hole is easier to reintroduce than to notice. Anything
# that maps a path or a name to "skip" is the mechanism this gate exists without.
new_case 'the detector carries no tracked-file exclusion mechanism'
if grep -nE '^[[:space:]]*(EXCLUDED|EXCLUDE|SKIP|IGNORE|ALLOW(ED)?_?(PATHS|FILES)?)[[:space:]]*[:=]' "${detector}" >"${report}"; then
	fail "the detector declares an exclusion list again: $(first_finding)"
fi
if grep -nE '\.name (in|==|!=)|path\.name|fnmatch|\.match\(|\.suffix (in|==)|str\(path\) (in|==)' "${detector}" >"${report}"; then
	fail "the detector branches on a file's name or extension: $(first_finding)"
fi

# ...and behaviourally, which is the half a grep cannot give. Every tracked path
# that is a file on disk has to come back out of --considered; a detector that
# quietly drops one -- by name, by extension, by an encoding it cannot decode --
# fails here rather than in the incident.
new_case 'every tracked file is considered, with nothing dropped'
mapfile -t tracked < <(cd "${repo_root}" && git ls-files)
considered="${tmp_dir}/considered"
expected="${tmp_dir}/expected"
(cd "${repo_root}" && printf '%s\n' "${tracked[@]}" | xargs python3 "${detector}" --considered) | sort >"${considered}"
(cd "${repo_root}" && for name in "${tracked[@]}"; do [[ -f ${name} ]] && printf '%s\n' "${name}"; done) | sort >"${expected}"
if ! diff -q "${expected}" "${considered}" >/dev/null; then
	fail "$(comm -23 "${expected}" "${considered}" | tr '\n' ' ')is tracked and was not considered"
elif [[ ! -s ${considered} ]]; then
	fail 'nothing was considered, so this case is vacuous'
fi

# A file the detector cannot decode as text is a file it is not really reading.
# latin-1 is why there is no such file; this is what says so.
new_case 'a file that is not valid UTF-8 is still read'
binary="${tmp_dir}/binary"
mkdir -p "${binary}"
{
	printf '\xff\xfe\x00binary preamble\x00'
	cat "${secret_body}"
} >"${binary}/blob.bin"
[[ "$(detect "${binary}/blob.bin")" == "found" ]] \
	|| fail 'a key inside a file that is not valid UTF-8 was not reported; the detector is skipping by encoding, which is an exclusion with another name'

# =============================================================================

if [[ ${failures} -gt 0 ]]; then
	printf '\n%s case(s) failed\n' "${failures}" >&2
	exit 1
fi

printf '\nkey-material contract holds\n'
