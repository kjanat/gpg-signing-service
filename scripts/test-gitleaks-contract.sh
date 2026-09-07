#!/usr/bin/env bash
# Covers the secret-scanning contract: what .gitleaks.toml is able to excuse,
# and which scanner is allowed to read it.
#
# #145: the scheduled Security workflow went red with 33 findings, all fixtures.
# Three defects stacked up, and only the third one is obvious:
#
#   1. gitleaks/gitleaks-action@v3 defaults GITLEAKS_VERSION to 8.24.3, and
#      8.24.3 *silently ignores* the `[[allowlists]]` array-of-tables form.
#      .gitleaks.toml declared four of them, so the repository had been running
#      with no global allowlist at all -- the config parsed, it just did
#      nothing. 8.24.3 likewise ignores `condition = "AND"`, which turns a
#      `paths` + `regexes` allowance into a bare path exclusion: broader than
#      written, and silently so.
#   2. .gitleaksignore was keyed by `<sha>:<file>:<rule>:<line>` fingerprints
#      from before the #111 history rewrite. New SHAs, no suppression.
#   3. The action scans `git log -p -U0 --full-history --all`, which reaches
#      abandoned branches *and the v1.2.0 tag* -- pre-rewrite commits that no
#      fingerprint derived from master can ever address.
#
# #146: the first fix for that traded a noisy scanner for a quiet one. It pinned
# each allowance to the head of the fixture text it excused, but gitleaks tests
# allowlist regexes with `MatchString` -- a substring test -- and the default
# `private-key` rule spans from an armor header to the next `KEY-----` at least
# 64 characters later. An entry matching the head of that span excused the whole
# span, so a freshly generated RSA private key committed underneath a fixture
# scanned clean. In five separate paths, `src/__tests__/` and `README.md` and
# plain application source alike.
#
# What holds it shut now is two properties, and this file exists to hold both:
#
#   A. The tracked tree needs no suppression. Armor markers in tests, scripts
#      and documents are assembled at run time or described rather than printed,
#      so the detector never fires on a fixture. Section 3 proves the shipped
#      config and a bare `useDefault` config see the corpus identically -- the
#      allowlist reaches nothing that is live.
#   B. Every allowlist entry is `\A`-anchored and `\z`-terminated, so gitleaks
#      can only skip a finding whose *entire* match is the historical text named.
#      Section 4 shows that anchor is load-bearing by rebuilding the #146 bypass
#      against the pinned scanner and watching it flip.
#
# Section 5 then plants freshly generated key material beside every fixture
# class that survives, including the exact adjacency from the #146 review.
#
# Every assertion runs against a scratch repository built from the working tree,
# so the mutants below are deliberately broken copies of what ships rather than
# hand-written fixtures that could drift away from it.
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

# --- the scanner -------------------------------------------------------------
#
# .mise.toml pins gitleaks to the version gitleaks-action@v3 runs, so this gate
# and the workflows read the configuration the same way. A gate that ran a
# different scanner than CI would be worse than no gate.

# Deliberately not the `exit 0` skip its sibling gates use. Those check that a
# generated file matches its source; this one is the only thing standing between
# the repository and a fail-open secret scanner, and a gate that quietly passes
# when it cannot run is the failure mode it exists to prevent. CI always has the
# scanner -- ci.yml's test job runs jdx/mise-action -- so this only stops a
# contributor who has not run `mise install`, and says so.
if ! command -v gitleaks >/dev/null 2>&1; then
	printf 'gitleaks is not on PATH -- run "mise install" (it is pinned in .mise.toml)\n' >&2
	exit 1
fi

scanner_version="$(gitleaks version 2>/dev/null | tr -d '\r')"
printf 'gitleaks: %s\n' "${scanner_version}"

# One scan. Echoes a finding count, or the literal `error`.
#
# The three outcomes have to stay distinguishable. A config gitleaks refuses to
# load exits 1 -- the same status as "leaks found" -- and a config whose regexes
# do not compile panics with 2. What separates a result from a non-result is the
# report: gitleaks writes `[]` for a clean scan and a JSON array for a dirty one,
# and writes nothing at all when it never got as far as scanning. Folding that
# into `0 findings`, as the first version of this file did, lets a broken config
# read as a clean repository -- the one wrong answer a secret-scanning gate must
# never give.
scan() {
	local root="$1" config="$2" report log rc
	report="$(mktemp -p "${tmp_dir}")"
	log="$(mktemp -p "${tmp_dir}")"
	rm -f "${report}"
	rc=0
	gitleaks detect \
		--source "${root}" \
		--config "${config}" \
		--report-format json \
		--report-path "${report}" \
		--no-banner \
		--log-level error >"${log}" 2>&1 || rc=$?
	if [[ ${rc} -gt 1 || ! -s ${report} || $(head -c 1 "${report}") != "[" ]]; then
		printf '    scanner: %s\n' "$(grep -m1 . "${log}" 2>/dev/null || printf 'no output, exit %s' "${rc}")" >&2
		printf 'error\n'
		return 0
	fi
	# `grep -c` exits 1 on no match and `pipefail` is on, so a clean report would
	# otherwise abort the caller's assignment instead of reporting zero.
	grep -c '"RuleID"' "${report}" || true
}

expect_clean() {
	local label="$1" root="$2" config result
	# `local` expands every word before it assigns any of them, so ${root} cannot
	# be referenced in a default here.
	config="${3:-"${root}/.gitleaks.toml"}"
	new_case "${label}"
	result="$(scan "${root}" "${config}")"
	case "${result}" in
		0) ;;
		error) fail 'the scanner did not run; a clean result here would be a lie' ;;
		*) fail "expected a clean scan, got ${result} finding(s)" ;;
	esac
}

expect_caught() {
	local label="$1" root="$2" config result
	config="${3:-"${root}/.gitleaks.toml"}"
	new_case "${label}"
	result="$(scan "${root}" "${config}")"
	case "${result}" in
		error) fail 'the scanner did not run, so nothing was checked' ;;
		0) fail 'the planted secret was not reported' ;;
		*) ;;
	esac
}

expect_error() {
	local label="$1" root="$2" config="$3" result
	new_case "${label}"
	result="$(scan "${root}" "${config}" 2>/dev/null)"
	[[ ${result} == "error" ]] \
		|| fail "a scan that could not run reported '${result}' instead of an error"
}

# --- scratch repositories ----------------------------------------------------
#
# The corpus is every tracked file as it currently stands on disk -- the working
# tree, not HEAD, so the gate covers the change you are about to commit.
# Committing that into a fresh repository gives a full history to scan in a
# single commit, which means this behaves identically in a shallow CI checkout
# and in a full clone.

corpus_tar="${tmp_dir}/corpus.tar"
git -C "${repo_root}" ls-files -z \
	| tar --create --directory "${repo_root}" --null --files-from - --file "${corpus_tar}"

scratch_root() {
	local root="${tmp_dir}/$1"
	mkdir -p "${root}"
	tar -xf "${corpus_tar}" -C "${root}"
	printf '%s\n' "${root}"
}

commit_scratch() {
	local root="$1"
	git -C "${root}" init -q .
	git -C "${root}" add -A
	git -C "${root}" -c user.email=gate@example.invalid -c user.name=gate \
		-c commit.gpgsign=false commit -qm "corpus"
}

bare_config="${tmp_dir}/bare.toml"
printf 'title = "bare"\n[extend]\nuseDefault = true\n' >"${bare_config}"

# --- probe material ----------------------------------------------------------
#
# Generated per run rather than committed. A gate that ships a realistic secret
# in its own source is a gate that trips the scanner it is testing.

probe_pem="${tmp_dir}/probe.pem"
openssl genrsa -traditional -out "${probe_pem}" 2048 2>/dev/null \
	|| openssl genrsa -out "${probe_pem}" 2048 2>/dev/null
probe_pem_body="$(sed -n '2p' "${probe_pem}")"
probe_b64="$(head -c 48 /dev/urandom | base64 | tr -d '\n')"
probe_aws_id="AKIA$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Z0-9' | head -c 16)"
probe_aws_key="$(head -c 40 /dev/urandom | base64 | head -c 40)"
probe_pat="ghp_$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)"

# This file is itself scanned by the thing it tests, so it must not contain an
# armor line -- a header sitting next to a body, or even next to a footer, is a
# finding, which is the contract working and not something to fix by widening
# the allowlist. Every marker below is assembled at run time, exactly as
# src/__tests__/helpers/armor.ts and scripts/key-size.py now do.

armor() { printf -- '-----%s %s-----' "$1" "$2"; }

pgp_begin="$(armor BEGIN 'PGP PRIVATE KEY BLOCK')"
pgp_end="$(armor END 'PGP PRIVATE KEY BLOCK')"
rsa_begin="$(armor BEGIN 'RSA PRIVATE KEY')"
rsa_end="$(armor END 'RSA PRIVATE KEY')"
backtick="$(printf '\140')"

# =============================================================================
# 1. The version contract, end to end
# =============================================================================
#
# These are textual on purpose. The point is that the configuration stays inside
# the subset of TOML that the *oldest* scanner in play understands, and a TOML
# parser resolved at run time would be one more thing that could disagree.

new_case 'gitleaks is pinned to a fixed version in .mise.toml'
pinned="$(sed -nE 's/^[[:space:]]*gitleaks[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${repo_root}/.mise.toml")"
if [[ -z ${pinned} ]]; then
	fail '.mise.toml does not pin gitleaks'
elif [[ ${pinned} == "latest" || ${pinned} != *.*.* ]]; then
	fail "gitleaks is pinned to '${pinned}'; the scanner version is part of the config contract"
fi

new_case 'the scanner on PATH is the pinned one'
if [[ -n ${pinned} && ${scanner_version} != "${pinned}" ]]; then
	fail "PATH has gitleaks ${scanner_version} but .mise.toml pins ${pinned}"
fi

# The half of the sentence .mise.toml cannot say. `gitleaks-action@v3` is a
# moving tag whose GITLEAKS_VERSION default lives upstream, so without this the
# coupling this whole file rests on could change without a commit here -- and
# every other case would stay green through it.
new_case 'both workflows run the pinned version explicitly'
for wf in .github/workflows/security.yml .github/workflows/gitleaks.yml; do
	path="${repo_root}/${wf}"
	if [[ ! -f ${path} ]]; then
		fail "${wf} is missing"
		continue
	fi
	if ! grep -q 'gitleaks/gitleaks-action@' "${path}"; then
		continue
	fi
	declared="$(sed -nE 's/.*GITLEAKS_VERSION:[[:space:]]*"?([0-9][0-9.]*)"?.*/\1/p' "${path}" | head -n1)"
	if [[ -z ${declared} ]]; then
		fail "${wf} uses gitleaks-action without GITLEAKS_VERSION, so CI runs whatever the action defaults to; add \`GITLEAKS_VERSION: \"${pinned}\"\` to its env"
	elif [[ ${declared} != "${pinned}" ]]; then
		fail "${wf} runs gitleaks ${declared} but .mise.toml pins ${pinned}"
	fi
done

# --all is the coverage the #145 diagnosis depends on: it is what reaches the
# v1.2.0 tag and the branches the #111 rewrite abandoned. gitleaks-action can
# only do that from an unshallow checkout.
new_case 'both workflows check out enough history for the --all scan'
for wf in .github/workflows/security.yml .github/workflows/gitleaks.yml; do
	path="${repo_root}/${wf}"
	[[ -f ${path} ]] || continue
	grep -q 'gitleaks/gitleaks-action@' "${path}" || continue
	grep -q 'fetch-depth: 0' "${path}" \
		|| fail "${wf} does not set fetch-depth: 0, so the scan cannot reach pre-rewrite history"
done

# The property everything else rests on. A literal armor header in a tracked file
# opens a private-key match that runs to the next `KEY-----` at least 64
# characters later, so a real key committed below it in the same file is part of
# that one match rather than a finding of its own -- and once the span grows past
# roughly 35 kB the match is dropped and nothing is reported at all. Measured on
# 8.24.3, that hid a generated RSA key in seven of this repository's files. Every
# marker is therefore assembled at run time (src/utils/armor.ts,
# client/**/armor_test.go, armor() in scripts/key-size.py) or described rather
# than printed (API.md, DEVELOPER_GUIDE.md, docs/github-app.md).
new_case 'no tracked file spells out a private-key armor header'
literal_header="$(printf -- '-{5}BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-{5}')"
offenders="$(git -C "${repo_root}" grep -lE -e "${literal_header}" -- . || true)"
if [[ -n ${offenders} ]]; then
	fail "these files open a private-key match that can swallow a real key below it; build the marker instead (src/utils/armor.ts):
${offenders}"
fi

new_case 'the global allowlist uses the singular [allowlist] table'
if ! grep -qE '^\[allowlist\]$' "${repo_root}/.gitleaks.toml"; then
	fail '.gitleaks.toml has no [allowlist] table -- 8.24.3 honours only that form'
fi

new_case '.gitleaks.toml declares no [[allowlists]] array-of-tables'
if grep -qE '^\[\[allowlists\]\]' "${repo_root}/.gitleaks.toml"; then
	fail 'gitleaks 8.24.3 parses [[allowlists]] and then ignores it entirely'
fi

new_case 'the global allowlist is content-scoped, not path- or SHA-scoped'
for key in paths commits condition; do
	if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${repo_root}/.gitleaks.toml"; then
		fail "global \`${key}\` would suppress by location; 8.24.3 also ignores \`condition\`"
	fi
done

new_case '.gitleaksignore carries no fingerprints at all'
if grep -qvE '^[[:space:]]*(#|$)' "${repo_root}/.gitleaksignore"; then
	fail 'fingerprints are keyed by position and cannot survive a history rewrite (#111)'
fi

# =============================================================================
# 2. The scanner really does ignore [[allowlists]]
# =============================================================================
#
# The claim the version pin exists to serve, measured rather than asserted, on a
# corpus small enough that nothing else can explain the result. If a future
# scanner starts honouring the plural form this goes red, which is the signal to
# revisit everything above.

semantics="${tmp_dir}/semantics"
mkdir -p "${semantics}"
probe_marker="GATEPROBE-$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)"
printf 'value = %s\n' "${probe_marker}" >"${semantics}/probe.txt"
commit_scratch "${semantics}"

# A rule of this file's own making, so the match is exactly the marker and the
# only variable left is which TOML spelling of the allowlist the scanner reads.
{
	printf 'title = "singular"\n\n'
	printf '[[rules]]\nid = "gate-probe"\ndescription = "gate probe"\nregex = \x27\x27\x27%s\x27\x27\x27\n\n' "${probe_marker}"
	printf '[allowlist]\nregexTarget = "match"\nregexes = [\x27\x27\x27\\A%s\\z\x27\x27\x27]\n' "${probe_marker}"
} >"${tmp_dir}/singular.toml"
sed 's/^\[allowlist\]$/[[allowlists]]/' "${tmp_dir}/singular.toml" >"${tmp_dir}/plural.toml"

new_case 'the probe rule fires when nothing excuses it'
{
	printf 'title = "unexcused"\n\n'
	printf '[[rules]]\nid = "gate-probe"\ndescription = "gate probe"\nregex = \x27\x27\x27%s\x27\x27\x27\n' "${probe_marker}"
} >"${tmp_dir}/unexcused.toml"
probe_count="$(scan "${semantics}" "${tmp_dir}/unexcused.toml")"
[[ ${probe_count} != "0" && ${probe_count} != "error" ]] \
	|| fail "the probe rule reported ${probe_count}; the two cases below would prove nothing"

new_case 'a singular [allowlist] is honoured by the pinned scanner'
singular_count="$(scan "${semantics}" "${tmp_dir}/singular.toml")"
[[ ${singular_count} == "0" ]] \
	|| fail "the singular table did not suppress its own fixture (got ${singular_count})"

new_case 'mutant: the same allowance under [[allowlists]] does nothing'
plural_count="$(scan "${semantics}" "${tmp_dir}/plural.toml")"
case "${plural_count}" in
	error) fail 'the scanner refused the plural form outright; re-check its semantics' ;;
	0) fail "gitleaks ${scanner_version} honours [[allowlists]]; the pin and this config were written for a version that does not" ;;
	*) ;;
esac

# =============================================================================
# 3. The allowlist does not reach anything that is live
# =============================================================================
#
# The entries in .gitleaks.toml exist for commits that already happened. If one
# of them ever starts excusing something in the working tree, these two cases
# disagree and the build stops -- which is the check that would have caught #146
# on the day it was written.

baseline="$(scratch_root baseline)"
commit_scratch "${baseline}"

expect_clean 'the tracked tree scans clean' "${baseline}"
expect_clean 'the tracked tree scans clean with no allowlist at all' "${baseline}" "${bare_config}"

new_case 'the allowlist suppresses nothing in the tracked tree'
shipped_count="$(scan "${baseline}" "${baseline}/.gitleaks.toml")"
bare_count="$(scan "${baseline}" "${bare_config}")"
if [[ ${shipped_count} == "error" || ${bare_count} == "error" ]]; then
	fail 'one of the two scans did not run, so they cannot be compared'
elif [[ ${shipped_count} != "${bare_count}" ]]; then
	fail "the allowlist changes the result on live files (${bare_count} without it, ${shipped_count} with); fix the fixture's representation instead of excusing it"
fi

new_case 'every allowlist regex is anchored to a whole match'
awk '/^regexes/,/^\]/' "${repo_root}/.gitleaks.toml" \
	| grep -oE "^  '''.*'''," \
	| while IFS= read -r line; do
		case "${line}" in
			"  '''\\A"*"\\z''',") ;;
			*) printf '%s\n' "${line:0:80}" ;;
		esac
	done >"${tmp_dir}/unanchored"
if [[ -s ${tmp_dir}/unanchored ]]; then
	fail "$(wc -l <"${tmp_dir}/unanchored" | tr -d ' ') allowlist entr(y|ies) are not \\A...\\z anchored, so each can excuse a longer match it happens to sit inside (#146):
$(cat "${tmp_dir}/unanchored")"
fi

new_case 'the allowlist is not empty, so the anchor check has something to check'
grep -qE "^  '''.*'''," "${repo_root}/.gitleaks.toml" \
	|| fail 'no allowlist entries found; either the format changed or the anchor case above is vacuous'

# =============================================================================
# 4. The anchor is load-bearing
# =============================================================================
#
# The #146 bypass, rebuilt from scratch against the pinned scanner so the
# mechanism is on the record rather than in a commit message: an armor header in
# a fixture and a real key below it are ONE private-key match, and an unanchored
# allowlist entry matching the head of that span excuses all of it.

bypass="${tmp_dir}/bypass"
mkdir -p "${bypass}/src/__tests__"
{
	printf 'const header = "%s\\n";\n' "${pgp_begin}"
	printf 'const deployKey = %s' "${backtick}"
	cat "${probe_pem}"
	printf '%s;\n' "${backtick}"
} >"${bypass}/src/__tests__/fixture.test.ts"
commit_scratch "${bypass}"

printf 'title = "unanchored"\n[extend]\nuseDefault = true\n[allowlist]\nregexTarget = "match"\nregexes = [\x27%s\x27]\n' \
	"$(printf -- '-{5}BEGIN PGP PRIVATE KEY BLOCK-{5}')" >"${tmp_dir}/unanchored.toml"
sed "s|regexes = \['|regexes = ['\\\\A|; s|'\]|\\\\z']|" "${tmp_dir}/unanchored.toml" >"${tmp_dir}/anchored.toml"

new_case 'mutant: an unanchored head-of-span entry hides a real key (the #146 bypass)'
unanchored_count="$(scan "${bypass}" "${tmp_dir}/unanchored.toml")"
[[ ${unanchored_count} == "0" ]] \
	|| fail "expected the unanchored entry to swallow the key (got ${unanchored_count}); if the scanner stopped matching allowlist regexes as substrings, the anchoring rule can be revisited"

expect_caught 'the same entry, anchored, reports the key' "${bypass}" "${tmp_dir}/anchored.toml"

# =============================================================================
# 5. The scanner's own failures are not clean results
# =============================================================================

expect_error 'a config that will not parse is an error, not a clean scan' \
	"${baseline}" "$(printf 'not toml [[[\n' >"${tmp_dir}/broken.toml" && printf '%s' "${tmp_dir}/broken.toml")"

expect_error 'a config that does not exist is an error, not a clean scan' \
	"${baseline}" "${tmp_dir}/absent.toml"

# =============================================================================
# 6. Planted secrets are still reported
# =============================================================================
#
# Each of these lands somewhere the pre-#145 configuration allowlisted wholesale
# -- src/__tests__/*.test.ts, scripts/, README.md -- or beside one of the fixture
# classes that survives in the tree. A blanket path exclusion passes the first
# group; the #146 allowlist passed the second.

plant() {
	local label="$1" rel="$2" payload="$3" root
	root="$(scratch_root "plant-$(printf '%s' "${label}" | tr -c 'a-zA-Z0-9' '-')")"
	mkdir -p "$(dirname "${root}/${rel}")"
	printf '%s\n' "${payload}" >>"${root}/${rel}"
	commit_scratch "${root}"
	expect_caught "planted: ${label}" "${root}"
}

# -- by location --------------------------------------------------------------

plant 'RSA private key in a test file' 'src/__tests__/planted.test.ts' \
	"const key = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'RSA private key in application source' 'src/planted.ts' \
	"export const key = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'RSA private key in scripts/' 'scripts/planted.sh' \
	"KEY=\"$(cat "${probe_pem}")\""

plant 'RSA private key in README.md' 'README.md' \
	"$(cat "${probe_pem}")"

plant 'RSA private key in a path no allowlist ever named' 'docs/planted.md' \
	"$(cat "${probe_pem}")"

plant 'AWS credentials in a test file' 'src/__tests__/planted.test.ts' \
	"const id = \"${probe_aws_id}\"; const secret = \"${probe_aws_key}\";"

plant 'a GitHub token in a test file' 'src/__tests__/planted.test.ts' \
	"const token = \"${probe_pat}\";"

# -- adjacency: a real key next to each fixture class that survives -------------
#
# This is the group #146 got wrong. The payload has to sit *against* a fixture,
# because that is what puts it inside a match the fixture's allowance describes.

plant 'a real key below an allowlisted armor-header fixture (the #146 review case)' \
	'src/__tests__/planted.test.ts' \
	"$(printf 'const header = "%s\\n";\nconst k = %s%s%s;' \
		"${pgp_begin}" "${backtick}" "$(cat "${probe_pem}")" "${backtick}")"

plant 'a real key appended to the runtime-armor helper itself' \
	'src/__tests__/helpers/armor.ts' \
	"export const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside a suite that builds its markers at run time' \
	'src/__tests__/schemas.test.ts' \
	"const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside the committed Ed25519 fixture body' \
	'src/__tests__/branded.test.ts' \
	"const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside the synthetic scrubber fixtures' \
	'src/__tests__/sentry.test.ts' \
	"const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside the armor() helper in scripts/key-size.py' \
	'scripts/key-size.py' \
	"planted = ${backtick}${backtick}${backtick}$(cat "${probe_pem}")${backtick}${backtick}${backtick}"

plant 'a real key beside the documented upload example' 'API.md' \
	"$(cat "${probe_pem}")"

plant 'a real key beside the armor syntax the GitHub App doc describes' \
	'docs/github-app.md' \
	"$(cat "${probe_pem}")"

plant 'a real key beside the production armor constants' 'src/utils/armor.ts' \
	"export const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside the schema that validates armor' 'src/schemas/keys.ts' \
	"export const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside the armor dispatch in key-expiry' 'src/utils/key-expiry.ts' \
	"export const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside the X.509 armor check' 'src/utils/x509.ts' \
	"export const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key beside a suite that builds PKCS#8 markers' \
	'src/__tests__/push-signing.test.ts' \
	"const planted = ${backtick}$(cat "${probe_pem}")${backtick};"

plant 'a real key in the Go client tests' 'client/pkg/client/methods_test.go' \
	"$(sed 's|^|// |' "${probe_pem}")"

plant 'a real key beside the Go armor helper' 'client/pkg/client/armor_test.go' \
	"$(sed 's|^|// |' "${probe_pem}")"

plant 'a real key beside the Go CLI armor helper' 'client/cmd/gpg-sign/armor_test.go' \
	"$(sed 's|^|// |' "${probe_pem}")"

plant 'a real bearer token beside the documented placeholder' 'README.md' \
	"curl -H \"Authorization: Bearer ${probe_pat}\" https://example.invalid/admin/keys"

plant 'a real bearer token beside the generate-key.sh instructions' 'scripts/generate-key.sh' \
	"# curl -H \"Authorization: Bearer ${probe_pat}\" https://example.invalid/admin/keys"

# -- mimicry ------------------------------------------------------------------
#
# Each of these copies the *shape* of something the historical allowlist excuses
# and swaps in real key material, which is how a content allowance fails if it
# was written one notch too loose.

plant 'key material behind the armor-header-as-string-literal shape' \
	'src/__tests__/planted.test.ts' \
	"$(printf 'const k = ["%s", "%s", "%s"];' "${rsa_begin}" "${probe_pem_body}" "${rsa_end}")"

plant 'key material behind the placeholder-body shape' \
	'src/__tests__/planted.test.ts' \
	"$(printf 'const k = "%s\\n%s\\n%s";' "${pgp_begin}" "${probe_b64}" "${pgp_end}")"

plant 'a PGP key that is not the historical Ed25519 fixture' \
	'src/__tests__/planted.test.ts' \
	"$(printf 'const k = %s%s\n\n%s%s\n=abcd\n%s%s;' \
		"${backtick}" "${pgp_begin}" "${probe_b64}" "${probe_b64}" "${pgp_end}" "${backtick}")"

# -- the one file that cannot be planted in -----------------------------------
#
# gitleaks' *own* default allowlist excludes every path ending in
# `gitleaks.toml`, so nothing committed to this repository's config is ever
# scanned -- not by this gate, and not by CI. Measured rather than assumed,
# because it is the reason the structural case above deliberately includes
# `.gitleaks.toml` in its sweep: that grep is the only thing standing between
# the config and a marker parked where the scanner will not look.

unscannable="${tmp_dir}/unscannable"
mkdir -p "${unscannable}"
cp "${probe_pem}" "${unscannable}/.gitleaks.toml"
cp "${probe_pem}" "${unscannable}/plain.txt"
commit_scratch "${unscannable}"

new_case 'the same key is reported outside the config and ignored inside it'
unscannable_count="$(scan "${unscannable}" "${bare_config}")"
case "${unscannable_count}" in
	1) ;;
	error) fail 'the scanner did not run' ;;
	0) fail 'neither copy was reported; the probe is not a detectable key' ;;
	*) fail "gitleaks reported ${unscannable_count} findings, so it no longer skips *gitleaks.toml; the config could carry a secret and this gate should start planting in it" ;;
esac

# =============================================================================

if [[ ${failures} -gt 0 ]]; then
	printf '\n%d case(s) failed\n' "${failures}" >&2
	exit 1
fi

printf '\ngitleaks contract holds (scanner %s)\n' "${scanner_version}"
