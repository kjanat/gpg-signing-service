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
#   C. A plant counts as caught only when the planted material is *inside* a
#      reported finding. The same span that made A necessary cuts the other way
#      too: put a literal header more than 64 characters above a key and the
#      match ends on the key's own BEGIN line, so gitleaks reports one finding
#      and the key is in none of them. `count > 0` calls that caught, which is
#      why every assertion here names a needle and reads the report for it.
#
# Section 6 then plants freshly generated key material beside every fixture
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
#
# A third argument names the report, so a caller can read *what* was found and
# not merely how much. `scan` is always called from a command substitution, so
# it cannot hand the path back in a variable -- the subshell's assignment dies
# with it -- but the file it writes outlives the subshell perfectly well.
scan() {
	local root="$1" config="$2" report="${3:-}" log rc
	[[ -n ${report} ]] || report="$(mktemp -p "${tmp_dir}")"
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

# Is this needle inside a reported finding?
#
# A finding is not the same as *this* finding, and the difference is the whole
# reason this file exists. `private-key` runs from an armor header to the next
# `KEY-----` at least 64 characters later, so a literal header sitting more than
# 64 characters *above* a planted key ends its span on the key's own BEGIN line:
# gitleaks reports one finding, the key body is inside none of them, and a
# `count > 0` assertion calls that caught. Section 4 measures exactly that, and
# the case after it runs this assertion against the result and requires it to
# say no.
#
# gitleaks writes one `"Match"` and one `"Secret"` per finding, each on its own
# line with the newlines escaped, so a fixed-string search over those two fields
# asks the right question and cannot be answered by a file path or a rule id.
# Read into a variable first: `grep ... | grep -q` exits the reader on its first
# match, which SIGPIPEs the writer, which `pipefail` then reports as a failure.
reported_in() {
	local fields
	fields="$(grep -E '^[[:space:]]*"(Match|Secret)":' "$1" || true)"
	grep -qF -- "$2" <<<"${fields}"
}

report_seq=0

expect_caught() {
	local label="$1" root="$2" needle="$3" config result report
	config="${4:-"${root}/.gitleaks.toml"}"
	new_case "${label}"
	report_seq=$((report_seq + 1))
	report="${tmp_dir}/caught-${report_seq}.json"
	result="$(scan "${root}" "${config}" "${report}")"
	case "${result}" in
		error) fail 'the scanner did not run, so nothing was checked' ;;
		0) fail 'the planted secret was not reported' ;;
		*)
			reported_in "${report}" "${needle}" \
				|| fail "${result} finding(s) were reported and the planted secret is in none of them; the scanner saw something adjacent, not the secret"
			;;
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

# `head -c N /dev/urandom | base64 | tr -dc CLASS | head -c N` asks for N
# characters and returns however many happen to survive the filter, which is
# always fewer and sometimes far fewer: over 300 runs the AWS id reached its full
# 16-character suffix 19 times. `aws-access-token` matches `AKIA` plus exactly
# 16, so in the other 94% it could not fire at all and the case named for it
# passed on `generic-api-key` picking up the assignment beside it instead -- a
# green case measuring a different rule.
#
# Draw until the requested length exists. `head` is upstream of `tr` here, so
# neither end of the pipe is closed early and `pipefail` has no SIGPIPE to trip
# on; 256 bytes yields ~36 characters of `A-Z0-9`, so this almost never loops.
rand_alnum() {
	local n="$1" class="$2" out=""
	while [[ ${#out} -lt ${n} ]]; do
		out+="$(LC_ALL=C head -c 256 /dev/urandom | LC_ALL=C tr -dc "${class}" || true)"
	done
	printf '%s' "${out:0:n}"
}

probe_pem="${tmp_dir}/probe.pem"
openssl genrsa -traditional -out "${probe_pem}" 2048 2>/dev/null \
	|| openssl genrsa -out "${probe_pem}" 2048 2>/dev/null
probe_pem_body="$(sed -n '2p' "${probe_pem}")"
probe_b64="$(head -c 48 /dev/urandom | base64 | tr -d '\n')"
probe_aws_id="AKIA$(rand_alnum 16 'A-Z0-9')"
probe_aws_key="$(head -c 40 /dev/urandom | base64 | head -c 40)"
probe_pat="ghp_$(rand_alnum 36 'A-Za-z0-9')"

# -- and the probes have to trip the rules they are named for -----------------
#
# A probe one character short of its rule is not a weaker test, it is a test of
# something else. These two are length-exact rules, so the shape is checkable
# without a scan; the case below then confirms the id really does reach
# `aws-access-token` and not some neighbouring generic match.

new_case 'the generated AWS id has the exact shape aws-access-token requires'
[[ ${probe_aws_id} =~ ^AKIA[A-Z0-9]{16}$ ]] \
	|| fail "the AWS probe generated ${#probe_aws_id} characters ('${probe_aws_id}'); the rule needs AKIA plus exactly 16"

new_case 'the generated GitHub token has the exact shape its rule requires'
[[ ${probe_pat} =~ ^ghp_[A-Za-z0-9]{36}$ ]] \
	|| fail "the PAT probe generated ${#probe_pat} characters; the rule needs ghp_ plus exactly 36"

aws_only="${tmp_dir}/aws-only"
mkdir -p "${aws_only}"
printf '%s\n' "${probe_aws_id}" >"${aws_only}/id.txt"
commit_scratch "${aws_only}"

new_case 'the generated AWS id trips aws-access-token on its own'
aws_report="${tmp_dir}/aws.json"
aws_count="$(scan "${aws_only}" "${bare_config}" "${aws_report}")"
if [[ ${aws_count} == "error" ]]; then
	fail 'the scanner did not run'
elif [[ ${aws_count} == "0" ]]; then
	fail "aws-access-token did not fire on '${probe_aws_id}' with nothing else on the line, so the plant that names it is exercising some other rule"
elif ! grep -q '"RuleID": "aws-access-token"' "${aws_report}"; then
	fail "the id was reported as $(sed -nE 's/.*"RuleID": "([^"]*)".*/\1/p' "${aws_report}" | head -n1) rather than aws-access-token"
elif ! reported_in "${aws_report}" "${probe_aws_id}"; then
	fail 'aws-access-token fired, but the id itself is in no finding'
fi

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
# `-i`, because the rule carries `(?i)`. The same marker in lower case opens the
# very same swallowing span, and a case-sensitive sweep walks straight past it --
# a structural check named for the detector has to match the case the detector
# matches. The corpus has no lower-case header to notice that with, so the two
# cases below build one at run time and measure both halves. (Spelling one out
# here, even in a comment, is what this very case exists to forbid: the first
# draft of this comment made the tracked tree dirty and three cases went red.)
offenders="$(git -C "${repo_root}" grep -lEi -e "${literal_header}" -- . || true)"
if [[ -n ${offenders} ]]; then
	fail "these files open a private-key match that can swallow a real key below it; build the marker instead (src/utils/armor.ts):
${offenders}"
fi

lowercase="${tmp_dir}/lowercase-header"
mkdir -p "${lowercase}"
{
	armor BEGIN 'RSA PRIVATE KEY' | LC_ALL=C tr '[:upper:]' '[:lower:]'
	printf '\n%s\n' "${probe_pem_body}"
	armor END 'RSA PRIVATE KEY' | LC_ALL=C tr '[:upper:]' '[:lower:]'
	printf '\n'
} >"${lowercase}/k.txt"
commit_scratch "${lowercase}"

expect_caught 'a lowercase armor header is a private-key finding all the same' \
	"${lowercase}" "${probe_pem_body}" "${bare_config}"

new_case 'mutant: the sweep pattern without -i walks past that same header'
if grep -qE -e "${literal_header}" "${lowercase}/k.txt"; then
	fail 'the pattern matched a lowercase header case-sensitively, so -i is not what is doing the work here and this case proves nothing'
fi
if ! grep -qEi -e "${literal_header}" "${lowercase}/k.txt"; then
	fail 'the sweep pattern does not match a lowercase header even with -i, so the tracked-file sweep above cannot see one'
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
probe_marker="GATEPROBE-$(rand_alnum 12 'A-Za-z0-9')"
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

# Every line inside the array that carries a `'''` delimiter has to be a
# complete, anchored entry on its own. Selecting the recognisable shape and
# ignoring the rest -- which is what `grep -oE "^  '''.*''',"` did -- makes the
# check opt-in by formatting: an entry indented four spaces, or a multi-line
# `'''` literal, was simply not looked at. Both are TOML the parser accepts and
# `dprint check` passes a multi-line one, so an unanchored head-of-span entry
# could ship with this case green. Anything that is not exactly one anchored
# entry per line is reported rather than skipped.
new_case 'every allowlist regex is anchored to a whole match'
awk '/^regexes/,/^\]/' "${repo_root}/.gitleaks.toml" \
	| grep -F "'''" \
	| while IFS= read -r line; do
		# `grep -o` prints one match per line, so this counts delimiters rather
		# than delimiter-carrying lines: exactly two, or a second entry is riding
		# along behind the anchored one this pattern matched.
		delims="$(printf '%s' "${line}" | grep -oF "'''" | grep -c . || true)"
		case "${line}" in
			*"'''\\A"*"\\z''',") [[ ${delims} == 2 ]] || printf '%s\n' "${line:0:80}" ;;
			*) printf '%s\n' "${line:0:80}" ;;
		esac
	done >"${tmp_dir}/unanchored"
if [[ -s ${tmp_dir}/unanchored ]]; then
	fail "$(wc -l <"${tmp_dir}/unanchored" | tr -d ' ') allowlist entr(y|ies) are not \\A...\\z anchored, so each can excuse a longer match it happens to sit inside (#146):
$(cat "${tmp_dir}/unanchored")"
fi

new_case 'the allowlist is not empty, so the anchor check has something to check'
grep -qE "^[[:space:]]*'''.*'''," "${repo_root}/.gitleaks.toml" \
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

expect_caught 'the same entry, anchored, reports the key' \
	"${bypass}" "${probe_pem_body}" "${tmp_dir}/anchored.toml"

# --- the other half of the span, which no allowlist reaches -------------------
#
# Above, the header and the key are adjacent, so the span has to run *through*
# the key to find its next `KEY-----` and the key is inside the match. Push them
# apart -- one comment line is enough, the minimum span is 64 characters -- and
# the span stops at the planted key's own BEGIN instead. gitleaks still reports
# exactly one finding, and the key body is inside none of them.
#
# No configuration is in play here: this is the bare `useDefault` config, so it
# is a property of the rule rather than of anything this repository writes. It
# is why `expect_caught` takes a needle, and it is a second, independent reason
# why no tracked file may spell an armor header out -- the allowlist could be
# perfect and this would still hide a key.

separated="${tmp_dir}/separated"
mkdir -p "${separated}/src/__tests__"
{
	printf 'const header = "%s\\n";\n' "${pgp_begin}"
	printf '// a comment line long enough to put more than 64 characters between the two\n'
	printf 'const deployKey = %s' "${backtick}"
	cat "${probe_pem}"
	printf '%s;\n' "${backtick}"
} >"${separated}/src/__tests__/fixture.test.ts"
commit_scratch "${separated}"

new_case 'mutant: a literal header far above a key reports a finding that is not the key'
separated_report="${tmp_dir}/separated.json"
separated_count="$(scan "${separated}" "${bare_config}" "${separated_report}")"
if [[ ${separated_count} == "error" ]]; then
	fail 'the scanner did not run'
elif [[ ${separated_count} == "0" ]]; then
	fail 'nothing at all was reported; the span mechanics have changed and section 4 needs re-measuring'
elif reported_in "${separated_report}" "${probe_pem_body}"; then
	fail "gitleaks ${scanner_version} now reports the key itself across a gap; the needle check is no longer load-bearing here and this case should be revisited"
fi

# The regression for the assertion rather than for the config. That corpus is
# precisely the shape a count-only `expect_caught` called caught -- one finding,
# no key -- so run the real assertion against it and require it to say no. If it
# ever stops saying no, the needle check has decayed back into a count and every
# plant in section 6 is decorative. The probe's own failure is expected, so it
# is discounted rather than counted.
guard_failures="${failures}"
expect_caught '(probe: a finding that is not the planted key -- expected to fail)' \
	"${separated}" "${probe_pem_body}" "${bare_config}" 2>/dev/null
guard_rejected=$((failures > guard_failures ? 1 : 0))
failures="${guard_failures}"

new_case 'expect_caught rejects a finding that does not contain the planted secret'
[[ ${guard_rejected} == 1 ]] \
	|| fail 'a finding with none of the planted secret in it was accepted as a catch; expect_caught is counting again (#146 review)'

# ...and the same file with the marker assembled instead of spelled out, which
# is what the tree actually does. No literal header, so no span for the key to
# hide inside: the key is its own finding and is reported as itself.
built="${tmp_dir}/built"
mkdir -p "${built}/src/__tests__"
{
	printf 'const header = armorMarker("BEGIN", "PGP PRIVATE KEY BLOCK");\n'
	printf '// a comment line long enough to put more than 64 characters between the two\n'
	printf 'const deployKey = %s' "${backtick}"
	cat "${probe_pem}"
	printf '%s;\n' "${backtick}"
} >"${built}/src/__tests__/fixture.test.ts"
commit_scratch "${built}"

expect_caught 'the same file with the marker built at run time reports the key itself' \
	"${built}" "${probe_pem_body}" "${bare_config}"

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

# The fourth argument is the needle: the piece of the planted material that has
# to turn up inside a finding. It defaults to the key body because most of these
# plant a PEM, but a plant whose payload is a token has to name that token --
# otherwise `generic-api-key` matching the assignment next to it answers for the
# rule the case is named after.
plant() {
	local label="$1" rel="$2" payload="$3" needle="${4:-${probe_pem_body}}" root
	root="$(scratch_root "plant-$(printf '%s' "${label}" | tr -c 'a-zA-Z0-9' '-')")"
	mkdir -p "$(dirname "${root}/${rel}")"
	printf '%s\n' "${payload}" >>"${root}/${rel}"
	commit_scratch "${root}"
	expect_caught "planted: ${label}" "${root}" "${needle}"
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
	"const id = \"${probe_aws_id}\"; const secret = \"${probe_aws_key}\";" \
	"${probe_aws_id}"

plant 'a GitHub token in a test file' 'src/__tests__/planted.test.ts' \
	"const token = \"${probe_pat}\";" \
	"${probe_pat}"

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
	"curl -H \"Authorization: Bearer ${probe_pat}\" https://example.invalid/admin/keys" \
	"${probe_pat}"

plant 'a real bearer token beside the generate-key.sh instructions' 'scripts/generate-key.sh' \
	"# curl -H \"Authorization: Bearer ${probe_pat}\" https://example.invalid/admin/keys" \
	"${probe_pat}"

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
	"$(printf 'const k = "%s\\n%s\\n%s";' "${pgp_begin}" "${probe_b64}" "${pgp_end}")" \
	"${probe_b64}"

plant 'a PGP key that is not the historical Ed25519 fixture' \
	'src/__tests__/planted.test.ts' \
	"$(printf 'const k = %s%s\n\n%s%s\n=abcd\n%s%s;' \
		"${backtick}" "${pgp_begin}" "${probe_b64}" "${probe_b64}" "${pgp_end}" "${backtick}")" \
	"${probe_b64}"

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
# 7. The allowlist describes its findings without spelling them out
# =============================================================================
#
# An exact-match entry cannot stop naming what it matches; that is what exact
# means. It can stop naming it as base64. Every long literal run in this config
# is written one `\xNN` per character, which parses to the same RE2 literal and
# leaves no run behind for the rest of the tooling to pick up.
#
# What this section owns is that the two spellings are the same expression --
# proved against the scanner, on a key generated during this run, using the real
# span gitleaks reports for it. What it does not own is whether the config is
# carrying key material: `scripts/key-material.py` undoes these escapes and
# decodes them, and `scripts/test-key-material.sh` is where the config is read
# like any other tracked file and where a fresh key in a well-formed entry is
# planted to prove the escaping is not a way in.
#
# That matters here more than anywhere else in the tree: gitleaks' own default
# allowlist drops every path ending `gitleaks.toml`, measured at the end of
# section 6. The config is the one file the scanner will not look at, so it is
# the one file that must not be carrying anything worth looking for.
#
# The equivalence is proved against the scanner rather than asserted, on a key
# generated during this run, using the real span gitleaks reports for it.

quote="$(printf "'''")"
allowlist_regex="${repo_root}/scripts/allowlist-regex.py"

new_case 'no allowlist entry spells out a long literal run'
if ! python3 "${allowlist_regex}" --check "${repo_root}/.gitleaks.toml" >"${tmp_dir}/runs" 2>&1; then
	fail "$(head -n1 "${tmp_dir}/runs")"
fi

# A `+` in the probe would be read as a quantifier rather than as a literal --
# which is correct, and would split one 64-character run into several short ones.
# The probe is drawn from the alphanumeric half of the alphabet so that what it
# measures is the threshold and not the draw.
new_case 'mutant: the run check reports an entry that does spell one out'
printf 'title = "spelled"\n[allowlist]\nregexTarget = "match"\nregexes = [\n  %s\\A%s\\z%s,\n]\n' \
	"${quote}" "$(rand_alnum 64 'A-Za-z0-9')" "${quote}" >"${tmp_dir}/spelled.toml"
if python3 "${allowlist_regex}" --check "${tmp_dir}/spelled.toml" >/dev/null 2>&1; then
	fail 'a 64-character base64 literal in an entry was not reported, so the check above passes vacuously'
fi

new_case 'mutant: an entry the run check cannot read is an error, not a pass'
printf 'title = "multiline"\n[allowlist]\nregexes = [\n  %s\\Aone\n  two\\z%s,\n]\n' \
	"${quote}" "${quote}" >"${tmp_dir}/multiline.toml"
if python3 "${allowlist_regex}" --check "${tmp_dir}/multiline.toml" >/dev/null 2>&1; then
	fail 'an entry split across lines was skipped silently, so an unreadable allowlist reads as a clean one'
fi

# --- the two forms, against the scanner --------------------------------------
#
# A real finding first: plant the probe key, scan with no allowlist, and take the
# span gitleaks reports. Describing a span invented here rather than one the
# scanner produced would test the entry against the wrong string.

equiv="$(scratch_root 'equivalence')"
mkdir -p "${equiv}/src/__tests__"
printf 'const key = %s%s%s;\n' "${backtick}" "$(cat "${probe_pem}")" "${backtick}" \
	>"${equiv}/src/__tests__/equivalence.test.ts"
commit_scratch "${equiv}"

equiv_report="${tmp_dir}/equivalence.json"
equiv_count="$(scan "${equiv}" "${bare_config}" "${equiv_report}")"

new_case 'the equivalence probe produces exactly one finding to describe'
if [[ ${equiv_count} != "1" ]]; then
	fail "expected one finding to build an entry from, got ${equiv_count}"
fi

# `Match` is JSON, so the span comes back through a JSON reader rather than a
# regex over the report: it carries newlines and quotes, and one of the two
# things being compared is precisely how such characters are escaped.
span="${tmp_dir}/span"
python3 -c 'import json,sys; sys.stdout.write(json.load(open(sys.argv[1]))[0]["Match"])' \
	"${equiv_report}" >"${span}" 2>/dev/null || printf '' >"${span}"

# Built from the span independently of each other, so that a byte form which has
# quietly stopped being exact -- a wildcard where a byte should be -- shows up as
# a difference rather than as two matching halves of the same mistake.
plain_entry="$(python3 "${allowlist_regex}" --plain <"${span}")"
bytes_entry="$(python3 "${allowlist_regex}" --literal <"${span}")"

new_case 'the byte form decodes back to the plain form exactly'
if [[ -z ${plain_entry} || -z ${bytes_entry} ]]; then
	fail 'no entry could be built from the reported span'
elif [[ ${plain_entry} == "${bytes_entry}" ]]; then
	fail 'the byte form is identical to the plain form, so this section is comparing an entry with itself'
elif [[ "$(printf '%s' "${bytes_entry}" | python3 "${allowlist_regex}" --decode)" != "${plain_entry}" ]]; then
	fail 'the byte form does not decode back to the entry it replaced, so it is a different expression and not a different spelling of one'
fi

# One config per form. `\` is not special in a TOML multi-line literal string, so
# both go in exactly as written.
entry_config() {
	printf 'title = "equivalence"\n[extend]\nuseDefault = true\n[allowlist]\nregexTarget = "match"\nregexes = [\n  %s%s%s,\n]\n' \
		"${quote}" "$1" "${quote}" >"$2"
}
plain_config="${tmp_dir}/entry-plain.toml"
bytes_config="${tmp_dir}/entry-bytes.toml"
entry_config "${plain_entry}" "${plain_config}"
entry_config "${bytes_entry}" "${bytes_config}"

# Asked of the two configs with the same check the shipped config answers, rather
# than by grepping for a slice of the key: a run in an entry is broken up by the
# escaping an entry needs -- `\+` for every plus -- so a substring of the key is
# not reliably a substring of the entry that matches it, and a case built on one
# passes or fails on where the pluses landed.
# What makes a prefix or a suffix extension unmatchable, given that gitleaks
# tests an entry against a finding with a substring match. Section 3 asserts this
# of every entry in the shipped config; asserted here of both generated forms,
# because an encoding that dropped an anchor would be a different language in the
# one direction the counting cases below cannot reach.
new_case 'both forms are anchored at both ends'
for form in "${plain_entry}" "${bytes_entry}"; do
	if [[ ${form} != '\A'* || ${form} != *'\z' ]]; then
		fail "an entry is not \\A...\\z anchored, so it is matched as a substring and excuses every longer span it sits inside"
	fi
done

new_case 'only the plain form spells the key out'
if python3 "${allowlist_regex}" --check "${plain_config}" >/dev/null 2>&1; then
	fail 'the plain form contains no long literal run, so the comparison below is not about key material'
elif ! python3 "${allowlist_regex}" --check "${bytes_config}" >/dev/null 2>&1; then
	fail 'the byte form still spells a long run out'
fi

# `compare <label> <root> <want>` -- the two forms must agree, and the caller says
# what they must agree on. `reported` is measured against the count with no
# allowlist at all rather than against zero: an entry that suppresses one of two
# findings has still reached something it was not written for, and "some findings
# remain" would call that a pass.
compare() {
	local label="$1" root="$2" want="$3" bare plain bytes
	bare="$(scan "${root}" "${bare_config}")"
	plain="$(scan "${root}" "${plain_config}")"
	bytes="$(scan "${root}" "${bytes_config}")"
	new_case "${label}"
	if [[ ${bare} == "error" || ${plain} == "error" || ${bytes} == "error" ]]; then
		fail 'the scanner did not run'
	elif [[ ${bare} == "0" ]]; then
		fail 'nothing is reported here without an allowlist either, so this case cannot tell an exact entry from a loose one'
	elif [[ ${plain} != "${bytes}" ]]; then
		fail "the two forms disagree: plain left ${plain} finding(s), bytes left ${bytes} -- they are not the same language"
	elif [[ ${want} == "suppressed" && ${plain} != "0" ]]; then
		fail "both forms left ${plain} of ${bare} finding(s); the entry does not describe the span the scanner reported"
	elif [[ ${want} == "reported" && ${plain} != "${bare}" ]]; then
		fail "both forms suppressed $((bare - plain)) of ${bare} finding(s) here; the entry reaches something it was not written for"
	fi
}

compare 'both forms suppress the finding they describe' "${equiv}" suppressed

# --- and neither reaches anything else ---------------------------------------
#
# The four ways an entry gets too wide. Each rebuilds the file so gitleaks
# reports a *different* span; an entry that still suppresses it was never exact.

variant() {
	local name="$1" body="$2" root
	root="$(scratch_root "equivalence-${name}")"
	mkdir -p "${root}/src/__tests__"
	printf '%s\n' "${body}" >"${root}/src/__tests__/equivalence.test.ts"
	commit_scratch "${root}"
	printf '%s\n' "${root}"
}

# A variant that did not move the span is not a variant. gitleaks starts a
# private-key match at the armor header and ends it at the footer, so text placed
# outside those two lines changes the file and not the finding -- and an entry
# that still suppresses it has been proved nothing about. Each `reported` case
# below therefore says first that the span it is about really did change.
span_of() {
	local root="$1" report
	report="$(mktemp -p "${tmp_dir}")"
	scan "${root}" "${bare_config}" "${report}" >/dev/null
	python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1]))[0]["Match"], end="")
except Exception:
    pass' "${report}"
}
original_span="$(cat "${span}")"

moved() {
	local label="$1" root="$2"
	new_case "${label}"
	if [[ "$(span_of "${root}")" == "${original_span}" ]]; then
		fail 'the reported span is unchanged, so the case that follows it cannot distinguish an exact entry from a loose one'
	fi
}

# A single byte of the key body changed, everything else identical.
mutated_pem="${tmp_dir}/mutated.pem"
python3 - "${probe_pem}" "${mutated_pem}" <<'MUTATE'
import sys

lines = open(sys.argv[1]).read().split("\n")
body = 1 + (len(lines) - 3) // 2  # a line in the middle of the key, not a marker
line = lines[body]
if not line:
    raise SystemExit("the probe key has no body line to change")
lines[body] = ("B" if line[0] == "A" else "A") + line[1:]
open(sys.argv[2], "w").write("\n".join(lines))
MUTATE

mutation_root="$(variant 'mutation' "$(printf 'const key = %s%s%s;' "${backtick}" "$(cat "${mutated_pem}")" "${backtick}")")"
moved 'a one-byte mutation moves the span' "${mutation_root}"
compare 'neither form suppresses a one-byte mutation' "${mutation_root}" reported

# The described text as a strict prefix of a longer span: an extra body line
# before the footer. This is the shape #146 turned on -- an entry matched as a
# substring excuses every span it sits inside, and `\A...\z` is what stops it.
extended_pem="${tmp_dir}/extended.pem"
python3 - "${probe_pem}" "${extended_pem}" <<'EXTEND'
import sys

lines = open(sys.argv[1]).read().rstrip("\n").split("\n")
lines.insert(len(lines) - 1, lines[1])  # one more body line, before the footer
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
EXTEND

extended_root="$(variant 'extension' "$(printf 'const key = %s%s%s;' "${backtick}" "$(cat "${extended_pem}")" "${backtick}")")"
moved 'an extra body line moves the span' "${extended_root}"
compare 'neither form suppresses a span that strictly contains the described one' \
	"${extended_root}" reported

# The described span with a whole second key against it: the #146 review case.
# Counting findings is the wrong question here -- the entry does describe the
# first key, so suppressing that one is correct -- and #146 failed on the right
# one, which is whether the *planted* key still turns up in a finding. Both
# configs are asked that, and asked to agree on the total.
adjacency_root="$(variant 'adjacency' "$(printf 'const key = %s%s%s;\nconst planted = %s%s%s;' \
	"${backtick}" "$(cat "${probe_pem}")" "${backtick}" \
	"${backtick}" "$(cat "${mutated_pem}")" "${backtick}")")"
planted_body="$(sed -n '2p' "${mutated_pem}")"

new_case 'neither form hides the key planted against the span it describes'
adjacency_plain="${tmp_dir}/adjacency-plain.json"
adjacency_bytes="${tmp_dir}/adjacency-bytes.json"
adjacency_plain_count="$(scan "${adjacency_root}" "${plain_config}" "${adjacency_plain}")"
adjacency_bytes_count="$(scan "${adjacency_root}" "${bytes_config}" "${adjacency_bytes}")"
if [[ ${adjacency_plain_count} == "error" || ${adjacency_bytes_count} == "error" ]]; then
	fail 'the scanner did not run'
elif [[ ${adjacency_plain_count} != "${adjacency_bytes_count}" ]]; then
	fail "the two forms disagree: plain left ${adjacency_plain_count} finding(s), bytes left ${adjacency_bytes_count}"
elif ! reported_in "${adjacency_plain}" "${planted_body}"; then
	fail 'the plain form hid the planted key, which is the #146 bypass'
elif ! reported_in "${adjacency_bytes}" "${planted_body}"; then
	fail 'the byte form hid the planted key, which is the #146 bypass'
fi

# =============================================================================

if [[ ${failures} -gt 0 ]]; then
	printf '\n%d case(s) failed\n' "${failures}" >&2
	exit 1
fi

printf '\ngitleaks contract holds (scanner %s)\n' "${scanner_version}"
