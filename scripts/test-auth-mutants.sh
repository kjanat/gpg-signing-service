#!/usr/bin/env bash
# Mutation tests for the credential checks: OIDC token verification in
# src/middleware/oidc.ts and the GitHub App JWT in src/utils/github-app.ts.
#
# Each mutant weakens one check and runs the suites that cover it; the suites
# must report a failing test. A surviving mutant fails this script, and so does
# a mutant whose target text is gone, so the list cannot rot silently when the
# code moves. Where a check exists twice (our pre-check and micro509's), the
# mutant removes both; removing one alone survives by design.
#
# Mutants are applied to a scratch copy of the tracked tree, never to the
# checkout, so an interrupted run cannot leave a weakened check behind.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"

scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

tree="${scratch}/tree"
mkdir -p "${tree}"
git -C "${repo_root}" ls-files -z --cached --others --exclude-standard \
	| (cd "${repo_root}" && tar --null --files-from=- -cf -) \
	| tar -xf - -C "${tree}"
ln -s "${repo_root}/node_modules" "${tree}/node_modules"

readonly oidc=src/middleware/oidc.ts
readonly app=src/utils/github-app.ts
readonly oidc_suites='src/__tests__/middleware.test.ts src/__tests__/branch-coverage.test.ts'
readonly app_suites='src/__tests__/github-app.test.ts'

failures=0

# run_suites <log> <suite>... -- vitest in the scratch tree, without coverage:
# its global thresholds fail any run of a few files.
run_suites() {
	local log="$1"
	shift
	(cd "${tree}" && MISE_TRUSTED_CONFIG_PATHS="${tree}" NO_COLOR=1 bun run test --coverage.enabled=false "$@") >"${log}" 2>&1
}

# mutant <name> <file> <suites> <old> <new> [<old> <new>...]
mutant() {
	local name="$1" file="$2" suites="$3"
	shift 3
	local target="${tree}/${file}" log="${scratch}/run.log"
	local -a suite_list
	read -ra suite_list <<<"${suites}"

	if ! python3 - "${target}" "$@" <<'PY'
import sys
path, *pairs = sys.argv[1:]
text = open(path).read()
for old, new in zip(pairs[::2], pairs[1::2]):
    if text.count(old) != 1:
        sys.exit(f"target appears {text.count(old)} times, expected once: {old!r}")
    text = text.replace(old, new)
open(path, "w").write(text)
PY
	then
		printf 'FAIL %s: the mutant no longer applies to %s\n' "${name}" "${file}" >&2
		failures=$((failures + 1))
		cp "${repo_root}/${file}" "${target}"
		return
	fi

	if run_suites "${log}" "${suite_list[@]}"; then
		printf 'FAIL %s: survived; %s still pass with it\n' "${name}" "${suites}" >&2
		failures=$((failures + 1))
	elif grep -Eq 'Tests +[0-9]+ failed' "${log}"; then
		printf 'killed %s\n' "${name}"
	else
		printf 'FAIL %s: the suites errored without a failing test:\n' "${name}" >&2
		cat "${log}" >&2
		failures=$((failures + 1))
	fi
	cp "${repo_root}/${file}" "${target}"
}

read -ra baseline <<<"${oidc_suites} ${app_suites}"
if ! run_suites "${scratch}/baseline.log" "${baseline[@]}"; then
	printf 'FAIL: the unmutated suites do not pass, so no mutant result means anything:\n' >&2
	cat "${scratch}/baseline.log" >&2
	exit 1
fi

mutant 'signature result ignored' "${oidc}" "${oidc_suites}" \
	$'\tif (!verified.ok) {\n\t\tmapVerifyFailure(verified.code);\n\t}\n' $'\tvoid verified;\n'

mutant 'HS256 admitted' "${oidc}" "${oidc_suites}" \
	'const ALLOWED_ALGORITHMS = ["RS256"];' 'const ALLOWED_ALGORITHMS = ["RS256", "HS256"];'

mutant 'audience unchecked' "${oidc}" "${oidc_suites}" \
	'if (!audiences.includes(expectedAudience)) {' 'if (false) {' \
	'audience: expectedAudience,' 'audience: { unchecked: true },'

mutant 'issuer unchecked' "${oidc}" "${oidc_suites}" \
	'if (!allowedIssuers.includes(payload.iss)) {' 'if (false) {' \
	'issuer: allowedIssuers,' 'issuer: { unchecked: true },'

mutant 'bad signature reported as a generic failure' "${oidc}" "${oidc_suites}" \
	$'case "invalid_signature":\n\t\t\tthrow new Error("Invalid token signature");' \
	$'case "invalid_signature":\n\t\t\tthrow new Error("Invalid token");'

mutant 'verified claims schema skipped' "${oidc}" "${oidc_suites}" \
	'if (!claims.success) {' 'if (false) {'

mutant 'JWKS re-serialised before caching' "${oidc}" "${oidc_suites}" \
	'await env.JWKS_CACHE.put(cacheKey, jwksText, {' 'await env.JWKS_CACHE.put(cacheKey, JSON.stringify(JSON.parse(jwksText)), {'

mutant 'App JWT iat not backdated' "${app}" "${app_suites}" \
	'iat: nowSeconds - CLOCK_SKEW / TIME.SECOND,' 'iat: nowSeconds,'

mutant 'App JWT outlives GitHub ceiling' "${app}" "${app_suites}" \
	'exp: nowSeconds + APP_JWT_TTL / TIME.SECOND,' 'exp: nowSeconds + 3600,'

mutant 'App JWT issuer wrong' "${app}" "${app_suites}" \
	'iss: appId,' 'iss: "0",'

mutant 'failed key import ignored' "${app}" "${app_suites}" \
	'if (!imported.ok) {' 'if (false) {'

if ((failures > 0)); then
	printf '%d mutant(s) not killed\n' "${failures}" >&2
	exit 1
fi
printf 'auth mutants: all killed\n'
