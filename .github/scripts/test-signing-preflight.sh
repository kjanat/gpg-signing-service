#!/usr/bin/env bash
# Covers every path through .github/scripts/signing-preflight.sh, which is the
# one place that decides whether a job signs. A composite action cannot be run
# outside a workflow, so this suite is the only thing standing between a change
# to that decision and a run that either silently stops signing or fails a whole
# Claude session at `git commit`.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
preflight="${repo_root}/.github/scripts/signing-preflight.sh"
action="${repo_root}/.github/actions/setup-claude-signing/action.yml"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

mkdir "${tmp_dir}/bin"

# The health stub. It records the argv it was given, so the bounds the preflight
# promises are asserted rather than assumed, and it fails however the case asks
# it to.
cat >"${tmp_dir}/bin/gpg-sign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$@" >>"${STUB_ARGV_FILE}"

if [[ -n "${STUB_SLEEP:-}" ]]; then
	sleep "${STUB_SLEEP}"
fi

if [[ -n "${STUB_STDERR:-}" ]]; then
	printf '%s\n' "${STUB_STDERR}" >&2
fi

exit "${STUB_RC:-0}"
EOF
chmod +x "${tmp_dir}/bin/gpg-sign"

# Every case runs with the mock ahead of PATH and a job-shaped environment, then
# overrides only what it is about. Clearing the OIDC variables first is not
# decoration: this suite runs inside a job that has them, and the case that
# asserts their absence would otherwise assert nothing.
run_preflight() {
	local rc=0
	: >"${tmp_dir}/argv"
	env \
		-u GPG_SIGN_DISABLE \
		-u GITHUB_STEP_SUMMARY \
		-u STUB_RC \
		-u STUB_STDERR \
		-u STUB_SLEEP \
		PATH="${tmp_dir}/bin:${PATH}" \
		STUB_ARGV_FILE="${tmp_dir}/argv" \
		ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example.test/token?api-version=2.0' \
		ACTIONS_ID_TOKEN_REQUEST_TOKEN='request-token-that-must-never-be-printed' \
		"$@" \
		bash "${preflight}" 'https://sign.example.test' \
		>"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
	printf '%s' "${rc}"
}

expect_rc() {
	local want="$1" got="$2" what="$3"
	if [[ "${got}" != "${want}" ]]; then
		echo "${what}: expected exit ${want}, got ${got}" >&2
		echo "--- stdout"
		cat "${tmp_dir}/out"
		echo "--- stderr"
		cat "${tmp_dir}/err"
		exit 1
	fi
}

expect_stdout() {
	if ! grep -qF "$1" "${tmp_dir}/out"; then
		echo "expected stdout to contain: $1" >&2
		cat "${tmp_dir}/out" >&2
		exit 1
	fi
}

refute_stdout() {
	if grep -qF "$1" "${tmp_dir}/out"; then
		echo "expected stdout NOT to contain: $1" >&2
		cat "${tmp_dir}/out" >&2
		exit 1
	fi
}

# The health stub was called, or was not. "Not" is the load-bearing half: the
# escape hatch and the configuration guards exist to answer without a network
# call, and a preflight that asked anyway would hang for its full budget during
# exactly the outage the hatch is for.
expect_health_called() {
	if [[ ! -s "${tmp_dir}/argv" ]]; then
		echo 'expected the health check to run' >&2
		exit 1
	fi
}

refute_health_called() {
	if [[ -s "${tmp_dir}/argv" ]]; then
		echo 'expected no health check for this case, but gpg-sign ran:' >&2
		cat "${tmp_dir}/argv" >&2
		exit 1
	fi
}

# --- the healthy path --------------------------------------------------------

rc="$(run_preflight)"
expect_rc 0 "${rc}" 'healthy service'
expect_health_called
expect_stdout '::notice title=Commit signing enabled::'

# The URL reaches the client as an argument rather than through whatever
# GPG_SIGN_URL the runner happens to carry, and the call is bounded. Both are
# asserted from argv because neither is visible in the result: an unbounded
# preflight passes this suite by hanging only in production.
grep -qx -- '--url' "${tmp_dir}/argv"
grep -qx -- 'https://sign.example.test' "${tmp_dir}/argv"
grep -qx -- '--timeout' "${tmp_dir}/argv"
grep -qx -- 'health' "${tmp_dir}/argv"

# Falsey values are the enabled path too, so an operator who set the variable to
# 0 to *re-enable* signing gets signing rather than the value being read as "set,
# therefore disabled".
for falsey in '' 0 false FALSE no off; do
	rc="$(run_preflight GPG_SIGN_DISABLE="${falsey}")"
	expect_rc 0 "${rc}" "GPG_SIGN_DISABLE=${falsey}"
	expect_health_called
done

# --- the escape hatch --------------------------------------------------------

for truthy in 1 true TRUE True yes on; do
	rc="$(run_preflight GPG_SIGN_DISABLE="${truthy}")"
	# 3, not 0. The caller distinguishes "signing is configured" from "signing
	# was deliberately not configured" by this number alone, and a hatch that
	# exited 0 would leave a job believing it signs while nothing set
	# commit.gpgsign.
	expect_rc 3 "${rc}" "GPG_SIGN_DISABLE=${truthy}"
	refute_health_called
	expect_stdout '::warning title=Commit signing disabled::'
	# Visibly intentional: the annotation says what will happen to the commits,
	# not merely that a switch was flipped.
	expect_stdout 'will NOT be signed'
done

# The hatch is for the outage, so it must not also require the configuration
# that only signing needs. An operator disabling signing because the service is
# unreachable should not then have to satisfy a URL check to get a green run.
rc=0
: >"${tmp_dir}/argv"
env -u GITHUB_STEP_SUMMARY \
	PATH="${tmp_dir}/bin:${PATH}" \
	STUB_ARGV_FILE="${tmp_dir}/argv" \
	GPG_SIGN_DISABLE=1 \
	bash "${preflight}" '' >"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
expect_rc 3 "${rc}" 'disabled with neither a service url nor OIDC variables'
refute_health_called

# An unsigned run is easy to miss in a log and expensive to discover later, so it
# is also written where GitHub shows it without scrolling.
rc="$(run_preflight GPG_SIGN_DISABLE=1 GITHUB_STEP_SUMMARY="${tmp_dir}/summary")"
expect_rc 3 "${rc}" 'disabled writes a step summary'
grep -q 'Commit signing disabled' "${tmp_dir}/summary"

# A typo must not read as "keep signing". Fail-closed would be safe and silent —
# the run would fail exactly as it did before the hatch existed, with nothing
# saying the hatch was ignored.
rc="$(run_preflight GPG_SIGN_DISABLE=ture)"
expect_rc 1 "${rc}" 'unrecognised GPG_SIGN_DISABLE'
expect_stdout 'CONFIG_DISABLE_VALUE'
refute_health_called

# --- the configuration guards ------------------------------------------------
#
# These are the acceptance criterion "missing service URL and OIDC credentials
# still fail before commit.gpgsign is enabled". They live here now, so this is
# where they are pinned.

rc=0
env -u GPG_SIGN_DISABLE \
	PATH="${tmp_dir}/bin:${PATH}" \
	STUB_ARGV_FILE="${tmp_dir}/argv" \
	ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example.test/token?api-version=2.0' \
	ACTIONS_ID_TOKEN_REQUEST_TOKEN='request-token-that-must-never-be-printed' \
	bash "${preflight}" '' >"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
expect_rc 1 "${rc}" 'empty service url'
expect_stdout 'CONFIG_SERVICE_URL'
refute_health_called

for missing in url token both; do
	oidc_args=(
		ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example.test/token?api-version=2.0'
		ACTIONS_ID_TOKEN_REQUEST_TOKEN='request-token-that-must-never-be-printed'
	)
	case "${missing}" in
		url) oidc_args=("${oidc_args[1]}") ;;
		token) oidc_args=("${oidc_args[0]}") ;;
		both) oidc_args=() ;;
	esac

	rc=0
	: >"${tmp_dir}/argv"
	env -u GPG_SIGN_DISABLE \
		-u ACTIONS_ID_TOKEN_REQUEST_URL \
		-u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
		PATH="${tmp_dir}/bin:${PATH}" \
		STUB_ARGV_FILE="${tmp_dir}/argv" \
		"${oidc_args[@]}" \
		bash "${preflight}" 'https://sign.example.test' \
		>"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
	expect_rc 1 "${rc}" "missing OIDC (${missing})"
	expect_stdout 'CONFIG_OIDC'
	expect_stdout 'id-token: write'
	refute_health_called
done

# The shim runs the same binary a few minutes later, so an install that did not
# happen is a signing failure this job will hit regardless of the service. Named
# here, it is one line; found at `git commit`, it is exit 128.
rc=0
: >"${tmp_dir}/argv"
mkdir -p "${tmp_dir}/no-client"
ln -sf "$(command -v bash)" "${tmp_dir}/no-client/bash"
env -u GPG_SIGN_DISABLE \
	PATH="${tmp_dir}/no-client:/usr/bin:/bin" \
	ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example.test/token?api-version=2.0' \
	ACTIONS_ID_TOKEN_REQUEST_TOKEN='request-token-that-must-never-be-printed' \
	bash "${preflight}" 'https://sign.example.test' \
	>"${tmp_dir}/out" 2>"${tmp_dir}/err" || rc=$?
expect_rc 1 "${rc}" 'gpg-sign missing from PATH'
expect_stdout 'CLIENT_MISSING'

# --- an unavailable service --------------------------------------------------
#
# One case per class an operator would act on differently. The generic
# "unavailable" is the thing this whole change exists to stop reporting.

assert_class() {
	local class="$1" stderr="$2" note="$3"

	rc="$(run_preflight STUB_RC=1 STUB_STDERR="${stderr}")"
	expect_rc 1 "${rc}" "${note}"
	expect_stdout "::error title=Commit signing unavailable (${class})::"
	# The service's own diagnostic survives. It carries the hint, the docs link
	# and the request id, which is what docs/troubleshooting.md asks for and what
	# no summary of ours can reconstruct.
	expect_stdout "${stderr}"
	# And the way out is in the same annotation as the failure.
	expect_stdout 'GPG_SIGN_DISABLE'
}

assert_class RATE_LIMITED \
	'Error: health check failed: rate limited: Rate limit exceeded (retry after 3s) (request req-429)' \
	'429 from the service'

# The class alone is not enough for a quota failure: "wait" and "re-run now" are
# different actions and only one of them works.
expect_stdout 'wait for the bucket to refill'

assert_class SERVICE_DEGRADED \
	'Error: health check failed: SERVICE_DEGRADED: Could not reach the OIDC configuration (status 503, retry after 5s, request req-503)' \
	'503 from the service'

assert_class SERVICE_MISCONFIGURED \
	'Error: health check failed: SERVICE_MISCONFIGURED: ALLOWED_ISSUERS names a URL this deployment refuses to fetch (status 500, request req-500)' \
	'500 from the service'

assert_class AUTH_INVALID \
	'Error: health check failed: authentication failed: AUTH_INVALID: token rejected (request req-401)' \
	'401 from the service'

assert_class SERVICE_UNREACHABLE \
	'Error: health check failed: Get "https://sign.example.test/health": dial tcp: lookup sign.example.test: no such host' \
	'no HTTP response at all'

# A code the classifier does not know must still fail closed and still forward
# what the service said, rather than being mistaken for something it is not.
assert_class UNKNOWN \
	'Error: health check failed: something nobody has written a branch for' \
	'an unrecognised failure'

# The budget is fed to `timeout` and evaluated arithmetically, so it is checked
# rather than coerced — `$(( ))` runs what it is given. The escape hatch still
# outranks it: an operator disabling signing must not be stopped by a setting
# only the health check reads.
for bad_budget in '' 0 abc 10s 1.5 '9(id)'; do
	rc="$(run_preflight GPG_SIGN_PREFLIGHT_TIMEOUT="${bad_budget}")"
	if [[ "${bad_budget}" == '' ]]; then
		# Empty takes the default rather than being an error, the same way the
		# bash example treats an empty MAX_RETRY_WAIT.
		expect_rc 0 "${rc}" 'an empty preflight budget takes the default'
		continue
	fi
	expect_rc 1 "${rc}" "GPG_SIGN_PREFLIGHT_TIMEOUT=${bad_budget}"
	expect_stdout 'CONFIG_PREFLIGHT_TIMEOUT'
	refute_health_called
done

rc="$(run_preflight GPG_SIGN_DISABLE=1 GPG_SIGN_PREFLIGHT_TIMEOUT=abc)"
expect_rc 3 "${rc}" 'the hatch outranks a bad preflight budget'

# --- the bound ---------------------------------------------------------------
#
# A setup step that hangs is the worst outcome available here: it burns the job's
# minutes and reports nothing, which is strictly worse than the exit 128 this
# preflight replaces. A regression does not fail, it waits, so the case is
# written to fail on the clock.
if command -v timeout >/dev/null 2>&1; then
	started="${SECONDS}"
	rc="$(run_preflight GPG_SIGN_PREFLIGHT_TIMEOUT=1 STUB_SLEEP=30)"
	elapsed=$((SECONDS - started))
	expect_rc 1 "${rc}" 'a hanging health check'
	if ((elapsed > 20)); then
		echo "expected the preflight to be bounded, it took ${elapsed}s" >&2
		exit 1
	fi
	expect_stdout 'SERVICE_UNREACHABLE'
else
	printf 'skipping the bounded-preflight case: no timeout(1) on PATH\n' >&2
fi

# --- the credential never appears in the log ---------------------------------
#
# The preflight checks the OIDC request variables for presence and asks an
# unauthenticated endpoint, so nothing should ever carry them into a log that is
# public on every pull request. Assert it rather than trusting the reading.
for disable_case in '' 1 ture; do
	rc="$(run_preflight GPG_SIGN_DISABLE="${disable_case}")" || true
	refute_stdout 'request-token-that-must-never-be-printed'
	if grep -qF 'request-token-that-must-never-be-printed' "${tmp_dir}/err"; then
		echo 'the OIDC request token reached stderr' >&2
		exit 1
	fi
done

rc="$(run_preflight STUB_RC=1 STUB_STDERR='Error: health check failed: boom')"
refute_stdout 'request-token-that-must-never-be-printed'

# --- the action actually uses all of this ------------------------------------
#
# Everything above tests a script that nothing has to call. These four
# assertions are what tie it to the composite action, which cannot itself be run
# outside a workflow — without them the suite stays green while the action goes
# back to deciding for itself.
grep -q 'disable-signing:' "${action}"
grep -q 'signing-preflight.sh' "${action}"
# shellcheck disable=SC2016  # the literal shell source in action.yml is the assertion
grep -q 'GPG_SIGN_DISABLE="${DISABLE_SIGNING-}"' "${action}"

# The fail-closed shape of the caller: exactly one status means "sign", exactly
# one means "deliberately do not", and everything else fails the step.
python3 - "${action}" <<'PY'
import sys, yaml

action = yaml.safe_load(open(sys.argv[1]))
run = next(s["run"] for s in action["runs"]["steps"] if s.get("id") == "configure")

for needle in (
    "0) signing_enabled=true ;;",
    "3) signing_enabled=false ;;",
    "*) exit 1 ;;",
    "git config --local commit.gpgsign true",
    "git config --local commit.gpgsign false",
):
    assert needle in run, f"action.yml no longer contains: {needle}"

# commit.gpgsign must stay downstream of the preflight. Nothing else in the step
# enforces the ordering the acceptance criteria are written in.
assert run.index("signing-preflight.sh") < run.index("commit.gpgsign true")
PY

printf 'signing preflight tests passed\n'
