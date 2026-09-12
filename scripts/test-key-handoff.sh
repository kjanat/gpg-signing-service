#!/usr/bin/env bash
# Covers scripts/key-handoff.sh -- the local-operator path for #147's last two
# acceptance criteria.
#
# That script runs exactly twice in the life of this repository, on a machine
# nobody else can see, against material no test will ever hold, and the operator
# deletes their local copies on the strength of what it says. There is no second
# attempt and no way to review the run afterwards. So every branch it can take
# is exercised here against throwaway keys generated during the run, and the
# cases that matter are the ones where the script must *refuse*: a backup that
# restores the wrong key, a passphrase from the wrong place, a revocation
# certificate for a different key, a keyserver that accepts an upload and then
# serves the unrevoked key back.
#
# Offline and deterministic. scripts/mock-keyserver.py stands in for the
# publication targets and speaks the same HKP that keys.openpgp.org does, so the
# upload and the fetch-back are real conversations with a real gpg, not stubs.
#
# Run: task test:key-handoff
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
handoff="${repo_root}/scripts/key-handoff.sh"
mock_server="${repo_root}/scripts/mock-keyserver.py"
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

# Not a quiet skip. This suite is the only review the operator procedure ever
# gets; a machine that cannot run it has not proved the procedure works, and
# saying so is more useful than a green line.
for tool in gpg python3; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		printf '%s is required to test the operator handoff path, and is not on PATH\n' "${tool}" >&2
		exit 1
	fi
done

fixture_home="${tmp_dir}/fixture-gnupg"
mkdir -p "${fixture_home}"
chmod 700 "${fixture_home}"

servers=()
cleanup() {
	local pid
	for pid in "${servers[@]}"; do
		kill "${pid}" 2>/dev/null || true
	done
	GNUPGHOME="${fixture_home}" gpgconf --kill all >/dev/null 2>&1 || true
	rm -rf "${tmp_dir}"
}
trap cleanup EXIT

# The script refuses to run under CI, which is where this suite runs. The
# override is set here and nowhere else, and case 20 proves the refusal is real
# by running without it.
export KEY_HANDOFF_ALLOW_CI='yes-i-am-a-local-operator'

# --- fixtures -----------------------------------------------------------------
# Four throwaway keys, generated once: the stand-ins for the replacement key,
# the retired key, the preserved key, and a stranger used wherever a case needs
# "some other key" -- a mismatched revocation certificate, a wrong-key backup.
PASSPHRASE='handoff-fixture-passphrase'
WRONG_PASSPHRASE='handoff-fixture-wrong-passphrase'

gen_key() {
	local label="$1"
	local params="${tmp_dir}/params-${label}"
	cat >"${params}" <<PARAMS
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: Handoff Fixture ${label}
Name-Email: ${label}@example.invalid
Expire-Date: 0
Passphrase: ${PASSPHRASE}
%commit
PARAMS
	GNUPGHOME="${fixture_home}" gpg --batch --quiet --gen-key "${params}" 2>/dev/null
	rm -f "${params}"
}

fpr_of() {
	GNUPGHOME="${fixture_home}" gpg --list-keys --with-colons "$1@example.invalid" \
		| awk -F: '/^fpr/{print $10; exit}'
}

export_secret() {
	GNUPGHOME="${fixture_home}" gpg --batch --quiet --pinentry-mode loopback \
		--passphrase "${PASSPHRASE}" --armor --export-secret-keys "$1"
}

export_public() {
	GNUPGHOME="${fixture_home}" gpg --batch --quiet --armor --export "$1"
}

gen_revocation() {
	# Fixture-side only. key-handoff.sh never does this -- ADR-004 turns on
	# publishing a certificate that already exists offline, and a script that
	# could mint one would be a script that could revoke the replacement by
	# accident. Case 21 asserts it holds no such code path.
	#
	# --gen-revoke refuses outright under --batch, so this drives it on
	# --command-fd instead: confirm, reason 1 (superseded), empty description,
	# confirm.
	printf 'y\n1\n\ny\n' | GNUPGHOME="${fixture_home}" gpg --yes --no-tty \
		--pinentry-mode loopback --passphrase "${PASSPHRASE}" --command-fd 0 \
		--output "$2" --armor --gen-revoke "$1" 2>/dev/null
}

printf '# fixtures\n'
for label in replacement retired preserved stranger; do
	gen_key "${label}"
done

REPLACEMENT_FPR="$(fpr_of replacement)"
RETIRED_FPR="$(fpr_of retired)"
PRESERVED_FPR="$(fpr_of preserved)"
STRANGER_FPR="$(fpr_of stranger)"
REPLACEMENT_ID="${REPLACEMENT_FPR: -16}"
RETIRED_ID="${RETIRED_FPR: -16}"
PRESERVED_ID="${PRESERVED_FPR: -16}"

for value in "${REPLACEMENT_FPR}" "${RETIRED_FPR}" "${PRESERVED_FPR}" "${STRANGER_FPR}"; do
	[ -n "${value}" ] || {
		printf 'could not generate the fixture keys\n' >&2
		exit 1
	}
done
printf '  -- four throwaway keys generated\n'

export KEY_HANDOFF_REPLACEMENT_KEY="${REPLACEMENT_ID}"
export KEY_HANDOFF_RETIRED_KEY="${RETIRED_ID}"
export KEY_HANDOFF_PRESERVED_KEY="${PRESERVED_ID}"

# A complete, well-formed handoff directory: what the operator should have.
good="${tmp_dir}/handoff"
mkdir -p "${good}"
export_secret "${REPLACEMENT_FPR}" >"${good}/replacement-secret.asc"
export_public "${REPLACEMENT_FPR}" >"${good}/replacement-public.asc"
export_secret "${PRESERVED_FPR}" >"${good}/preserved-secret.asc"
export_public "${RETIRED_FPR}" >"${good}/retired-public.asc"
gen_revocation "${REPLACEMENT_FPR}" "${good}/replacement-revocation.asc"
gen_revocation "${RETIRED_FPR}" "${good}/retired-revocation.asc"
gen_revocation "${STRANGER_FPR}" "${tmp_dir}/stranger-revocation.asc"
export_secret "${STRANGER_FPR}" >"${tmp_dir}/stranger-secret.asc"

for required in replacement-secret replacement-public preserved-secret \
	retired-public replacement-revocation retired-revocation; do
	[ -s "${good}/${required}.asc" ] || {
		printf 'fixture %s was not produced\n' "${required}" >&2
		exit 1
	}
done
printf '  -- a complete handoff directory assembled\n'

# The two backup locations. Separate directories, because that is the property
# under test and half these cases are about what happens when they are not.
backup_key="${tmp_dir}/backup-vault-a"
backup_pass="${tmp_dir}/backup-vault-b"
mkdir -p "${backup_key}" "${backup_pass}"
cp "${good}/replacement-secret.asc" "${backup_key}/replacement.asc"
cp "${good}/preserved-secret.asc" "${backup_key}/preserved.asc"
printf '%s\n' "${PASSPHRASE}" >"${backup_pass}/passphrase.txt"

run_handoff() {
	# Captures both streams and the status, so a case can assert on either
	# without the suite aborting under `set -e`.
	set +e
	"${handoff}" "$@" >"${tmp_dir}/out" 2>"${tmp_dir}/err"
	last_status=$?
	set -e
	last_output="$(cat "${tmp_dir}/out" "${tmp_dir}/err")"
}

start_server() {
	# Prints the base URL. Reads the bound port off the server's own stdout
	# rather than picking one, so cases never race each other for a port.
	local state="$1"
	shift
	mkdir -p "${state}"
	local portfile="${state}/port"
	python3 "${mock_server}" --state "${state}" "$@" >"${portfile}" 2>"${state}/log" &
	servers+=("$!")
	local port="" attempt=0
	while [ -z "${port}" ] && [ "${attempt}" -lt 100 ]; do
		port="$(sed -n 's/^listening \([0-9]*\)$/\1/p' "${portfile}" 2>/dev/null || true)"
		[ -n "${port}" ] || sleep 0.05
		attempt=$((attempt + 1))
	done
	[ -n "${port}" ] || {
		printf 'the mock keyserver never bound a port\n' >&2
		exit 1
	}
	printf 'hkp://127.0.0.1:%s' "${port}"
}

upload_count() {
	find "$1/uploads" -name '*.asc' 2>/dev/null | wc -l | tr -d ' '
}

# --- 1. structural validation -------------------------------------------------
printf '\n# 1. handoff structure\n'

new_case 'a complete handoff directory validates'
run_handoff validate --handoff "${good}"
[ "${last_status}" = 0 ] || fail "a well-formed handoff was rejected: ${last_output}"
grep -q "replacement secret key present" <<<"${last_output}" \
	|| fail 'the replacement secret key was not recognised'
grep -q "retired-key revocation certificate present" <<<"${last_output}" \
	|| fail 'the retired revocation certificate was not recognised'

new_case 'a missing handoff directory is an error, not an empty pass'
run_handoff validate --handoff "${tmp_dir}/not-a-directory"
[ "${last_status}" != 0 ] || fail 'a nonexistent handoff directory validated'
grep -q "offline by design" <<<"${last_output}" \
	|| fail 'the error does not explain that the material is deliberately absent'

new_case 'the wrong replacement key in the handoff is caught'
# Every file is right except that the secret key is a stranger's: the shape of a
# handoff assembled from the wrong export.
wrong_key_handoff="${tmp_dir}/handoff-wrong-key"
cp -r "${good}" "${wrong_key_handoff}"
cp "${tmp_dir}/stranger-secret.asc" "${wrong_key_handoff}/replacement-secret.asc"
rm -f "${wrong_key_handoff}/replacement-public.asc"
run_handoff validate --handoff "${wrong_key_handoff}"
[ "${last_status}" != 0 ] || fail 'a handoff whose replacement key is a different key validated'
grep -q "no secret key for the replacement" <<<"${last_output}" \
	|| fail "the failure does not name the missing replacement key: ${last_output}"

new_case 'a revocation certificate for the wrong key is caught'
mismatched="${tmp_dir}/handoff-mismatched-revocation"
cp -r "${good}" "${mismatched}"
cp "${tmp_dir}/stranger-revocation.asc" "${mismatched}/retired-revocation.asc"
run_handoff validate --handoff "${mismatched}"
[ "${last_status}" != 0 ] || fail 'a handoff carrying a revocation for an unrelated key validated'
grep -q "no revocation certificate for the retired" <<<"${last_output}" \
	|| fail "the failure does not identify the mismatched certificate: ${last_output}"

new_case 'missing preserved material is caught'
no_preserved="${tmp_dir}/handoff-no-preserved"
cp -r "${good}" "${no_preserved}"
rm -f "${no_preserved}/preserved-secret.asc"
run_handoff validate --handoff "${no_preserved}"
[ "${last_status}" != 0 ] || fail 'a handoff missing the preserved key validated'
grep -q "no preserved material" <<<"${last_output}" \
	|| fail 'the failure does not mention the preserved key'

new_case 'a missing replacement revocation certificate is caught'
no_repl_rev="${tmp_dir}/handoff-no-replacement-revocation"
cp -r "${good}" "${no_repl_rev}"
rm -f "${no_repl_rev}/replacement-revocation.asc"
run_handoff validate --handoff "${no_repl_rev}"
[ "${last_status}" != 0 ] || fail 'a handoff with no way to ever retire the replacement key validated'

new_case 'validation classifies by content, not by filename'
# The same material under names that say nothing. A checker that pattern-matched
# filenames would report a directory of unknown blobs; this one decodes.
renamed="${tmp_dir}/handoff-renamed"
mkdir -p "${renamed}"
index=0
for f in "${good}"/*.asc; do
	cp "${f}" "${renamed}/blob-${index}.bin"
	index=$((index + 1))
done
run_handoff validate --handoff "${renamed}"
[ "${last_status}" = 0 ] || fail "opaque filenames defeated validation: ${last_output}"

# --- 2. backup retrieval ------------------------------------------------------
printf '\n# 2. backup retrieval\n'

new_case 'a good backup verifies, and the originals are left untouched'
before_digest="$(find "${backup_key}" "${backup_pass}" -type f -exec sha256sum {} + | sort | sha256sum)"
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" = 0 ] || fail "a good backup failed verification: ${last_output}"
grep -q "unlocks with the separately stored passphrase" <<<"${last_output}" \
	|| fail 'the unlock proof did not run'
after_digest="$(find "${backup_key}" "${backup_pass}" -type f -exec sha256sum {} + | sort | sha256sum)"
[ "${before_digest}" = "${after_digest}" ] \
	|| fail 'verification modified the backup files'

new_case 'the restored key is proved to be the right key, not just a key'
run_handoff verify-backup \
	--private-backup "${tmp_dir}/stranger-secret.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'a backup holding an entirely different key verified'
grep -q "is not ${REPLACEMENT_ID}" <<<"${last_output}" \
	|| fail "the failure does not say which key was expected: ${last_output}"

new_case 'a wrong passphrase fails, even though the import succeeds'
# The distinction this case exists for: gpg imports an encrypted secret key
# without ever consulting the passphrase, so "it imported" is not evidence the
# other backup is the right one. Only making the key sign something is.
wrong_pass_dir="${tmp_dir}/backup-vault-c"
mkdir -p "${wrong_pass_dir}"
printf '%s\n' "${WRONG_PASSPHRASE}" >"${wrong_pass_dir}/passphrase.txt"
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${wrong_pass_dir}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'a backup with the wrong passphrase verified'
grep -q "did not unlock" <<<"${last_output}" \
	|| fail "the failure does not identify the passphrase: ${last_output}"

new_case 'a missing backup file fails closed'
run_handoff verify-backup \
	--private-backup "${tmp_dir}/no-such-backup.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'a nonexistent backup file verified'
grep -q "not a backup" <<<"${last_output}" \
	|| fail 'the failure does not explain what was missing'

new_case 'the private key and its passphrase in one file is refused'
together="${tmp_dir}/backup-vault-together"
mkdir -p "${together}"
cp "${backup_key}/replacement.asc" "${together}/both.asc"
run_handoff verify-backup \
	--private-backup "${together}/both.asc" \
	--passphrase-backup "${together}/both.asc" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'one file holding both the key and its passphrase was accepted'
grep -q "same file" <<<"${last_output}" \
	|| fail "the failure does not name the shared location: ${last_output}"

new_case 'the private key and its passphrase in one directory is refused'
# The failure that actually happens: two files, one folder, one `cp -r`.
cp "${backup_pass}/passphrase.txt" "${backup_key}/passphrase.txt"
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_key}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'a key and its passphrase in the same directory were accepted'
grep -q "same directory" <<<"${last_output}" \
	|| fail "the failure does not name the shared directory: ${last_output}"
rm -f "${backup_key}/passphrase.txt"

new_case 'the same-directory refusal survives the environment route'
# KEY_HANDOFF_PASSPHRASE_FILE is documented as an equal alternative to
# --passphrase-backup, so it has to face the same hygiene check. It did not:
# routing the path through the environment skipped distinct_locations entirely
# and the run still printed "the separately stored passphrase" and "Retrieval is
# proven" over a key and its passphrase sharing one directory. That claim is what
# the operator deletes their local copies on.
cp "${backup_pass}/passphrase.txt" "${backup_key}/passphrase.txt"
set +e
env KEY_HANDOFF_PASSPHRASE_FILE="${backup_key}/passphrase.txt" \
	"${handoff}" verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--preserved-backup "${backup_key}/preserved.asc" \
	>"${tmp_dir}/env-out" 2>&1
env_status=$?
set -e
rm -f "${backup_key}/passphrase.txt"
[ "${env_status}" != 0 ] \
	|| fail 'a key and its passphrase in one directory were accepted via KEY_HANDOFF_PASSPHRASE_FILE'
grep -q "same directory" "${tmp_dir}/env-out" \
	|| fail "the environment route does not name the shared directory: $(cat "${tmp_dir}/env-out")"

new_case 'the environment route still works when the locations are distinct'
set +e
env KEY_HANDOFF_PASSPHRASE_FILE="${backup_pass}/passphrase.txt" \
	"${handoff}" verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--preserved-backup "${backup_key}/preserved.asc" \
	>"${tmp_dir}/env-ok" 2>&1
env_ok_status=$?
set -e
[ "${env_ok_status}" = 0 ] \
	|| fail "a well-separated passphrase supplied through the environment was rejected: $(cat "${tmp_dir}/env-ok")"

new_case 'skipping the preserved key is refused rather than silently allowed'
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt"
[ "${last_status}" != 0 ] || fail 'a backup check that never touched the preserved key passed'
grep -q -- "--preserved-backup" <<<"${last_output}" \
	|| fail 'the failure does not say what to pass'

new_case 'the passphrase is refused as a command-line argument'
# /proc/*/cmdline is world-readable; a flag that took the passphrase would hand
# it to every local user for the life of the process.
run_handoff verify-backup --private-backup "${backup_key}/replacement.asc" \
	--passphrase "${PASSPHRASE}"
[ "${last_status}" != 0 ] || fail '--passphrase was accepted'
grep -q "world-readable" <<<"${last_output}" \
	|| fail 'the refusal does not explain why'

new_case 'the passphrase never appears in any output'
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
if grep -qF "${PASSPHRASE}" <<<"${last_output}"; then
	fail 'the passphrase was echoed into the output'
fi
# Nor any of the secret key's armor body, which is the other thing that must
# never be logged. The third line of an armored block is body, never header.
secret_line="$(sed -n '4p' "${backup_key}/replacement.asc")"
[ -n "${secret_line}" ] || fail 'the fixture key is too short to check for leaked body'
if grep -qF "${secret_line}" <<<"${last_output}"; then
	fail 'a line of the secret key body was echoed into the output'
fi

# --- 3. revocation, verify-only -----------------------------------------------
printf '\n# 3. revocation without publishing\n'

new_case 'verify-only proves the revocation locally and uploads nothing'
state_dry="${tmp_dir}/server-dry"
url_dry="$(start_server "${state_dry}")"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_dry}"
[ "${last_status}" = 0 ] || fail "verify-only failed on a valid revocation: ${last_output}"
grep -q "is revoked in the local keyring" <<<"${last_output}" \
	|| fail 'the local revocation was not proved'
grep -q "Nothing was uploaded" <<<"${last_output}" \
	|| fail 'verify-only did not say it published nothing'
[ "$(upload_count "${state_dry}")" = 0 ] \
	|| fail 'verify-only uploaded a key'

new_case '--dry-run beats --confirm-publish'
# Belt and braces: an operator who pastes a command with both should get the
# safe one. The unsafe combination is the one worth pinning down.
state_both="${tmp_dir}/server-both"
url_both="$(start_server "${state_both}")"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_both}" \
	--confirm-publish --dry-run
[ "${last_status}" = 0 ] || fail "the safe combination errored: ${last_output}"
[ "$(upload_count "${state_both}")" = 0 ] \
	|| fail '--dry-run uploaded anyway'

new_case 'a revocation certificate for another key is refused before any upload'
state_wrong="${tmp_dir}/server-wrong-cert"
url_wrong="$(start_server "${state_wrong}")"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_wrong}" \
	--revocation "${tmp_dir}/stranger-revocation.asc" --confirm-publish
[ "${last_status}" != 0 ] || fail 'a certificate revoking an unrelated key was published'
grep -q "not ${RETIRED_ID}" <<<"${last_output}" \
	|| fail "the failure does not name the key the certificate actually revokes: ${last_output}"
[ "$(upload_count "${state_wrong}")" = 0 ] \
	|| fail 'the wrong certificate reached the keyserver'

new_case 'a handoff with no retired public key refuses rather than guessing'
no_pub="${tmp_dir}/handoff-no-retired-public"
cp -r "${good}" "${no_pub}"
rm -f "${no_pub}/retired-public.asc"
run_handoff publish-revocation --handoff "${no_pub}" --keyserver "${url_wrong}" --confirm-publish
[ "${last_status}" != 0 ] || fail 'publication proceeded with no key to carry the revocation'
grep -q -- "--retired-public" <<<"${last_output}" \
	|| fail 'the failure does not say what to supply'

# --- 4. publication and fetch-back --------------------------------------------
printf '\n# 4. publication\n'

new_case 'publication uploads, then proves the key comes back revoked'
state_ok="${tmp_dir}/server-ok"
url_ok="$(start_server "${state_ok}")"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_ok}" --confirm-publish
[ "${last_status}" = 0 ] || fail "a valid publication failed: ${last_output}"
[ "$(upload_count "${state_ok}")" -ge 1 ] || fail 'nothing was uploaded'
grep -q "reports it revoked" <<<"${last_output}" \
	|| fail 'the fetch-back did not assert the revoked state'

new_case 'the fetch-back reads from a keyring that has never seen the key'
# Otherwise the check is self-fulfilling: the keyring used to publish already
# holds the revoked key, so a keyserver serving nothing at all would pass.
state_empty="${tmp_dir}/server-empty"
url_empty="$(start_server "${state_empty}" --not-found)"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_empty}" --confirm-publish
[ "${last_status}" != 0 ] || fail 'publication succeeded against a keyserver serving nothing back'
grep -q "did not serve" <<<"${last_output}" \
	|| fail "the failure does not say the key was not served: ${last_output}"

new_case 'a keyserver that serves the key back unrevoked fails the run'
# The case the whole fetch-back exists for. keys.openpgp.org and
# keyserver.ubuntu.com both 200 an upload they have not finished applying.
state_stale="${tmp_dir}/server-stale"
url_stale="$(start_server "${state_stale}" --serve "${good}/retired-public.asc")"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_stale}" --confirm-publish
[ "${last_status}" != 0 ] || fail 'a keyserver still handing out the live key was accepted'
grep -q "does NOT report it revoked" <<<"${last_output}" \
	|| fail "the failure does not distinguish served-but-live: ${last_output}"
[ "$(upload_count "${state_stale}")" -ge 1 ] \
	|| fail 'the case did not actually get as far as uploading'

new_case 'an upload failure is not reported as publication'
state_reject="${tmp_dir}/server-reject"
url_reject="$(start_server "${state_reject}" --reject-upload)"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_reject}" --confirm-publish
[ "${last_status}" != 0 ] || fail 'a rejected upload was reported as published'
grep -q "not claiming publication" <<<"${last_output}" \
	|| fail "the failure does not refuse the claim: ${last_output}"

new_case 'one failing target out of two fails the whole publication'
# A partial publication is the state that leaves a verifier accepting a
# signature from a key everyone else already knows is dead.
run_handoff publish-revocation --handoff "${good}" \
	--keyserver "${url_ok}" --keyserver "${url_stale}" --confirm-publish
[ "${last_status}" != 0 ] || fail 'publication passed with one target serving the key unrevoked'
grep -q "of 2 target" <<<"${last_output}" \
	|| fail "the failure does not count the targets: ${last_output}"

new_case 'verify-published re-checks without uploading anything'
before_ok="$(upload_count "${state_ok}")"
run_handoff verify-published --keyserver "${url_ok}"
[ "${last_status}" = 0 ] || fail "a re-check of a published revocation failed: ${last_output}"
[ "$(upload_count "${state_ok}")" = "${before_ok}" ] \
	|| fail 'verify-published uploaded something'

new_case 'the retired public key survives revocation, so old signatures still verify'
# ADR-004 decision 2. Revoking must not be allowed to become deleting: v1.2.0
# and every pre-cutover signature verify against this key and nothing else.
verify_home="${tmp_dir}/verify-gnupg"
mkdir -p "${verify_home}"
chmod 700 "${verify_home}"
printf 'signed before the retirement\n' >"${tmp_dir}/historical"
GNUPGHOME="${fixture_home}" gpg --batch --quiet --pinentry-mode loopback \
	--passphrase "${PASSPHRASE}" --local-user "${RETIRED_FPR}" \
	--detach-sign --output "${tmp_dir}/historical.sig" "${tmp_dir}/historical" 2>/dev/null
GNUPGHOME="${verify_home}" gpg --batch --quiet --import "$(find "${state_ok}/uploads" -name '*.asc' | sort | tail -1)" 2>/dev/null \
	|| fail 'the published key did not import'
GNUPGHOME="${verify_home}" gpg --batch --verify "${tmp_dir}/historical.sig" "${tmp_dir}/historical" 2>/dev/null \
	|| fail 'a signature made before the revocation stopped verifying against the published key'
GNUPGHOME="${verify_home}" gpgconf --kill all >/dev/null 2>&1 || true

# --- 5. structural guarantees -------------------------------------------------
printf '\n# 5. structural guarantees\n'

new_case 'the script refuses to run in CI without the explicit override'
set +e
env -u KEY_HANDOFF_ALLOW_CI CI=true "${handoff}" validate --handoff "${good}" \
	>"${tmp_dir}/ci-out" 2>&1
ci_status=$?
set -e
[ "${ci_status}" != 0 ] || fail 'the script ran under CI with no override'
grep -q "offline by design" "${tmp_dir}/ci-out" \
	|| fail 'the CI refusal does not explain itself'
grep -q "KEY_HANDOFF_ALLOW_CI" "${tmp_dir}/ci-out" \
	|| fail 'the CI refusal does not name the override'

new_case 'a plausible-looking override value is not enough'
set +e
env KEY_HANDOFF_ALLOW_CI=1 CI=true "${handoff}" validate --handoff "${good}" \
	>"${tmp_dir}/ci-out2" 2>&1
ci_status2=$?
set -e
[ "${ci_status2}" != 0 ] || fail 'KEY_HANDOFF_ALLOW_CI=1 was accepted as the override'

new_case 'the script contains no way to generate a key or a revocation'
# The one code path that would let this script destroy what it is protecting.
# grep over the source rather than over behaviour, because the failure mode is
# somebody adding a convenient fallback later.
if grep -nE -- '--(gen|generate)-(revoke|revocation|key)|--quick-gen|--full-gen' "${handoff}" \
	| grep -vE '^\s*[0-9]+:\s*#' | grep -q .; then
	fail 'key-handoff.sh can generate key or revocation material'
fi

new_case 'the script takes no passphrase, key or certificate from the environment as a value'
# Paths are fine; values are not. An environment variable holding the passphrase
# is inherited by every child process, including gpg's, and shows up in a core
# dump and in `ps e`.
if grep -nE '^\s*(PASSPHRASE|KEY_HANDOFF_PASSPHRASE)=' "${handoff}" | grep -q .; then
	fail 'key-handoff.sh reads a passphrase value out of the environment'
fi

new_case 'the temporary directory is cleaned up on interruption, not only on normal exit'
# bash does not run an EXIT trap when it dies on an uncaught SIGINT, and the long
# part of a real run is a keyserver round trip -- exactly where Ctrl-C lands.
# What survives is the plaintext passphrase and a keyring holding the unlocked
# secret key. Asserted over the source because reproducing the race in a suite
# would be the flakiest case here.
grep -qE "^\s*trap .* INT\b" "${handoff}" \
	|| fail 'nothing traps SIGINT, so Ctrl-C leaves the passphrase on disk'
grep -qE "^\s*trap .* TERM\b" "${handoff}" \
	|| fail 'nothing traps SIGTERM'

new_case 'the default publication targets are the ones ADR-004 names'
grep -q 'hkps://keys.openpgp.org' "${handoff}" \
	|| fail 'keys.openpgp.org is not a default target'
grep -q 'hkps://keyserver.ubuntu.com' "${handoff}" \
	|| fail 'keyserver.ubuntu.com is not a default target'

new_case 'the production identities and paths are the defaults, so a bare run needs no arguments'
# The needles are source lines verbatim, `${...}` and all, so the single quotes
# are the point rather than an oversight. A rotation that moved on without
# moving these would leave the operator running the procedure against the wrong
# key and being told it passed.
# shellcheck disable=SC2016
expected_defaults=(
	'REPLACEMENT_KEY="${KEY_HANDOFF_REPLACEMENT_KEY:-AFD5E3EC68371856}"'
	'RETIRED_KEY="${KEY_HANDOFF_RETIRED_KEY:-62E75E54497815DD}"'
	'PRESERVED_KEY="${KEY_HANDOFF_PRESERVED_KEY:-D8BC04E534E7706F}"'
	'HANDOFF_DIR="${KEY_HANDOFF_DIR:-.keys/rotation-20260908}"'
)
for needle in "${expected_defaults[@]}"; do
	grep -qF "${needle}" "${handoff}" \
		|| fail "a default has drifted from the rotation: ${needle}"
done

new_case 'the deployed key is the replacement this procedure backs up'
# key-handoff.sh's replacement default and wrangler.toml's KEY_ID are two copies
# of one fact. test-key-material.sh already pins the retired side of the pair;
# this pins the live one, so a future rotation cannot move production and leave
# the operator procedure pointing at the key it just replaced.
deployed_key_id="$(sed -nE 's/^KEY_ID[[:space:]]*=[[:space:]]*"([0-9A-Fa-f]{16})".*/\1/p' "${repo_root}/wrangler.toml" | head -n1)"
[ -n "${deployed_key_id}" ] || fail 'no KEY_ID found in wrangler.toml'
grep -qF ":-${deployed_key_id}}" "${handoff}" \
	|| fail "wrangler.toml deploys ${deployed_key_id} and key-handoff.sh does not treat it as the replacement key"

new_case 'no handoff material is tracked in the repository'
# The invariant the whole exercise turns on. .gitignore excludes .keys/, but an
# ignored path is one `git add -f` away from tracked, and this suite is where
# that would be noticed.
if git -C "${repo_root}" ls-files --error-unmatch .keys >/dev/null 2>&1; then
	fail '.keys is tracked in the repository'
fi
if git -C "${repo_root}" ls-files | grep -q '^\.keys/'; then
	fail 'handoff material is tracked under .keys/'
fi

new_case 'an unknown option is an error rather than a silently ignored typo'
run_handoff validate --handoff "${good}" --confrim-publish
[ "${last_status}" != 0 ] || fail 'a misspelled flag was ignored'

new_case 'an unknown command is an error'
run_handoff publish --handoff "${good}"
[ "${last_status}" != 0 ] || fail 'an unknown command ran'

# --- result -------------------------------------------------------------------
printf '\n'
if [ "${failures}" -gt 0 ]; then
	printf 'key-handoff: %d case(s) failed\n' "${failures}" >&2
	exit 1
fi
printf 'key-handoff: all cases passed\n'
