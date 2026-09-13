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
reap_servers() {
	# Two sources, because the array alone was not one. start_server used to be
	# called as `url="$(start_server ...)"`, so `servers+=("$!")` ran in the
	# command-substitution subshell and was discarded with it: the array the trap
	# read was always empty and every mock keyserver a run started outlived it.
	# start_server now assigns through a global instead, and writes a pidfile as
	# well, so a future caller who reaches for a subshell again still gets reaped.
	local pid pidfile
	for pid in ${servers[@]+"${servers[@]}"}; do
		kill "${pid}" 2>/dev/null || true
	done
	for pidfile in "${tmp_dir}"/*/pid; do
		[ -f "${pidfile}" ] || continue
		pid="$(cat "${pidfile}" 2>/dev/null || true)"
		[ -n "${pid}" ] || continue
		kill "${pid}" 2>/dev/null || true
	done
}

cleanup() {
	reap_servers
	GNUPGHOME="${fixture_home}" gpgconf --kill all >/dev/null 2>&1 || true
	rm -rf "${tmp_dir}"
}
trap cleanup EXIT
# bash runs no EXIT trap when it dies on an uncaught SIGINT, and this suite
# spawns HTTP servers. Route the signals back through the EXIT trap so an
# interrupted run leaves nothing listening.
trap 'exit 130' INT
trap 'exit 143' TERM HUP

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

gen_bare_key() {
	# A secret key with no passphrase at all: what an operator ends up with after
	# `--export-secret-keys` from a keyring whose protection was stripped, or
	# after a key generated in a hurry with %no-protection. gpg signs with it
	# without ever consulting --passphrase-file, so a backup check that treats a
	# successful signature as an unlock proof would call any passphrase correct.
	local label="$1"
	local params="${tmp_dir}/params-${label}"
	cat >"${params}" <<PARAMS
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: Handoff Fixture ${label}
Name-Email: ${label}@example.invalid
Expire-Date: 0
%no-protection
%commit
PARAMS
	GNUPGHOME="${fixture_home}" gpg --batch --quiet --gen-key "${params}" 2>/dev/null
	rm -f "${params}"
}

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
gen_bare_key unprotected

REPLACEMENT_FPR="$(fpr_of replacement)"
RETIRED_FPR="$(fpr_of retired)"
PRESERVED_FPR="$(fpr_of preserved)"
STRANGER_FPR="$(fpr_of stranger)"
UNPROTECTED_FPR="$(fpr_of unprotected)"
UNPROTECTED_ID="${UNPROTECTED_FPR: -16}"
REPLACEMENT_ID="${REPLACEMENT_FPR: -16}"
RETIRED_ID="${RETIRED_FPR: -16}"
PRESERVED_ID="${PRESERVED_FPR: -16}"

for value in "${REPLACEMENT_FPR}" "${RETIRED_FPR}" "${PRESERVED_FPR}" "${STRANGER_FPR}" \
	"${UNPROTECTED_FPR}"; do
	[ -n "${value}" ] || {
		printf 'could not generate the fixture keys\n' >&2
		exit 1
	}
done
printf '  -- five throwaway keys generated\n'

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
# The unprotected key exports without a passphrase, because there is none.
GNUPGHOME="${fixture_home}" gpg --batch --quiet --armor \
	--export-secret-keys "${UNPROTECTED_FPR}" >"${tmp_dir}/unprotected-secret.asc"
[ -s "${tmp_dir}/unprotected-secret.asc" ] || {
	printf 'the unprotected fixture key was not exported\n' >&2
	exit 1
}

show_keys_isolated() {
	# `--show-keys` needs no keyring, and running it against ${fixture_home} races
	# the keybox lock the fixture helpers leave behind: the call comes back empty
	# and the assertion built on it silently inverts. Its own home, every time.
	local home="${tmp_dir}/show-keys-gnupg"
	mkdir -p "${home}"
	chmod 700 "${home}"
	GNUPGHOME="${home}" gpg --batch --no-tty --quiet --show-keys --with-colons "$1" 2>/dev/null || true
}

revoked_export() {
	# revoked_export <public-key-file> <revocation-file> <out>
	#
	# The public half with its own revocation already applied: what the retired
	# key's material looks like once the retirement has been published, and what
	# the replacement's material must never look like while production is signing
	# with it.
	local home="${tmp_dir}/revoked-export-gnupg"
	rm -rf "${home}"
	mkdir -p "${home}"
	chmod 700 "${home}"
	GNUPGHOME="${home}" gpg --batch --quiet --import "$1" 2>/dev/null
	GNUPGHOME="${home}" gpg --batch --quiet --import "$2" 2>/dev/null
	GNUPGHOME="${home}" gpg --batch --quiet --armor --export >"$3" 2>/dev/null
	GNUPGHOME="${home}" gpgconf --kill all >/dev/null 2>&1 || true
	rm -rf "${home}"
	[ -s "$3" ] || {
		printf 'could not build a pre-revoked export\n' >&2
		exit 1
	}
}

corrupt_certificate() {
	# A revocation certificate whose packet structure survives and whose issuer
	# subpacket still names the right key, but whose signature no longer checks
	# out: what a bit-rotted or truncated certificate looks like from the
	# outside. `gpg --show-keys` reports the `rvs` record and the expected key id
	# for this file exactly as it does for the good one, which is why an id
	# comparison cannot be the whole check.
	GNUPGHOME="${fixture_home}" gpg --dearmor <"$1" >"${tmp_dir}/dearmored.bin" 2>/dev/null
	python3 - "${tmp_dir}/dearmored.bin" "$2" <<'CORRUPT'
import sys

data = bytearray(open(sys.argv[1], "rb").read())
# Late enough to land inside the signature MPI rather than in the header or the
# hashed subpackets, so the issuer id the id check reads is left intact.
data[-3] ^= 0xFF
open(sys.argv[2], "wb").write(bytes(data))
CORRUPT
	rm -f "${tmp_dir}/dearmored.bin"
}

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

server_url=""
start_server() {
	# Sets ${server_url}, deliberately rather than printing it: a function whose
	# result has to be captured with $(...) cannot register the PID it spawned,
	# because the registration dies with the subshell. Reads the bound port off
	# the server's own stdout rather than picking one, so cases never race each
	# other for a port.
	local state="$1"
	shift
	mkdir -p "${state}"
	local portfile="${state}/port"
	python3 "${mock_server}" --state "${state}" "$@" >"${portfile}" 2>"${state}/log" &
	local pid=$!
	servers+=("${pid}")
	printf '%s\n' "${pid}" >"${state}/pid"
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
	server_url="hkp://127.0.0.1:${port}"
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

new_case 'a file gpg cannot decode stops validation instead of being skipped'
# Silently walking past anything that is not key-shaped is how a truncated
# export, or a passphrase left in the same directory as the key it protects,
# gets reported as a sound handoff directory.
with_note="${tmp_dir}/handoff-with-note"
cp -r "${good}" "${with_note}"
printf 'remember: the passphrase is in the other vault\n' >"${with_note}/README.txt"
run_handoff validate --handoff "${with_note}"
[ "${last_status}" != 0 ] || fail 'a handoff directory holding an undecodable file validated'
grep -q "cannot decode" <<<"${last_output}" \
	|| fail "the failure does not say the file could not be decoded: ${last_output}"
grep -q "README.txt" <<<"${last_output}" \
	|| fail 'the failure does not name the file'

new_case 'a truncated key is caught by the same refusal, not mistaken for a note'
truncated="${tmp_dir}/handoff-truncated"
cp -r "${good}" "${truncated}"
head -c 200 "${good}/preserved-secret.asc" >"${truncated}/preserved-secret.asc"
run_handoff validate --handoff "${truncated}"
[ "${last_status}" != 0 ] || fail 'a handoff holding a truncated secret key validated'
grep -q "cannot decode" <<<"${last_output}" \
	|| fail "a truncated key was not reported as undecodable: ${last_output}"

new_case '--allow-note acknowledges one named file, and only that one'
run_handoff validate --handoff "${with_note}" --allow-note "${with_note}/README.txt"
[ "${last_status}" = 0 ] || fail "an acknowledged note still blocked validation: ${last_output}"
printf 'and another one\n' >"${with_note}/NOTES.txt"
run_handoff validate --handoff "${with_note}" --allow-note "${with_note}/README.txt"
[ "${last_status}" != 0 ] || fail 'acknowledging one file waved a second one through'
grep -q "NOTES.txt" <<<"${last_output}" \
	|| fail 'the failure does not name the unacknowledged file'
rm -f "${with_note}/NOTES.txt"

new_case '--allow-note matches the file, not the spelling of its path'
# A relative path, a `..` and a symlink all have to reach the same answer, or
# the acknowledgement is a string comparison wearing a check's clothes.
run_handoff validate --handoff "${with_note}" \
	--allow-note "${with_note}/../$(basename "${with_note}")/README.txt"
[ "${last_status}" = 0 ] || fail "an acknowledgement spelled with .. was not recognised: ${last_output}"

new_case 'a file in the handoff directory that cannot be read is refused'
if [ "$(id -u)" = 0 ]; then
	printf '    -- skipped: running as root, where file modes prove nothing\n'
else
	unreadable="${tmp_dir}/handoff-unreadable"
	cp -r "${good}" "${unreadable}"
	chmod 000 "${unreadable}/replacement-public.asc"
	run_handoff validate --handoff "${unreadable}"
	chmod 644 "${unreadable}/replacement-public.asc"
	[ "${last_status}" != 0 ] || fail 'a handoff holding an unreadable file validated'
	grep -q "cannot read" <<<"${last_output}" \
		|| fail "the failure does not say the file could not be read: ${last_output}"
fi

new_case 'a dangling symlink in the handoff directory is refused'
# `find -type f` walks straight past one, so the directory would inventory clean
# while holding a pointer at material that is not there.
dangling="${tmp_dir}/handoff-dangling"
cp -r "${good}" "${dangling}"
ln -s "${dangling}/gone.asc" "${dangling}/replacement-backup.asc"
run_handoff validate --handoff "${dangling}"
[ "${last_status}" != 0 ] || fail 'a handoff holding a dangling symlink validated'
grep -q "not a regular file\|cannot read" <<<"${last_output}" \
	|| fail "the failure does not account for the symlink: ${last_output}"

new_case 'a revocation certificate that names the right key but cannot revoke it is refused'
# The gap an id comparison leaves open. `gpg --show-keys` reads the issuer out of
# the packet without checking the signature, so a certificate corrupted in
# storage reports the expected key id right up until the day it is needed.
corrupt_cert="${tmp_dir}/handoff-corrupt-replacement-cert"
cp -r "${good}" "${corrupt_cert}"
corrupt_certificate "${good}/replacement-revocation.asc" \
	"${corrupt_cert}/replacement-revocation.asc"
# The premise this case rests on: the corrupted certificate still reports the
# replacement key id, exactly as the good one does. Without that it would only be
# proving that unreadable files are rejected, which is a different case.
show_keys_isolated "${corrupt_cert}/replacement-revocation.asc" \
	| grep -qi "^rvs:.*${REPLACEMENT_ID}" \
	|| fail 'the corrupted certificate no longer names the replacement key, so this case proves nothing'
run_handoff validate --handoff "${corrupt_cert}"
[ "${last_status}" != 0 ] || fail 'a replacement revocation certificate that cannot revoke anything validated'
grep -q "does not check out\|still reporting the key as live" <<<"${last_output}" \
	|| fail "the failure does not distinguish naming from revoking: ${last_output}"

new_case 'a replacement key that already carries a revocation is refused'
# Two failures wearing one face. The replacement is what production signs with,
# so a revoked copy of it in the handoff means the wrong key was handed off or
# the live one has been retired without anyone saying so -- and in that state the
# certificate cannot be checked at all, because importing it into a keyring that
# already reports the key revoked changes nothing observable. The first draft
# read that as "nothing to do here" and moved on.
prerevoked_repl="${tmp_dir}/handoff-prerevoked-replacement"
cp -r "${good}" "${prerevoked_repl}"
revoked_export "${good}/replacement-public.asc" "${good}/replacement-revocation.asc" \
	"${prerevoked_repl}/replacement-public.asc"
run_handoff validate --handoff "${prerevoked_repl}"
[ "${last_status}" != 0 ] \
	|| fail "a handoff whose replacement key is already revoked validated: ${last_output}"
grep -q "already reports" <<<"${last_output}" \
	|| fail "the failure does not say the key arrived revoked: ${last_output}"
grep -q "stays unproved\|which key is actually live" <<<"${last_output}" \
	|| fail "the failure does not say the certificate went unchecked: ${last_output}"

new_case 'an already-revoked retired key passes, and the run says what it did not check'
# The other side of the same rule. The retired key carrying its revocation is
# the end state this whole procedure is pushing towards, so an operator
# re-running validate after publication must not be stopped by success -- but
# the certificate was not checked in that state either, and the run has to say
# so rather than print the line that means it was.
prerevoked_retired="${tmp_dir}/handoff-prerevoked-retired"
cp -r "${good}" "${prerevoked_retired}"
revoked_export "${good}/retired-public.asc" "${good}/retired-revocation.asc" \
	"${prerevoked_retired}/retired-public.asc"
run_handoff validate --handoff "${prerevoked_retired}"
[ "${last_status}" = 0 ] \
	|| fail "an already-published retirement was treated as a broken handoff: ${last_output}"
grep -q "NOT proved usable" <<<"${last_output}" \
	|| fail "the run claims more about the retired certificate than it checked: ${last_output}"
grep -q "Not proved by this run" <<<"${last_output}" \
	|| fail 'the closing summary does not repeat what went unchecked'
grep -q "the revocation certificate actually revokes ${RETIRED_ID}" <<<"${last_output}" \
	&& fail 'the run claimed it proved a certificate it never imported'

new_case 'the same holds for the retired key certificate'
corrupt_retired="${tmp_dir}/handoff-corrupt-retired-cert"
cp -r "${good}" "${corrupt_retired}"
corrupt_certificate "${good}/retired-revocation.asc" \
	"${corrupt_retired}/retired-revocation.asc"
run_handoff validate --handoff "${corrupt_retired}"
[ "${last_status}" != 0 ] || fail 'a retired revocation certificate that cannot revoke anything validated'

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
# And before anything was imported or unlocked. The right refusal after the
# operator has already fetched a passphrase out of a vault is the wrong moment.
grep -q "unlocks with the separately stored passphrase" <<<"${last_output}" \
	&& fail 'the missing flag was only noticed after the replacement key had been unlocked'

new_case 'verify-backup refuses a passphrase that was never in a backup'
# The acceptance criterion is that the passphrase is retrievable from its own
# backup. A passphrase held in the operator's head satisfies the signing test and
# none of the criterion, and this command's closing sentence is what the local
# copies get deleted on.
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'verify-backup ran with no passphrase backup named'
grep -q -- "--passphrase-backup PATH is required" <<<"${last_output}" \
	|| fail "the failure does not demand the passphrase backup: ${last_output}"
grep -q -- "--check-unlock" <<<"${last_output}" \
	|| fail 'the failure does not point at the command that does accept a typed passphrase'

new_case 'and refuses it on a terminal too, where the prompt would otherwise fire'
if command -v script >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
	# Under a real pty, a version that still prompted would sit on `read` for
	# ever rather than fail, and a suite that hangs in CI is worse than one that
	# reports. The timeout converts that into a case failure with the transcript
	# attached.
	set +e
	timeout 30 script -qec "KEY_HANDOFF_ALLOW_CI=${KEY_HANDOFF_ALLOW_CI} \
		KEY_HANDOFF_REPLACEMENT_KEY=${KEY_HANDOFF_REPLACEMENT_KEY} \
		KEY_HANDOFF_RETIRED_KEY=${KEY_HANDOFF_RETIRED_KEY} \
		KEY_HANDOFF_PRESERVED_KEY=${KEY_HANDOFF_PRESERVED_KEY} \
		${handoff} verify-backup --private-backup ${backup_key}/replacement.asc \
		--preserved-backup ${backup_key}/preserved.asc" /dev/null >"${tmp_dir}/tty-out" 2>&1
	tty_status=$?
	set -e
	[ "${tty_status}" != 124 ] \
		|| fail 'verify-backup sat waiting for a passphrase at a terminal prompt instead of refusing'
	[ "${tty_status}" != 0 ] \
		|| fail "verify-backup prompted for a passphrase and called the result backup retrieval: $(cat "${tmp_dir}/tty-out")"
	grep -q -- "--passphrase-backup PATH is required" "${tmp_dir}/tty-out" \
		|| fail "the terminal route does not give the same refusal: $(cat "${tmp_dir}/tty-out")"
else
	printf '    -- skipped: no script(1) and timeout(1) to allocate a pty safely\n'
fi

new_case 'validate --check-unlock is the place a typed passphrase is honest'
# Same passphrase, different claim: this one is about the handoff original, which
# is a thing a prompt can support. It is refused on verify-backup by name.
run_handoff verify-backup --check-unlock \
	--private-backup "${backup_key}/replacement.asc" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail '--check-unlock was accepted on verify-backup'
grep -q "belongs to validate" <<<"${last_output}" \
	|| fail "the refusal does not say where the flag belongs: ${last_output}"
# And it does work on validate, reading the passphrase from a file because this
# suite has no terminal to type at.
run_handoff validate --handoff "${good}" --check-unlock \
	--passphrase-backup "${backup_pass}/passphrase.txt"
[ "${last_status}" = 0 ] || fail "validate --check-unlock failed on a good handoff: ${last_output}"
grep -q "says nothing about any backup" <<<"${last_output}" \
	|| fail 'validate --check-unlock does not disclaim what it has not proved'

new_case 'an unencrypted secret-key backup is refused, not called unlocked'
# gpg signs with an unprotected key without ever reading --passphrase-file, so
# the nonce-signing proof succeeds against any passphrase at all -- including one
# belonging to a different key. The run would report retrieval proven over a
# private key sitting in the backup in the clear.
set +e
env KEY_HANDOFF_REPLACEMENT_KEY="${UNPROTECTED_ID}" "${handoff}" verify-backup \
	--private-backup "${tmp_dir}/unprotected-secret.asc" \
	--passphrase-backup "${wrong_pass_dir}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc" \
	>"${tmp_dir}/bare-out" 2>&1
bare_status=$?
set -e
[ "${bare_status}" != 0 ] \
	|| fail "an unprotected secret key plus an unrelated passphrase verified: $(cat "${tmp_dir}/bare-out")"
grep -q "not passphrase-protected" "${tmp_dir}/bare-out" \
	|| fail "the failure does not name the missing protection: $(cat "${tmp_dir}/bare-out")"

new_case 'the handoff original cannot be passed off as the private-key backup'
# The rule the missing-flag message has stated since the first draft, and which
# nothing enforced: verifying the original proves the file you already have is
# readable, and nothing about the copy you are about to rely on.
run_handoff verify-backup --handoff "${good}" \
	--private-backup "${good}/replacement-secret.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'the handoff original was accepted as its own backup'
grep -q "inside the handoff directory" <<<"${last_output}" \
	|| fail "the failure does not say where the file came from: ${last_output}"

new_case 'nor can a symlink or a .. path that lands back inside it'
alias_dir="${tmp_dir}/backup-alias"
mkdir -p "${alias_dir}"
ln -sf "${good}/replacement-secret.asc" "${alias_dir}/replacement.asc"
run_handoff verify-backup --handoff "${good}" \
	--private-backup "${alias_dir}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'a symlink into the handoff directory was accepted as a backup'
grep -q "inside the handoff directory" <<<"${last_output}" \
	|| fail "the symlink was not resolved before the check: ${last_output}"
run_handoff verify-backup --handoff "${good}" \
	--private-backup "${backup_key}/../$(basename "${good}")/replacement-secret.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'a .. path into the handoff directory was accepted as a backup'

new_case 'the preserved backup and the passphrase backup face the same rule'
run_handoff verify-backup --handoff "${good}" \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${good}/preserved-secret.asc"
[ "${last_status}" != 0 ] || fail 'the preserved handoff original was accepted as its own backup'
grep -q "preserved-key backup" <<<"${last_output}" \
	|| fail "the failure does not name the preserved backup: ${last_output}"
run_handoff verify-backup --handoff "${good}" \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${good}/../$(basename "${good}")/replacement-public.asc" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] || fail 'a passphrase path inside the handoff directory was accepted'

new_case 'the preserved key and its passphrase in one directory is refused'
# The separation rule is per key, not per run. Keeping the replacement backup
# somewhere else was enough to satisfy the first draft while D8BC04E534E7706F --
# which the rotation moved onto the replacement's passphrase -- sat in the
# passphrase's own directory. Whoever copies that directory gets a usable key
# and the passphrase that opens it, which is the entire thing this check is for.
cp "${good}/preserved-secret.asc" "${backup_pass}/preserved.asc"
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_pass}/preserved.asc"
rm -f "${backup_pass}/preserved.asc"
[ "${last_status}" != 0 ] \
	|| fail 'the preserved key and the passphrase that opens it shared a directory and the run passed'
grep -q "same directory" <<<"${last_output}" \
	|| fail "the failure does not name the shared directory: ${last_output}"
grep -q "preserved-key backup" <<<"${last_output}" \
	|| fail "the failure does not say which key it is about: ${last_output}"
grep -q "Retrieval is proven" <<<"${last_output}" \
	&& fail 'the run reached its closing claim anyway'

new_case 'and the same file, by the same rule'
together_preserved="${tmp_dir}/backup-vault-preserved-together"
mkdir -p "${together_preserved}"
cp "${good}/preserved-secret.asc" "${together_preserved}/both.asc"
run_handoff verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${together_preserved}/both.asc" \
	--preserved-backup "${together_preserved}/both.asc"
[ "${last_status}" != 0 ] || fail 'one file holding the preserved key and the passphrase was accepted'
grep -q "same file" <<<"${last_output}" \
	|| fail "the failure does not name the shared file: ${last_output}"

new_case 'a real backup still verifies with the handoff directory named'
# The refusal above must not have made the ordinary run unusable: the whole
# point is that backups live somewhere else, and naming --handoff as well is
# what an operator working through the runbook in order will do.
run_handoff verify-backup --handoff "${good}" \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" = 0 ] || fail "a genuine backup was refused alongside --handoff: ${last_output}"
grep -q "Retrieval is proven" <<<"${last_output}" \
	|| fail 'the successful run no longer says so'

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
start_server "${state_dry}"
url_dry="${server_url}"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_dry}"
[ "${last_status}" = 0 ] || fail "verify-only failed on a valid revocation: ${last_output}"
grep -q "is revoked in the local keyring" <<<"${last_output}" \
	|| fail 'the local revocation was not proved'
grep -q "Nothing was uploaded" <<<"${last_output}" \
	|| fail 'verify-only did not say it published nothing'
[ "$(upload_count "${state_dry}")" = 0 ] \
	|| fail 'verify-only uploaded a key'

new_case 'publish-revocation says so too when the key arrives already revoked'
# The same rule as validate's, in the other command that imports a certificate.
# Publishing an already-revoked key is still right -- what reaches the keyserver
# is revoked either way -- but the certificate was not what put the revocation
# there, and the closing sentence is what the operator reads as evidence.
prepublished="${tmp_dir}/handoff-prepublished"
cp -r "${good}" "${prepublished}"
revoked_export "${good}/retired-public.asc" "${good}/retired-revocation.asc" \
	"${prepublished}/retired-public.asc"
state_pre="${tmp_dir}/server-prerevoked"
start_server "${state_pre}"
run_handoff publish-revocation --handoff "${prepublished}" --keyserver "${server_url}"
[ "${last_status}" = 0 ] \
	|| fail "a re-run after publication was treated as a broken handoff: ${last_output}"
grep -q "NOT exercised by this run" <<<"${last_output}" \
	|| fail "the run claims the certificate was proved when it was not: ${last_output}"
grep -q "by the certificate this run imported" <<<"${last_output}" \
	&& fail 'the run credits the certificate for a revocation that was already there'
[ "$(upload_count "${state_pre}")" = 0 ] || fail 'verify-only uploaded a key'

new_case '--dry-run beats --confirm-publish'
# Belt and braces: an operator who pastes a command with both should get the
# safe one. The unsafe combination is the one worth pinning down.
state_both="${tmp_dir}/server-both"
start_server "${state_both}"
url_both="${server_url}"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_both}" \
	--confirm-publish --dry-run
[ "${last_status}" = 0 ] || fail "the safe combination errored: ${last_output}"
[ "$(upload_count "${state_both}")" = 0 ] \
	|| fail '--dry-run uploaded anyway'

new_case 'a revocation certificate for another key is refused before any upload'
state_wrong="${tmp_dir}/server-wrong-cert"
start_server "${state_wrong}"
url_wrong="${server_url}"
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
start_server "${state_ok}"
url_ok="${server_url}"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_ok}" --confirm-publish
[ "${last_status}" = 0 ] || fail "a valid publication failed: ${last_output}"
[ "$(upload_count "${state_ok}")" -ge 1 ] || fail 'nothing was uploaded'
grep -q "reports it revoked" <<<"${last_output}" \
	|| fail 'the fetch-back did not assert the revoked state'

new_case 'the fetch-back reads from a keyring that has never seen the key'
# Otherwise the check is self-fulfilling: the keyring used to publish already
# holds the revoked key, so a keyserver serving nothing at all would pass.
state_empty="${tmp_dir}/server-empty"
start_server "${state_empty}" --not-found
url_empty="${server_url}"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_empty}" --confirm-publish
[ "${last_status}" != 0 ] || fail 'publication succeeded against a keyserver serving nothing back'
grep -q "did not serve" <<<"${last_output}" \
	|| fail "the failure does not say the key was not served: ${last_output}"

new_case 'a keyserver that serves the key back unrevoked fails the run'
# The case the whole fetch-back exists for. keys.openpgp.org and
# keyserver.ubuntu.com both 200 an upload they have not finished applying.
state_stale="${tmp_dir}/server-stale"
start_server "${state_stale}" --serve "${good}/retired-public.asc"
url_stale="${server_url}"
run_handoff publish-revocation --handoff "${good}" --keyserver "${url_stale}" --confirm-publish
[ "${last_status}" != 0 ] || fail 'a keyserver still handing out the live key was accepted'
grep -q "does NOT report it revoked" <<<"${last_output}" \
	|| fail "the failure does not distinguish served-but-live: ${last_output}"
[ "$(upload_count "${state_stale}")" -ge 1 ] \
	|| fail 'the case did not actually get as far as uploading'

new_case 'an upload failure is not reported as publication'
state_reject="${tmp_dir}/server-reject"
start_server "${state_reject}" --reject-upload
url_reject="${server_url}"
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

new_case 'nothing is written into the GnuPG home the operator owns'
# `gpg --show-keys` was the hole: every other call routes through a throwaway
# GNUPGHOME, but classification ran a bare gpg, which on a clean account creates
# pubring.kbx and trustdb.gpg in ~/.gnupg and on an established one takes that
# keyring's locks. The script has no business writing there at all.
sentinel_home="${tmp_dir}/sentinel-home"
sentinel_gnupg="${tmp_dir}/sentinel-gnupg"
mkdir -p "${sentinel_home}" "${sentinel_gnupg}"
chmod 700 "${sentinel_gnupg}"
set +e
env HOME="${sentinel_home}" GNUPGHOME="${sentinel_gnupg}" \
	"${handoff}" validate --handoff "${good}" >"${tmp_dir}/sentinel-out" 2>&1
sentinel_status=$?
set -e
[ "${sentinel_status}" = 0 ] \
	|| fail "validate failed against the sentinel home: $(cat "${tmp_dir}/sentinel-out")"
for sentinel in "${sentinel_home}" "${sentinel_gnupg}"; do
	left="$(find "${sentinel}" -mindepth 1 2>/dev/null)"
	[ -z "${left}" ] \
		|| fail "the run wrote into ${sentinel}, which belongs to the operator: ${left}"
done

new_case 'every mock keyserver this suite starts is registered and reaped'
# start_server used to be called as `url="$(start_server ...)"`, so the PID it
# recorded was recorded in a command-substitution subshell and thrown away with
# it. The trap read an empty array and every server a run started outlived the
# run. Asserted on the registration and on an actual kill, because "the array is
# non-empty" alone would have passed a version that appended the wrong thing.
registered_before="${#servers[@]}"
state_reap="${tmp_dir}/server-reap"
start_server "${state_reap}"
[ "${#servers[@]}" -gt "${registered_before}" ] \
	|| fail 'starting a mock keyserver did not register its PID in the parent shell'
reap_pid="${servers[-1]}"
kill -0 "${reap_pid}" 2>/dev/null || fail 'the registered PID is not a live process'
[ -f "${state_reap}/pid" ] || fail 'no pidfile was written for the spawned server'
[ "$(cat "${state_reap}/pid")" = "${reap_pid}" ] \
	|| fail 'the pidfile and the registered PID disagree'
reap_servers
reaped=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
	if ! kill -0 "${reap_pid}" 2>/dev/null; then
		reaped=1
		break
	fi
	sleep 0.1
done
[ "${reaped}" = 1 ] || fail 'reap_servers left the mock keyserver running'

new_case 'the suite cleans up its servers on interruption, not only on normal exit'
grep -qE "^\s*trap .* INT\b" "${BASH_SOURCE[0]}" \
	|| fail 'this suite does not trap SIGINT, so Ctrl-C leaves mock keyservers listening'
grep -q 'reap_servers' "${BASH_SOURCE[0]}" \
	|| fail 'nothing reaps the spawned servers'

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

# --- 6. portability -----------------------------------------------------------
# The runbook says an operator may run this on a Mac. This runner is not a Mac
# and never will be, so the honest thing is to model what a Mac withholds rather
# than to test on Linux and claim the difference away: no `sha256sum`, no
# `sort -z`, no `readlink -f`, and nothing else on PATH beyond what the script
# declares it needs. The declared list is read out of the script itself, so a
# future call to some coreutils convenience shows up here as a missing program
# rather than as a green run on the one platform that happens to have it.
printf '\n# 6. portability\n'

declared_tools="$(sed -n 's/^REQUIRED_TOOLS=(\(.*\))$/\1/p' "${handoff}")"
[ -n "${declared_tools}" ] || {
	printf 'could not read REQUIRED_TOOLS out of %s\n' "${handoff}" >&2
	exit 1
}

real_readlink="$(command -v readlink)"

build_bin() {
	# A PATH holding exactly the named tools and nothing else. `bash` and `env`
	# come along unasked because the shebang needs them before a line of the
	# script has run.
	local dir="$1"
	shift
	rm -rf "${dir}"
	mkdir -p "${dir}"
	local tool src
	for tool in "$@" bash env; do
		src="$(command -v "${tool}" 2>/dev/null || true)"
		[ -n "${src}" ] || continue
		ln -sf "${src}" "${dir}/${tool}"
	done
}

write_bsd_readlink() {
	# readlink as BSD and macOS have it: one link at a time, and the GNU
	# spellings are errors rather than quiet successes.
	#
	# Unlinked first, never written through: build_bin left a symlink to the
	# real readlink there, and `>` follows a symlink to its target.
	rm -f "$1/readlink"
	cat >"$1/readlink" <<SHIM
#!/bin/sh
case "\${1:-}" in
	-f | -e | -m | --canonicalize*)
		printf 'readlink: illegal option -- %s\n' "\$1" >&2
		exit 1
		;;
esac
[ "\${1:-}" = "--" ] && shift
exec ${real_readlink} "\$@"
SHIM
	chmod +x "$1/readlink"
}

run_portable() {
	# ${1} becomes the entire PATH. env -i so nothing of this suite's own
	# environment -- least of all a PATH pointing back at /usr/bin -- leaks in.
	local path="$1"
	shift
	set +e
	env -i PATH="${path}" HOME="${HOME}" TMPDIR="${tmp_dir}" \
		KEY_HANDOFF_ALLOW_CI="${KEY_HANDOFF_ALLOW_CI}" \
		KEY_HANDOFF_REPLACEMENT_KEY="${KEY_HANDOFF_REPLACEMENT_KEY}" \
		KEY_HANDOFF_RETIRED_KEY="${KEY_HANDOFF_RETIRED_KEY}" \
		KEY_HANDOFF_PRESERVED_KEY="${KEY_HANDOFF_PRESERVED_KEY}" \
		bash "${handoff}" "$@" >"${tmp_dir}/portable-out" 2>&1
	last_status=$?
	set -e
	last_output="$(cat "${tmp_dir}/portable-out")"
}

bsd_bin="${tmp_dir}/bsd-bin"
# shellcheck disable=SC2086 # the declared list is a word list on purpose
build_bin "${bsd_bin}" ${declared_tools}
write_bsd_readlink "${bsd_bin}"

new_case 'the script runs with nothing on PATH but the tools it declares'
run_portable "${bsd_bin}" validate --handoff "${good}"
[ "${last_status}" = 0 ] \
	|| fail "validate needs something it does not declare: ${last_output}"
run_portable "${bsd_bin}" verify-backup \
	--private-backup "${backup_key}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" = 0 ] \
	|| fail "verify-backup needs something it does not declare: ${last_output}"
grep -q "byte-identical" <<<"${last_output}" \
	|| fail 'the before/after digest did not run without sha256sum'

new_case 'a readlink with no -f does not weaken the handoff-original refusal'
# The check this all exists for. `readlink -f ... || printf %s "$1"` answers with
# its own input where -f is not understood, so the refusal that rejects a
# symlink pointing back into the handoff directory would compare the path
# against itself and let it through -- on the one platform nobody here can test
# by accident.
run_portable "${bsd_bin}" verify-backup --handoff "${good}" \
	--private-backup "${alias_dir}/replacement.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] \
	|| fail 'a symlink into the handoff directory was accepted where readlink has no -f'
grep -q "inside the handoff directory" <<<"${last_output}" \
	|| fail "the symlink was not resolved without readlink -f: ${last_output}"
run_portable "${bsd_bin}" verify-backup --handoff "${good}" \
	--private-backup "${backup_key}/../$(basename "${good}")/replacement-secret.asc" \
	--passphrase-backup "${backup_pass}/passphrase.txt" \
	--preserved-backup "${backup_key}/preserved.asc"
[ "${last_status}" != 0 ] \
	|| fail 'a .. path into the handoff directory was accepted where readlink has no -f'

new_case 'a canonicaliser that answers with its own input stops the run'
# Not a platform, a shape: the fallback the script used to have, and the shim an
# operator writes to make an error message go away. It has to be caught by the
# script rather than trusted, and caught before any handoff material is read.
lying_bin="${tmp_dir}/lying-bin"
# shellcheck disable=SC2086 # the declared list is a word list on purpose
build_bin "${lying_bin}" ${declared_tools}
rm -f "${lying_bin}/readlink"
cat >"${lying_bin}/readlink" <<'SHIM'
#!/bin/sh
for arg in "$@"; do :; done
printf '%s\n' "${arg}"
SHIM
chmod +x "${lying_bin}/readlink"
run_portable "${lying_bin}" validate --handoff "${good}"
[ "${last_status}" != 0 ] \
	|| fail 'a readlink that resolves nothing was good enough to validate a handoff'
grep -q "path canonicalisation does not work" <<<"${last_output}" \
	|| fail "the refusal does not name the broken primitive: ${last_output}"
grep -q "inventoried" <<<"${last_output}" \
	&& fail 'handoff material was read before the path primitives were checked'

new_case 'a declared tool that is missing is named, before anything is read'
missing_bin="${tmp_dir}/missing-bin"
# shellcheck disable=SC2086 # the declared list is a word list on purpose
build_bin "${missing_bin}" ${declared_tools}
rm -f "${missing_bin}/od"
run_portable "${missing_bin}" validate --handoff "${good}"
[ "${last_status}" != 0 ] || fail 'the script ran with a declared tool missing'
grep -q " od" <<<"${last_output}" || fail "the failure does not name od: ${last_output}"
grep -q "Nothing has been read yet" <<<"${last_output}" \
	|| fail 'the failure does not say it stopped before reading anything'

new_case 'no GNU-only spelling survives in the script, in any branch'
# The PATH cases above only cover the code they reach. This covers the rest:
# a `sha256sum` on an error path nothing in this suite triggers is still a
# `sha256sum` that is not there on the day.
script_code="$(grep -vE '^[[:space:]]*#' "${handoff}")"
for gnuism in 'readlink -f' 'readlink -e' 'readlink -m' 'sha256sum' 'sha1sum' \
	'sort -z' 'stat -c' 'date -d' 'sed -i' 'cp -T' 'grep -P'; do
	if grep -qF -- "${gnuism}" <<<"${script_code}"; then
		fail "the script uses ${gnuism}, which a stock macOS or BSD userland does not have"
	fi
done

new_case 'the declared tool list is the one the capability check reads'
# Two copies of one fact otherwise: the list above drives every case in this
# section, and a check that walked some other list would leave them testing
# nothing.
# shellcheck disable=SC2016 # the literal shell source is the thing being matched
grep -q 'for tool in "\${REQUIRED_TOOLS\[@\]}"' "${handoff}" \
	|| fail 'the capability check no longer iterates REQUIRED_TOOLS, so this section proves nothing'

# --- result -------------------------------------------------------------------
printf '\n'
if [ "${failures}" -gt 0 ]; then
	printf 'key-handoff: %d case(s) failed\n' "${failures}" >&2
	exit 1
fi
printf 'key-handoff: all cases passed\n'
