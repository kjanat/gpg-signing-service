#!/usr/bin/env bash
# Local-operator path for the two #147 items that cannot be finished from this
# repository or from CI: proving the replacement credentials are restorable from
# backup, and publishing the retired key's revocation.
#
# Both need the offline handoff material under .keys/rotation-20260908, which is
# deliberately absent from every checkout (.gitignore excludes .keys/) and must
# stay absent. This script is the procedure, not the material.
#
#   key-handoff.sh validate            structural check of the handoff directory
#   key-handoff.sh verify-backup       restore the backups and prove they work
#   key-handoff.sh publish-revocation  publish the retired key's revocation
#   key-handoff.sh verify-published    fetch the retired key back and re-check
#
# Everything is fail-closed: an unreadable file, an unexpected key id, a
# passphrase that does not unlock, a keyserver that will not serve the key back
# as revoked -- each is an error, never a warning. Nothing writes to the handoff
# directory or to the backups; every import lands in a throwaway GNUPGHOME that
# is removed on exit.
#
# What this script will never do: generate a key, generate a revocation
# certificate, or read a passphrase from the command line. See ADR-004 and
# docs/key-handoff-runbook.md.
set -euo pipefail

# --- production identities ----------------------------------------------------
# Public key ids. These appear in wrangler.toml, in the audit trail and on every
# signature the keys ever made; they are identifiers, not secrets. Overridable so
# the test suite can drive the same code with throwaway keys.
REPLACEMENT_KEY="${KEY_HANDOFF_REPLACEMENT_KEY:-AFD5E3EC68371856}"
RETIRED_KEY="${KEY_HANDOFF_RETIRED_KEY:-62E75E54497815DD}"
PRESERVED_KEY="${KEY_HANDOFF_PRESERVED_KEY:-D8BC04E534E7706F}"

# ADR-004's intended public distribution path. keys.openpgp.org distributes
# revocations without the email round-trip it requires for user ids, which is
# what makes it usable here; keyserver.ubuntu.com is the second target because
# it is what most verifiers' gpg still defaults to.
DEFAULT_KEYSERVERS=("hkps://keys.openpgp.org" "hkps://keyserver.ubuntu.com")

HANDOFF_DIR="${KEY_HANDOFF_DIR:-.keys/rotation-20260908}"

usage() {
	cat <<'EOF'
Usage: key-handoff.sh <command> [options]

Commands:
  validate            Structurally check the offline handoff directory.
  verify-backup       Restore the operator's backups into an isolated keyring
                      and prove the replacement key imports, unlocks and is the
                      expected key, and that the preserved key is recoverable.
  publish-revocation  Apply the existing offline revocation certificate for the
                      retired key, prove it is revoked locally, publish the
                      revoked public key, then fetch it back and re-prove it.
                      Verify-only unless --confirm-publish is given.
  verify-published    Fetch the retired key from each target into a fresh
                      keyring and assert it is observably revoked. No upload.

Options:
  --handoff DIR            Handoff directory (default: .keys/rotation-20260908)
  --private-backup PATH    Restored copy of the replacement secret key
  --passphrase-backup PATH File holding the passphrase, from its own location
  --preserved-backup PATH  Restored copy of the preserved D8BC04E534E7706F key
  --retired-public PATH    Retired public key, if not found in the handoff dir
  --revocation PATH        Retired key's revocation certificate, if not found
  --keyserver URL          Publication target; repeatable, replaces defaults
  --confirm-publish        Actually upload. Without it, nothing leaves the host.
  --dry-run                Never upload, even with --confirm-publish.
  -h, --help               This text.

Secrets are never taken as arguments. The passphrase is read from the file named
by --passphrase-backup, or from KEY_HANDOFF_PASSPHRASE_FILE, or prompted for on
the terminal. It is never placed on a command line, in an environment variable
that a child process inherits, or in any output.

This script refuses to run under CI. See docs/key-handoff-runbook.md.
EOF
}

# --- output -------------------------------------------------------------------
# Everything printed here is a role, a key id, a fingerprint or a path. Key
# material, passphrases and revocation certificate contents are never printed,
# hashed into output, or written anywhere outside the throwaway keyring.
fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}
ok() { printf '  ok - %s\n' "$1"; }
note() { printf '  -- %s\n' "$1"; }
section() { printf '\n# %s\n' "$1"; }

# --- CI refusal ---------------------------------------------------------------
# The handoff material is offline on purpose. A runner that has it has already
# lost the property this script exists to protect, so the refusal lands before
# anything reads a file or opens a socket, and cannot be turned off by a flag --
# only by an environment variable whose value is a sentence the operator had to
# mean. `--help` is deliberately still reachable: a refusal that hides the
# documentation teaches nobody why it refused.
CI_OVERRIDE_SENTINEL='yes-i-am-a-local-operator'
refuse_ci() {
	local marker=""
	for var in CI GITHUB_ACTIONS GITLAB_CI BUILDKITE CIRCLECI JENKINS_URL TF_BUILD; do
		if [ -n "${!var:-}" ]; then
			marker="$var"
			break
		fi
	done
	[ -n "$marker" ] || return 0
	if [ "${KEY_HANDOFF_ALLOW_CI:-}" = "$CI_OVERRIDE_SENTINEL" ]; then
		note "CI detected via \$$marker; running anyway on the local-operator override"
		return 0
	fi
	fail "refusing to run: \$$marker is set, so this looks like CI. The handoff material is offline by design and must not reach a runner. If this really is a local shell that happens to export \$$marker, set KEY_HANDOFF_ALLOW_CI=${CI_OVERRIDE_SENTINEL}."
}

# --- isolated keyrings --------------------------------------------------------
WORK=""
cleanup() {
	# Kill the agents first: gpg-agent holds a socket inside the directory and
	# an unlocked copy of whatever was imported, and removing the directory out
	# from under it leaves the process alive with the key still in memory.
	if [ -n "$WORK" ]; then
		for home in "$WORK"/gnupg-*; do
			[ -d "$home" ] || continue
			GNUPGHOME="$home" gpgconf --kill all >/dev/null 2>&1 || true
		done
		rm -rf "$WORK"
	fi
}

new_keyring() {
	# A fresh GNUPGHOME per proof. "Fresh" is the whole point of the fetch-back
	# check: a keyring that already holds the revoked key would report success
	# without the keyserver having served anything.
	local home
	home="$(mktemp -d "$WORK/gnupg-XXXXXX")"
	chmod 700 "$home"
	printf 'no-tty\nbatch\n' >"$home/gpg.conf"
	printf '%s' "$home"
}

gpg_in() {
	local home="$1"
	shift
	GNUPGHOME="$home" gpg --batch --no-tty --quiet "$@"
}

# --- key identity helpers -----------------------------------------------------
# `gpg --show-keys --with-colons` reads a file without importing it and reports
# one record per key-shaped thing it finds: `sec` for secret key material, `pub`
# for public, `rvs` for a bare revocation signature. Field 5 is the long key id
# and, for `rvs`, field 13 is the fingerprint of the key being revoked. Parsing
# that is why this script never has to guess at filenames.
show_keys() {
	gpg --batch --no-tty --quiet --show-keys --with-colons "$1" 2>/dev/null || true
}

classify_file() {
	# Prints "ROLE KEYID" for each key-shaped record in the file, or nothing.
	local records
	records="$(show_keys "$1")"
	[ -n "$records" ] || return 0
	awk -F: '
		$1 == "sec" { print "secret " toupper($5) }
		$1 == "pub" { print "public " toupper($5) }
		$1 == "rvs" { print "revocation " toupper($5) }
	' <<<"$records"
}

key_id_matches() {
	# The handoff may name keys by long id while gpg reports the same; compare
	# case-insensitively and accept a fingerprint whose tail is the long id, so
	# an operator who wrote the full fingerprint somewhere is not punished.
	local have="${1^^}" want="${2^^}"
	[ "$have" = "$want" ] || [ "${have: -16}" = "${want: -16}" ]
}

# --- handoff inventory --------------------------------------------------------
# Populated by inventory_handoff: role -> newline-separated paths.
INV_SECRET=""
INV_PUBLIC=""
INV_REVOCATION=""

inventory_handoff() {
	local dir="$1" f role id line
	[ -d "$dir" ] || fail "handoff directory not found: $dir. This material is offline by design; point --handoff at the mounted copy."
	INV_SECRET=""
	INV_PUBLIC=""
	INV_REVOCATION=""
	local found=0
	while IFS= read -r -d '' f; do
		found=$((found + 1))
		while IFS= read -r line; do
			[ -n "$line" ] || continue
			role="${line%% *}"
			id="${line##* }"
			case "$role" in
				secret) INV_SECRET+="${id}"$'\t'"${f}"$'\n' ;;
				public) INV_PUBLIC+="${id}"$'\t'"${f}"$'\n' ;;
				revocation) INV_REVOCATION+="${id}"$'\t'"${f}"$'\n' ;;
			esac
		done < <(classify_file "$f")
	done < <(find "$dir" -type f -print0 | sort -z)
	[ "$found" -gt 0 ] || fail "handoff directory $dir holds no files"
	note "inventoried $found file(s) in $dir"
}

inventory_has() {
	# inventory_has <role-list> <key-id>
	local list="$1" want="$2" id
	while IFS=$'\t' read -r id _; do
		[ -n "$id" ] || continue
		if key_id_matches "$id" "$want"; then return 0; fi
	done <<<"$list"
	return 1
}

inventory_path() {
	local list="$1" want="$2" id path
	while IFS=$'\t' read -r id path; do
		[ -n "$id" ] || continue
		if key_id_matches "$id" "$want"; then
			printf '%s' "$path"
			return 0
		fi
	done <<<"$list"
	return 1
}

# --- backup-location hygiene --------------------------------------------------
distinct_locations() {
	# A passphrase stored next to the key it protects is one compromised backup,
	# not two. Same file is the obvious failure; same directory is the one that
	# actually happens, because a single `cp -r` of a folder takes both.
	local a="$1" b="$2"
	local ra rb
	ra="$(readlink -f "$a" 2>/dev/null || printf '%s' "$a")"
	rb="$(readlink -f "$b" 2>/dev/null || printf '%s' "$b")"
	[ "$ra" != "$rb" ] \
		|| fail "the private-key backup and the passphrase backup are the same file. Keep them in separate locations; a single backup holding both is a single point of compromise."
	[ "$(dirname "$ra")" != "$(dirname "$rb")" ] \
		|| fail "the private-key backup and the passphrase backup are in the same directory ($(dirname "$ra")). Anything that copies that directory copies both. Put the passphrase somewhere else entirely."
}

# --- passphrase acquisition ---------------------------------------------------
# The passphrase reaches gpg as a file path, never as an argument. /proc/*/cmdline
# is world-readable on Linux, so `--passphrase "$SECRET"` publishes it to every
# local user for the lifetime of the process; `--passphrase-file` does not.
PASSPHRASE_FILE=""
acquire_passphrase() {
	local supplied="${1:-}"
	local target="$WORK/passphrase"
	if [ -n "$supplied" ]; then
		[ -f "$supplied" ] || fail "passphrase backup not found: $supplied"
		[ -s "$supplied" ] || fail "passphrase backup is empty: $supplied"
		# First line only, trailing newline stripped: a passphrase written by an
		# editor almost always has one, and gpg would otherwise fold it in.
		head -n 1 "$supplied" | tr -d '\r\n' >"$target"
	elif [ -n "${KEY_HANDOFF_PASSPHRASE_FILE:-}" ]; then
		[ -f "$KEY_HANDOFF_PASSPHRASE_FILE" ] || fail "KEY_HANDOFF_PASSPHRASE_FILE points at nothing: $KEY_HANDOFF_PASSPHRASE_FILE"
		head -n 1 "$KEY_HANDOFF_PASSPHRASE_FILE" | tr -d '\r\n' >"$target"
	elif [ -t 0 ]; then
		local entered=""
		printf 'Passphrase for the replacement key (not echoed): ' >&2
		IFS= read -rs entered </dev/tty
		printf '\n' >&2
		printf '%s' "$entered" >"$target"
		unset entered
	else
		fail "no passphrase source. Give --passphrase-backup PATH, set KEY_HANDOFF_PASSPHRASE_FILE, or run this on a terminal so it can prompt. It is never accepted as a command-line argument."
	fi
	chmod 600 "$target"
	[ -s "$target" ] || fail "the passphrase source produced nothing"
	PASSPHRASE_FILE="$target"
}

# --- proofs -------------------------------------------------------------------
prove_unlock() {
	# Importing a secret key proves the file parses. It does not prove the
	# passphrase in the other backup is the passphrase for *this* key -- gpg
	# imports an encrypted secret key without ever touching the passphrase. The
	# only proof is making the key do work, so this signs a nonce and verifies
	# the result.
	local home="$1" keyid="$2" label="$3"
	local nonce="$WORK/nonce-$keyid"
	printf 'key-handoff unlock proof %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$nonce"
	gpg_in "$home" --pinentry-mode loopback --passphrase-file "$PASSPHRASE_FILE" \
		--local-user "$keyid" --detach-sign --output "$nonce.sig" "$nonce" 2>/dev/null \
		|| fail "$label ($keyid) did not unlock with the passphrase from the separate backup. Either the passphrase backup is stale or it belongs to a different key; this is exactly the failure the backup check exists to catch before the originals are deleted."
	gpg_in "$home" --verify "$nonce.sig" "$nonce" 2>/dev/null \
		|| fail "$label ($keyid) produced a signature its own public half will not verify"
	ok "$label unlocks with the separately stored passphrase and signs ($keyid)"
}

assert_imported_id() {
	local home="$1" want="$2" label="$3"
	local ids
	ids="$(gpg_in "$home" --list-keys --with-colons 2>/dev/null | awk -F: '$1=="pub"{print toupper($5)}' || true)"
	local id
	while IFS= read -r id; do
		[ -n "$id" ] || continue
		if key_id_matches "$id" "$want"; then
			ok "$label is $want, as expected"
			return 0
		fi
	done <<<"$ids"
	fail "$label is not $want. The keyring holds: ${ids//$'\n'/, }. Restoring the wrong key is indistinguishable from restoring no key."
}

is_revoked() {
	local home="$1" keyid="$2"
	gpg_in "$home" --list-keys --with-colons "$keyid" 2>/dev/null \
		| awk -F: -v want="${keyid^^}" '
			$1 == "pub" && (toupper($5) == want || substr(toupper($5), length(toupper($5)) - 15) == substr(want, length(want) - 15)) {
				if ($2 == "r") { found = 1 }
			}
			END { exit(found ? 0 : 1) }
		'
}

# --- commands -----------------------------------------------------------------
cmd_validate() {
	section "handoff structure: $HANDOFF_DIR"
	inventory_handoff "$HANDOFF_DIR"

	inventory_has "$INV_SECRET" "$REPLACEMENT_KEY" \
		|| fail "no secret key for the replacement $REPLACEMENT_KEY in $HANDOFF_DIR. Without it there is nothing to back up."
	ok "replacement secret key present ($REPLACEMENT_KEY)"

	if inventory_has "$INV_PUBLIC" "$REPLACEMENT_KEY"; then
		ok "replacement public key present ($REPLACEMENT_KEY)"
	else
		# The public half is derivable from the secret half, so its absence is
		# worth saying out loud but is not a reason to refuse.
		note "no standalone public key for $REPLACEMENT_KEY; it is derivable from the secret key, so this is not fatal"
	fi

	if inventory_has "$INV_REVOCATION" "$REPLACEMENT_KEY"; then
		ok "replacement revocation certificate present, and belongs to $REPLACEMENT_KEY"
	else
		fail "no revocation certificate for the replacement $REPLACEMENT_KEY. Losing it means the replacement can never be retired the way $RETIRED_KEY is being retired now."
	fi

	inventory_has "$INV_REVOCATION" "$RETIRED_KEY" \
		|| fail "no revocation certificate for the retired $RETIRED_KEY in $HANDOFF_DIR. This script will not generate one -- ADR-004 turns on publishing the certificate that already exists."
	ok "retired-key revocation certificate present, and belongs to $RETIRED_KEY"

	if inventory_has "$INV_PUBLIC" "$RETIRED_KEY" || inventory_has "$INV_SECRET" "$RETIRED_KEY"; then
		ok "retired public key material present, so the revocation has a key to travel on ($RETIRED_KEY)"
	else
		note "no retired public key in $HANDOFF_DIR; pass --retired-public PATH before publishing. Neither keyserver currently carries $RETIRED_KEY, so the revocation cannot be uploaded on its own."
	fi

	inventory_has "$INV_SECRET" "$PRESERVED_KEY" \
		|| fail "no preserved material for $PRESERVED_KEY. That key now shares the replacement's passphrase, so it is part of this handoff whether or not it was part of the rotation."
	ok "preserved key material present ($PRESERVED_KEY)"

	if [ -n "$PRIVATE_BACKUP" ] && [ -n "$PASSPHRASE_BACKUP" ]; then
		distinct_locations "$PRIVATE_BACKUP" "$PASSPHRASE_BACKUP"
		ok "the private-key backup and the passphrase backup are in separate locations"
	fi

	printf '\nvalidate: handoff structure is sound. This proves the material is present and internally consistent. It does not prove any of it was backed up.\n'
}

cmd_verify_backup() {
	section "backup retrieval: replacement $REPLACEMENT_KEY"
	[ -n "$PRIVATE_BACKUP" ] || fail "--private-backup PATH is required: point it at the copy read back out of the backup, not at the handoff directory. Verifying the original proves nothing about the backup."
	[ -f "$PRIVATE_BACKUP" ] || fail "private-key backup not found: $PRIVATE_BACKUP. A backup that cannot be read back is not a backup."
	[ -n "$PASSPHRASE_BACKUP" ] || [ -n "${KEY_HANDOFF_PASSPHRASE_FILE:-}" ] || [ -t 0 ] \
		|| fail "no passphrase source; see --help"
	if [ -n "$PASSPHRASE_BACKUP" ]; then
		distinct_locations "$PRIVATE_BACKUP" "$PASSPHRASE_BACKUP"
		ok "the private-key backup and the passphrase backup are in separate locations"
	fi

	# Fingerprint the originals before touching them, and again afterwards. The
	# operator is about to delete the local copies on the strength of this run,
	# so "left the originals untouched" has to be measured rather than asserted.
	local before after
	before="$(backup_digest)"

	acquire_passphrase "$PASSPHRASE_BACKUP"

	local home
	home="$(new_keyring)"
	gpg_in "$home" --import "$PRIVATE_BACKUP" 2>/dev/null \
		|| fail "the private-key backup at $PRIVATE_BACKUP did not import. It is corrupt, truncated, or not OpenPGP key material."
	ok "the private-key backup imports into a clean keyring"
	assert_imported_id "$home" "$REPLACEMENT_KEY" "the restored key"
	prove_unlock "$home" "$REPLACEMENT_KEY" "the restored replacement key"

	if [ -n "$PRESERVED_BACKUP" ]; then
		section "backup retrieval: preserved $PRESERVED_KEY"
		[ -f "$PRESERVED_BACKUP" ] || fail "preserved-key backup not found: $PRESERVED_BACKUP"
		local phome
		phome="$(new_keyring)"
		gpg_in "$phome" --import "$PRESERVED_BACKUP" 2>/dev/null \
			|| fail "the preserved-key backup at $PRESERVED_BACKUP did not import"
		assert_imported_id "$phome" "$PRESERVED_KEY" "the restored preserved key"
		prove_unlock "$phome" "$PRESERVED_KEY" "the restored preserved key"
	else
		fail "--preserved-backup PATH is required: $PRESERVED_KEY now uses the replacement's passphrase, so it is part of the same handoff and the same backup check. Pass it explicitly."
	fi

	after="$(backup_digest)"
	[ "$before" = "$after" ] || fail "the backup files changed during verification. Nothing here writes to them; investigate before trusting this run."
	ok "the backup files are byte-identical to how this run found them"

	printf '\nverify-backup: the backups restore, the restored keys are the expected keys, and the separately stored passphrase unlocks them. Retrieval is proven.\n'
}

backup_digest() {
	local f
	for f in "$PRIVATE_BACKUP" "$PASSPHRASE_BACKUP" "$PRESERVED_BACKUP"; do
		[ -n "$f" ] && [ -f "$f" ] || continue
		sha256sum "$f"
	done | sha256sum | cut -d' ' -f1
}

# Set by prepare_revoked_keyring. A return value cannot travel on stdout here:
# the same function prints the proofs it just made, and a caller capturing the
# path would capture those too.
REVOKED_HOME=""

prepare_revoked_keyring() {
	# Builds the keyring that will be published from, into REVOKED_HOME. The
	# revocation certificate is *imported*, never created: gpg has no way to
	# produce one here anyway without the retired secret key, which is the point.
	local home revocation retired_pub
	home="$(new_keyring)"

	retired_pub="$RETIRED_PUBLIC"
	if [ -z "$retired_pub" ]; then
		inventory_handoff "$HANDOFF_DIR"
		retired_pub="$(inventory_path "$INV_PUBLIC" "$RETIRED_KEY" || true)"
		[ -n "$retired_pub" ] || retired_pub="$(inventory_path "$INV_SECRET" "$RETIRED_KEY" || true)"
		[ -n "$retired_pub" ] || fail "no public key for the retired $RETIRED_KEY found in $HANDOFF_DIR; pass --retired-public PATH. A revocation certificate is a signature over a key, and a keyserver that has never seen the key has nothing to attach it to."
		[ -n "$REVOCATION_FILE" ] || REVOCATION_FILE="$(inventory_path "$INV_REVOCATION" "$RETIRED_KEY" || true)"
	fi
	[ -f "$retired_pub" ] || fail "retired public key not found: $retired_pub"

	revocation="$REVOCATION_FILE"
	if [ -z "$revocation" ]; then
		inventory_handoff "$HANDOFF_DIR"
		revocation="$(inventory_path "$INV_REVOCATION" "$RETIRED_KEY" || true)"
	fi
	[ -n "$revocation" ] || fail "no revocation certificate for $RETIRED_KEY; pass --revocation PATH. This script never generates one."
	[ -f "$revocation" ] || fail "revocation certificate not found: $revocation"

	# The certificate has to belong to the key being revoked. A certificate for
	# some other key imports without complaint and leaves the key unrevoked, so
	# check the binding before the import rather than inferring it after.
	local cert_ids
	cert_ids="$(classify_file "$revocation" | awk '$1 == "revocation" { print $2 }')"
	[ -n "$cert_ids" ] || fail "$revocation is not a revocation certificate"
	local matched=0 id
	while IFS= read -r id; do
		[ -n "$id" ] || continue
		if key_id_matches "$id" "$RETIRED_KEY"; then matched=1; fi
	done <<<"$cert_ids"
	[ "$matched" = 1 ] \
		|| fail "the revocation certificate at $revocation revokes ${cert_ids//$'\n'/, }, not $RETIRED_KEY. Publishing it would revoke the wrong key and leave the retired one live."
	ok "the revocation certificate belongs to $RETIRED_KEY"

	gpg_in "$home" --import "$retired_pub" 2>/dev/null \
		|| fail "the retired public key at $retired_pub did not import"
	assert_imported_id "$home" "$RETIRED_KEY" "the retired public key"
	if is_revoked "$home" "$RETIRED_KEY"; then
		note "the retired key already carried a revocation before this run"
	fi

	gpg_in "$home" --import "$revocation" 2>/dev/null \
		|| fail "the revocation certificate did not import"
	is_revoked "$home" "$RETIRED_KEY" \
		|| fail "after importing the certificate, gpg still reports $RETIRED_KEY as live. Nothing is published until this holds locally."
	ok "$RETIRED_KEY is revoked in the local keyring"

	REVOKED_HOME="$home"
}

fetch_back() {
	# A 200 from an upload endpoint says the request was accepted, not that the
	# key is being served, and certainly not that it is being served as revoked.
	# Each target gets a keyring that has never seen the key.
	local failures=0 server home
	for server in "${KEYSERVERS[@]}"; do
		home="$(new_keyring)"
		if ! gpg_in "$home" --keyserver "$server" --recv-keys "$RETIRED_KEY" >/dev/null 2>&1; then
			printf '  !! %s did not serve %s back\n' "$server" "$RETIRED_KEY" >&2
			failures=$((failures + 1))
			continue
		fi
		if is_revoked "$home" "$RETIRED_KEY"; then
			ok "$server serves $RETIRED_KEY and reports it revoked"
		else
			printf '  !! %s serves %s but does NOT report it revoked\n' "$server" "$RETIRED_KEY" >&2
			failures=$((failures + 1))
		fi
	done
	[ "$failures" = 0 ] \
		|| fail "$failures of ${#KEYSERVERS[@]} target(s) do not serve $RETIRED_KEY as revoked. The revocation is not published until every configured target does; a partial publication is what leaves a verifier accepting a signature from a key everyone else knows is dead."
}

cmd_publish_revocation() {
	section "retired-key revocation: $RETIRED_KEY"
	prepare_revoked_keyring
	local home="$REVOKED_HOME"

	printf '  -- targets: %s\n' "${KEYSERVERS[*]}"

	if [ "$DRY_RUN" = 1 ] || [ "$CONFIRM_PUBLISH" != 1 ]; then
		printf '\npublish-revocation: verify-only. The certificate is valid, it belongs to %s, and it revokes the key locally. Nothing was uploaded.\nRe-run with --confirm-publish to publish to: %s\n' \
			"$RETIRED_KEY" "${KEYSERVERS[*]}"
		return 0
	fi

	section "publishing"
	local server failures=0
	for server in "${KEYSERVERS[@]}"; do
		if gpg_in "$home" --keyserver "$server" --send-keys "$RETIRED_KEY" >/dev/null 2>&1; then
			ok "uploaded the revoked $RETIRED_KEY to $server"
		else
			printf '  !! upload to %s failed\n' "$server" >&2
			failures=$((failures + 1))
		fi
	done
	[ "$failures" = 0 ] || fail "$failures of ${#KEYSERVERS[@]} upload(s) failed; not claiming publication"

	section "independent fetch-back"
	fetch_back

	printf '\npublish-revocation: %s is published as revoked and every target serves it back that way. Its public material is intact, so v1.2.0 and every pre-cutover signature still verify.\n' "$RETIRED_KEY"
}

cmd_verify_published() {
	section "published state: $RETIRED_KEY"
	printf '  -- targets: %s\n' "${KEYSERVERS[*]}"
	fetch_back
	printf '\nverify-published: every configured target serves %s as revoked.\n' "$RETIRED_KEY"
}

# --- argument parsing ---------------------------------------------------------
PRIVATE_BACKUP=""
PASSPHRASE_BACKUP=""
PRESERVED_BACKUP=""
RETIRED_PUBLIC=""
REVOCATION_FILE=""
CONFIRM_PUBLISH=0
DRY_RUN=0
KEYSERVERS=()

main() {
	[ $# -gt 0 ] || {
		usage
		exit 1
	}
	local command="$1"
	shift
	case "$command" in
		-h | --help | help)
			usage
			exit 0
			;;
		validate | verify-backup | publish-revocation | verify-published) ;;
		*)
			printf 'unknown command: %s\n\n' "$command" >&2
			usage >&2
			exit 1
			;;
	esac

	while [ $# -gt 0 ]; do
		case "$1" in
			--handoff)
				HANDOFF_DIR="${2:?--handoff needs a directory}"
				shift 2
				;;
			--private-backup)
				PRIVATE_BACKUP="${2:?--private-backup needs a path}"
				shift 2
				;;
			--passphrase-backup)
				PASSPHRASE_BACKUP="${2:?--passphrase-backup needs a path}"
				shift 2
				;;
			--preserved-backup)
				PRESERVED_BACKUP="${2:?--preserved-backup needs a path}"
				shift 2
				;;
			--retired-public)
				RETIRED_PUBLIC="${2:?--retired-public needs a path}"
				shift 2
				;;
			--revocation)
				REVOCATION_FILE="${2:?--revocation needs a path}"
				shift 2
				;;
			--keyserver)
				KEYSERVERS+=("${2:?--keyserver needs a URL}")
				shift 2
				;;
			--confirm-publish)
				CONFIRM_PUBLISH=1
				shift
				;;
			--dry-run)
				DRY_RUN=1
				shift
				;;
			--passphrase | --passphrase=*)
				fail "the passphrase is never a command-line argument: /proc/*/cmdline is world-readable, so it would be visible to every local user. Use --passphrase-backup PATH, KEY_HANDOFF_PASSPHRASE_FILE, or the terminal prompt."
				;;
			-h | --help)
				usage
				exit 0
				;;
			*)
				fail "unknown option: $1"
				;;
		esac
	done

	[ "${#KEYSERVERS[@]}" -gt 0 ] || KEYSERVERS=("${DEFAULT_KEYSERVERS[@]}")

	refuse_ci
	command -v gpg >/dev/null 2>&1 || fail "gpg not found; this whole procedure is GnuPG"

	WORK="$(mktemp -d)"
	trap cleanup EXIT
	chmod 700 "$WORK"

	case "$command" in
		validate) cmd_validate ;;
		verify-backup) cmd_verify_backup ;;
		publish-revocation) cmd_publish_revocation ;;
		verify-published) cmd_verify_published ;;
	esac
}

main "$@"
