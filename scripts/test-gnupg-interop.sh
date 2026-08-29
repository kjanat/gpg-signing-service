#!/usr/bin/env bash
# GnuPG/Git interoperability check for the service's OpenPGP signatures.
#
# Proves four things against real gpg and real git, not against openpgp.js's own
# verifier:
#
#   1. git's native signature over a commit is sigclass 0x00 (binary);
#   2. the service's signature over the same payload is also 0x00;
#   3. gpg accepts the service's signature over the exact commit bytes; and
#   4. `git verify-commit` accepts a commit object assembled from that signature.
#
# It also asserts the byte binding: gpg must *reject* the signature when the
# payload's line endings are rewritten. A canonical-text signature (sigclass
# 0x01, what `createMessage({ text })` produces) passes that mutation, which is
# why this check exists.
#
# Run: task test:gnupg-interop
set -euo pipefail

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}
ok() { printf '  ok - %s\n' "$1"; }

for tool in gpg git bun; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf 'SKIP: %s not available; GnuPG interoperability check not run\n' "$tool"
		exit 0
	fi
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
export GNUPGHOME="$WORK/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
cleanup() {
	gpgconf --kill all >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

printf '# GnuPG interoperability\n'

# --- an ephemeral signing key, held only in $WORK -----------------------------
cat >"$WORK/keyparams" <<'PARAMS'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: Interop Test
Name-Email: interop@example.com
Expire-Date: 0
%commit
PARAMS
gpg --batch --quiet --gen-key "$WORK/keyparams" 2>/dev/null
FPR="$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"
[ -n "$FPR" ] || fail "could not generate a test key"
gpg --batch --quiet --armor --export-secret-keys "$FPR" >"$WORK/secret.asc"

# --- a real commit, signed by git itself --------------------------------------
export GIT_DIR="$WORK/repo/.git" GIT_WORK_TREE="$WORK/repo"
mkdir -p "$WORK/repo"
git init --quiet "$WORK/repo"
git config user.name "Interop Test"
git config user.email "interop@example.com"
git config commit.gpgsign false
git config gpg.program gpg
git config user.signingkey "$FPR"
printf 'interop\n' >"$WORK/repo/a.txt"
git add a.txt
git commit --quiet -m "interop fixture"

sigclass_of() {
	gpg --list-packets "$1" 2>/dev/null | sed -n 's/.*sigclass \(0x[0-9a-f]*\).*/\1/p' | head -1
}

git commit --quiet --amend --no-edit -S
git cat-file commit HEAD \
	| sed -n '/BEGIN PGP SIGNATURE/,/END PGP SIGNATURE/p' \
	| sed -e 's/^gpgsig //' -e 's/^ //' >"$WORK/git-native.asc"
GIT_CLASS="$(sigclass_of "$WORK/git-native.asc")"
[ "$GIT_CLASS" = "0x00" ] || fail "git's own signature is sigclass ${GIT_CLASS:-unknown}, expected 0x00"
ok "git signs commits with a binary signature (sigclass 0x00)"

# --- the payload git would hand a signing program -----------------------------
git commit --quiet --amend --no-edit --no-gpg-sign
git cat-file commit HEAD >"$WORK/payload"

# --- the service's signature over those exact bytes ---------------------------
(cd "$REPO_ROOT" && bun scripts/gnupg-interop-sign.ts "$WORK/secret.asc" "$WORK/payload") >"$WORK/service.asc"

SERVICE_CLASS="$(sigclass_of "$WORK/service.asc")"
[ "$SERVICE_CLASS" = "0x00" ] \
	|| fail "service signature is sigclass ${SERVICE_CLASS:-unknown}, expected 0x00 (0x01 means canonical-text)"
ok "service emits a binary signature (sigclass 0x00)"

gpg --batch --quiet --verify "$WORK/service.asc" "$WORK/payload" 2>/dev/null \
	|| fail "gpg rejected the service signature over the exact commit bytes"
ok "gpg verifies the service signature against the exact commit bytes"

# A canonical-text signature survives this mutation; a binary one must not.
sed 's/$/\r/' "$WORK/payload" >"$WORK/payload.crlf"
if gpg --batch --quiet --verify "$WORK/service.asc" "$WORK/payload.crlf" 2>/dev/null; then
	fail "signature also verified against a CRLF-rewritten payload — that is a canonical-text signature"
fi
ok "gpg rejects the same signature over a CRLF-rewritten payload"

# --- assemble a commit object from the service signature ----------------------
awk -v sigfile="$WORK/service.asc" '
	function emit_sig(   line, first) {
		first = 1
		while ((getline line < sigfile) > 0) {
			if (first) { print "gpgsig " line; first = 0 } else { print " " line }
		}
		close(sigfile)
	}
	!inserted && /^$/ { emit_sig(); inserted = 1 }
	{ print }
' "$WORK/payload" >"$WORK/payload.signed"

SIGNED_SHA="$(git hash-object -t commit -w --stdin <"$WORK/payload.signed")"
git verify-commit "$SIGNED_SHA" >/dev/null 2>&1 \
	|| fail "git verify-commit rejected a commit carrying the service signature"
ok "git verify-commit accepts a commit carrying the service signature"

printf 'GnuPG interoperability: all checks passed\n'
