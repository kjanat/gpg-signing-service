#!/usr/bin/env bash
# Generate a new GPG key for the signing service
# This script creates keys in .keys/ directory - NOT in ~/.gnupg

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${PROJECT_DIR}/.keys"

# Show help by default
show_help() {
	cat <<EOF
Usage: $(basename "$0") <name> <email> [comment] [passphrase]

Generate a GPG signing key for the GPG Signing Service.
Keys are created in .keys/ directory (NOT in ~/.gnupg).

Arguments:
  name        Real name for the key (required)
  email       Email address for the key (required)
  comment     Key comment (default: "Cloudflare Worker Signing Key")
  passphrase  Passphrase to protect the key (optional, recommended)

Examples:
  $(basename "$0") "My Company" "signing@company.com"
  $(basename "$0") "My Company" "signing@company.com" "Production Key" "secret123"

Output:
  .keys/private-key.asc  - Armored private key (keep secure!)
  .keys/public-key.asc   - Armored public key
  .keys/gnupg/           - GPG keyring directory

Next steps after generation:
  1. Set passphrase: wrangler secret put KEY_PASSPHRASE
  2. Set admin token: wrangler secret put ADMIN_TOKEN
  3. Upload key via /admin/keys endpoint

EOF
	exit 0
}

# Show help if no arguments or help flag
if [ $# -eq 0 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
	show_help
fi

# Require at least name and email
if [ $# -lt 2 ]; then
	echo "Error: name and email are required" >&2
	echo "Run '$(basename "$0") --help' for usage information" >&2
	exit 1
fi

# Key parameters
KEY_NAME="$1"
KEY_EMAIL="$2"
KEY_COMMENT="${3:-Cloudflare Worker Signing Key}"
PASSPHRASE="${4:-}"

# Create keys directory if it doesn't exist
mkdir -p "$KEYS_DIR"

# Set GNUPGHOME to project directory - NOT touching ~/.gnupg
export GNUPGHOME="${KEYS_DIR}/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

echo "Generating GPG key..."
echo "  Name:       $KEY_NAME"
echo "  Email:      $KEY_EMAIL"
echo "  Comment:    $KEY_COMMENT"
echo "  GNUPGHOME:  $GNUPGHOME (NOT ~/.gnupg)"
echo "  Passphrase: ${PASSPHRASE:-none}"

# Generate key using batch mode
if [ -n "$PASSPHRASE" ]; then
	gpg --batch --gen-key <<EOF
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign
Name-Real: ${KEY_NAME}
Name-Comment: ${KEY_COMMENT}
Name-Email: ${KEY_EMAIL}
Expire-Date: 2y
Passphrase: ${PASSPHRASE}
%commit
EOF
else
	gpg --batch --gen-key <<EOF
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign
Name-Real: ${KEY_NAME}
Name-Comment: ${KEY_COMMENT}
Name-Email: ${KEY_EMAIL}
Expire-Date: 2y
%no-protection
%commit
EOF
fi

# Get the key ID
KEY_ID=$(gpg --list-keys --keyid-format long "${KEY_EMAIL}" | grep -E "^pub" | awk '{print $2}' | cut -d'/' -f2)

{
	echo ""
	echo "Key generated successfully!"
	echo "  Key ID: $KEY_ID"
}

# Export private key
PRIVATE_KEY_FILE="${KEYS_DIR}/private-key.asc"
if [ -n "$PASSPHRASE" ]; then
	gpg --batch --pinentry-mode loopback --passphrase "$PASSPHRASE" --armor --export-secret-keys "$KEY_ID" >"$PRIVATE_KEY_FILE"
else
	gpg --armor --export-secret-keys "$KEY_ID" >"$PRIVATE_KEY_FILE"
fi

# Export public key
PUBLIC_KEY_FILE="${KEYS_DIR}/public-key.asc"
gpg --armor --export "$KEY_ID" >"$PUBLIC_KEY_FILE"

# Get fingerprint
FINGERPRINT=$(gpg --fingerprint "$KEY_ID" | grep -A1 "pub" | tail -1 | tr -d ' ')

{
	echo ""
	echo "Keys exported to:"
	echo "  Private: $PRIVATE_KEY_FILE"
	echo "  Public:  $PUBLIC_KEY_FILE"
	echo ""
	echo "Fingerprint: $FINGERPRINT"
	echo ""
	echo "Next steps:"
	echo "  1. Set passphrase as secret: wrangler secret put KEY_PASSPHRASE"
	echo "  2. Upload key to service:"
	# shellcheck disable=SC1003
	echo '     curl -X POST https://your-worker.workers.dev/admin/keys \'
	# shellcheck disable=SC1003
	echo '       -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \'
	# shellcheck disable=SC1003
	echo '       -H "Content-Type: application/json" \'
	echo "       -d '{\"armoredPrivateKey\": \"$(cat "$PRIVATE_KEY_FILE" | sed ':a;N;$!ba;s/\n/\\n/g')\", \"keyId\": \"signing-key-v1\"}'"
	echo ""
	echo "IMPORTANT: Keep $PRIVATE_KEY_FILE secure and add .keys/ to .gitignore!"
}
