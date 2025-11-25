# GPG Signing Service Examples

Complete, working examples for integrating with the GPG Signing Service API.

## Directory Structure

```tree
gpg-signing-service/examples/
├── bash/                  # Shell script examples
│   ├── sign-commit.sh     # Production-quality signing script
│   └── query-audit.sh     # Audit log query script
├── python/                # Python SDK examples
│   └── manage_keys.py     # Key management CLI
└── README.md              # This file (with inline CI/CD examples)
```

> **Note**: GitHub Actions and GitLab CI examples are provided inline below rather than
> as separate files, since they're meant to be copied into your own repositories.

## Quick Start

### 1. Sign a Commit (GitHub Actions)

```yaml
# .github/workflows/sign-commits.yml
name: Sign Commits
on: [push]

permissions:
  id-token: write
  contents: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - name: Sign commits
        env:
          GPG_SERVICE_URL: https://gpg.kajkowalski.nl
        run: |
          # Get OIDC token
          OIDC_TOKEN=$(
            curl -s \
              -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
              "$ACTIONS_ID_TOKEN_REQUEST_URL" \
            | jq -r '.token'
          )

          # Get public key
          curl -s "$GPG_SERVICE_URL/public-key" | gpg --import

          # Sign current commit
          COMMIT_DATA=$(git cat-file commit HEAD)
          SIGNATURE=$(curl -s -X POST \
            -H "Authorization: Bearer $OIDC_TOKEN" \
            --data-raw "$COMMIT_DATA" \
            "$GPG_SERVICE_URL/sign"
          )

          # Display signature
          echo "Signature created successfully"
          echo "$SIGNATURE" | head -5
```

### 2. Sign a Commit (GitLab CI)

```yaml
# .gitlab-ci.yml
sign_commits:
  stage: build
  script:
    - echo "Signing commit with GPG service..."
    # Get public key
    - curl https://gpg.kajkowalski.nl/public-key | gpg --import
    # Sign commit
    - |
        SIGNATURE=$(curl -X POST \
          -H "Authorization: Bearer $CI_JOB_JWT" \
          --data-raw "$(git cat-file commit HEAD)" \
          https://gpg.kajkowalski.nl/sign)
        echo "Signed successfully"
```

### 3. Manage Keys (Admin)

```bash
#!/usr/env/bin bash

ADMIN_TOKEN="your-admin-token"
BASE_URL="https://gpg.kajkowalski.nl"

# Upload a new key
echo "Uploading signing key..."
RESPONSE=$(
  curl -s -X POST "${BASE_URL}/admin/keys" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d @- << EOF
{
  "keyId": "signing-key-prod-v1",
  "armoredPrivateKey": "$(cat signing-key.asc | jq -Rs .)"
}
EOF
)

echo "Upload response:"
echo "$RESPONSE" | jq .

# List all keys
echo "Available keys:"
curl -s $BASE_URL/admin/keys \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq '.keys[] | {keyId, fingerprint, algorithm}'
```

### 4. Query Audit Logs

```bash
#!/usr/bin/env bash

ADMIN_TOKEN="your-admin-token"
BASE_URL="https://gpg.kajkowalski.nl"

# Get signing operations from last 24 hours
YESTERDAY=$(date -u -d '1 day ago' +%Y-%m-%dT00:00:00Z)
echo "Signing operations (last 24 hours):"
curl -s "${BASE_URL}/admin/audit?action=sign&startDate=${YESTERDAY}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq '.logs[] | {timestamp, subject, success}'

# Find failed operations
echo "Failed operations:"
curl -s "${BASE_URL}/admin/audit" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq '.logs[] | select(.success == false) | {timestamp, action, errorCode}'
```

## Complete Examples

<details>
<summary>Sign Commit with Error Handling (Bash)</summary>

**File**: `bash/sign-commit.sh`

```bash
#!/usr/bin/env bash

set -euo pipefail

# Configuration
BASE_URL="https://gpg.kajkowalski.nl"
OIDC_TOKEN="${OIDC_TOKEN:-}"
MAX_RETRIES=3
RETRY_DELAY=2

# Functions
log_info() {
  echo "[INFO] $*" >&2
}

log_error() {
  echo "[ERROR] $*" >&2
}

check_requirements() {
  local required_tools=("curl" "jq" "git" "gpg")
  for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      log_error "Required tool not found: $tool"
      return 1
    fi
  done
}

get_oidc_token() {
  if [ -z "$OIDC_TOKEN" ]; then
    if [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
      log_error "OIDC token not provided and not in GitHub Actions"
      return 1
    fi

    log_info "Fetching OIDC token from GitHub Actions..."
    OIDC_TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r '.token')
  fi

  if [ -z "$OIDC_TOKEN" ] || [ "$OIDC_TOKEN" = "null" ]; then
    log_error "Failed to get OIDC token"
    return 1
  fi
}

import_public_key() {
  log_info "Importing public key from signing service..."

  local public_key
  public_key=$(curl -sf "$BASE_URL/public-key")

  if [ -z "$public_key" ]; then
    log_error "Failed to retrieve public key"
    return 1
  fi

  echo "$public_key" | gpg --import --quiet
  log_info "Public key imported successfully"
}

sign_commit() {
  local commit_ref="${1:-HEAD}"
  local keyid="${2:-}"
  local retry_count=0

  log_info "Signing commit: $commit_ref"

  # Get commit data
  local commit_data
  commit_data=$(git cat-file commit "$commit_ref")

  # Build request URL
  local request_url="$BASE_URL/sign"
  if [ -n "$keyid" ]; then
    request_url="$request_url?keyId=$keyid"
  fi

  # Retry logic
  while [ $retry_count -lt $MAX_RETRIES ]; do
    log_info "Signing attempt $((retry_count + 1))/$MAX_RETRIES..."

    local response
    local http_code
    response=$(curl -sw "\n%{http_code}" -X POST \
      -H "Authorization: Bearer $OIDC_TOKEN" \
      -H "X-Request-ID: $(uuidgen)" \
      --data-raw "$commit_data" \
      "$request_url")

    http_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | head -n -1)

    case "$http_code" in
      200)
        log_info "Commit signed successfully"
        echo "$body"
        return 0
        ;;
      429)
        local retry_after
        retry_after=$(echo "$body" | jq -r '.retryAfter // 30')
        log_info "Rate limited, waiting ${retry_after}s..."
        sleep "$retry_after"
        retry_count=$((retry_count + 1))
        ;;
      401)
        log_error "Authentication failed: $(echo "$body" | jq -r .error)"
        return 1
        ;;
      *)
        log_error "Signing failed (HTTP $http_code): $(echo "$body" | jq -r .error // .)"
        return 1
        ;;
    esac
  done

  log_error "Signing failed after $MAX_RETRIES retries"
  return 1
}

main() {
  log_info "GPG Signing Service - Commit Signing"

  check_requirements || return 1
  get_oidc_token || return 1
  import_public_key || return 1

  local signature
  signature=$(sign_commit "$@") || return 1

  log_info "Signature:"
  echo "$signature"
}

main "$@"
```

</details>

<details>
<summary>Manage Keys (Python)</summary>

**File**: `python/manage_keys.py`

```python
#!/usr/bin/env python3
"""Manage GPG signing keys via the GPG Signing Service API."""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class GPGSigningServiceClient:
    """Client for GPG Signing Service API."""

    def __init__(
        self,
        base_url: str = "https://gpg.kajkowalski.nl",
        admin_token: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token or os.environ.get("ADMIN_TOKEN")
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retries."""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 503],
            allowed_methods=["GET", "POST", "DELETE"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _admin_headers(self) -> dict:
        """Get headers for admin requests."""
        if not self.admin_token:
            raise ValueError("Admin token not configured")
        return {
            "Authorization": f"Bearer {self.admin_token}",
            "Content-Type": "application/json",
        }

    def upload_key(self, key_id: str, armored_private_key: str) -> dict:
        """Upload a new signing key."""
        payload = {
            "keyId": key_id,
            "armoredPrivateKey": armored_private_key,
        }

        response = self.session.post(
            f"{self.base_url}/admin/keys",
            headers=self._admin_headers(),
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    def list_keys(self) -> list:
        """List all signing keys."""
        response = self.session.get(
            f"{self.base_url}/admin/keys",
            headers=self._admin_headers(),
        )
        response.raise_for_status()
        data = response.json()
        return data.get("keys", [])

    def get_public_key(self, key_id: str) -> str:
        """Get public key for a specific key ID."""
        response = self.session.get(
            f"{self.base_url}/admin/keys/{key_id}/public",
            headers=self._admin_headers(),
        )
        response.raise_for_status()
        return response.text

    def delete_key(self, key_id: str) -> dict:
        """Delete a signing key."""
        response = self.session.delete(
            f"{self.base_url}/admin/keys/{key_id}",
            headers=self._admin_headers(),
        )
        response.raise_for_status()
        return response.json()

    def get_audit_logs(
        self,
        action: Optional[str] = None,
        subject: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """Query audit logs."""
        params = {
            "limit": limit,
            "offset": offset,
        }

        if action:
            params["action"] = action
        if subject:
            params["subject"] = subject
        if start_date:
            params["startDate"] = start_date
        if end_date:
            params["endDate"] = end_date

        response = self.session.get(
            f"{self.base_url}/admin/audit",
            headers=self._admin_headers(),
            params=params,
        )
        response.raise_for_status()
        return response.json()

    def rotate_keys(
        self,
        new_key_id: str,
        armored_private_key: str,
        old_key_id: Optional[str] = None,
        grace_period_hours: int = 24,
    ) -> dict:
        """Rotate signing keys (upload new, delete old after grace period)."""
        results = {}

        # Upload new key
        print(f"Uploading new key: {new_key_id}")
        results["new_key"] = self.upload_key(new_key_id, armored_private_key)
        print(f"✓ New key uploaded successfully")
        print(f"  Fingerprint: {results['new_key']['fingerprint']}")
        print(f"  Algorithm: {results['new_key']['algorithm']}")

        # Wait grace period if old key specified
        if old_key_id:
            print(f"\nWaiting {grace_period_hours} hours grace period...")
            print(f"Old key: {old_key_id}")
            print(f"New key is now active, workflows should be updated")

            # In real usage, would wait:
            # time.sleep(grace_period_hours * 3600)

            # Then delete old key
            print(f"\nDeleting old key: {old_key_id}")
            results["deleted"] = self.delete_key(old_key_id)
            print(f"✓ Old key deleted successfully")

        return results


def main():
    """CLI for key management."""
    parser = argparse.ArgumentParser(
        description="Manage GPG signing keys via GPG Signing Service API"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # List command
    subparsers.add_parser("list", help="List all signing keys")

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a new signing key")
    upload_parser.add_argument("key_id", help="Key identifier")
    upload_parser.add_argument("key_file", help="Path to armored private key file")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a signing key")
    delete_parser.add_argument("key_id", help="Key identifier to delete")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Query audit logs")
    audit_parser.add_argument(
        "--action", help="Filter by action (sign, key_upload, key_rotate)"
    )
    audit_parser.add_argument("--subject", help="Filter by subject")
    audit_parser.add_argument("--days", type=int, default=7, help="Days to include")
    audit_parser.add_argument("--limit", type=int, default=50, help="Max entries")

    # Rotate command
    rotate_parser = subparsers.add_parser("rotate", help="Rotate signing keys")
    rotate_parser.add_argument("new_key_id", help="New key identifier")
    rotate_parser.add_argument("key_file", help="Path to armored private key file")
    rotate_parser.add_argument("--old-key-id", help="Old key to delete")
    rotate_parser.add_argument(
        "--grace-hours",
        type=int,
        default=24,
        help="Grace period before deleting old key",
    )

    args = parser.parse_args()

    client = GPGSigningServiceClient()

    try:
        if args.command == "list":
            keys = client.list_keys()
            if not keys:
                print("No keys found")
                return

            print("Signing Keys:")
            print("-" * 80)
            for key in keys:
                print(f"ID: {key['keyId']}")
                print(f"   Fingerprint: {key['fingerprint']}")
                print(f"   Algorithm: {key['algorithm']}")
                print(f"   Created: {key['createdAt']}")
                print()

        elif args.command == "upload":
            with open(args.key_file, "r") as f:
                armored_key = f.read()

            print(f"Uploading key: {args.key_id}")
            result = client.upload_key(args.key_id, armored_key)
            print(json.dumps(result, indent=2))

        elif args.command == "delete":
            print(f"Deleting key: {args.key_id}")
            result = client.delete_key(args.key_id)
            print(json.dumps(result, indent=2))

        elif args.command == "audit":
            start_date = (
                datetime.utcnow() - timedelta(days=args.days)
            ).isoformat() + "Z"
            result = client.get_audit_logs(
                action=args.action,
                subject=args.subject,
                start_date=start_date,
                limit=args.limit,
            )

            print(f"Audit logs (last {args.days} days):")
            print("-" * 80)
            for log in result["logs"]:
                print(
                    f"{log['timestamp']} | {log['action']:12} | {log['subject']:20} | {'✓' if log['success'] else '✗'}"
                )
            print(f"\nTotal: {result['count']} entries")

        elif args.command == "rotate":
            with open(args.key_file, "r") as f:
                armored_key = f.read()

            result = client.rotate_keys(
                args.new_key_id,
                armored_key,
                old_key_id=args.old_key_id,
                grace_period_hours=args.grace_hours,
            )
            print(json.dumps(result, indent=2))

    except requests.RequestException as e:
        print(f"API Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

</details>

<details>
<summary>Query Audit Logs (Bash)</summary>

**File**: `bash/query-audit.sh`

```bash
#!/usr/bin/env bash

# Query audit logs with filtering and formatting

ADMIN_TOKEN="${ADMIN_TOKEN}"
BASE_URL="https://gpg.kajkowalski.nl"

if [ -z "$ADMIN_TOKEN" ]; then
  echo "Error: ADMIN_TOKEN not set"
  exit 1
fi

# Helper functions
query_logs() {
  local query_params="$1"
  curl -s "$BASE_URL/admin/audit?$query_params" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
}

format_logs() {
  jq -r '.logs[] | "\(.timestamp | split("T")[0]) \(.timestamp | split("T")[1]
) | \(.action:12) | \(.subject:20) | \(if .success then "✓" else "✗" end)"'
}

# Different query types
case "${1:-all}" in
  all)
    echo "Recent audit logs:"
    query_logs "limit=50" | format_logs
    ;;

  signing)
    echo "Signing operations:"
    query_logs "action=sign&limit=100" | format_logs
    ;;

  keys)
    echo "Key management operations:"
    query_logs "action=key_upload,key_rotate&limit=100" | format_logs
    ;;

  failures)
    echo "Failed operations:"
    query_logs "limit=100" | jq '.logs[] | select(.success == false) |
      "\(.timestamp) | \(.action) | \(.errorCode // "unknown")"'
    ;;

  by-repo)
    local repo="$2"
    if [ -z "$repo" ]; then
      echo "Usage: $0 by-repo <subject>"
      exit 1
    fi
    echo "Operations for subject: $repo"
    query_logs "subject=$repo&limit=100" | format_logs
    ;;

  *)
    echo "Usage: $0 {all|signing|keys|failures|by-repo <subject>}"
    exit 1
    ;;
esac
```

</details>

## Running the Examples

### Prerequisites

```bash
# Install required tools
# Bash
curl --version
jq --version
git --version
gpg --version

# Python
pip install requests
```

### Set Credentials

```bash
# For admin operations
export ADMIN_TOKEN="your-admin-token"

# For GitHub Actions (automatic in workflow)
export ACTIONS_ID_TOKEN_REQUEST_TOKEN="..."
export ACTIONS_ID_TOKEN_REQUEST_URL="..."
```

### Run Examples

```bash
# Sign a commit
./bash/sign-commit.sh HEAD

# List keys
python3 python/manage_keys.py list

# Upload a key
python3 python/manage_keys.py upload \
  my-key signing-key.asc

# Query audit logs
./bash/query-audit.sh signing

# Rotate keys
python3 python/manage_keys.py rotate \
  new-key-v2 signing-key-v2.asc \
  --old-key-id old-key-v1
```

## Integration with Your Project

1. Copy examples to your repository
2. Update credentials and URLs
3. Add to CI/CD workflows
4. Monitor audit logs for operations
5. Implement error handling as needed

For more details, see the main `API.md` and `openapi.yaml` files.
