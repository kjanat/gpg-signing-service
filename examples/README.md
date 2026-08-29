# GPG Signing Service Examples

> [!WARNING]
> Some examples below are historical and are not maintained as drop-in
> workflows. Start with the current [CI integrations](../docs/integrations.md),
> [authentication](../docs/authentication.md), and
> [security model](../docs/security-model.md).

Historical examples for integrating with the GPG Signing Service API. Compare
them with the generated contract and canonical guides before adapting them.

## Directory Structure

```tree
gpg-signing-service/examples/
├── bash/                  # Shell script examples
│   ├── sign-commit.sh
│   ├── manage-keys.sh
│   └── query-audit.sh
├── github-actions/        # GitHub Actions workflows
│   └── sign-commits.yml
├── gitlab-ci/             # GitLab CI pipelines
│   └── sign-commits.yml
├── python/                # Python SDK examples
│   ├── sign_commit.py
│   └── manage_keys.py
└── README.md              << This file
```

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

**File**: [`bash/sign-commit.sh`](bash/sign-commit.sh)

The script is not reproduced here. It was, and the copy went stale: it retried
on the body's `retryAfter` alone, slept after the attempt it had no retry left
for, had no `503` branch and no ceiling on a server-chosen wait — the opposite
of every rule in [Retry and Transport Behaviour](#retry-and-transport-behaviour-bashsign-commitsh) below, which is
what the file now does and what
`.github/scripts/test-sign-commit-example.sh` pins. A reader who pasted the
listing got the behaviour the tests exist to prevent.

Read it in the repository, or run it:

```bash
BASE_URL=https://gpg.kajkowalski.nl \
  OIDC_TOKEN="${OIDC_TOKEN}" \
  bash examples/bash/sign-commit.sh HEAD
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

### Retry and Transport Behaviour (`bash/sign-commit.sh`)

The signing example retries only the two statuses the service invites a caller
to repeat — `429` and `503` — and takes the wait off the response rather than
choosing one itself.

| Variable         | Default                      | Meaning                                               |
| ---------------- | ---------------------------- | ----------------------------------------------------- |
| `BASE_URL`       | `https://gpg.kajkowalski.nl` | Service origin                                        |
| `MAX_RETRIES`    | `3`                          | Total signing attempts, not retries after the first   |
| `MAX_RETRY_WAIT` | `120`                        | Ceiling, in seconds, on a wait the _server_ asked for |

Rules the script follows, and which the shell suite pins:

- **The `Retry-After` header outranks the body.** A `429` from an edge throttle
  in front of the service answers with a page and a header, and a `retryAfter`
  in a body underneath it can be stale. The body's value is the fallback for
  when there is no readable header, which is how this service's own limiter is
  read. A `503` has no body field at all — `ErrorResponse` declares none.
- **Both `Retry-After` forms are read, and only those.** Delay-seconds and an
  absolute HTTP-date, per RFC 9110 §10.2.3 — the date in any of the three
  formats §5.6.7 permits, checked by shape before `date(1)` sees it. `date -d`
  is a natural-language parser, so ungated it reads `tomorrow` as a day and
  `5 seconds` as five, and a malformed header would outrank a perfectly good
  `retryAfter` in the body. A value that is neither form — `soon-ish`, or a
  negative number the delay-seconds grammar does not admit — counts as _no
  hint_, and the next source answers instead.
- **A zero-delay header is a hint, not the absence of one.** `Retry-After: 0`
  and a date that has already come round both mean the wait is over, so they
  keep their precedence over a body that disagrees and are not replaced by the
  30-second default. The next attempt goes immediately, without a `sleep`, and
  `MAX_RETRIES` is what bounds it. Every wait the script derives is a whole
  number of seconds between `0` and `MAX_RETRY_WAIT`.
- **The last allowed attempt is never slept on.** Once the attempt count
  reaches `MAX_RETRIES` the run is over, and a ten-minute hint on that last
  refusal would be ten minutes of CI time spent to reach a failure the script
  already knows about.
- **A single attempt is bounded in time.** `--connect-timeout 10` and
  `--max-time 60`, because curl's own defaults are a 300-second connect and no
  ceiling at all on a stalled transfer. `MAX_RETRY_WAIT` bounds the waits
  between attempts; without these, a connection that is dropped rather than
  refused parks the job on an attempt, where the clamp cannot see it.
- **A `curl` that never connected is reported as such.** DNS, TLS, a refused
  connection or a timeout produce no HTTP status; the script says no response
  was received and quotes curl's exit code, rather than sorting a `000` through
  the status branches as though the service had refused.
- **`MAX_RETRY_WAIT` and `MAX_RETRIES` are validated before any arithmetic.**
  Both come from the environment and both end up inside `(( ))`, where a bare
  word evaluates to zero and an array subscript is evaluated as an expression.
  A non-numeric or zero value stops the run with a message, before the token
  fetch, the key import, and any `sleep`.

Verify the behaviour without touching the network:

```bash
task test:sign-commit-example   # also runs as part of `task test` / `task tc`
```

## Integration with Your Project

1. Copy examples to your repository
2. Update credentials and URLs
3. Add to CI/CD workflows
4. Monitor audit logs for operations
5. Implement error handling as needed

For more details, see the main `API.md` and the generated
[`client/openapi.json`](../client/openapi.json) contract.
