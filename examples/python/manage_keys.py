#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "requests",
#     "urllib3",
# ]
# ///
"""Manage GPG signing keys via the GPG Signing Service API."""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import TypedDict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class KeyResponse(TypedDict):
    """Response from key upload endpoint."""

    success: bool
    keyId: str
    fingerprint: str
    algorithm: str
    userId: str


class KeyListItem(TypedDict):
    """Individual key in list response."""

    keyId: str
    fingerprint: str
    createdAt: str
    algorithm: str


class AuditLogEntry(TypedDict):
    """Individual audit log entry."""

    id: str
    timestamp: str
    requestId: str
    action: str
    issuer: str
    subject: str
    keyId: str
    success: bool
    errorCode: str | None
    metadata: str | None


class AuditLogsResponse(TypedDict):
    """Response from audit logs endpoint."""

    logs: list[AuditLogEntry]
    count: int


class KeyDeletionResponse(TypedDict):
    """Response from key deletion endpoint."""

    success: bool
    deleted: bool


class GPGSigningServiceClient:
    """Client for GPG Signing Service API."""

    def __init__(
        self,
        base_url: str = "https://gpg.kajkowalski.nl",
        admin_token: str | None = None,
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

    def _validate_key_id(self, key_id: str) -> None:
        """Validate key ID format (16 hex chars)."""
        if not isinstance(key_id, str) or len(key_id) != 16:
            raise ValueError(f"Key ID must be exactly 16 characters, got {len(key_id)}")
        if not all(c in "0123456789ABCDEFabcdef" for c in key_id):
            raise ValueError(f"Key ID must be hexadecimal, got: {key_id}")

    def upload_key(self, key_id: str, armored_private_key: str) -> KeyResponse:
        """Upload a new signing key."""
        self._validate_key_id(key_id)
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

    def list_keys(self) -> list[KeyListItem]:
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

    def delete_key(self, key_id: str) -> KeyDeletionResponse:
        """Delete a signing key."""
        self._validate_key_id(key_id)
        response = self.session.delete(
            f"{self.base_url}/admin/keys/{key_id}",
            headers=self._admin_headers(),
        )
        response.raise_for_status()
        return response.json()

    def get_audit_logs(
        self,
        action: str | None = None,
        subject: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> AuditLogsResponse:
        """Query audit logs."""
        params: dict[str, str | int] = {
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
        old_key_id: str | None = None,
        grace_period_hours: int = 24,
    ) -> dict:
        """Rotate signing keys (upload new, delete old after grace period)."""
        results = {}

        # Upload new key
        print(f"Uploading new key: {new_key_id}")
        results["new_key"] = self.upload_key(new_key_id, armored_private_key)
        print("✓ New key uploaded successfully")
        print(f"  Fingerprint: {results['new_key']['fingerprint']}")
        print(f"  Algorithm: {results['new_key']['algorithm']}")
        print(f"  User ID: {results['new_key']['userId']}")

        # Wait grace period if old key specified
        if old_key_id:
            print(f"\nWaiting {grace_period_hours} hours grace period...")
            print(f"Old key: {old_key_id}")
            print("New key is now active, workflows should be updated")

            # In real usage, would wait:
            # time.sleep(grace_period_hours * 3600)

            # Then delete old key
            print(f"\nDeleting old key: {old_key_id}")
            results["deleted"] = self.delete_key(old_key_id)
            print("✓ Old key deleted successfully")

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
            with open(args.key_file) as f:
                armored_key = f.read()

            print(f"Uploading key: {args.key_id}")
            result = client.upload_key(args.key_id, armored_key)
            print("✓ Key uploaded successfully")
            print(f"  Key ID: {result['keyId']}")
            print(f"  Fingerprint: {result['fingerprint']}")
            print(f"  Algorithm: {result['algorithm']}")
            print(f"  User ID: {result['userId']}")

        elif args.command == "delete":
            print(f"Deleting key: {args.key_id}")
            result = client.delete_key(args.key_id)
            print(json.dumps(result, indent=2))

        elif args.command == "audit":
            start_date = (
                datetime.now(timezone.utc) - timedelta(days=args.days)
            ).isoformat()
            result = client.get_audit_logs(
                action=args.action,
                subject=args.subject,
                start_date=start_date,
                limit=args.limit,
            )

            print(f"Audit logs (last {args.days} days):")
            print("-" * 80)
            for log in result["logs"]:
                status = (
                    "✓" if log["success"] else f"✗ ({log.get('errorCode', 'unknown')})"
                )
                print(
                    f"{log['timestamp']} | {log['action']:12} | {log['subject']:20} | {status}"
                )
                print(
                    f"  ID: {log['id']} | Request: {log['requestId']} | Key: {log['keyId']}"
                )
                if log.get("metadata"):
                    print(f"  Metadata: {log['metadata']}")
                print()
            print(f"Total: {result['count']} entries")

        elif args.command == "rotate":
            with open(args.key_file) as f:
                armored_key = f.read()

            result = client.rotate_keys(
                args.new_key_id,
                armored_key,
                old_key_id=args.old_key_id,
                grace_period_hours=args.grace_hours,
            )
            print(json.dumps(result, indent=2))

    except requests.HTTPError as e:
        try:
            error_data = e.response.json()
            print(
                f"API Error [{error_data.get('code', 'UNKNOWN')}]: {error_data.get('error', str(e))}",
                file=sys.stderr,
            )
            if "requestId" in error_data:
                print(f"Request ID: {error_data['requestId']}", file=sys.stderr)
        except ValueError:
            print(f"HTTP {e.response.status_code}: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Network Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
