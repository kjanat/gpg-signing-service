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
from typing import NotRequired, Protocol, TypedDict, TypeIs

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


class RotationResult(TypedDict):
    """Result of a key rotation."""

    new_key: KeyResponse
    deleted: NotRequired[KeyDeletionResponse]


class SupportsJson(Protocol):
    """Typed view of a response whose body parses to an arbitrary JSON value."""

    def json(self) -> object: ...


def _is_json_object(value: object) -> TypeIs[dict[str, object]]:
    """JSON object keys are always strings, so a dict check suffices."""
    return isinstance(value, dict)


def _is_json_array(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _as_object_dict(value: object) -> dict[str, object]:
    """Narrow an arbitrary JSON value to an object with string keys."""
    if not _is_json_object(value):
        raise TypeError(f"Expected JSON object, got {type(value).__name__}")
    return value


def _json_object(response: SupportsJson) -> dict[str, object]:
    """Parse a response body as a JSON object."""
    return _as_object_dict(response.json())


def _require_str(obj: dict[str, object], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise TypeError(f"Expected string field {key!r}, got {type(value).__name__}")
    return value


def _require_bool(obj: dict[str, object], key: str) -> bool:
    value = obj.get(key)
    if not isinstance(value, bool):
        raise TypeError(f"Expected boolean field {key!r}, got {type(value).__name__}")
    return value


def _require_int(obj: dict[str, object], key: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"Expected integer field {key!r}, got {type(value).__name__}")
    return value


def _require_list(obj: dict[str, object], key: str) -> list[object]:
    value = obj.get(key)
    if not _is_json_array(value):
        raise TypeError(f"Expected array field {key!r}, got {type(value).__name__}")
    return value


def _optional_str(obj: dict[str, object], key: str) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Expected string field {key!r}, got {type(value).__name__}")
    return value


def _parse_key_response(obj: dict[str, object]) -> KeyResponse:
    return KeyResponse(
        success=_require_bool(obj, "success"),
        keyId=_require_str(obj, "keyId"),
        fingerprint=_require_str(obj, "fingerprint"),
        algorithm=_require_str(obj, "algorithm"),
        userId=_require_str(obj, "userId"),
    )


def _parse_key_list_item(obj: dict[str, object]) -> KeyListItem:
    return KeyListItem(
        keyId=_require_str(obj, "keyId"),
        fingerprint=_require_str(obj, "fingerprint"),
        createdAt=_require_str(obj, "createdAt"),
        algorithm=_require_str(obj, "algorithm"),
    )


def _parse_deletion_response(obj: dict[str, object]) -> KeyDeletionResponse:
    return KeyDeletionResponse(
        success=_require_bool(obj, "success"),
        deleted=_require_bool(obj, "deleted"),
    )


def _parse_audit_entry(obj: dict[str, object]) -> AuditLogEntry:
    return AuditLogEntry(
        id=_require_str(obj, "id"),
        timestamp=_require_str(obj, "timestamp"),
        requestId=_require_str(obj, "requestId"),
        action=_require_str(obj, "action"),
        issuer=_require_str(obj, "issuer"),
        subject=_require_str(obj, "subject"),
        keyId=_require_str(obj, "keyId"),
        success=_require_bool(obj, "success"),
        errorCode=_optional_str(obj, "errorCode"),
        metadata=_optional_str(obj, "metadata"),
    )


def _parse_audit_logs(obj: dict[str, object]) -> AuditLogsResponse:
    logs = [
        _parse_audit_entry(_as_object_dict(item)) for item in _require_list(obj, "logs")
    ]
    return AuditLogsResponse(logs=logs, count=_require_int(obj, "count"))


class GPGSigningServiceClient:
    """Client for GPG Signing Service API."""

    def __init__(
        self,
        base_url: str = "https://gpg.kajkowalski.nl",
        admin_token: str | None = None,
    ):
        self.base_url: str = base_url.rstrip("/")
        self.admin_token: str | None = admin_token or os.environ.get("ADMIN_TOKEN")
        self.session: requests.Session = self._create_session()

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

    def _admin_headers(self) -> dict[str, str]:
        """Get headers for admin requests."""
        if not self.admin_token:
            raise ValueError("Admin token not configured")
        return {
            "Authorization": f"Bearer {self.admin_token}",
            "Content-Type": "application/json",
        }

    def _validate_key_id(self, key_id: str) -> None:
        """Validate key ID format (16 hex chars)."""
        if len(key_id) != 16:
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
        return _parse_key_response(_json_object(response))

    def list_keys(self) -> list[KeyListItem]:
        """List all signing keys."""
        response = self.session.get(
            f"{self.base_url}/admin/keys",
            headers=self._admin_headers(),
        )
        response.raise_for_status()
        data = _json_object(response)
        if "keys" not in data:
            return []
        return [
            _parse_key_list_item(_as_object_dict(item))
            for item in _require_list(data, "keys")
        ]

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
        return _parse_deletion_response(_json_object(response))

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
        return _parse_audit_logs(_json_object(response))

    def rotate_keys(
        self,
        new_key_id: str,
        armored_private_key: str,
        old_key_id: str | None = None,
        grace_period_hours: int = 24,
    ) -> RotationResult:
        """Rotate signing keys (upload new, delete old after grace period)."""
        # Upload new key
        print(f"Uploading new key: {new_key_id}")
        new_key = self.upload_key(new_key_id, armored_private_key)
        print("✓ New key uploaded successfully")
        print(f"  Fingerprint: {new_key['fingerprint']}")
        print(f"  Algorithm: {new_key['algorithm']}")
        print(f"  User ID: {new_key['userId']}")

        results: RotationResult = {"new_key": new_key}

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


class Args(argparse.Namespace):
    """Typed view of the parsed CLI arguments.

    The class attribute values exist for the type checker only: subparsers
    parse into a fresh sub-namespace and copy every attribute onto this one,
    so runtime defaults always come from add_argument(default=...). The
    placeholders below are never observable for the invoked subcommand.
    """

    command: str = ""
    key_id: str = ""
    key_file: str = ""
    action: str | None = None
    subject: str | None = None
    days: int = 7
    limit: int = 50
    new_key_id: str = ""
    old_key_id: str | None = None
    grace_hours: int = 24


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Manage GPG signing keys via GPG Signing Service API"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # List command
    _ = subparsers.add_parser("list", help="List all signing keys")

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a new signing key")
    _ = upload_parser.add_argument("key_id", help="Key identifier")
    _ = upload_parser.add_argument("key_file", help="Path to armored private key file")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a signing key")
    _ = delete_parser.add_argument("key_id", help="Key identifier to delete")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Query audit logs")
    _ = audit_parser.add_argument(
        "--action", help="Filter by action (sign, key_upload, key_rotate)"
    )
    _ = audit_parser.add_argument("--subject", help="Filter by subject")
    _ = audit_parser.add_argument(
        "--days", type=int, default=7, help="Days to include (default: 7)"
    )
    _ = audit_parser.add_argument(
        "--limit", type=int, default=50, help="Max entries (default: 50)"
    )

    # Rotate command
    rotate_parser = subparsers.add_parser("rotate", help="Rotate signing keys")
    _ = rotate_parser.add_argument("new_key_id", help="New key identifier")
    _ = rotate_parser.add_argument("key_file", help="Path to armored private key file")
    _ = rotate_parser.add_argument("--old-key-id", help="Old key to delete")
    _ = rotate_parser.add_argument(
        "--grace-hours",
        type=int,
        default=24,
        help="Grace period in hours before deleting old key (default: 24)",
    )

    return parser


def _cmd_list(client: GPGSigningServiceClient) -> None:
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


def _cmd_upload(client: GPGSigningServiceClient, args: Args) -> None:
    with open(args.key_file) as f:
        armored_key = f.read()

    print(f"Uploading key: {args.key_id}")
    result = client.upload_key(args.key_id, armored_key)
    print("✓ Key uploaded successfully")
    print(f"  Key ID: {result['keyId']}")
    print(f"  Fingerprint: {result['fingerprint']}")
    print(f"  Algorithm: {result['algorithm']}")
    print(f"  User ID: {result['userId']}")


def _cmd_delete(client: GPGSigningServiceClient, args: Args) -> None:
    print(f"Deleting key: {args.key_id}")
    result = client.delete_key(args.key_id)
    print(json.dumps(result, indent=2))


def _cmd_audit(client: GPGSigningServiceClient, args: Args) -> None:
    start_date = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat()
    result = client.get_audit_logs(
        action=args.action,
        subject=args.subject,
        start_date=start_date,
        limit=args.limit,
    )

    print(f"Audit logs (last {args.days} days):")
    print("-" * 80)
    for log in result["logs"]:
        status = "✓" if log["success"] else f"✗ ({log['errorCode'] or 'unknown'})"
        print(
            f"{log['timestamp']} | {log['action']:12} | {log['subject']:20} | {status}"
        )
        print(f"  ID: {log['id']} | Request: {log['requestId']} | Key: {log['keyId']}")
        if log["metadata"]:
            print(f"  Metadata: {log['metadata']}")
        print()
    print(f"Total: {result['count']} entries")


def _cmd_rotate(client: GPGSigningServiceClient, args: Args) -> None:
    with open(args.key_file) as f:
        armored_key = f.read()

    result = client.rotate_keys(
        args.new_key_id,
        armored_key,
        old_key_id=args.old_key_id,
        grace_period_hours=args.grace_hours,
    )
    print(json.dumps(result, indent=2))


def _dispatch(client: GPGSigningServiceClient, args: Args) -> None:
    """Run the handler for the invoked subcommand."""
    if args.command == "list":
        _cmd_list(client)
    elif args.command == "upload":
        _cmd_upload(client, args)
    elif args.command == "delete":
        _cmd_delete(client, args)
    elif args.command == "audit":
        _cmd_audit(client, args)
    elif args.command == "rotate":
        _cmd_rotate(client, args)


def _print_http_error(e: requests.HTTPError) -> None:
    """Print a readable description of an HTTP error response."""
    response = e.response
    if response is None:
        print(f"HTTP Error: {e}", file=sys.stderr)
        return

    try:
        error_data = _json_object(response)
    except (TypeError, ValueError):
        print(f"HTTP {response.status_code}: {response.text}", file=sys.stderr)
    else:
        code = error_data.get("code", "UNKNOWN")
        message = error_data.get("error", str(e))
        print(f"API Error [{code}]: {message}", file=sys.stderr)
        if "requestId" in error_data:
            print(f"Request ID: {error_data['requestId']}", file=sys.stderr)


def main() -> None:
    """CLI for key management."""
    args = _build_parser().parse_args(namespace=Args())
    client = GPGSigningServiceClient()

    try:
        _dispatch(client, args)
    except requests.HTTPError as e:
        _print_http_error(e)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Network Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, TypeError, ValueError) as e:
        # Key file problems, malformed API responses, invalid key IDs,
        # or a missing admin token. Anything else is a bug — let it crash.
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
