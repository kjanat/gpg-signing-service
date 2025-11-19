# GPG Signing Service API Documentation

## Overview

The GPG Signing Service is an edge-deployed Git commit signing API running on
Cloudflare Workers. It provides OIDC-based signing capabilities for CI/CD
pipelines and comprehensive administrative key management.

**Base URL**: `https://gpg.kajkowalski.nl`

## Quick Start

### 1. Retrieve Public Key (No Auth)

```bash
curl https://gpg.kajkowalski.nl/public-key
```

Returns an armored GPG public key for importing into Git:

```bash
curl https://gpg.kajkowalski.nl/public-key | gpg --import
git config user.signingkey <KEY_ID>
```

### 2. Sign Commit Data (OIDC Auth)

Requires a valid OIDC token from GitHub Actions or GitLab CI:

```bash
# GitHub Actions
OIDC_TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r '.token')

# Sign commit
SIGNATURE=$(curl -X POST \
  -H "Authorization: Bearer $OIDC_TOKEN" \
  --data-raw "$(git cat-file commit HEAD)" \
  https://gpg.kajkowalski.nl/sign)
```

### 3. Manage Keys (Admin Auth)

```bash
# Upload a new key
curl -X POST https://gpg.kajkowalski.nl/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "signing-key-v1",
    "armoredPrivateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n..."
  }'
```

## Authentication

### Public Endpoints

No authentication required. These endpoints are rate-limited by global defaults.

- `GET /health` - Service health status
- `GET /public-key` - Retrieve public signing key

### Protected Endpoints (/sign)

**Authentication**: OIDC Bearer Token

**Rate Limit**: 100 requests/minute per OIDC identity

**Headers**:

```
Authorization: Bearer <oidc-token>
```

#### GitHub Actions

1. Add `id-token: write` to workflow permissions:

```yaml
permissions:
  id-token: write
```

2. Request OIDC token:

```yaml
- name: Get OIDC Token
  run: |
    OIDC_TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r '.token')
    echo "OIDC_TOKEN=$OIDC_TOKEN" >> $GITHUB_ENV
```

3. Use in API calls:

```yaml
- name: Sign with service
  run: |
    curl -X POST https://gpg.kajkowalski.nl/sign \
      -H "Authorization: Bearer $OIDC_TOKEN" \
      --data-raw "$(git cat-file commit HEAD)"
```

#### GitLab CI

GitLab provides OIDC token as `$CI_JOB_JWT`:

```yaml
sign_with_service:
  script:
    - curl -X POST https://gpg.kajkowalski.nl/sign \
        -H "Authorization: Bearer $CI_JOB_JWT" \
        --data-raw "$(git cat-file commit HEAD)"
```

### Admin Endpoints (/admin/\*)

**Authentication**: Bearer Token (ADMIN_TOKEN)

**Rate Limit**: 60 requests/minute

**Headers**:

```
Authorization: Bearer <admin-token>
```

Set admin token:

```bash
wrangler secret put ADMIN_TOKEN
# Enter your secure token
```

## API Endpoints

### Health & Public

#### GET /health

Health check for all service dependencies.

**Response** (200 OK - All healthy):

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:45.123Z",
  "version": "1.0.0",
  "checks": { "keyStorage": true, "database": true }
}
```

**Response** (503 Service Unavailable - Degraded):

```json
{
  "status": "degraded",
  "timestamp": "2024-01-15T10:30:45.123Z",
  "version": "1.0.0",
  "checks": { "keyStorage": false, "database": true }
}
```

---

#### GET /public-key

Retrieve the armored public key for signature verification.

**Parameters**:

- `keyId` (query, optional): Key identifier. Defaults to `KEY_ID` environment
  variable.

**Response** (200 OK):

```text
Content-Type: application/pgp-keys

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v6.0.0
Comment: https://openpgpjs.org

xjMEZbI4sRYJKwYBBAHaM...
-----END PGP PUBLIC KEY BLOCK-----
```

**Error** (404):

```json
{ "error": "Key not found", "code": "KEY_NOT_FOUND" }
```

---

### Signing

#### POST /sign

Sign commit data using a private key.

**Authentication**: OIDC Bearer Token

**Parameters**:

- `keyId` (query, optional): Key to use for signing. Defaults to `KEY_ID`.
- `X-Request-ID` (header, optional): Request identifier for audit correlation.

**Request Body**: Raw commit data (text/plain)

```text
tree abc123
parent def456
author Name <email@example.com> 1234567890 +0000
committer Name <email@example.com> 1234567890 +0000

Commit message
```

**Response** (200 OK):

```text
Content-Type: text/plain

-----BEGIN PGP SIGNATURE-----
Version: OpenPGP.js v6.0.0
Comment: https://openpgpjs.org

wpYEAREBAgAGBQJlsji1AAoJEP...
-----END PGP SIGNATURE-----
```

**Response Headers**:

- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets
- `X-Request-ID`: Unique request identifier

**Error** (400 - Missing data):

```json
{
  "error": "No commit data provided",
  "code": "INVALID_REQUEST",
  "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Error** (401 - Auth failed):

```json
{ "error": "Unauthorized", "code": "AUTH_INVALID" }
```

**Error** (429 - Rate limited):

```json
{ "error": "Rate limit exceeded", "code": "RATE_LIMITED", "retryAfter": 45 }
```

**Example Usage**:

```bash
#!/usr/bin/env bash
OIDC_TOKEN="..."
COMMIT_DATA=$(git cat-file commit HEAD)

RESPONSE=$(curl -w "\n%{http_code}" -X POST \
  -H "Authorization: Bearer $OIDC_TOKEN" \
  -H "X-Request-ID: $(uuidgen)" \
  --data-raw "$COMMIT_DATA" \
  https://gpg.kajkowalski.nl/sign)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
SIGNATURE=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
  # Use signature in git config
  git config user.signingkey "$SIGNATURE"
else
  # Handle error
  echo "Signing failed: $RESPONSE"
fi
```

---

### Admin - Key Management

#### POST /admin/keys

Upload a new signing key.

**Authentication**: Bearer Token

**Request Body** (application/json):

```json
{
  "keyId": "signing-key-v1",
  "armoredPrivateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: OpenPGP.js v6.0.0\n...\n-----END PGP PRIVATE KEY BLOCK-----"
}
```

**Response** (201 Created):

```json
{
  "success": true,
  "keyId": "signing-key-v1",
  "fingerprint": "1234567890ABCDEF1234567890ABCDEF12345678",
  "algorithm": "rsa4096",
  "userId": "Signing Service <signer@example.com>"
}
```

**Error** (400 - Validation):

```json
{ "error": "Missing armoredPrivateKey or keyId", "code": "INVALID_REQUEST" }
```

**Error** (500 - Processing):

```json
{
  "error": "Invalid key format",
  "code": "KEY_UPLOAD_ERROR",
  "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

#### GET /admin/keys

List all stored signing keys (metadata only, no private key exposure).

**Authentication**: Bearer Token

**Response** (200 OK):

```json
{
  "keys": [
    {
      "keyId": "signing-key-v1",
      "fingerprint": "1234567890ABCDEF1234567890ABCDEF12345678",
      "algorithm": "rsa4096",
      "createdAt": "2024-01-15T10:30:45.123Z"
    },
    {
      "keyId": "signing-key-v2",
      "fingerprint": "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
      "algorithm": "ed25519",
      "createdAt": "2024-01-10T14:20:30.456Z"
    }
  ]
}
```

---

#### GET /admin/keys/{keyId}/public

Get the public key component of a stored private key.

**Authentication**: Bearer Token

**Path Parameters**:

- `keyId`: The key identifier

**Response** (200 OK):

```text
Content-Type: application/pgp-keys

-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----
```

**Error** (404 - Not found):

```json
{ "error": "Key not found", "code": "KEY_NOT_FOUND" }
```

---

#### DELETE /admin/keys/{keyId}

Permanently delete a signing key.

**Authentication**: Bearer Token

**Path Parameters**:

- `keyId`: The key identifier

**Headers** (optional):

- `X-Request-ID`: Request identifier for audit correlation

**Response** (200 OK):

```json
{ "success": true, "deleted": true }
```

---

### Admin - Audit Logs

#### GET /admin/audit

Query audit log entries with filtering and pagination.

**Authentication**: Bearer Token

**Query Parameters**:

- `limit` (integer, default: 100, max: 1000): Entries per page
- `offset` (integer, default: 0): Skip first N entries
- `action` (string, optional): Filter by action (sign, key_upload, key_rotate)
- `subject` (string, optional): Filter by subject (OIDC subject or "admin")
- `startDate` (ISO 8601, optional): Range start (inclusive)
- `endDate` (ISO 8601, optional): Range end (inclusive)

**Response** (200 OK):

```json
{
  "logs": [
    {
      "id": "audit-001",
      "timestamp": "2024-01-15T10:30:45.123Z",
      "requestId": "550e8400-e29b-41d4-a716-446655440000",
      "action": "sign",
      "issuer": "https://token.actions.githubusercontent.com",
      "subject": "owner/repo",
      "keyId": "signing-key-v1",
      "success": true,
      "metadata": "{\"repository\":\"owner/repo\",\"dataLength\":542}"
    },
    {
      "id": "audit-002",
      "timestamp": "2024-01-15T10:29:30.456Z",
      "requestId": "660e8400-e29b-41d4-a716-446655440001",
      "action": "key_upload",
      "issuer": "admin",
      "subject": "admin",
      "keyId": "signing-key-v2",
      "success": true,
      "metadata": "{\"fingerprint\":\"ABCDEF...\",\"algorithm\":\"ed25519\"}"
    }
  ],
  "count": 2
}
```

**Filtering Examples**:

```bash
# Get all signing operations from a specific repository
curl "https://gpg.kajkowalski.nl/admin/audit?action=sign&subject=owner/repo" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Get key operations in a date range
curl "https://gpg.kajkowalski.nl/admin/audit?action=key_upload&startDate=2024-01-01&endDate=2024-01-31" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Paginate through large result sets
curl "https://gpg.kajkowalski.nl/admin/audit?limit=50&offset=0" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Error Codes Reference

| Code                   | HTTP  | Description                                        |
| ---------------------- | ----- | -------------------------------------------------- |
| `AUTH_MISSING`         | `401` | Authorization header not provided                  |
| `AUTH_INVALID`         | `401` | Invalid or expired authentication token            |
| `KEY_NOT_FOUND`        | `404` | Requested key does not exist                       |
| `KEY_PROCESSING_ERROR` | `500` | Error processing key data (extraction, parsing)    |
| `KEY_LIST_ERROR`       | `500` | Error retrieving list of keys                      |
| `KEY_UPLOAD_ERROR`     | `500` | Error uploading or storing new key                 |
| `KEY_DELETE_ERROR`     | `500` | Error deleting key                                 |
| `SIGN_ERROR`           | `500` | Signing operation failed                           |
| `RATE_LIMIT_ERROR`     | `503` | Rate limiter service unavailable                   |
| `RATE_LIMITED`         | `429` | Rate limit exceeded for this identity              |
| `INVALID_REQUEST`      | `400` | Malformed request (missing fields, invalid format) |
| `AUDIT_ERROR`          | `500` | Failed to retrieve audit logs                      |
| `NOT_FOUND`            | `404` | Endpoint not found                                 |
| `INTERNAL_ERROR`       | `500` | Unexpected server error                            |

---

## Rate Limiting

### Token Bucket Algorithm

The service uses a token bucket rate limiter:

- Each OIDC identity has its own rate limit bucket
- Tokens are consumed per request
- Tokens are refilled over time
- When bucket is empty, requests are rejected with HTTP 429

### Limits by Endpoint Type

| Endpoint         | Limit          | Window            |
| ---------------- | -------------- | ----------------- |
| Public endpoints | Global default | Per request       |
| `/sign`          | 100 req/min    | Per OIDC identity |
| `/admin/*`       | 60 req/min     | Per admin token   |

### Rate Limit Headers

All responses include rate limit information:

- `X-RateLimit-Remaining`: Tokens remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets

### Handling Rate Limits

When rate limited (HTTP 429):

```json
{ "error": "Rate limit exceeded", "code": "RATE_LIMITED", "retryAfter": 45 }
```

Implementation:

```bash
RETRY_AFTER=$(curl ... | jq .retryAfter)
sleep $RETRY_AFTER
# Retry request
```

---

## Audit Logging

All operations are logged to D1 database with:

- **Timestamp**: ISO 8601 format
- **Request ID**: UUID for correlation
- **Action**: sign, key_upload, key_rotate
- **Identity**: OIDC issuer and subject (or "admin")
- **Key ID**: Which key was used
- **Success**: Whether operation succeeded
- **Error Code**: If operation failed
- **Metadata**: Additional JSON context

### Retention

Audit logs are retained indefinitely in the database. Query with:

```bash
# All operations from last 7 days
curl "https://gpg.kajkowalski.nl/admin/audit?startDate=$(date -u -d '7 days ago' +%Y-%m-%dT00:00:00Z)" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Failed operations only
curl "https://gpg.kajkowalski.nl/admin/audit?limit=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq '.logs | map(select(.success == false))'
```

---

## Security Considerations

### OIDC Token Validation

Tokens are validated by:

1. Checking cryptographic signature against JWKS endpoint
2. Verifying issuer is in `ALLOWED_ISSUERS` list
3. Checking token is not expired (`exp` claim)
4. Validating audience claim (`aud`)

### Private Key Security

- Private keys are encrypted at rest in Durable Objects
- Decrypted only in memory for signing operations
- Never exposed via API endpoints
- Passphrase required for key operations (set via `wrangler secret`)

### CORS Policy

Production deployment uses restricted CORS:

- Only specified origins allowed
- Credentials excluded from browser requests

### Rate Limiting

Prevents brute force attacks:

- Per-identity rate limiting on /sign
- Per-token rate limiting on admin endpoints
- Fail-closed when limiter unavailable (503 Service Unavailable)

### TLS/HTTPS

All connections require HTTPS. HTTP requests are not accepted.

---

## Integration Guides

### GitHub Actions

Complete workflow for signing commits:

```yaml
name: Sign Commits
on:
  push:
    branches: [master, main]

permissions:
  id-token: write
  contents: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get OIDC Token
        run: |
          OIDC_TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r '.token')
          echo "OIDC_TOKEN=$OIDC_TOKEN" >> $GITHUB_ENV

      - name: Configure git
        run: |
          git config user.email "actions@github.com"
          git config user.name "GitHub Actions"

      - name: Sign commits
        run: |
          # Get public key
          curl https://gpg.kajkowalski.nl/public-key | gpg --import

          # For each commit, create signature
          for COMMIT in $(git log origin/master..HEAD --pretty=format:%H); do
            COMMIT_DATA=$(git cat-file commit $COMMIT)
            SIGNATURE=$(curl -s -X POST \
              -H "Authorization: Bearer $OIDC_TOKEN" \
              --data-raw "$COMMIT_DATA" \
              https://gpg.kajkowalski.nl/sign)

            # Update commit with signature (requires custom git flow)
            git config commit.gpgsign true
          done

      - name: Push signed commits
        run: |
          git push origin HEAD:master
```

### GitLab CI

Complete pipeline for signing commits:

```yaml
stages:
  - sign

sign_commits:
  stage: sign
  script:
    # Get public key
    - curl https://gpg.kajkowalski.nl/public-key | gpg --import

    # Configure git
    - git config user.email "ci@gitlab.com"
    - git config user.name "GitLab CI"
    - |
      git config user.signingkey "$(
        curl -s https://gpg.kajkowalski.nl/public-key |
        gpg --import-options show-only --import --with-colons 2>/dev/null |
        awk -F: '/^fpr:/{print $10; exit}'
      )"

    # Sign and push
    - git commit --amend -S --no-edit || true
    - git push https://oauth2:$CI_JOB_TOKEN@$CI_SERVER_HOST/$CI_PROJECT_PATH.git
      HEAD:$CI_COMMIT_BRANCH

  only:
    - master
    - master
  needs:
    - job: build
      artifacts: false
```

---

## OpenAPI Specification

Full OpenAPI 3.1 specification available in `openapi.yaml`. Use with:

- **Swagger UI**: Host openapi.yaml for interactive API explorer
- **Code Generation**: Generate SDKs in multiple languages
- **Documentation**: Generate beautiful API docs
- **Testing**: Automated validation against spec

Example hosting:

```bash
# Using Swagger UI Docker
docker run -p 8080:8080 -e SWAGGER_JSON=/openapi.yaml \
  -v $(pwd)/openapi.yaml:/openapi.yaml \
  swaggerapi/swagger-ui
```

---

## Support & Feedback

- Repository: [https://github.com/kjanat/gpg-signing-service][repo]
- Issues: [https://github.com/kjanat/gpg-signing-service/issues][repo:issues]
- Security: Contact via GitHub security advisory

[repo]: https://github.com/kjanat/gpg-signing-service
[repo:issues]: https://github.com/kjanat/gpg-signing-service/issues
[repo:security]:
  https://github.com/kjanat/gpg-signing-service/security/advisories
[repo:license]:
  https://github.com/kjanat/gpg-signing-service/blob/master/LICENSE
