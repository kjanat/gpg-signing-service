# Developer Guide - API Documentation

> [!WARNING]
> This historical guide lists files and examples that no longer exist. Use the
> current [documentation index](docs/README.md) and repository instructions in
> [`CLAUDE.md`](CLAUDE.md).

This directory contains comprehensive, production-ready API documentation for
the GPG Signing Service.

## Documentation Files

### Core Documentation

| File                      | Purpose                                | Audience                              |
| ------------------------- | -------------------------------------- | ------------------------------------- |
| **`client/openapi.json`** | Generated OpenAPI 3.0 specification    | Tools, code generators, API platforms |
| **API.md**                | Developer-friendly guide with examples | Software engineers, integrators       |
| **DOCUMENTATION.md**      | Overview and usage guide               | Everyone                              |
| **DEVELOPER_GUIDE.md**    | This file - navigation and context     | Contributors, API users               |

### Examples

| File                            | Purpose                          |
| ------------------------------- | -------------------------------- |
| **`examples/README.md`**        | Complete working code examples   |
| `examples/bash/*.sh`            | Shell scripts for common tasks   |
| `examples/python/*.py`          | Python SDK examples              |
| `examples/github-actions/*.yml` | GitHub Actions workflow examples |
| `examples/gitlab-ci/*.yml`      | GitLab CI pipeline examples      |

## Where to Start

### For API Consumers

1. **Quick Start**: Read first 100 lines of `API.md`
2. **Authentication**: See "Authentication Methods" section
3. **Examples**: Check `examples/` directory for your platform
4. **Reference**: Detailed endpoint docs in `API.md` sections

### For API Integration

1. **OpenAPI Import**: Load `client/openapi.json` into Swagger UI or Postman
2. **Code Generation**: Use `client/openapi.json` with code generators
3. **Documentation**: Browse the deployed Swagger UI at `GET /ui`, or host
   `client/openapi.json` with ReDoc or similar
4. **Testing**: Use examples as test cases

### For Administration

1. **Key Management**: See `examples/bash/manage-keys.sh`
2. **Audit Queries**: See `examples/bash/query-audit.sh`
3. **Monitoring**: Setup via health check endpoint
4. **Troubleshooting**: See "Troubleshooting" in `DOCUMENTATION.md`

## API Endpoints Overview

### Public (No Auth)

- `GET /health` - Service status
- `GET /public-key` - Retrieve public signing key

### Protected (OIDC)

- `POST /sign` - Sign commit data

### Admin (Bearer Token)

- `POST /admin/keys` - Upload key
- `GET /admin/keys` - List keys
- `GET /admin/keys/{keyId}/public` - Get public key
- `DELETE /admin/keys/{keyId}` - Delete key
- `GET /admin/audit` - Query audit logs

## Key Concepts

### Authentication

**OIDC Tokens** (for /sign endpoint):

- From GitHub Actions: `$ACTIONS_ID_TOKEN_REQUEST_TOKEN`
- From GitLab CI: `$CI_JOB_JWT` or `$CI_JOB_JWT_V2`
- Validated against JWKS endpoints

**Bearer Token** (for /admin endpoints):

- Static token: `ADMIN_TOKEN` secret
- Included in Authorization header

### Rate Limiting

Token bucket algorithm:

- `/sign`: 100 requests/minute per OIDC identity
- `/admin/*`: 60 requests/minute per bearer token
- Response headers: `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- `HTTP 429` when exceeded (includes `retryAfter` in response)

### Error Handling

All errors follow format:

```json
{ "error": "Human message", "code": "MACHINE_CODE", "requestId": "uuid" }
```

Error codes documented in API.md "Error Codes Reference" section.

### Audit Logging

All operations logged with:

- Timestamp, Request ID
- Action type: `sign`, `key_upload`, `key_rotate`
- OIDC identity or "admin"
- Success/failure with error codes
- Optional metadata (JSON)

Query via `GET /admin/audit` with filtering.

## Common Tasks

### Add Signing to Workflow

See `examples/` for platform-specific:

- GitHub Actions: `examples/github-actions/sign-commits.yml`
- GitLab CI: `examples/gitlab-ci/sign-commits.yml`
- Bash: `examples/bash/sign-commit.sh`
- Python: `examples/python/sign_commit.py`

### Upload New Key

```bash
curl -X POST https://gpg.kajkowalski.nl/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "signing-key-prod",
    "armoredPrivateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n..."
  }'
```

See `examples/python/manage_keys.py` for production example.

### Check Service Health

```bash
curl https://gpg.kajkowalski.nl/health | jq .
```

### Query Audit Logs

```bash
# All signing operations from last 7 days
DAYS_AGO=$(date -u -d '7 days ago' +%Y-%m-%dT00:00:00Z)
curl "https://gpg.kajkowalski.nl/admin/audit?action=sign&startDate=$DAYS_AGO" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

See examples/bash/query-audit.sh for advanced queries.

### Rotate Keys

See examples/python/manage_keys.py rotate command for complete implementation.

## Integration Checklist

- [ ] Import `client/openapi.json` into API documentation tool
- [ ] Setup OIDC token retrieval in CI/CD
- [ ] Test signing with public key retrieval
- [ ] Configure admin token as secret
- [ ] Verify rate limiting behavior
- [ ] Setup audit log monitoring
- [ ] Document key rotation procedure
- [ ] Test error scenarios
- [ ] Configure alerting for failures
- [ ] Document for team

## Testing the API

### Manual Testing

1. **Get public key** (no auth):

   ```bash
   curl https://gpg.kajkowalski.nl/public-key
   ```

2. **Check health** (no auth):

   ```bash
   curl https://gpg.kajkowalski.nl/health | jq .
   ```

3. **List keys** (needs admin token):

   ```bash
   curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://gpg.kajkowalski.nl/admin/keys | jq .
   ```

### With Postman

1. Import `client/openapi.json` as Postman collection
2. Create environment with variables:
   - `base_url`: https://gpg.kajkowalski.nl
   - `admin_token`: your token value
   - `oidc_token`: from your CI/CD system
3. Run requests with pre-request scripts for OIDC

### With Swagger UI

The deployed service already hosts Swagger UI at
<https://gpg.kajkowalski.nl/ui>. To run it against the checked-in contract:

```bash
# Local Swagger UI pointing to client/openapi.json
docker run -p 8080:8080 \
  -v $(pwd)/client/openapi.json:/openapi.json:ro \
  -e SWAGGER_JSON=/openapi.json \
  swaggerapi/swagger-ui
```

## Troubleshooting

### 401 Unauthorized

Check:

- Authorization header present and formatted correctly
- Token not expired
- Correct token for endpoint type (OIDC vs Bearer)
- Token scopes/claims valid

### 429 Rate Limited

Check:

- Request frequency within limits
- Implementing backoff (use `retryAfter` value)
- Different identities for parallel requests

### 503 Service Unavailable

Check:

- Service dependencies (key storage, database)
- Use `/health` endpoint to diagnose
- Service should auto-recover

### Signature Verification Fails

Check:

- Used correct public key (from `/public-key` endpoint)
- Commit data hasn't been modified
- Key hasn't been rotated since signing

## API Specification Format

OpenAPI 3.0.0 with:

- Full endpoint documentation
- Request/response schemas
- Error codes and examples
- Security scheme definitions
- Rate limiting headers
- Audit logging details

> [!NOTE]
> The spec is pinned to 3.0.0 on purpose: `oapi-codegen` does not support
> OpenAPI 3.1.x yet
> ([oapi-codegen#373](https://github.com/oapi-codegen/oapi-codegen/issues/373)).
> The pin lives in `src/lib/openapi.ts`.

### Specification Compliance

All endpoints and responses validate against the `client/openapi.json` schema.\
Use tools like:

```bash
# Validate the spec
bunx @redocly/cli lint client/openapi.json

# Generate tests from spec
dredd client/openapi.json https://gpg.kajkowalski.nl
```

## Keeping Documentation Updated

The spec is generated from the route definitions in `src/`; it is never edited
by hand. When the API changes:

1. **Update the route/schema definitions** in `src/` (`@hono/zod-openapi`
   registrations plus `src/lib/openapi.ts`)
2. **Regenerate**: `task gen` (runs `scripts/generate-openapi.ts` and the Go
   client generator, refreshing `client/openapi.json`)
3. **Update `docs/api.md`** with new examples
4. **Update examples/** directory
5. **Commit and push** the regenerated spec and documentation changes

## Support

- **Issues/Questions**: GitHub repository issues
- **Specification**: See `client/openapi.json` for complete definition
- **Examples**: See `examples/` directory
- **Troubleshooting**: See DOCUMENTATION.md

## Files Summary

### Documentation (in root directory)

```
API.md                722 lines - Developer guide with examples
DOCUMENTATION.md      386 lines - Overview and usage
DEVELOPER_GUIDE.md              - This file
```

The OpenAPI specification is generated, not hand-written, and lives at
`client/openapi.json`.

### Examples (in examples/ directory)

```tree
bash/
  sign-commit.sh      - Production-quality signing script
  manage-keys.sh      - Key management operations
  query-audit.sh      - Audit log queries

python/
  sign_commit.py      - Complete Python signing example
  manage_keys.py      - Python key management client

github-actions/
  sign-commits.yml    - GitHub Actions workflow

gitlab-ci/
  sign-commits.yml    - GitLab CI pipeline
```

## Statistics

- **OpenAPI Schema**: `client/openapi.json` (generated)
- **API Documentation**: 722 lines (markdown)
- **Complete Examples**: 4 bash scripts, 2 Python modules, 2 CI workflows
- **Total Documentation**: 3000+ lines of production-ready content

---

Last updated: 2025-11-19\
OpenAPI Version: `3.0.0`\
API Version: `1.0.0`
