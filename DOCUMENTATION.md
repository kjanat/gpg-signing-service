# API Documentation Summary

## What's Included

This directory contains comprehensive API documentation for the GPG Signing
Service:

### Files

1. **client/openapi.json** - OpenAPI 3.1 specification in JSON format
   - Machine-readable API contract
   - Auto-generated from Hono route definitions via `task generate:api`
   - Compatible with code generators, documentation tools, and testing frameworks
   - Includes all endpoints, parameters, request/response schemas
   - Security schemes and error codes defined

2. **API.md** - Developer-friendly API documentation
   - Quick start examples
   - Authentication flows for GitHub Actions and GitLab CI
   - Endpoint documentation with examples
   - Error reference and rate limiting explanation
   - Integration guides and code samples

3. **DOCUMENTATION.md** (this file) - Overview and usage guide

## Quick Links

### For Developers

- Start with **API.md** for quick start and examples
- Reference **client/openapi.json** for detailed specs
- Use integration guides for GitHub Actions or GitLab CI

### For API Consumers

- Import **client/openapi.json** into Swagger UI for interactive testing
- Generate client SDKs in your preferred language
- Use with Postman, Insomnia, or other API clients

### For DevOps/Tools

- Use **client/openapi.json** with code generation tools
- Reference error codes in monitoring/alerting
- Query audit logs via GET /admin/audit endpoint

## Key Information

### Base URL

```text
https://gpg.kajkowalski.nl
```

### Authentication Methods

#### Public Endpoints (no auth)

- `GET /health`
- `GET /public-key`

#### Protected Endpoints (OIDC)

- `POST /sign` (requires GitHub Actions or GitLab CI OIDC token)
- Rate limited: 100 req/minute per identity

#### Admin Endpoints (Bearer token)

- `POST /admin/keys` (upload key)
- `GET /admin/keys` (list keys)
- `GET /admin/keys/{keyId}/public` (get public key)
- `DELETE /admin/keys/{keyId}` (delete key)
- `GET /admin/audit` (audit logs)
- Rate limited: 60 req/minute

### Response Headers

All responses include:

- `X-Request-ID` - Unique request identifier
- `X-RateLimit-Remaining` - Requests remaining in rate limit window
- `X-RateLimit-Reset` - Unix timestamp when limit resets

## Using the OpenAPI Specification

### Swagger UI (Interactive Testing)

The service exposes a built-in Swagger UI at `/ui` and OpenAPI spec at `/doc`.

Alternatively, host the specification locally:

```bash
# Using Docker with local openapi.json
docker run -p 8080:8080 \
  -v $(pwd)/client/openapi.json:/openapi.json:ro \
  -e SWAGGER_JSON=/openapi.json \
  swaggerapi/swagger-ui
```

### Postman

1. File → Import → Select `client/openapi.json` from the repository
2. Create environment variables for authentication tokens
3. Use generated examples for all endpoints

### ReDoc (Beautiful Documentation)

```bash
bunx @redocly/cli build-docs client/openapi.json
```

or

```html
<!DOCTYPE html>
<html>
  <head>
    <title>GPG Signing Service API</title>
    <style>
      body {
        margin: 0;
        padding: 0;
      }
    </style>
  </head>
  <body>
    <redoc spec-url="./client/openapi.json"></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"></script>
  </body>
</html>
```

### Code Generation

Generate client libraries in multiple languages:

```bash
# Using openapi-generator-cli
bunx @openapitools/openapi-generator-cli generate \
  -i client/openapi.json \
  -g python \
  -o ./python-client

# JavaScript/TypeScript
bunx @openapitools/openapi-generator-cli generate \
  -i client/openapi.json \
  -g typescript-fetch \
  -o ./typescript-client

# Go (already generated in client/pkg/api/)
bunx @openapitools/openapi-generator-cli generate \
  -i client/openapi.json \
  -g go \
  -o ./go-client
```

## Common Use Cases

### Setup Git Commit Signing

#### GitHub Actions

```yaml
- name: Configure GPG signing
  run: |
    # Import public key
    curl https://gpg.kajkowalski.nl/public-key | gpg --import

    # Get OIDC token
    OIDC_TOKEN=$(
      curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL" \
      | jq -r '.token'
    )

    # Sign commit
    SIGNATURE=$(curl -X POST \
      -H "Authorization: Bearer $OIDC_TOKEN" \
      --data-raw "$(git cat-file commit HEAD)" \
      https://gpg.kajkowalski.nl/sign)
```

#### GitLab CI

```yaml
sign_commits:
  script:
    - curl https://gpg.kajkowalski.nl/public-key | gpg --import
    - curl -X POST -H "Authorization{:} Bearer $CI_JOB_JWT" \
    --data-raw "$(git cat-file commit HEAD)" \
      https://gpg.kajkowalski.nl/sign
```

### Monitor Service Health

```bash
# Check service status
curl https://gpg.kajkowalski.nl/health | jq .

# Alert if degraded
curl -s https://gpg.kajkowalski.nl/health \
  | jq 'if .status != "healthy" then "ALERT: Service degraded" else "OK" end'
```

### Audit Key Operations

```bash
# Get all key uploads in last 7 days
DAYS_AGO="$(date -u -d '7 days ago' +%Y-%m-%dT00:00:00Z)"
curl "https://gpg.kajkowalski.nl/admin/audit?action=key_upload&startDate=${DAYS_AGO}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq '.logs'

# Get failed signing attempts
curl "https://gpg.kajkowalski.nl/admin/audit?action=sign" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq '.logs | map(select(.success == false))'
```

### Rotate Signing Keys

```bash
#!/usr/bin/env bash

ADMIN_TOKEN="..."
OLD_KEY_ID="signing-key-v1"
NEW_KEY_ID="signing-key-v2"

# Upload new key
NEW_KEY="$(cat new-key.asc)" # Armored private key
curl -X POST \
  https://gpg.kajkowalski.nl/admin/keys \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{'keyId': \"${NEW_KEY_ID}\", 'armoredPrivateKey': \"${NEW_KEY}\"}"

# Verify new key works
curl "https://gpg.kajkowalski.nl/public-key?keyId=${NEW_KEY_ID}" \
  | gpg --import

# Update CI/CD to use new key
# ... (update workflows to use keyId=$NEW_KEY_ID) ...

# Delete old key after transition period
sleep 86400 # Wait 24 hours
curl -X DELETE \
  "https://gpg.kajkowalski.nl/admin/keys/${OLD_KEY_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## Error Handling

All errors follow consistent format:

```json
{
  "error": "Human-readable message",
  "code": "MACHINE_READABLE_CODE",
  "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

Reference error codes in the Error Codes section of `API.md`.

## Rate Limiting Strategy

### Token Bucket Algorithm

Each identity has a refillable bucket of tokens:

- `/sign` endpoint: 100 tokens/minute per OIDC identity
- `/admin/*` endpoints: 60 tokens/minute per bearer token
- When bucket empty, requests rejected with `HTTP 429`

### Handling Rate Limits

```bash
#!/usr/bin/env bash

MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  RESPONSE=$(curl -w "\n%{http_code}" -X POST \
    -H "Authorization: Bearer $TOKEN" \
    --data-raw "$DATA" \
    https://gpg.kajkowalski.nl/sign)

  HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  BODY=$(echo "$RESPONSE" | head -n -1)

  if [[ "$HTTP_CODE" = "200" ]]; then
    echo "$BODY"
    exit 0
  elif [[ "$HTTP_CODE" = "429" ]]; then
    RETRY_AFTER=$(echo "$BODY" | jq .retryAfter)
    echo "Rate limited, waiting ${RETRY_AFTER}s..."
    sleep $RETRY_AFTER
    RETRY_COUNT=$((RETRY_COUNT + 1))
  else
    echo "Error: $BODY"
    exit 1
  fi
done

echo "Failed after $MAX_RETRIES retries"
exit 1
```

## Security Best Practices

### OIDC Token Handling

- Tokens are short-lived and automatically validated
- Never store tokens in logs or audit trails
- Use `X-Request-ID` for correlation instead

### Admin Token Management

- Store `ADMIN_TOKEN` as secret in CI/CD system
- Rotate periodically (monthly recommended)
- Use different tokens for different environments
- Never commit to version control

### Key Management

- Keep private keys encrypted and backed up
- Rotate keys regularly (annually minimum)
- Verify key fingerprints before uploading
- Monitor key usage via audit logs

## Troubleshooting

### `401 Unauthorized`

**Cause**: Invalid or missing authentication

- Check `Authorization` header is present
- Verify token is not expired
- Ensure token format is `Bearer <token>`

**Solution**:

```bash
# For OIDC
OIDC_TOKEN=$(
  curl -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL" \
    | jq -r '.token'
)

# For Admin
curl -X POST https://gpg.kajkowalski.nl/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### `429 Rate Limited`

**Cause**: Too many requests in short time

- Check `X-RateLimit-Remaining` header
- Wait until `X-RateLimit-Reset` timestamp

**Solution**: Implement exponential backoff with jitter

### `503 Service Unavailable`

**Cause**: Rate limiter Durable Object offline

- Service will recover automatically
- Request will fail safely (fail-closed)

**Solution**: Retry after brief delay, use circuit breaker pattern

### `Key Not Found (404)`

**Cause**: Key ID doesn't exist or typo

- Verify key was uploaded: `GET /admin/keys`
- Check keyId spelling and case sensitivity
- Ensure using correct environment's base URL

**Solution**:

```bash
# List all available keys
curl https://gpg.kajkowalski.nl/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq '.keys[].keyId'
```

## API Versioning

Current version: **1.0.0**

Breaking changes will result in new version. Current approach:

- Additive changes to existing endpoints
- New endpoints added with `/v2/` prefix if incompatible changes needed
- Deprecated endpoints marked in documentation

## Support Resources

- **Documentation**: See `API.md` for detailed examples
- **OpenAPI Spec**: Import `client/openapi.json` into API tools
- **Live Swagger UI**: Available at `/ui` on the deployed service
- **Repository**: https://github.com/kjanat/gpg-signing-service
- **Issues**: https://github.com/kjanat/gpg-signing-service/issues
- **Security**: GitHub security advisory process

## Next Steps

1. **Import OpenAPI spec** into your API documentation tool (Swagger, ReDoc,
   etc.)
2. **Setup authentication** - Get OIDC token from your CI/CD system
3. **Test endpoints** - Use Postman or curl to verify connectivity
4. **Integrate signing** - Use API in your CI/CD workflows
5. **Monitor audits** - Regularly check audit logs for anomalies

For detailed examples and integration guides, see **API.md**.
