# GPG Signing Service

Edge-deployed Git commit signing API using Hono on Cloudflare Workers with
openpgp.js.

## Features

- GPG-compatible commit signing via REST API
- OIDC authentication for GitHub Actions and GitLab CI
- Durable Objects for secure key storage
- D1 database for audit logging
- Rate limiting per CI identity
- Multi-key support with rotation

## Architecture

```mermaid
flowchart LR
    CI[CI Pipeline] -->|OIDC Token| SS[Signing Service]
    SS -->|Signed Commit| SC[Signed Commit]

    subgraph Storage
        direction TB
        DO[("Durable Object\n(Key Storage)")]
        D1[("D1 Database\n(Audit Logs)")]
    end

    SS --> DO
    SS --> D1
```

<!--
```
CI Pipeline -> OIDC Token -> Signing Service -> Signed Commit
                                   |
                    +--------------+--------------+
                    |                             |
              Durable Object               D1 Database
              (Key Storage)               (Audit Logs)
```
-->

## Setup

### 1. Prerequisites

- [Cloudflare account](https://dash.cloudflare.com/)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- GPG installed locally

### 2. Create Cloudflare Resources

```bash
# Create D1 database
bun run db:create
# Copy the database_id to wrangler.toml

# Create KV namespace
bun run kv:create
# Copy the id to wrangler.toml

# Set secrets
wrangler secret put KEY_PASSPHRASE
wrangler secret put ADMIN_TOKEN
```

### 3. Generate Signing Key

```bash
# Generate key in .keys/ directory (NOT ~/.gnupg)
bun run generate-key "Your Name" "your@email.com" "Signing Key" "your-passphrase"
```

### 4. Deploy

```bash
# Run database migration
bun run db:migrate

# Deploy to Cloudflare
bun run deploy
```

### 5. Upload Key to Service

```bash
curl -X POST https://your-worker.workers.dev/admin/keys \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "armoredPrivateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----",
    "keyId": "signing-key-v1"
  }'
```

## API Endpoints

### Public

- `GET /health` - Health check
- `GET /public-key` - Get public key for signature verification

### Protected (OIDC Auth)

- `POST /sign` - Sign commit data

### Admin (Admin Token)

- `POST /admin/keys` - Upload signing key
- `GET /admin/keys` - List keys
- `GET /admin/keys/:keyId/public` - Get public key
- `DELETE /admin/keys/:keyId` - Delete key
- `GET /admin/audit` - Get audit logs

## CI Integration

### GitHub Actions

1. Set repository variable `SIGNING_SERVICE_URL`
2. Add workflow from `.github/workflows/sign-commits.yml`
3. Configure OIDC audience in your worker's `ALLOWED_ISSUERS`

### GitLab CI

1. Set CI variable `SIGNING_SERVICE_URL`
2. Add pipeline from `.gitlab-ci.yml`
3. Configure OIDC audience

## Development

```bash
# Install dependencies
bun install

# Run locally
bun run dev

# Type check
bun run typecheck

# Generate API schema and Go client
bun run generate:api
```

### API Documentation

The service exposes API documentation at both:

- `/doc` - OpenAPI 3.0 JSON spec
- `/ui` - Swagger UI for interactive API exploration

### API Generation

The API uses `@hono/zod-openapi` to auto-generate an OpenAPI schema from the Hono route definitions. The Go client is then auto-generated from this schema using `oapi-codegen`.

**Workflow:**

1. Edit route files in `src/routes/` with Zod schemas
2. Run `bun run generate:api` (or commit changes - pre-commit hook runs it automatically)
3. OpenAPI spec is generated at `client/openapi.json`
4. Go client code is generated at `client/pkg/api/api.gen.go`

This ensures the client is always in sync with the server API.

## Security

- Private keys stored encrypted in Durable Objects
- Passphrase stored in CF Secrets
- Keys decrypted per-request in memory only
- OIDC token validation with JWKS
- All operations audit logged
- Rate limiting per CI identity

## Environment Variables

| Variable          | Description                      |
| ----------------- | -------------------------------- |
| `ALLOWED_ISSUERS` | Comma-separated OIDC issuer URLs |
| `KEY_ID`          | Default signing key ID           |
| `KEY_PASSPHRASE`  | Secret: Key passphrase           |
| `ADMIN_TOKEN`     | Secret: Admin API token          |
