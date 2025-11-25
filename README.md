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
architecture-beta
    group cf(cloud)[Cloudflare Platform]
    service worker(server)[Signing Worker] in cf
    service durable(database)[Durable Object Key Store] in cf
    service d1(database)[Audit Log DB] in cf
    service kv(disk)[Rate Limit KV] in cf

    group ext(cloud)[Integrations]

    group ci(cloud)[CI Pipelines] in ext
    service gha(cloud)[GitHub Actions] in ci
    service gitlab(cloud)[GitLab CI] in ci

    group admin(cloud)[Admin Channel] in ext
    service admincli(server)[Admin Client] in admin

    service jwks(internet)[OIDC Issuers]

    gha{group}:R -- L:worker{group}
    gitlab{group}:R -- L:worker{group}

    admincli{group}:R -- L:worker{group}

    worker:T -- B:kv
    worker:R -- L:d1
    worker:B -- T:durable

    worker{group}:T -- B:jwks
```

## Setup

### 1. Prerequisites

- [Cloudflare account][cloudflare:dashboard]
- [Wrangler CLI][wrangler:install]
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
bun run generate-key \
  "Your Name" \
  "your@email.com" \
  "Signing Key" \
  "your-passphrase"
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
curl -X POST https://gpg.kajkowalski.nl/admin/keys \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "armoredPrivateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----
    <<<...INSERT YOUR GPG KEY HERE...>>>
    -----END PGP PRIVATE KEY BLOCK-----",
    "keyId": "signing-key-v1"
  }'
```

## API Endpoints

### Public

| Method | Path          | Description                               |
| :----- | :------------ | :---------------------------------------- |
| `GET`  | `/health`     | Health check                              |
| `GET`  | `/public-key` | Get public key for signature verification |

### Protected (OIDC Auth)

| Method | Path    | Description      |
| :----- | :------ | :--------------- |
| `POST` | `/sign` | Sign commit data |

### Admin (Admin Token)

| Method   | Path                        | Description        |
| :------- | :-------------------------- | :----------------- |
| `GET`    | `/admin/keys/:keyId/public` | Get public key     |
| `GET`    | `/admin/keys`               | List keys          |
| `POST`   | `/admin/keys`               | Upload signing key |
| `DELETE` | `/admin/keys/:keyId`        | Delete key         |
| `GET`    | `/admin/audit`              | Get audit logs     |

## CI Integration

### GitHub Actions

1. Set repository variable `SIGNING_SERVICE_URL`
2. Add workflow from [`sign-commits.yml`][actions:sign-commits]
3. Configure OIDC audience in your worker's `ALLOWED_ISSUERS`

### GitLab CI

1. Set CI variable `SIGNING_SERVICE_URL`
2. Add pipeline from [`.gitlab-ci.yml`][gitlab:sign-commits]
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

| Path   | Description                                |
| :----- | :----------------------------------------- |
| `/doc` | OpenAPI 3.0 JSON spec                      |
| `/ui`  | Swagger UI for interactive API exploration |

### API Generation

The API uses [`@hono/zod-openapi`][npm:@hono/zod-openapi] to auto-generate an
OpenAPI schema from the Hono route definitions.\
The Go client is then auto-generated from this schema using
[`oapi-codegen`][github:oapi-codegen].

**Workflow:**

1. Edit route files in `src/routes/` with Zod schemas
2. Run `bun run generate:api` (or commit changes - pre-commit hook runs it
   automatically)
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
| :---------------- | :------------------------------- |
| `ADMIN_TOKEN`     | Secret: Admin API token          |
| `ALLOWED_ISSUERS` | Comma-separated OIDC issuer URLs |
| `KEY_ID`          | Default signing key ID           |
| `KEY_PASSPHRASE`  | Secret: Key passphrase           |

## License

**Dual licensed**: MIT OR AGPL-3.0 ([LICENSE-MIT](LICENSE-MIT) · [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0))

<details>
<summary><b>Which license applies?</b></summary>

**Use MIT** for:

- Personal/private use
- Internal company projects (not exposed externally)
- Self-hosting for private use

**Use AGPL-3.0** for:

- Commercial/business use
- Providing as a service to external users
- Running on publicly accessible servers

**AGPL-3.0 requires**: Making complete source code (including modifications) available to network users.

**SPDX**: `AGPL-3.0-only OR MIT`

</details>

<!-- link definitions -->

<!--prettier-ignore-start-->

[actions:sign-commits]: .github/workflows/sign-commits.yml "Example GitHub Actions workflow"
[cloudflare:dashboard]: https://dash.cloudflare.com/ "Cloudflare Dashboard"
[github:oapi-codegen]: https://github.com/oapi-codegen/oapi-codegen "oapi-codegen GitHub repository"
[gitlab:sign-commits]: .gitlab-ci.yml "Example GitLab CI pipeline"
[npm:@hono/zod-openapi]: https://www.npmjs.com/package/@hono/zod-openapi "npm package: @hono/zod-openapi"
[wrangler:install]: https://developers.cloudflare.com/workers/wrangler/install-and-update/ "Install Wrangler CLI"

<!--prettier-ignore-end-->
