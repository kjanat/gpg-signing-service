# GPG Signing Service

## Project Overview

Edge-deployed Git commit signing API using Hono on Cloudflare Workers with
openpgp.js for GPG-compatible signatures.

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Framework**: Hono
- **Crypto**: openpgp.js v6
- **Storage**: Durable Objects (keys), D1 (audit), KV (JWKS cache)
- **Auth**: OIDC (GitHub Actions, GitLab CI)

## Development Commands

```bash
bun run dev          # Local development
bun run deploy       # Deploy to Cloudflare
bun run typecheck    # TypeScript check
bun run db:migrate   # Run D1 migrations
bun run generate-key # Generate GPG key in .keys/
```

## Project Structure

```tree
src/
  index.ts              # Main Hono app
  types.ts              # TypeScript interfaces
  durable-objects/      # DO classes
    key-storage.ts      # Private key storage
    rate-limiter.ts     # Token bucket rate limiter
  middleware/
    oidc.ts             # OIDC validation
  routes/
    sign.ts             # POST /sign endpoint
    admin.ts            # Admin endpoints
  utils/
    signing.ts          # OpenPGP signing logic
    audit.ts            # D1 audit logging
```

## Key Files

- `wrangler.toml` - Cloudflare bindings (DO, D1, KV)
- `migrations/` - D1 schema migrations
- `scripts/generate-key.sh` - GPG key generation (uses .keys/, NOT ~/.gnupg)

## Secrets (via wrangler secret put)

- `KEY_PASSPHRASE` - Passphrase for encrypted private key
- `ADMIN_TOKEN` - Token for admin endpoints
