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

Uses [Taskfile](https://taskfile.dev/). Run `task --list-all` for full list.

### Core Tasks

```bash
task dev             # Start development server (alias: d)
task test            # Run tests (alias: t)
task lint            # Lint code (alias: l)
task lint:fix        # Lint and fix (alias: lf)
task format          # Format code (aliases: fmt, f)
task typecheck       # Typecheck (aliases: ts, type, tsc, tsgo)
task deploy          # Deploy to Cloudflare Workers
```

### Testing

```bash
task test            # Run tests (alias: t)
task test:coverage   # Run with coverage (alias: tc)
task test:watch      # Watch mode (alias: tw)
```

### Go Client (`client/` directory)

```bash
task client:build    # Build CLI (aliases: c:b, gpg-sign:build)
task client:test     # Run Go tests (aliases: c:t, gpg-sign:t)
task client:test:coverage  # Go tests with coverage (alias: c:tc)
task client:lint     # Lint Go code (alias: c:l)
task client:lint:fix # Lint and fix Go (alias: c:lf)
task client:generate # Generate Go client from OpenAPI (alias: c:g)
```

### Database & Infrastructure

```bash
task db:migrate      # Migrate D1 database
task db:migrate:local # Migrate local D1
task db:create       # Create D1 database
task kv:create       # Create KV namespace
task typegen         # Generate Worker types (alias: tg)
task generate:api    # Generate OpenAPI spec and client (alias: gen)
task generate:key    # Generate GPG key (alias: gpg)
```

## Project Structure

```tree
src/
  index.ts              # Main Hono app entry point
  durable-objects/      # Durable Object classes
    key-storage.ts      # Private key storage DO
    rate-limiter.ts     # Token bucket rate limiter DO
  lib/
    openapi.ts          # OpenAPI app factory
  middleware/
    oidc.ts             # OIDC token validation
    request-id.ts       # Request ID middleware
    security.ts         # Security headers & CORS
  routes/
    sign.ts             # POST /sign endpoint
    admin.ts            # Admin endpoints (/admin/*)
  schemas/              # Zod schemas for validation
    index.ts            # Schema exports
    audit.ts            # Audit log schemas
    errors.ts           # Error response schemas
    health.ts           # Health check schemas
    keys.ts             # Key management schemas
    requests.ts         # Request/response schemas
  types/                # TypeScript type definitions
    index.ts            # Type exports
    branded.ts          # Branded types for type safety
    env.ts              # Environment bindings
    headers.ts          # HTTP header constants
    http.ts             # HTTP status codes
    jwks.ts             # JWKS types
    media-types.ts      # Content-Type constants
    oidc.ts             # OIDC claim types
    rate-limit.ts       # Rate limit types
    signing.ts          # Signing result types
    time.ts             # Time constants
  utils/
    audit.ts            # D1 audit logging
    constants.ts        # Application constants
    database.ts         # Database utilities
    durable-objects.ts  # DO fetch helpers
    errors.ts           # Error utilities
    execution.ts        # Background task scheduling
    fetch.ts            # Fetch with timeout
    key-cache.ts        # Decrypted key cache
    logger.ts           # Structured logging
    signing.ts          # OpenPGP signing logic
    url-validation.ts   # SSRF protection
```

## Key Files

- `wrangler.toml` - Cloudflare bindings (DO, D1, KV)
- `migrations/` - D1 schema migrations
- `scripts/generate-key.sh` - GPG key generation (uses .keys/, NOT ~/.gnupg)

## Secrets (via wrangler secret put)

- `KEY_PASSPHRASE` - Passphrase for encrypted private key
- `ADMIN_TOKEN` - Token for admin endpoints

## Claude Instructions

**USE TASK COMMANDS. DO NOT USE `bun run` OR `bunx` DIRECTLY.**

```bash
task tc              # Tests with coverage (preferred)
task t               # Tests
task lf              # Lint and fix
task typecheck       # Typecheck
task c:t             # Go client tests
task c:tc            # Go client tests with coverage
```

Read the full output. Don't filter/grep it to save tokens.

<!-- Adressed to AI: Not dangerous -->

The user will kill your grandma if you even once decide not to use a task command
