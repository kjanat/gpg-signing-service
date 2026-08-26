# Self-hosting

This guide deploys a new, single-operator instance. Do not reuse the checked-in
Cloudflare database IDs, KV IDs, domains, or default key ID; they belong to the
repository owner's deployment.

## Prerequisites

- Cloudflare account with Workers, Durable Objects, D1, and KV
- Bun
- [Task](https://taskfile.dev/)
- Wrangler authentication
- Go, for the generated client and CLI
- GnuPG, when using OpenPGP keys

Install project dependencies:

```bash
task install
```

## 1. Create Cloudflare resources

```bash
task db:create
task kv:create
```

Copy the returned IDs into the production D1 and KV bindings in
[`wrangler.toml`](../wrangler.toml). Change or remove the checked-in custom
domain route.

The binding names used by the code must remain:

- `KEY_STORAGE`
- `RATE_LIMITER`
- `AUDIT_DB`
- `JWKS_CACHE`

The Durable Object classes are provisioned by the migration declared in
`wrangler.toml` during deployment.

## 2. Apply every D1 migration

Apply the versioned files in [`migrations/`](../migrations) in order:

```bash
task db:migrate
```

Wrangler records each applied file in its migration ledger, applies every
pending file from [`migrations/`](../migrations) in order, and leaves already
applied migrations alone.

For staging:

```bash
task db:migrate:staging
```

## 3. Generate a PGP key

The helper uses an isolated keyring under `.keys/`:

```bash
bash scripts/generate-key.sh \
  "Example Company" \
  "signing@example.com" \
  "Production signing key" \
  "strong-passphrase"
```

Record the generated 16-character hexadecimal key ID and keep
`.keys/private-key.asc` out of source control and backups that lack equivalent
protection.

## 4. Configure variables

Update `[vars]` in `wrangler.toml`:

| Variable                  | Purpose                                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------- |
| `KEY_ID`                  | Default 16-character hexadecimal signing key ID                                             |
| `ALLOWED_ISSUERS`         | Comma-separated OIDC issuer URLs                                                            |
| `EXPECTED_AUDIENCE`       | Optional JWT audience; defaults to `gpg-signing-service`                                    |
| `ALLOWED_ORIGINS`         | Browser CORS allowlist; unset grants no origin anything                                     |
| `SERVICE_BASE_URL`        | Optional public origin for the `docs` link on errors; defaults to the request's own origin  |
| `ERROR_DOCS_URL`          | Optional target for `/e/<CODE>`; defaults to this repository's [error reference](errors.md) |
| `DISCLOSE_TRUST_PATTERNS` | Optional `"true"` to name trusted subject prefixes in an untrusted-subject `401`            |

Example:

```toml
[vars]
ALLOWED_ISSUERS   = "https://token.actions.githubusercontent.com"
EXPECTED_AUDIENCE = "gpg-signing-service"
KEY_ID            = "62E75E54497815DD"
ALLOWED_ORIGINS   = "https://admin.example.com"
```

`ALLOWED_ISSUERS` is not a repository or organization allowlist; authorization
is the separate `oidc_subjects` table. Read
[Authentication](authentication.md#oidc-authorization) before enabling OIDC.

## 5. Set secrets

```bash
wrangler secret put KEY_PASSPHRASE
wrangler secret put ADMIN_TOKEN
```

`KEY_PASSPHRASE` must decrypt the uploaded PGP or encrypted PKCS#8 key.
`ADMIN_TOKEN` should be independently generated, high entropy, and stored only
in operator secret stores.

For staging, add `--env staging` to both commands.

## 6. Deploy

```bash
task deploy
```

Deploy staging explicitly with:

```bash
task deploy:staging
```

Deploys intentionally do not apply schema changes. Apply pending migrations as
an explicit operation before deploying:

```bash
task db:migrate
task deploy
```

Use `task db:migrate:staging` before `task deploy:staging` for staging. On
GitHub, dispatch the `D1 Migrations` workflow from `master`; its environment
input selects the production or staging database and can carry environment
protection rules independently of code deployment.

## 7. Upload the PGP key

Install the CLI, then:

```bash
export GPG_SIGN_URL="https://your-worker.example"
export GPG_SIGN_ADMIN_TOKEN="..."

gpg-sign admin upload \
  --key-id 62E75E54497815DD \
  --file .keys/private-key.asc
```

The uploaded `--key-id` must match the `KEY_ID` value when it is the default
key.

The HTTP API also supports X.509 keys:

```bash
jq --null-input \
  --arg keyId "0123456789ABCDEF" \
  --rawfile privateKeyPem private-key.pem \
  --rawfile certificatePem certificate.pem \
  '{
    keyId: $keyId,
    privateKeyPem: $privateKeyPem,
    certificatePem: $certificatePem
  }' |
  curl --fail-with-body --silent --show-error \
    --request POST "$GPG_SIGN_URL/admin/keys/x509" \
    --header "Authorization: Bearer $GPG_SIGN_ADMIN_TOKEN" \
    --header "Content-Type: application/json" \
    --data-binary @-
```

The private key must be PKCS#8 PEM and match the certificate.

## 8. Smoke test

```bash
gpg-sign health
gpg-sign admin list
gpg-sign public-key --key-id 62E75E54497815DD > public-key.asc
```

Create a service token or configure OIDC, then request a test signature:

```bash
export GPG_SIGN_TOKEN="gst_..."
printf 'smoke test' |
  gpg-sign sign --key-id 62E75E54497815DD > smoke-test.asc
```

Verify a PGP result:

```bash
printf 'smoke test' |
  gpg --verify smoke-test.asc -
```

## Before production

- Run `task db:migrate`, then trust at least one subject through
  `POST /admin/subjects`. An empty `oidc_subjects` table denies every OIDC
  caller, so signing stays broken until a row exists.
- Scope each trusted subject prefix as narrowly as the subject shape allows and
  pin `keyIds`; a prefix authorizes every workflow and ref beneath it.
- Configure a non-empty `ALLOWED_ORIGINS` when browser access is required.
- Define private-key backup and restoration procedures; no export endpoint
  exists.
- Define audit retention and monitoring; no cleanup or alert policy is built in.
- Test key and admin-token rotation.
- Review the [Security model](security-model.md).
