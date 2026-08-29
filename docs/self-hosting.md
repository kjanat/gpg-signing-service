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
| `SERVICE_BASE_URL`        | Public origin for the `docs` link on errors; defaults to the request's own origin           |
| `ERROR_DOCS_URL`          | Optional target for `/e/<CODE>`; defaults to this repository's [error reference](errors.md) |
| `DISCLOSE_TRUST_PATTERNS` | Optional `"true"` to name the trust list and the accepted issuers in a `401` hint           |

`SERVICE_BASE_URL` is worth setting on any deployment with a name of its own.
Unset, the `docs` link is built from the origin the request arrived on — which
is the caller's `Host` header, so a request that forges it gets a link back on a
hostname of its sender's choosing. Nothing reaches a third party that way, and
Cloudflare routing constrains which hostnames arrive at all, but `docs` is the
one field a human is invited to click, and one line in `[vars]` makes it say the
same thing on every request. A value that is not an absolute `http`/`https` URL
is ignored and the request's origin used instead.

`DISCLOSE_TRUST_PATTERNS` covers two hints, both off by default:

- the untrusted-subject `401` appends the rule counts for the issuer and the
  active subject prefixes;
- the `Issuer not allowed` `401` appends the contents of `ALLOWED_ISSUERS`.

Both are readable by strangers when the issuer is a shared one — anyone who can
run a GitHub Actions workflow can obtain a verified token — and the issuer hint
is reachable with no valid credential at all, since the issuer check runs before
the signature is ever verified. Turn it on where the trust list is not a secret:
a private issuer, or a deployment whose tenants are public knowledge.

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

Every entry must be a public host. Discovery and JWKS URLs go through SSRF
validation, so an issuer on a private address, a loopback or a metadata
endpoint is refused before it is fetched — and every request for that issuer
then answers
[`500 SERVICE_MISCONFIGURED`](errors.md#service_misconfigured) rather than
timing out. Clients stop on that code instead of retrying, so it shows up as a
fast, repeatable failure rather than a slow one.

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

## Key expiry monitoring

A signing key that lapses breaks every caller at once, with no warning from the
service itself: nothing in the sign path refuses a key because it is close to
expiring. `.github/workflows/key-expiry-check.yml` covers that gap. It runs
weekly, and on demand through **Actions → Key expiry check → Run workflow**.

The check discovers keys rather than reading a list someone maintains by hand:

1. `GET /admin/keys` returns the keys the deployment actually holds.
2. Every `KEY_ID` in `wrangler.toml` is cross-checked against that list. A key
   the Worker is configured to sign with, that the deployment no longer holds,
   is reported as `missing`.
3. Each key's expiry is read out of its own material from
   `GET /admin/keys/{keyId}/public` — the PGP public key's expiration time
   (whichever of the primary key and the signing subkey lapses first), or the
   X.509 certificate's `notAfter`. No expiry date is ever transcribed into a
   config file, so none can drift from the key it describes.

Keys inside the threshold, already expired, unreadable or missing are collected
into a report that is written to the job summary and used to open or update a
GitHub issue labelled `key-expiry`. The issue is updated rather than duplicated,
so a key that stays inside the window produces one issue, not one per run.

| Setting              | Where                                     | Default |
| -------------------- | ----------------------------------------- | ------- |
| Warning threshold    | `KEY_EXPIRY_WARN_DAYS` env var            | 60 days |
| Deployment to check  | `SIGNING_SERVICE_URL` repository variable | —       |
| Admin credential     | `ADMIN_TOKEN` repository secret           | —       |
| Notification channel | GitHub issue labelled `key-expiry`        | —       |

Both `SIGNING_SERVICE_URL` and `ADMIN_TOKEN` are required; without them the
check fails loudly rather than reporting every key as healthy.

Run it locally against any deployment:

```bash
export SIGNING_SERVICE_URL="https://gpg.example.com"
export GPG_SIGN_ADMIN_TOKEN="..."
ADMIN_TOKEN="$GPG_SIGN_ADMIN_TOKEN" KEY_EXPIRY_WARN_DAYS=90 task check:key-expiry
```

It exits `0` when every key is clear, `1` when at least one needs attention, and
`2` when the check could not run at all.

## Key rotation

Run this before the expiry date, not after it. Both keys stay uploaded during
the overlap, so in-flight callers keep working.

1. Generate the replacement key offline: `task generate:key`. It writes to
   `.keys/`, never `~/.gnupg`.
2. Upload it alongside the current key with `POST /admin/keys` (see
   [Upload the PGP key](#7-upload-the-pgp-key)). The service holds both.
3. Publish the new public key to every verifier that needs it — GitHub account
   GPG keys, and any `gpg --import` step in a consuming pipeline. Signatures
   from the new key are rejected until this lands.
4. Add the new key ID to the `keyIds` of every trusted subject
   (`POST /admin/subjects`) and to any service token that pins key IDs.
5. Point the deployment at the new key: update `KEY_ID` in `wrangler.toml` for
   each environment, then `task deploy`. The expiry check reads `KEY_ID`, so
   this step is also what puts the new key under monitoring.
6. Smoke test as in [Smoke test](#8-smoke-test), signing with the new key ID.
7. Once no caller signs with the old key — check the audit log — remove it with
   `DELETE /admin/keys/{keyId}` and drop its ID from `wrangler.toml` and from
   every subject and token allowlist.
8. Close the `key-expiry` issue, or re-run the check and let it confirm.

Rotating `ADMIN_TOKEN` is separate and immediate: `wrangler secret put
ADMIN_TOKEN`, then update the repository secret the expiry check uses. There is
no overlap period, so every admin caller must be updated at the same time.

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
- Set the `SIGNING_SERVICE_URL` variable and `ADMIN_TOKEN` secret so
  [Key expiry monitoring](#key-expiry-monitoring) can reach the deployment, and
  confirm a manual run reports every key you expect.
- Walk [Key rotation](#key-rotation) once on staging, and rotate the admin token.
- Review the [Security model](security-model.md).
