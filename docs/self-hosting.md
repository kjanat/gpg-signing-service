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

### Which keys are checked

"Every stored key" would be wrong in both directions, so the set is derived from
the deployment's own live configuration instead:

- **Stored is not active.** A superseded key kept on purpose is still in
  `GET /admin/keys`, and warning about it every week is how a monitor gets
  muted.
- **`KEY_ID` is not the whole set.** It is only the default for a caller that
  names no key. `POST /sign?keyId=…` accepts any key the caller's grant permits,
  so a key nobody configured as the default can still be signing commits today.

A key is therefore **monitored when this deployment could sign with it right
now** — the same test `src/routes/sign.ts` applies:

1. The checked environment's `KEY_ID` from `wrangler.toml`, since that is what a
   caller naming no key gets. One environment, not all of them: aggregating
   `[env.*.vars]` and then checking a single URL reports the other
   environment's key as `missing` every week, forever.
2. Every key a **live** grant permits — a trusted OIDC subject
   (`GET /admin/subjects`) or a service token (`GET /admin/tokens`) that is
   neither revoked nor expired, tested exactly as the sign path tests it.
3. A grant that pins no key ids means _every_ key, in the service's own
   authorization model. When one exists, storage really is the activation
   boundary and every stored key is monitored — and the report says so, and says
   which grant caused it, because scoping that grant is what narrows the report.
4. Anything else in storage is retained but unreachable. It is listed in the
   report's scope note and never warned about.

A key that is expected but absent — the environment's `KEY_ID`, or a key a live
grant names — is reported `missing`, naming which of the two it was, because the
fixes are opposite: deploy the key, or re-scope the credential.

Each monitored key's expiry is then read out of its own material from
`GET /admin/keys/{keyId}/public` — the PGP public key's expiration time, or the
X.509 certificate's `notAfter`. No expiry date is ever transcribed into a config
file, so none can drift from the key it describes.

For a PGP key that is a question about its **signing subkeys**, since those are
what sign a commit, not the primary key:

- A revoked primary key is reported first. It takes every subkey down with it,
  so which one would have signed stops mattering.
- A key with no signing subkey signs with its primary key, and that key's own
  expiry is the whole answer.
- Otherwise the answer comes from the subkeys that can still sign — not from
  whichever one openpgp happens to select. Asking openpgp for a signing key
  returns the first _acceptable_ one: it skips a revoked subkey and falls back
  to the next, or to the primary key, so a deployment whose only signing subkey
  had been revoked used to report its primary key's distant expiry and read as
  healthy.
- Signing keeps working until the **last** usable signing subkey lapses, so that
  is the reported date, capped by the primary key's own. Taking the earliest
  instead would warn about an outage that a valid replacement subkey already
  prevents — revoking a subkey and issuing a new one is what rotation looks
  like, and it must not raise an alarm.
- When no signing subkey is usable, signing is already broken. That is reported
  as `revoked` when a revocation is why, and `unknown` when the material is
  unusable for some other reason, because those need opposite fixes.

**Where the rule is imprecise**, stated in every report rather than only here:

- The set is a snapshot. A grant created after a run is covered by the next one.
- `KEY_ID` is read from `wrangler.toml` in this repository, which a deployment
  whose vars were changed elsewhere can disagree with.
- A grant is trusted to mean what it says, so a key id it names that no longer
  exists is reported `missing` rather than quietly dropped.

Keys inside the threshold, already expired, revoked, unreadable or missing are
collected into a report that is written to the job summary and used to open or
update a GitHub issue labelled `key-expiry`. The issue is updated rather than
duplicated, so a key that stays inside the window produces one issue, not one
per run.

### Configuration

| Setting              | Where                                     | Default   |
| -------------------- | ----------------------------------------- | --------- |
| Warning threshold    | `KEY_EXPIRY_WARN_DAYS` env var            | 60 days   |
| Deployment to check  | `SIGNING_SERVICE_URL` repository variable | —         |
| Admin credential     | `ADMIN_TOKEN` repository secret           | —         |
| Wrangler environment | `WRANGLER_ENV` env var                    | top-level |
| Notification channel | GitHub issue labelled `key-expiry`        | —         |

Both `SIGNING_SERVICE_URL` and `ADMIN_TOKEN` are required; without them the
check fails loudly rather than reporting every key as healthy. Point
`WRANGLER_ENV` at the environment whose deployment `SIGNING_SERVICE_URL`
addresses — `staging` for the staging Worker — so the two agree about which
`KEY_ID` is the default. An unknown name is refused rather than silently falling
back to production's key.

Run it locally against any deployment:

```bash
export SIGNING_SERVICE_URL="https://gpg.example.com"
export GPG_SIGN_ADMIN_TOKEN="..."
ADMIN_TOKEN="$GPG_SIGN_ADMIN_TOKEN" KEY_EXPIRY_WARN_DAYS=90 task check:key-expiry
```

It exits `0` when every key is clear, `1` when at least one needs attention, and
`2` when the check could not run at all — including when the grant lists cannot
be read, since a report whose scope is unknown is worse than no report.

Checking staging is a second run of the same command:

```bash
SIGNING_SERVICE_URL="https://staging.gpg.example.com" WRANGLER_ENV=staging \
  ADMIN_TOKEN="$GPG_SIGN_STAGING_ADMIN_TOKEN" task check:key-expiry
```

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
   (`POST /admin/subjects`) and to any service token that pins key IDs. This is
   also what puts the new key under expiry monitoring — the check watches what
   live grants permit, so a key becomes monitored the moment something is
   allowed to sign with it.
5. Point the deployment at the new key: update `KEY_ID` in `wrangler.toml` for
   each environment, then `task deploy`. Callers that name no key move over
   here.
6. Smoke test as in [Smoke test](#8-smoke-test), signing with the new key ID.
7. Once no caller signs with the old key — check the audit log — drop its ID
   from `wrangler.toml` and from every subject and token allowlist, then remove
   it with `DELETE /admin/keys/{keyId}`. Revoking the allowlists first is what
   takes the old key out of the report; a key that is merely retained in storage
   raises nothing, but a key a live grant still names does.
8. Close the `key-expiry` issue, or re-run the check and let it confirm.

Rotating `ADMIN_TOKEN` is separate and immediate: `wrangler secret put
ADMIN_TOKEN`, then update the repository secret the expiry check uses. There is
no overlap period, so every admin caller must be updated at the same time.

## Before production

- Run `task db:migrate`, then trust at least one subject through
  `POST /admin/subjects`. An empty `oidc_subjects` table denies every OIDC
  caller, so signing stays broken until a row exists.
- Scope each trusted subject prefix as narrowly as the subject shape allows and
  pin `keyIds`; a prefix authorizes every workflow and ref beneath it. A grant
  that pins no key ids permits _every_ stored key, which also means expiry
  monitoring cannot narrow its set below "everything in storage".
- Configure a non-empty `ALLOWED_ORIGINS` when browser access is required.
- Define private-key backup and restoration procedures; no export endpoint
  exists.
- Define audit retention and monitoring; no cleanup or alert policy is built in.
- Set the `SIGNING_SERVICE_URL` variable and `ADMIN_TOKEN` secret so
  [Key expiry monitoring](#key-expiry-monitoring) can reach the deployment, and
  confirm a manual run reports every key you expect — and, in its scope note,
  excludes every key you do not.
- Walk [Key rotation](#key-rotation) once on staging, and rotate the admin token.
- Review the [Security model](security-model.md).
