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
| `ENVIRONMENT`             | Optional label for this deployment, e.g. `staging`; names the deployment in alert mail      |
| `KEY_EXPIRY_ALERT_FROM`   | Address the expiry monitor mails from; must be on a domain onboarded to Email Service       |
| `KEY_EXPIRY_ALERT_TO`     | Address the expiry monitor mails to; must be a verified Email Service destination           |
| `KEY_EXPIRY_WARN_DAYS`    | Days ahead of expiry the monitor starts reporting a key; defaults to `60`                   |

`SERVICE_BASE_URL` is worth setting on any deployment with a name of its own.
Unset, the `docs` link is built from the origin the request arrived on — which
is the caller's `Host` header, so a request that forges it gets a link back on a
hostname of its sender's choosing. Nothing reaches a third party that way, and
Cloudflare routing constrains which hostnames arrive at all, but `docs` is the
one field a human is invited to click, and one line in `[vars]` makes it say the
same thing on every request. A value that is not an absolute `http`/`https` URL
is ignored and the request's origin used instead.

Only the origin of the value is used. The short links are served from the root
of the Worker, so `https://gpg.example/service` yields
`https://gpg.example/e/<CODE>` — any path, query, or fragment in the setting is
dropped rather than spliced into the link. Credentials go the same way: a value
pasted in whole as `https://ops:secret@gpg.example/` yields
`https://gpg.example`, so nothing from the setting's userinfo reaches the `docs`
field that every [coded error](errors.md#the-envelope) carries into a CI log. A
non-default port is kept, since that is part of where the service answers.

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

### The read-only admin credential

`ADMIN_READONLY_TOKEN` is an optional third secret: a bearer accepted on `GET`
and `HEAD` admin routes and refused, with
[`403 AUTH_SCOPE_INSUFFICIENT`](errors.md#auth_scope_insufficient), on every
admin route that changes state. Provision it for anything that only needs to
_look_ at the deployment — the scheduled key-expiry check is the case it was
built for, and without it that workflow's repository secret would also be able
to delete the signing key.

```bash
# Generate a value unrelated to ADMIN_TOKEN, then put it.
openssl rand -base64 32 | tr -d '\n' | wrangler secret put ADMIN_READONLY_TOKEN
```

Leave it unset if nothing needs it: an unset or empty value means the credential
does not exist and no bearer can obtain the read-only scope. Setting it to the
same value as `ADMIN_TOKEN` is refused outright — the two would be
indistinguishable at the comparison, so the credential labelled read-only would
silently be a full administrator. The whole admin surface answers
`500 SERVICE_MISCONFIGURED` until they differ, which is loud on purpose: the
alternative failure is silent and total.

The response body does not say which fault it was — that guard runs before the
`Authorization` header is read, so its message would go to unauthenticated
callers. Look in the Workers log for the line naming both secrets:

```bash
wrangler tail --format pretty | grep ADMIN_READONLY_TOKEN
```

It reduces authority, not disclosure. The holder can still enumerate every key
id and fingerprint, every trust rule, every service-token name and the whole
audit log. Store it like any other secret.

To hand it to the key-expiry workflow, put the same value in the repository
secret the workflow reads:

```bash
gh secret set ADMIN_READONLY_TOKEN
```

#### Rotating it

Rotation is a straight replacement with no coordination window, because nothing
caches the value and no request spans the change:

```bash
NEW=$(openssl rand -base64 32 | tr -d '\n')
printf '%s' "$NEW" | wrangler secret put ADMIN_READONLY_TOKEN
printf '%s' "$NEW" | gh secret set ADMIN_READONLY_TOKEN
unset NEW
```

The Worker picks up the new secret on its next deployment of the secret, which
`wrangler secret put` performs immediately. Any in-flight request carrying the
old value gets a `401 AUTH_INVALID`; for a weekly scheduled job that window is
irrelevant, and re-running the workflow is the whole remedy. Rotate it whenever
a workflow log, a fork PR or a departing operator could have seen it — it is
cheaper to rotate than `ADMIN_TOKEN`, so rotate it more readily.

To retire the credential entirely, delete it and the surface reverts to a single
admin token:

```bash
wrangler secret delete ADMIN_READONLY_TOKEN
```

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

## 9. Key expiry monitoring

Nothing in the sign path refuses a key that is about to lapse, so without a
monitor the first sign of an expiry is every caller failing at once. A Cron
Trigger runs the check inside this same Worker and emails when — and only when —
a key needs a human.

```toml
[triggers]
crons = ["0 7 * * 2"]  # Tuesdays, 07:00 UTC

[[send_email]]
name                     = "KEY_EXPIRY_ALERTS"
destination_address      = "ops@example.com"
allowed_sender_addresses = ["gpg-signing-service@example.com"]

[vars]
KEY_EXPIRY_ALERT_FROM = "gpg-signing-service@example.com"
KEY_EXPIRY_ALERT_TO   = "ops@example.com"
```

The monitor needs **no credential of any kind**. It reads the `KeyStorage`
Durable Object and the grant tables directly, so it holds neither `ADMIN_TOKEN`
nor `ADMIN_READONLY_TOKEN`, and Cloudflare Email Service is reached through a
binding rather than an API token or an SMTP password. There is nothing here to
copy into another system and nothing to rotate.

Both addresses are plain `[vars]`, not secrets: an address is not a credential,
and a threshold nobody can read is a threshold nobody can trust. The two
restrictions on the binding are what actually constrain it —
`destination_address` means the Worker cannot mail anyone else even if it is
compromised, and `allowed_sender_addresses` pins the `From` line.

**Dashboard setup**, once per account, in **Compute & AI → Email Service**:

1. Onboard the sending domain and add the SPF and DKIM records it gives you.
2. Verify the destination address, so it can receive from a binding.

Neither step produces a secret.

### What gets monitored

The set is derived, not maintained by hand. A key is checked when this
deployment could sign with it _right now_:

- the deployment's own `KEY_ID`, which is what a caller that names no key gets;
- every key a **live** grant — a trusted OIDC subject row or a service token —
  permits, with revoked and expired grants ignored;
- every stored key, when some live grant pins no key ids at all, because such a
  grant reaches all of them.

A stored key that no live grant reaches is deliberately left out, so retaining a
superseded key raises nothing. A key that is configured or granted but _not_
stored is reported as `missing` — signing through it is already broken.

Expiry is read out of the key material itself rather than from a date typed into
a config file: for a PGP key, the _latest_ still-usable signing subkey's
expiration, capped by the primary key's — signing keeps working until the last
usable subkey lapses, so reading the earliest instead would warn about an outage
a valid replacement subkey already prevents. For an X.509 key, the certificate's
`notAfter`. Revocation is reported too, including a signing subkey revoked
under an otherwise healthy primary key.

### Checking it by hand

```bash
# Fire the scheduled handler against a local dev server.
wrangler dev --test-scheduled
curl "http://localhost:8787/__scheduled?cron=0+7+*+*+2"
```

Add `remote = true` to the `send_email` binding to send real mail from
`wrangler dev`; without it the binding is simulated and the message is logged
instead. The staging environment carries the binding but no cron
(`[env.staging.triggers] crons = []`), because it signs with the same key id as
production and a second schedule would mail the same warning twice.

A run that cannot read its own state, or cannot send mail it had to send, fails
the invocation rather than reporting success. The mail configuration is checked
_before_ any key is read, so a broken alerting path surfaces on a quiet week
rather than on the one where it had something to say.

## Key rotation

The monitor buys time; this is what to do with it.

1. **Generate the replacement offline.** `task generate:key` writes to `.keys/`,
   never `~/.gnupg`. Give it a lifetime you are willing to repeat.
2. **Upload it** with `POST /admin/keys`, under its own key id. Both keys are
   now stored; nothing has switched over yet.
3. **Publish the new public key** to every verifier — GitHub/GitLab account
   keys, and anyone pinning `GET /public-key?keyId=<new>`. Do this before
   anything signs with it, or the first signature verifies nowhere.
4. **Point callers at it.** Update `KEY_ID` in `wrangler.toml` and redeploy for
   the default, and update the `keyIds` allowlist on every trusted subject and
   service token that pinned the old id. A grant naming a key that no longer
   exists is reported `missing` on the next run.
5. **Verify.** Sign something and check it against the published key, then
   confirm the next monitor run lists the new id and no longer lists the old
   one as active.
6. **Retire the old key.** Leaving it stored is fine — an unreachable key is not
   monitored — but revoke it with GnuPG and publish the revocation if the
   private half may have been exposed. `DELETE /admin/keys/{keyId}` removes it.

Rotate the admin credentials the same way and on their own schedule; nothing
automates either, and `ADMIN_READONLY_TOKEN` must never be set equal to
`ADMIN_TOKEN`.

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
- Walk the [key rotation procedure](#key-rotation) end to end once, on a key
  nothing depends on, before you need it on one that everything does. Rotate the
  admin tokens the same way, including `ADMIN_READONLY_TOKEN` if it is
  provisioned.
- Configure the [expiry monitor](#9-key-expiry-monitoring): the cron trigger,
  the `send_email` binding, and both alert addresses. Confirm it by running the
  scheduled handler by hand — a monitor nobody has ever seen fire is a guess.
- Give any scheduled or monitoring workflow that does call the admin API
  `ADMIN_READONLY_TOKEN` rather than `ADMIN_TOKEN`; a job that only reads should
  not hold the authority to delete a key or mint a service token. The expiry
  monitor needs neither.
- Review the [Security model](security-model.md).
