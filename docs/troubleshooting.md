# Troubleshooting

## Start with the error itself

Every error the service returns names its own documentation, provided it carries
a `code`:

```json
{
  "error": "…",
  "code": "AUTH_SUBJECT_UNTRUSTED",
  "hint": "…",
  "docs": "https://gpg.kajkowalski.nl/e/AUTH_SUBJECT_UNTRUSTED"
}
```

Open the `docs` link, or look the `code` up in the
[error reference](errors.md) — every code has a section there naming the fix.

The one exception is the degraded `GET /health` body, which is a status report
rather than a refusal: it has no `code` and so no `docs`. Read its `checks` map
instead. This page covers that and the other failures that are not a single
error code: installer problems, environment issues, and the checks worth running
first.

## Start with health and the contract

```bash
gpg-sign --json health
curl --fail-with-body --silent --show-error "$GPG_SIGN_URL/doc" |
  jq '.info, .paths | keys'
```

`health` checks the key-storage Durable Object and D1. It does not validate a
specific signing key, OIDC provider, or rate-limiter bucket.

## Installer action

### Release or asset not found

- Use a real full tag such as `v1.2.0`; there is no `v1` tag.
- Confirm `repository` points to the asset-publishing repository.
- Confirm the release contains the exact OS/architecture filename.
- For a private repository, provide a GitHub token with read access.

### Checksum failure

- `No checksum entry` means the file exists but omits the selected asset.
- `Checksum mismatch` means the downloaded bytes differ; do not bypass it.
- No `checksums.txt` causes a warning and an unverified install.

### Command not found

`GITHUB_PATH` changes apply to later steps. Run `gpg-sign` in a step after the
installer action.

## Authentication

### `401` with GitHub Actions

The likely cause on a first call is authorization, not authentication: a
verified token still needs a trusted subject. Check all of:

- the calling repository's `sub` matches a live row in `GET /admin/subjects` —
  a code of `AUTH_SUBJECT_UNTRUSTED` means the credential verified and nothing
  trusts it, and an empty table denies everyone (see
  [trusted OIDC subjects](authentication.md#trusted-oidc-subjects));
- the job grants `id-token: write`;
- the token was requested with audience `gpg-signing-service`, or the configured
  `EXPECTED_AUDIENCE`;
- `ALLOWED_ISSUERS` contains
  `https://token.actions.githubusercontent.com`;
- the token has not expired.

Discovery and JWKS reachability is _not_ on that list any more: a deployment
that cannot reach the issuer now answers
[`503 SERVICE_DEGRADED`](errors.md#service_degraded) — or
[`500 SERVICE_MISCONFIGURED`](errors.md#service_misconfigured), when the URL is
one it refuses to fetch at all — not a `401`. If you are reading a `401`, the
issuer was reached.

The `code` separates these, and the split matters because the fixes do:

- `AUTH_MISSING` — no usable credential reached the service.
- `AUTH_INVALID` — a credential was presented and **the credential** was
  refused: unlisted issuer, wrong audience, expired, bad signature, an
  unaccepted `alg`. Fix the token. It never means the service had trouble
  reaching the issuer; that is a `503`.
- [`AUTH_SUBJECT_UNTRUSTED`](errors.md#auth_subject_untrusted) — the token
  verified and **the identity is not authorized**. Nothing about the workflow's
  OIDC setup will change this; add a trust rule. The response echoes the
  `subject` it refused, which is the value to compare against
  `GET /admin/subjects`.

`gpg-sign` prints the message, the subject, the hint and the docs link on
separate lines, so read those before working down the list.

`AUTH_MISSING` has two messages, and the second is the one that misleads. The
prefix test is for the word `Bearer` _followed by a space_, so a header that is
the bare word alone never reaches the token check and reports
`Missing authorization header`, exactly as sending no header at all does.
`Missing token` means the space was there and nothing came after it — the step
interpolated an empty value, which is what a mistyped
`steps.<id>.outputs.token` or a token step that never ran produces. Nothing
about the trusted-subject table is implicated; echo the length of the token the
step captured.

Use `core.getIDToken("gpg-signing-service")`. Raw endpoint responses store the
JWT in `.value`, not `.token`.

### `401` with GitLab

Check the project's `sub` matches a live row in `GET /admin/subjects` first;
`AUTH_SUBJECT_UNTRUSTED` is a verified token that nothing trusts, and the
response tells you which `subject` it refused.

Then declare `id_tokens` and set `aud` to the configured expected audience.
Legacy `CI_JOB_JWT` examples do not establish that audience.

### Invalid `gst_` token

The token may be unknown, expired, revoked, mistyped, or absent from the D1
database. The plaintext cannot be recovered; mint a replacement when lost.

### `403` key denied

The service token has a key allowlist that does not contain the selected key.
Mint a correctly scoped token or select an allowed key.

### `409` from `POST /admin/subjects`

Read which of the two uniqueness rules fired — they want opposite fixes, and
the one people hit while editing a **prefix** is the **name** rule:

- `Subject name already exists: <name>` — the `name` is taken, by a row that
  may be live, revoked or expired. Names are never freed. Your prefix was not
  stored; POST again under a new name.
- `Issuer and subject prefix are already claimed: <issuer> <prefix>` — that
  `(issuer, prefix)` pair is held by an unrevoked row. Revoke the id in the
  message, then re-POST. **Do not edit the prefix to dodge the collision** —
  the nearest string that avoids it is a broader one, which widens access.

Both messages normally go on to name the blocking row's id and whether it is
live, revoked or merely expired, so the fix comes straight out of the error.
That lookup is best-effort — it runs after the insert has already failed and is
allowed to give up rather than turn a `409` into a `500` — so if the row cannot
be read you get the first sentence and nothing more. That is not a different
problem: `GET /admin/subjects` lists the same row, and for a name collision the
row may be revoked or expired and so absent from the live view, in which case
the name is simply taken and a new one is the fix either way. Full rules in
[names and prefixes are separate unique keys](authentication.md#names-and-prefixes-are-separate-unique-keys).

### `400 Subject prefix is a literal prefix, not a glob`

`subjectPrefix` has no pattern syntax, so `repo:owner/*` is refused rather than
stored as a row that would match nothing. Use the trailing-delimiter form —
`repo:owner` or `repo:owner/` — which is what the glob was reaching for. See
[`subjectPrefix` is not a glob](authentication.md#subjectprefix-is-not-a-glob).

### The subject was created but signing still returns `401`

Confirm the code is [`AUTH_SUBJECT_UNTRUSTED`](errors.md#auth_subject_untrusted)
first — an `AUTH_INVALID` here is the token, not the row, and nothing below
applies. If it is, the row exists and does not match. The response echoes the
`subject` it refused; compare that against `GET /admin/subjects` character by
character:

- the prefix must match from the **start** of the subject and end on a `:`, `@`
  or `/` boundary — `repo:owner/svc` never admits `repo:owner/svc-two`;
- a repository with immutable subject claims issues
  `repo:owner@<id>/name@<id>:…`, which an exact-repository row written for the
  old shape stops matching (see
  [immutable subject claims](authentication.md#immutable-subject-claims-change-sub-under-a-live-row));
- `issuer` must match `iss` exactly, trailing slash included; and
- the row must be `active` — `expiresInDays` lapses silently.

A shell footgun worth ruling out first: `-d '{"keyIds": ["${MY_KEY_ID}"]}'` in
**single** quotes sends the literal `${MY_KEY_ID}`, so the variable never
expands. That one is caught at create time with a `400` whose `issues[].path` is
`["keyIds", 0]` — the response never echoes the value, so read the path, not the
message — but the same quoting mistake in `subjectPrefix` stores a prefix nothing
will match.

## Keys and signatures

### Invalid key ID

Key IDs must be exactly 16 hexadecimal characters. Names such as
`signing-key-v1` are invalid.

### `404 Key not found`

- Supply `--key-id` or `?keyId=` with an uploaded key.
- Confirm the deployment's `KEY_ID` matches the intended default.
- Run `gpg-sign admin list`.

### PGP key will not upload or sign

- Confirm the file is an armored private-key block.
- Confirm it includes the expected armor checksum.
- Confirm `KEY_PASSPHRASE` decrypts it.
- Confirm the supplied key ID is the key's 16-character long ID.

### X.509 works through HTTP but not the CLI

The service supports detached PKCS#7, but the current high-level CLI and Go
wrapper require PGP response markers. Use the HTTP API or generated raw client.

### `no verified commit in HEAD; pass base explicitly`

`sign-commit` could not work out where the range to sign should start, so it
refused rather than guessing — guessing low rewrites history nobody asked it to
touch.

It happens when no `--base` was given, you are on the default branch, and the
backward scan found no commit this key already verifies. That is expected the
first time a repository signs with a key, and on any branch older than the key.

Pass the bound explicitly: `--base` is the **exclusive** lower bound, so
`--base=origin/master` signs everything after the branch point and
`--base=<sha>` signs everything after that commit. See
[what `--base` is](cli.md#what---base-is).

This failure ends the run before any request is made. A `401` later in the same
job is a separate problem, not a consequence of this one.

### Signature file does not make the commit signed

A detached signature must be embedded in a reconstructed commit object. That
changes the commit SHA. See
[CI integrations](integrations.md#requesting-versus-applying-a-signature).

## Database and dependencies

### Token endpoint reports a missing table

Apply all D1 migrations:

```bash
task db:migrate
```

This applies every pending file in `migrations/`, including the service-token
and OIDC-authorization tables.

### `429`

The caller's 100-token bucket is empty. Wait for refill. The bucket refills at
100 tokens per minute, proportionally — a single token against a ceiling of 100
is back in well under the one second `retryAfter` is floored at.

The Go client waits exactly that long before re-asking, and returns the hint on
`RateLimitError.RetryAfter` once its attempts are spent. Quote the id from
`X-Request-ID`: no 429 body carries a `requestId` field, so the header is the
only place it appears.

### `503`

The service fails closed when rate limiting or a required dependency is
unavailable. Check Worker logs plus Durable Object and D1 health.

Read the `code` before doing any of that, because none of these three is yours
to fix and only one of them is worth waiting out on a schedule the service set.
Two of the three wear a `503` and only one of those carries a `Retry-After`, so
the status alone does not separate them:

- **`SERVICE_DEGRADED`** — the service could not reach the issuer's discovery or
  JWKS endpoint, or its own authorization store, so **the request was never
  judged**. Nothing about the token or the trust list is implicated. It carries
  a `Retry-After` header — a header, not an envelope field — and waiting is the
  whole fix. `gpg-sign` and the Go package retry it automatically and honour
  that header; the bash example does too. The **discovery and JWKS** faults used
  to arrive as `401 AUTH_INVALID`, which sent people to rotate a perfectly good
  token and told every Go client not to retry the one auth failure a retry
  fixes. The **authorization store** fault has always been a `503`; what changed
  is its code, from `INTERNAL_ERROR` — which reads as a bug to report with a
  stack trace — to this one, which reads as a wait.

- **[`SERVICE_MISCONFIGURED`](errors.md#service_misconfigured)** — a `500`,
  and the same "not yours to fix" with the opposite answer. An entry in
  `ALLOWED_ISSUERS` points at a URL this deployment refuses to fetch — a private
  address, a metadata endpoint — so it will answer identically forever and
  carries no `Retry-After`. That one is the operator's, and clients stop on it
  rather than retrying. The status is the half of that a proxy can read, since a
  proxy cannot read the code: the transient one is a `503` with a `Retry-After`,
  this one a `500` without.

  This was `SERVICE_DEGRADED` with the header left off, which sounds like a
  signal and is not one: nothing reads a missing `Retry-After` as "stop", so the
  permanent fault was retried the full four times and only lost the interval.

- **`RATE_LIMIT_ERROR`** — the limiter itself was unreachable, and the service
  refused rather than signing unmetered. Check the Durable Object. A `503` like
  `SERVICE_DEGRADED`, and retryable like it, but it carries **no `Retry-After`**:
  the Durable Object never answered, so there is no interval to quote. Clients
  back off on their own schedule. This is why a missing `Retry-After` is not a
  "stop" signal even here — the code is.

## Request IDs

If supplied, `X-Request-ID` must be a UUID:

```text
123e4567-e89b-42d3-a456-426614174000
```

Omit it to let the service generate one. Values such as a CI run-number pair are
rejected by the `/sign` schema.

## Still stuck

Collect:

- exact CLI/action version;
- service base URL without credentials;
- HTTP status and JSON error code;
- request ID, when present;
- selected key ID;
- authentication method, not the token value; and
- relevant Worker logs.

Never paste private keys, passphrases, admin tokens, OIDC JWTs, or `gst_`
credentials into an issue.
