# Troubleshooting

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
  a body of `Subject is not trusted for signing` means the credential verified
  and nothing trusts it, and an empty table denies everyone (see
  [trusted OIDC subjects](authentication.md#trusted-oidc-subjects));
- the job grants `id-token: write`;
- the token was requested with audience `gpg-signing-service`, or the configured
  `EXPECTED_AUDIENCE`;
- `ALLOWED_ISSUERS` contains
  `https://token.actions.githubusercontent.com`;
- the token has not expired; and
- discovery and JWKS endpoints are reachable.

The response body separates these: `AUTH_MISSING` is an absent header,
`Issuer not allowed: <iss>` an unlisted issuer, `Subject is not trusted for
signing` an unregistered caller, and any other `AUTH_INVALID` a verification
failure. `gpg-sign` prints that body, so read it before working down the list.

Use `core.getIDToken("gpg-signing-service")`. Raw endpoint responses store the
JWT in `.value`, not `.token`.

### `401` with GitLab

Check the project's `sub` matches a live row in `GET /admin/subjects` first;
`Subject is not trusted for signing` is a verified token that nothing trusts.

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

The row exists and does not match. Compare the failing run's `sub` against
`GET /admin/subjects` character by character:

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
100 tokens per minute.

### `503`

The service fails closed when rate limiting or a required dependency is
unavailable. Check Worker logs plus Durable Object and D1 health.

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
