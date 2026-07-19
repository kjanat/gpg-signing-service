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

- Use a real full tag such as `v1.1.1`; there is no `v1` tag.
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

Check all of:

- the job grants `id-token: write`;
- the token was requested with audience `gpg-signing-service`, or the configured
  `EXPECTED_AUDIENCE`;
- `ALLOWED_ISSUERS` contains
  `https://token.actions.githubusercontent.com`;
- the token has not expired; and
- discovery and JWKS endpoints are reachable.

Use `core.getIDToken("gpg-signing-service")`. Raw endpoint responses store the
JWT in `.value`, not `.token`.

### `401` with GitLab

Declare `id_tokens` and set `aud` to the configured expected audience. Legacy
`CI_JOB_JWT` examples do not establish that audience.

### Invalid `gst_` token

The token may be unknown, expired, revoked, mistyped, or absent from the D1
database. The plaintext cannot be recovered; mint a replacement when lost.

### `403` key denied

The service token has a key allowlist that does not contain the selected key.
Mint a correctly scoped token or select an allowed key.

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
bunx wrangler d1 migrations apply gpg-signing-audit --remote
```

Fresh deployments need both `0001_initial.sql` and
`0002_service_tokens.sql`.

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
