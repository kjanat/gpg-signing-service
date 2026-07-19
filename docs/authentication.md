# Authentication and access

## Access matrix

| Surface                                 | Credential           | Intended caller                                  |
| --------------------------------------- | -------------------- | ------------------------------------------------ |
| `/health`, `/public-key`, `/doc`, `/ui` | None                 | Monitoring, verification, API discovery          |
| `/sign`                                 | OIDC JWT             | GitHub Actions or GitLab CI                      |
| `/sign`                                 | `gst_` service token | CI systems and automation without supported OIDC |
| `/admin/*`                              | `ADMIN_TOKEN`        | Deployment operator                              |
| GitHub installer action                 | GitHub API token     | Release lookup and asset download                |

The install action's `token` input is unrelated to all service credentials.

## Current OIDC authorization boundary

> [!WARNING]
> The service validates issuer, audience, time, algorithm, key ID, and JWT
> signature. It does not authorize GitHub repository, organization, workflow,
> ref, environment, GitLab namespace, or project claims.

With the checked-in issuer list, any GitHub Actions or GitLab job that can
request a valid token with the expected audience can authenticate to `/sign`
and select any stored key. Repository and project claims are used only as audit
metadata.

Do not treat `ALLOWED_ISSUERS` as a repository allowlist. Before exposing a
shared deployment, add claim-based authorization or use narrowly scoped service
tokens instead of broad OIDC access.

## OIDC validation

The Worker:

1. accepts `RS256`, `RS384`, `RS512`, `ES256`, or `ES384`;
2. checks `iss` against comma-separated `ALLOWED_ISSUERS`;
3. checks `nbf` and `exp` with 60 seconds of clock tolerance;
4. checks `aud` against `EXPECTED_AUDIENCE`, which defaults to
   `gpg-signing-service`;
5. fetches OIDC discovery and JWKS documents after SSRF validation;
6. caches JWKS data in KV for five minutes; and
7. verifies the JWT signature and signing-key usage.

### GitHub Actions

The job needs `id-token: write`. Request the audience expected by the service:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - id: oidc
    uses: actions/github-script@v9
    with:
      script: |
        const token = await core.getIDToken("gpg-signing-service");
        core.setSecret(token);
        core.setOutput("token", token);

  - name: Use token
    env:
      GPG_SIGN_TOKEN: ${{ steps.oidc.outputs.token }}
    run: your-signing-command
```

`id-token: write` permits requesting an OIDC JWT; it does not grant write access
to repository contents.

When requesting the token with `ACTIONS_ID_TOKEN_REQUEST_URL` directly, append
`&audience=gpg-signing-service` and read the `.value` property from the JSON
response. The toolkit example above is less error-prone.

### GitLab CI

Declare a job ID token with the expected audience:

```yaml
sign:
  id_tokens:
    GPG_SIGN_TOKEN:
      aud: gpg-signing-service
  script:
    - your-signing-command
```

Do not rely on legacy `CI_JOB_JWT` examples; explicit `id_tokens` binds the
token's audience.

## Service tokens

Service tokens support arbitrary CI systems and local automation. They:

- begin with `gst_`;
- contain 256 bits of random material;
- are stored in D1 only as SHA-256 hashes;
- may expire after 1 to 3650 days;
- may be restricted to a list of 16-character hexadecimal key IDs; and
- are returned in plaintext only when created.

An omitted or empty key list permits every stored key.

### Create

```bash
created="$(
  curl --fail-with-body --silent --show-error \
    --request POST "$GPG_SIGN_URL/admin/tokens" \
    --header "Authorization: Bearer $GPG_SIGN_ADMIN_TOKEN" \
    --header "Content-Type: application/json" \
    --data '{
      "name": "ci/woodpecker",
      "keyIds": ["D8BC04E534E7706F"],
      "expiresInDays": 90
    }'
)"

printf '%s\n' "$created" | jq
```

Save `.token` immediately in the CI system's secret store. Listing tokens later
returns metadata but never the plaintext credential.

### Use

The CLI sends either an OIDC JWT or a service token through the same variable:

```bash
export GPG_SIGN_URL="https://your-worker.example"
export GPG_SIGN_TOKEN="gst_..."

printf 'data to sign' | gpg-sign sign --key-id D8BC04E534E7706F
```

### List and revoke

```bash
curl --fail-with-body --silent --show-error \
  "$GPG_SIGN_URL/admin/tokens" \
  --header "Authorization: Bearer $GPG_SIGN_ADMIN_TOKEN"

curl --fail-with-body --silent --show-error \
  --request DELETE "$GPG_SIGN_URL/admin/tokens/TOKEN_UUID" \
  --header "Authorization: Bearer $GPG_SIGN_ADMIN_TOKEN"
```

Revocation is immediate. A token's name becomes its audit subject and
rate-limit identity.

## Admin token

All `/admin/*` endpoints share one static `ADMIN_TOKEN` stored as a Cloudflare
Worker secret. The Worker compares it in constant time. There are no roles,
per-operator identities, expiration, or built-in rotation workflow.

Set or rotate it with:

```bash
wrangler secret put ADMIN_TOKEN
```

Clients expose it as `GPG_SIGN_ADMIN_TOKEN` or `--admin-token`.

## Credential names

| Name                   | Sent to                                           |
| ---------------------- | ------------------------------------------------- |
| Action input `token`   | GitHub Releases API                               |
| `GPG_SIGN_TOKEN`       | Signing service `/sign`                           |
| `GPG_SIGN_ADMIN_TOKEN` | Signing service `/admin/*`                        |
| `KEY_PASSPHRASE`       | Worker crypto routines; never a client credential |

Never substitute one credential for another.

## Rate-limit identities

- OIDC callers: `issuer:subject`
- Service-token callers: synthetic service-token issuer plus token name
- Admin callers: source IP address

Signing and admin buckets each hold 100 tokens and refill at 100 tokens per
minute. Rate-limiter failure is fail-closed with HTTP `503`.
