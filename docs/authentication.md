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

## OIDC authorization

A verified token is not an authorized one. `ALLOWED_ISSUERS` is not a
repository allowlist: `token.actions.githubusercontent.com` issues tokens to
every repository on GitHub Actions, `gitlab.com` to every project there, and
the audience is a public string. Issuer plus audience therefore says nothing
about _who_ is calling.

Authorization is a separate table of trusted subjects, managed through
[`/admin/subjects`](#trusted-oidc-subjects). A token is refused with
`Subject is not trusted for signing` unless its issuer and `sub` match a live
row, and each row carries its own key allowlist, expiry and revocation — the
same lifecycle as a service token.

**An empty table denies everyone.** A fresh deployment cannot sign over OIDC
until at least one subject is trusted, which is the intended failure direction.

## Trusted OIDC subjects

| Method   | Path                   | Purpose                             |
| -------- | ---------------------- | ----------------------------------- |
| `POST`   | `/admin/subjects`      | Trust an issuer and subject prefix  |
| `GET`    | `/admin/subjects`      | List trusted subjects and their use |
| `DELETE` | `/admin/subjects/{id}` | Revoke a trust (see below)          |

```bash
curl -X POST "$GPG_SIGN_URL/admin/subjects" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "kjanat-repos",
    "issuer": "https://token.actions.githubusercontent.com",
    "subjectPrefix": "repo:kjanat",
    "keyIds": ["D8BC04E534E7706F"],
    "expiresInDays": 365
  }'
```

`subjectPrefix` is matched with a delimiter boundary, so `repo:owner/name`
does not also admit `repo:owner/name-evil`. A prefix that ends at a delimiter
is deliberately broader: `repo:owner/` trusts every repository of that owner,
while still refusing `repo:ownerevil/`. Where several rows match, the longest
prefix wins, so a specific repository can be granted different keys than the
owner-wide row covering the rest.

> [!TIP]
> For an owner-wide trust prefer `repo:owner` over `repo:owner/`. The boundary
> then falls on either `/` or `@`, so the row keeps matching if the repository
> later enables immutable subject claims and its `sub` changes shape. It still
> refuses `repo:ownerevil`. The failure is closed either way — signing breaks,
> nothing opens — but it breaks at an awkward moment.

A prefix must also contain a delimiter with something after it. `repo:` and
`repo` are refused, because a prefix ending at a delimiter is owner-wide and a
bare scheme would therefore be _host_-wide — every repository on the issuer.
The practical consequence: an identity provider whose subjects are opaque, with
no `:`, `@` or `/` in them, cannot be trusted through this table even by naming
one in full. Neither GitHub nor GitLab produces such subjects, but a custom
entry in `ALLOWED_ISSUERS` might.

Omit `keyIds` to allow every key. Omit `expiresInDays` for a trust that does
not expire.

### Revoke is not subtraction

Resolution takes the longest **live** prefix. Revoking a narrow row therefore
does not necessarily stop the subject signing — it promotes the next row up,
**with that row's key grant**:

```
repo:kjanat/       keyIds: []                 ← owner-wide, every key
repo:kjanat/svc    keyIds: [D8BC04E534E7706F] ← this repo, one key
```

Revoke `repo:kjanat/svc` and that repository keeps signing, now under the
owner-wide row — which pins no keys, so it just gained access to _every_ key.
The revoke widened the grant.

Revoking the **broad** row is the mirror image: rows nested underneath it are
not touched, so the part of the scope you meant to cut keeps signing. Revoke
`repo:kjanat/` and `repo:kjanat/svc` carries on.

`DELETE /admin/subjects/{id}` answers with both:

```json
{
  "success": true,
  "id": "…",
  "name": "kjanat-svc",
  "stillCoveredBy": [
    {
      "id": "…",
      "name": "kjanat-repos",
      "subjectPrefix": "repo:kjanat/",
      "keyIds": null
    }
  ],
  "stillTrustedWithin": []
}
```

- `stillCoveredBy` — rows that **cover** the revoked prefix, most specific
  first. The whole revoked scope keeps signing, under their grants. The first
  entry is the one resolution picks only where no `stillTrustedWithin` row
  claims the subject: those are nested under the revoked prefix, so they are
  longer than everything here and win. A pinned `keyIds` at the top of this list
  is therefore not proof the scope was narrowed — read both lists.
- `stillTrustedWithin` — rows **nested under** it, outermost first: where one of
  these contains another, the container is listed above it. Rows in disjoint
  scopes are not ordered against each other — a one-repo row can precede a
  team-wide one — so read the whole list, not just the first entry.

**Only when both are empty was the revoke final.** During an incident, revoke
those rows too, or replace them with narrower ones that exclude the compromised
subject. The service also logs
`Revoked subject is still trusted through another row` and records both lists of
names in the `subject_revoke` audit event.

Expiry does the same thing with nobody watching: `expiresInDays` on a narrow,
key-scoped row is a promotion to the parent's grant on its expiry date, not an
end to access. Prefer revoking to letting a nested row lapse.

### Renewing an expired trust

Uniqueness on (issuer, prefix) covers every row that has not been revoked, and
an expired row has not been revoked — it authorizes nobody but still holds the
slot. So re-POSTing the same prefix after it expires returns `409`. Revoke the
old row first, which frees the slot, then create the replacement:

```bash
curl -X DELETE "$GPG_SIGN_URL/admin/subjects/$OLD_ID" -H "Authorization: Bearer $ADMIN_TOKEN"
# then POST the new trust as above
```

The `409` names the blocking row's id and its expiry, so `$OLD_ID` comes
straight from the error. **Do not reach for a different prefix to get around
it** — the nearest string that avoids the collision is a broader one, which
widens access instead of renewing it.

Names are also unique across all rows, revoked ones included, so a replacement
needs a new `name`. Treat the name as a permanent label for one generation of a
trust rather than a slot to reuse: every OIDC `sign` audit event carries the
authorizing row's name in `metadata.subjectPolicy`, next to the JWT subject in
`subject`. The subject alone cannot answer "what did the trust I just revoked
sign?" — prefixes overlap, and a revoked row leaves no mark on the tokens it
admitted. `DELETE /admin/subjects/:id` returns that name and logs it on the
`subject_revoke` event too, so the trail joins to itself without a lookup
against `oidc_subjects`.

### What gets audited

Every `sign` failure lands in `audit_logs` with `success: false` and one of:

| `errorCode`       | Meaning                                                                                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `KEY_NOT_ALLOWED` | A live, trusted row asked for a key its `keyIds` grant does not cover — a misconfigured workflow, or a trust being used by something that should not hold it. |
| `KEY_NOT_FOUND`   | The caller was authorized and the requested key is not stored.                                                                                                |
| `SIGN_ERROR`      | The caller was authorized and signing itself failed.                                                                                                          |
| `AUTH_INVALID`    | A **revoked** trust was presented. `metadata.reason` is `revoked_trust_presented`, with the row's `subjectId`, `subjectPolicy` and `revokedAt`.               |

The two to alert on are `KEY_NOT_ALLOWED` and `AUTH_INVALID`: both require a
credential this service either trusts now or trusted deliberately in the past.

Refusals before the route are metered before they are written, so a caller
cannot flood the table that shares a database with the authorization store. If
the limiter says no, or is unreachable, the refusal still stands but no row is
written.

Two refusals are **not** recorded in `audit_logs`, and are visible only in the
structured logs:

| Log message                       | Meaning                                                                                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Expired OIDC trust presented`    | A trust lapsed and its workflow has not noticed. Routine, and actionable by the row's owner.                                                     |
| `Rejected untrusted OIDC subject` | An unknown subject. Mostly background traffic — both issuers are shared with every repository on their platform, so strangers arrive unprompted. |

> [!IMPORTANT]
> Workers Logs retention is short — 7 days on paid plans, 3 on Free, with
> head-sampling above 5 billion logs/day account-wide. Anything you want to
> alert on from these two lines has to be shipped off-platform first. The
> durable events are the `audit_logs` rows above.

Every refusal returns the same `401 Subject is not trusted for signing` body
regardless of which of the three it was: telling a caller that its subject
matches a revoked row would confirm the row exists. The `revoked` arm does cost
a rate-limiter round-trip and a token of the caller's budget where the other two
cost neither, so the three are not indistinguishable by timing — only by
content. The audience for that difference is bounded to whoever can match a
stored prefix, which on GitHub means the org that held the trust.

The `key_id` on a `revoked_trust_presented` row is the sentinel `*`, not a key:
the request never reached the point of choosing one. Filters and joins on
`key_id` need to allow for it.

### Subject shapes

GitHub subjects are `repo:<owner>/<repo>:<context>`, or
`repo:<owner>@<ownerId>/<repo>@<repoId>:<context>` when the repository has
[immutable subject claims](https://docs.github.com/en/actions/reference/security/oidc)
enabled. The immutable form is stronger — a renamed or re-created repository of
the same name cannot assume it — but the two are stored and matched
identically, so trust whichever form your repositories actually issue. Check
yours under **Settings → Actions → OIDC configuration**.

## OIDC validation

The Worker:

1. accepts `RS256`, `RS384`, `RS512`, `ES256`, or `ES384`;
2. checks `iss` against comma-separated `ALLOWED_ISSUERS`;
3. checks `nbf` and `exp` with 60 seconds of clock tolerance;
4. checks `aud` against `EXPECTED_AUDIENCE`, which defaults to
   `gpg-signing-service`;
5. fetches OIDC discovery and JWKS documents after SSRF validation;
6. caches JWKS data in KV for five minutes;
7. verifies the JWT signature and signing-key usage; and
8. resolves `iss` and `sub` to a trusted subject, refusing the request when
   none matches and applying that subject's key allowlist.

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
