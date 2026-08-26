# Error reference

Every error this service returns carries a `docs` field pointing at its own
section here:

```json
{
  "error": "Subject is not trusted for signing",
  "code": "AUTH_SUBJECT_UNTRUSTED",
  "subject": "repo:kjanat/kjanat:ref:refs/heads/master",
  "hint": "No active trust rule matches this subject. 4 rule(s) exist for issuer https://token.actions.githubusercontent.com, 4 of them active. …",
  "docs": "https://gpg.kajkowalski.nl/e/AUTH_SUBJECT_UNTRUSTED",
  "requestId": "628c9a74-c46d-403c-84c6-9c873298a17f"
}
```

The link is a redirect served by the deployment itself — `GET /e/<CODE>` — not a
deep link into this file. That keeps it short enough to survive a wrapped and
truncated CI log, and keeps links printed into archived logs working if this
document ever moves. Lowercase works too, so `…/e/auth_invalid` is fine to
retype off a screen. Set `ERROR_DOCS_URL` to point the redirect at your own copy
of this file.

## The envelope

| Field        | Always   | Meaning                                                                      |
| ------------ | -------- | ---------------------------------------------------------------------------- |
| `error`      | yes      | What happened, in prose. The service may reword these; do not match on them. |
| `code`       | yes      | Stable identifier. Branch on this.                                           |
| `docs`       | yes      | `<service>/e/<CODE>` — this document's section for that code.                |
| `requestId`  | mostly   | The id in `X-Request-ID`, in the logs, and in `audit_logs.request_id`.       |
| `hint`       | often    | What to change. Absent where the message already is the action.              |
| `subject`    | 401 only | The `sub` claim the caller presented, echoed back.                           |
| `retryAfter` | 429 only | Whole seconds to wait.                                                       |

`gpg-sign` prints `subject`, `hint`, `docs` and `requestId` on their own lines
underneath the one-line error, so a failed CI step reads as text rather than as
a JSON blob. Callers using the Go package read them off `client.Guidance`; see
[the CLI guide](cli.md#reading-a-failure).

## Authentication and authorization

### AUTH_MISSING

**401.** No usable credential was presented: no `Authorization` header, a header
that is not `Bearer …`, or a `Bearer` with nothing after it.

The last case is the common one in CI — an unset variable expands to an empty
string, and `Authorization: Bearer $TOKEN` becomes a syntactically valid header
carrying nothing. Check that the step that mints the token ran, and that its
output reached this step.

Retrying with the same configuration cannot change this answer.

### AUTH_INVALID

**401.** A credential was presented and the **credential** was refused. The
message names which check failed:

| Message                                           | Fix                                                                                                                                                                            |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Token expired` / `Token not yet valid`           | Mint the OIDC token immediately before calling `/sign`; check the runner's clock. There is 60s of skew tolerance.                                                              |
| `Invalid token audience`                          | Request the token with the audience this deployment expects — `EXPECTED_AUDIENCE`, default `gpg-signing-service`. In GitHub Actions, `core.getIDToken("gpg-signing-service")`. |
| `Issuer not allowed: <iss>`                       | The `iss` is not in this deployment's `ALLOWED_ISSUERS`.                                                                                                                       |
| `Invalid token format` / `Invalid token encoding` | The header did not carry a JWT.                                                                                                                                                |
| `Invalid token signature` / `Key not found`       | The issuer's JWKS does not verify the token. Usually a forged or truncated token; occasionally a key rotation the cache has not caught up with.                                |
| `Invalid service token`                           | A `gst_` token that is unknown, revoked or expired. `GET /admin/tokens` lists the live ones; mint a replacement with `POST /admin/tokens`.                                     |
| `Invalid admin token`                             | The bearer did not match the deployment's `ADMIN_TOKEN` secret.                                                                                                                |

This code does **not** cover "the token is fine but this identity may not sign"
— that is [`AUTH_SUBJECT_UNTRUSTED`](#auth_subject_untrusted). The two used to
share a code, which meant the two fixes (mend the credential; edit the trust
list) were indistinguishable from the response.

### AUTH_SUBJECT_UNTRUSTED

**401.** The credential verified — right issuer, right audience, good signature,
not expired — and the identity it proves holds no active trust rule.

Nothing about the workflow's OIDC configuration will change this. The fix is a
trust rule.

The response echoes the `subject` that was presented. That is the value to
compare against the stored rules, and the field that tells a wrong ref from a
wrong repository:

```
subject: repo:kjanat/kjanat:ref:refs/heads/master
```

A rule is a **prefix** of the subject, and it must end at a `:`, `@` or `/`
boundary. So:

- `repo:kjanat/kjanat` covers every ref of that repository;
- `repo:kjanat/kjanat:ref:refs/tags/` covers tags only, and refuses the `master`
  subject above;
- `repo:kjanat/` covers every repository of that owner;
- `repo:kjanat/kjanat` does **not** cover `repo:kjanat/kjanat-evil:…`.

Where several rules match, the longest live one wins.

Check and fix:

```bash
# What is trusted now. `active: false` is a revoked or expired rule.
curl --fail-with-body --silent \
  -H "Authorization: Bearer $GPG_SIGN_ADMIN_TOKEN" \
  "$GPG_SIGN_URL/admin/subjects" | jq '.subjects[] | {name, subjectPrefix, active}'

# Authorize one.
curl --fail-with-body --silent \
  -H "Authorization: Bearer $GPG_SIGN_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"kjanat/kjanat","issuer":"https://token.actions.githubusercontent.com","subjectPrefix":"repo:kjanat/kjanat","keyIds":[]}' \
  "$GPG_SIGN_URL/admin/subjects"
```

The `hint` says how many rules exist for the issuer. **Zero** means nobody was
ever authorized on this deployment for that issuer — an empty table denies
everyone rather than admitting everyone. **More than zero** means this
particular subject is not among them, so look at the ref or repository part of
the claim.

The hint does not name the trusted prefixes by default. Both issuers this
service accepts are shared with every repository on their platform, so any
stranger who can run a workflow can obtain a verified token and read whatever a
refusal says — and the list of prefixes is the list of everyone who signs here.
Operators who run a private issuer, or who consider that list public, can set
`DISCLOSE_TRUST_PATTERNS=true` to have the active prefixes named in the hint.

Three different situations answer with this same code and message: the subject
matches nothing, it matches a **revoked** rule, and it matches an **expired**
one. They are not distinguished in the response, because telling the holder of a
token that their subject matches a revoked rule confirms the rule exists. They
_are_ distinguished in the logs, keyed by the `requestId` from the response —
see [Looking a refusal up](#looking-a-refusal-up).

### KEY_NOT_ALLOWED

**403.** The credential was accepted and is trusted; its grant does not cover
the requested key.

Both trusted subjects and service tokens carry an optional key allowlist. Either
select a key the credential is scoped to, or widen the grant. An empty `keyIds`
means every key.

This denial is recorded in `audit_logs` — it is the highest-signal event the
service produces, since it is either a misconfigured workflow or a credential
being used by something that should not hold it.

## Keys

### KEY_NOT_FOUND

**404.** No key is stored under that id. Check `gpg-sign admin list`, the
`?keyId=` parameter, and the deployment's default `KEY_ID`.

### KEY_PROCESSING_ERROR

**500.** A stored key could not be parsed or converted. The key material in
storage is damaged or was uploaded in an unexpected format.

### KEY_LIST_ERROR

**500.** The key-storage Durable Object failed to enumerate keys. Check
`gpg-sign health` and the Worker logs.

### KEY_UPLOAD_ERROR

**500.** The key could not be stored. Either the Durable Object failed, or the
material was rejected — confirm it is an armored private-key block with its
armor checksum, and that the supplied id is the key's 16-character long id.

### KEY_DELETE_ERROR

**500.** The key-storage Durable Object failed to remove the key. Check
`gpg-sign health` and the Worker logs.

## Requests

### INVALID_REQUEST

**400.** The request did not satisfy the contract: an empty body on `/sign`, a
`keyId` that is not 16 hexadecimal characters, or a body that failed schema
validation (those carry an `issues` array).

Key ids are the 16-character long id — `62E75E54497815DD`, not
`signing-key-v1`.

### NOT_FOUND

**404.** No route matches. Also returned by `/e/<CODE>` for a code this service
does not define, which usually means a typo rather than an undocumented error.

## Rate limiting

### RATE_LIMITED

**429.** The caller exceeded a token bucket. `retryAfter` is whole seconds, at
least one.

There are two tiers, and the response does not say which one refused. The first
is per caller (`<issuer>:<subject>`); the second is per trusted rule, an order
of magnitude higher, and exists so one rule cannot be multiplied into unbounded
signing by minting fresh subjects — which GitHub makes easy, since the ref is
part of `sub`.

### RATE_LIMIT_ERROR

**503.** The rate limiter itself was unreachable or answered with an error. The
service refuses rather than signing unmetered. Retry.

## Signing and the service

### SIGN_ERROR

**500.** Signing failed after the key was fetched — a passphrase that does not
decrypt the key, or an unusable key. Check `KEY_PASSPHRASE`.

### AUDIT_ERROR

**500.** An audit query failed. Usually a migration that has not been applied;
run `task db:migrate`.

### INTERNAL_ERROR

**500**, or **503** for `Authorization store unavailable`.

The 503 form is worth separating: it means the D1 lookup of trusted subjects
failed. That is _not_ a credential problem — reporting it as a 401 would point
an operator at credentials on the day the real cause is an unapplied migration.
Run `task db:migrate` and check `gpg-sign health`.

## Looking a refusal up

Every error carries a `requestId`, which is also the `X-Request-ID` response
header. It is the key to two places:

```bash
# Audit records, for the events that write one
gpg-sign --json admin audit | jq '.. | objects | select(.requestId? == "628c9a74-…")'

# Live logs, for the refusals that deliberately do not write one
wrangler tail --format json | grep 628c9a74-
```

Not every refusal writes an audit row, on purpose. `AUTH_SUBJECT_UNTRUSTED` for
an unknown subject is reachable by anyone holding any token the issuer will
mint, so a durable write there would be an unmetered way to flood the table that
every authorization decision reads. Those refusals are logged instead, with the
same `requestId`, including the fields the response withholds:

| Log message                       | What happened                                                                                                                 |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `Rejected untrusted OIDC subject` | The subject matched no rule at all.                                                                                           |
| `Revoked OIDC trust presented`    | It matched a rule someone revoked. This one is an incident: a killed credential is still in use. It also writes an audit row. |
| `Expired OIDC trust presented`    | It matched a rule that lapsed.                                                                                                |

## Adding a code

1. Add it to `ErrorCodeSchema` in `src/schemas/errors.ts`.
2. Add a `## THE_CODE` section here. The `/e/` redirect derives the anchor by
   lowercasing, so the heading is all the wiring there is.
3. `src/__tests__/error-docs.test.ts` asserts a redirect for every code in the
   enum, so a code with no section fails the suite rather than shipping a link
   that goes nowhere.

The `docs` field itself needs no work: `src/middleware/error-docs.ts` adds it to
any JSON error body carrying a `code`.
