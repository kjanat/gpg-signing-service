# Security model

This document describes current behavior, including limitations. It is not a
security certification.

## Trust boundary

The deployment operator and Cloudflare infrastructure are trusted with:

- uploaded private-key material;
- `KEY_PASSPHRASE`, `ADMIN_TOKEN` and `ADMIN_READONLY_TOKEN`;
- data submitted for signing;
- generated signatures;
- audit records; and
- service-token hashes and metadata.

There is no HSM, external KMS, per-tenant vault, or operator role model.

## Signing authority

`POST /sign` accepts any non-empty text. It does not prove that the text is a
Git commit or that it belongs to the repository named in an OIDC claim.

An accepted signing credential is therefore authority to obtain signatures over
arbitrary text using accessible keys.

OIDC callers are authorized against the `oidc_subjects` table: a verified token
must also match a trusted `(issuer, subject_prefix)` row, which carries its own
expiry, revocation, and optional key allowlist. An empty table denies everyone,
so a fresh deployment cannot sign over OIDC until a subject is trusted. See
[Authentication](authentication.md#trusted-oidc-subjects).

Authorization is on the subject prefix, matched at a delimiter boundary. It does
not separately authorize workflow, ref, or environment claims, so a row granting
`repo:owner/name` covers every workflow and every ref in that repository. Scope
rows as narrowly as the subject shape allows and pin `keyIds`.

## Key material

Key records are stored as JSON in one globally named `KeyStorage` Durable
Object:

- PGP keys are stored in the armored form supplied by the operator.
- X.509 private keys are stored in the supplied PKCS#8 PEM form.
- Application-level encryption is not added by the Durable Object.
- Encrypted inputs are decrypted with the deployment-wide `KEY_PASSPHRASE`.
- Unencrypted PGP and PKCS#8 inputs are accepted.
- Decrypted PGP keys are cached in a Worker isolate for five minutes.
- X.509 keys are imported for each signing operation.

Use encrypted key inputs and control both the Cloudflare account and repository
deployment credentials. There is no private-key export endpoint.

## Authentication controls

- OIDC algorithms are restricted to asymmetric RSA and ECDSA variants.
- Issuers are checked before discovery and JWKS retrieval.
- OIDC discovery and JWKS URLs pass SSRF validation.
- JWKS responses are cached for five minutes and refreshed for an unknown
  `kid`.
- Service tokens contain 256 random bits and are stored only as SHA-256 hashes.
- Service tokens support expiration, revocation, and optional key allowlists.
- Trusted OIDC subjects support the same three, managed at runtime through
  `/admin/subjects` rather than by redeploying.
- Both static admin tokens are compared in constant time. When
  `ADMIN_READONLY_TOKEN` is provisioned, both comparisons run on every request,
  so which of the two a valid bearer matched is not observable by timing. When
  it is unset the second comparison is skipped rather than run against a
  placeholder — so whether a deployment provisioned the credential at all is
  timeable. That bit is not a secret; the values are, and those stay
  constant-time either way.

Service-token hashes are not a substitute for high entropy. An attacker who
obtains a plaintext `gst_` token can use it until expiration or revocation.

## The two admin credentials

`/admin/*` accepts two bearers, and they differ only in which HTTP methods they
may use.

| Secret                 | Accepted on                   | Refused on                                                           |
| ---------------------- | ----------------------------- | -------------------------------------------------------------------- |
| `ADMIN_TOKEN`          | every admin route             | —                                                                    |
| `ADMIN_READONLY_TOKEN` | `GET` and `HEAD` admin routes | every state-changing admin route, with `403 AUTH_SCOPE_INSUFFICIENT` |

Concretely, the read-only credential may call `GET /admin/keys`,
`GET /admin/keys/{keyId}/public`, `GET /admin/subjects`, `GET /admin/tokens` and
`GET /admin/audit`. It may not upload a key, delete a key, mint or revoke a
service token, or trust or revoke an OIDC subject.

The boundary is drawn on the method rather than on a list of paths, and that is
a deliberate trade rather than brevity. It runs one way: a route added later
that **changes state** is denied to the read-only credential by construction,
where a path allowlist would grant it to anyone who forgot to edit the list.

It does not run the other way. A route added later that **reads** is _granted_
to the read-only credential by construction — a future
`GET /admin/keys/{keyId}/export` would be reachable with the monitoring secret
the moment it is mounted, without anyone deciding that it should be. Nothing in
the middleware prevents that. What prevents it is
`src/__tests__/admin-scope.test.ts`, which pins the read set literally and
diffs it against the generated OpenAPI document: widening the read side fails
CI until the list is edited on purpose. Mutations are closed by code; reads are
opened by code and closed by review.

`ADMIN_READONLY_TOKEN` exists for the scheduled key-expiry monitor, which needs
four `GET`s and nothing else. Without it, a repository secret readable by that
workflow would also carry the authority to delete the signing key. What it does
_not_ reduce is read exposure: the credential can enumerate every key id,
fingerprint, trust rule, service-token name and audit record. Treat it as
sensitive; it is narrower in authority, not in disclosure.

Two constraints the service enforces rather than documents:

- An unset or empty `ADMIN_READONLY_TOKEN` means the credential does not exist,
  and no bearer obtains the read-only scope.
- Setting it to the same value as `ADMIN_TOKEN` is refused. The comparison
  cannot tell two identical secrets apart, so the "read-only" holder would
  silently be a full administrator — the exact outcome the split exists to
  prevent, and one that is invisible from the outside because every call the
  monitor makes still succeeds. The whole admin surface answers `500
  SERVICE_MISCONFIGURED` until they differ. The body says only that admin
  authentication is misconfigured: the guard runs before the `Authorization`
  header is read, so anything more specific would be handed to unauthenticated
  callers. The diagnosis and the fix go to the Workers log, keyed by the same
  `requestId` the caller was given.

Neither credential is scoped by key, and neither writes an audit row for a
refusal on the scope boundary; a refused mutation is a warn-level log line
carrying the request id.

## Rate limiting

The token bucket holds 100 requests and refills at 100 per minute.

| Surface                    | Identity                           |
| -------------------------- | ---------------------------------- |
| `/sign` with OIDC          | `issuer:subject`                   |
| `/sign` with service token | synthetic issuer plus token name   |
| Revoked-trust reuse record | `oidc-revoked-reuse:<subject row>` |
| `/admin/*`                 | Client IP                          |
| Public routes              | No application rate limiter        |

Rate-limiter failure returns `503` rather than allowing the request.

The OIDC signing identity is the caller's `sub`, and GitHub varies `sub` per ref,
so one trusted row is not bounded to one bucket: a caller who can push branches
gets a fresh budget per branch, and every distinct `sub` leaves a key in the
limiter Durable Object that nothing reaps. Service tokens are metered per
credential and do not have this. See the note on `oidcAuth` in
`src/middleware/oidc.ts`.

## Audit behavior

D1 records successful and failed signing outcomes plus selected key and token
lifecycle operations. Audit writes are scheduled in the background; an audit
failure does not fail the primary operation.

The service does not audit every rejected request, but it does record the two
refusals that carry signal. A denied key selection is written as
`KEY_NOT_ALLOWED` on both auth paths, and a revoked OIDC trust being presented is
written as `AUTH_SUBJECT_UNTRUSTED` with a `metadata.reason` of
`revoked_trust_presented`.
Both writes are rate limited, so neither refusal can be used to flood the table
it is recorded in.

Invalid bodies, rate-limit rejections, and the remaining authentication failures
return before any audit is scheduled. An unknown subject and an expired trust are
logged only, the first because it is reachable by any holder of any token the
issuer will mint.

There is no built-in retention, export, alerting, or tamper-evident log chain.

## Browser access

`ALLOWED_ORIGINS` controls CORS, and it fails **closed**: when it is unset or
empty, no `Access-Control-Allow-Origin` is sent at all. The service's callers are
CI runners and the Go client, neither of which is a browser, so the default grant
is nothing. Set an explicit comma-separated allowlist for deployments reachable
from browsers; entries are trimmed, and a `*` entry opts into public browser
access by echoing the literal wildcard rather than reflecting the request origin.
The wildcard is honoured wherever it appears in the list and is not narrowed by
the entries beside it, so `https://app.example.com,*` grants every origin.
Entries are matched exactly against the serialized request origin, so each one
must be a bare scheme, host and optional port — a trailing slash or an uppercase
host never matches, and the deployment silently grants nothing.

`Access-Control-Allow-Credentials` is never sent. Authentication is a bearer
token in `Authorization`, which a browser does not attach ambiently, so there is
no ambient credential for a cross-origin page to replay. A cookie- or client
certificate-based flow would have to add the header to the preflight _and_ the
actual response deliberately.

The `Origin: null` that sandboxed iframes, `data:` URLs and `file://` documents
send is refused even if it appears in the allowlist — it is a shared origin any
attacker can choose to present. A `*` entry is the exception: it answers every
origin, `null` included, because the CORS spec already lets an opaque origin
read a wildcard response, so refusing it there would be theatre. Every
origin-dependent response carries `Vary: Origin` so a shared cache cannot hand
one origin another's grant.

A granted origin may read `X-Request-ID` — the id to quote when reporting a
refusal — plus whichever rate-limit headers and `Retry-After` the response
carries; `Access-Control-Expose-Headers` names exactly those and nothing else.
`Retry-After` is on the list because a `503 SERVICE_DEGRADED` carries the wait
in a header rather than in the envelope, so withholding it leaves a browser
caller reading a hint that names a value its fetch layer hid. See
[Response headers](api.md#response-headers).

Security headers include HSTS, CSP, frame denial, MIME sniffing prevention, and
a restricted Permissions Policy.

## Release installer

The GitHub Action downloads an executable from a GitHub release:

- pin the action ref and the binary `version` independently;
- use a GitHub token only for release access;
- verify that the release contains `checksums.txt`; and
- note that the checksum is published alongside the binary, not through an
  independent trust channel.

The action fails on checksum mismatch, but only warns and continues when the
release has no checksum file.

## Operational gaps

Before relying on the service for protected production branches, account for:

- OIDC authorization that stops at the subject prefix, so a trusted row covers
  every workflow and ref in its scope;
- an OIDC signing rate limit keyed on the caller-chosen `sub`, which does not
  bound a trusted row;
- no HSM or external key-management boundary;
- no private-key backup or restoration workflow;
- no automated passphrase, admin-token, or key rotation — including
  `ADMIN_READONLY_TOKEN`, which is rotated by hand like the rest — and no
  enforcement in the sign path against a key that is close to expiring: expiry
  is monitored and rotation is documented, but both are carried out by hand;
- a read-only admin credential that is narrower in _authority_ than
  `ADMIN_TOKEN` but not in _disclosure_: it still reads every key id,
  trust rule, token name and audit record;
- no audit retention or alert configuration;
- PGP-only behavior in the high-level CLI and Go wrapper; and
- Git history rewriting when a detached signature is attached after commit
  creation.

See [Self-hosting](self-hosting.md#before-production) for an operator checklist.

## Key expiry monitoring

The service does not refuse to sign with a key that is about to expire, so an
unnoticed expiry breaks every caller at once. A scheduled GitHub Actions check
(`.github/workflows/key-expiry-check.yml`, weekly plus manual dispatch) closes
that gap.

The check derives both halves of the question rather than trusting a hand-written
list.

**Which keys count** is the deployment's own authorization state, not its
storage. `GET /admin/keys` says what is held; `GET /admin/subjects` and
`GET /admin/tokens` say who may use it. A key is monitored when a live
credential could sign with it right now, plus the checked environment's `KEY_ID`
default from `wrangler.toml`. This matters in both directions: a superseded key
kept in storage with no live grant reaching it raises nothing, while a key that
is signing today under a grant nobody wrote into `KEY_ID` is not missed.

The service's authorization model bounds how precise that can be. A grant with
no `keyIds` allowlist permits _every_ stored key — `routes/sign.ts` reads a null
allowlist as unrestricted — so where one live grant is unscoped, storage is the
activation boundary and the report says so, names the grant, and monitors
everything. There is no way to narrow it further without changing what the
service would actually accept, and a monitor that claims a narrower set than the
sign path honours is worse than a broad one. The report also states its other
limits inline: the set is a snapshot between runs, `wrangler.toml` can disagree
with vars edited outside the repository, and a grant naming a key that no longer
exists is reported `missing` rather than dropped.

**When a key lapses** is read out of the key material returned by
`GET /admin/keys/{keyId}/public` — the PGP expiration time (whichever of the
primary key and the signing subkey lapses first) or the X.509 certificate's
`notAfter`. No expiry date is stored anywhere that could drift from the key it
describes.

- **Threshold**: `KEY_EXPIRY_WARN_DAYS`, default 60 days. Keys inside the window,
  already expired, revoked, unreadable or missing are all treated as needing
  action.
- **Channel**: a GitHub issue labelled `key-expiry`, opened on the first run
  inside the window and updated in place afterwards. The report is also written
  to the workflow job summary.
- **Credentials**: the workflow reads the `SIGNING_SERVICE_URL` repository
  variable and the `ADMIN_READONLY_TOKEN` secret — not `ADMIN_TOKEN`. The check
  needs read on exactly four routes (`/admin/keys`,
  `/admin/keys/{keyId}/public`, `/admin/subjects`, `/admin/tokens`), all `GET`s,
  which is the whole scope `ADMIN_READONLY_TOKEN` grants. The credential in that
  repository secret therefore cannot delete a signing key, mint a service token
  or rewrite the trust list. `ADMIN_TOKEN` is not accepted as a fallback: the
  check exits `2` and names the substitution rather than performing it, because
  falling back would widen the monitor's authority precisely on the run where
  the narrow credential was absent, silently.

  What the secret does still carry is **disclosure**, not authority: it reads
  every stored key id, every trust rule, every token name and the audit log. A
  workflow log or a compromised runner leaks that set. Rotate it on its own
  schedule — cheaper than `ADMIN_TOKEN`, so rotate it more readily.
- **Scope of a run**: one deployment, one wrangler environment (`WRANGLER_ENV`).
  Checking staging is a second run against staging's URL and token, not a wider
  read from the production run.

The check reports; it does not rotate. See
[Key rotation](self-hosting.md#key-rotation) for the procedure it points at.
