# Security model

This document describes current behavior, including limitations. It is not a
security certification.

## Trust boundary

The deployment operator and Cloudflare infrastructure are trusted with:

- uploaded private-key material;
- `KEY_PASSPHRASE` and `ADMIN_TOKEN`;
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
- The static admin token is compared in constant time.

Service-token hashes are not a substitute for high entropy. An attacker who
obtains a plaintext `gst_` token can use it until expiration or revocation.

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
- no automated passphrase, admin-token, or key rotation, and no enforcement in
  the sign path against a key that is close to expiring — expiry is monitored
  and rotation is documented, but both are carried out by hand;
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

The check derives its subjects rather than trusting a hand-written list: it asks
the deployment for the keys it holds through `GET /admin/keys`, cross-checks
those against every `KEY_ID` in `wrangler.toml` so a configured-but-absent key is
reported too, and reads each expiry out of the key material returned by
`GET /admin/keys/{keyId}/public` — the PGP expiration time, or the X.509
certificate's `notAfter`. No expiry date is stored anywhere that could drift from
the key it describes.

- **Threshold**: `KEY_EXPIRY_WARN_DAYS`, default 60 days. Keys inside the window,
  already expired, unreadable or missing are all treated as needing action.
- **Channel**: a GitHub issue labelled `key-expiry`, opened on the first run
  inside the window and updated in place afterwards. The report is also written
  to the workflow job summary.
- **Credentials**: the workflow reads the `SIGNING_SERVICE_URL` repository
  variable and the `ADMIN_TOKEN` secret. This widens the admin token's blast
  radius to that workflow, which is the cost of checking the live deployment
  instead of a transcribed date; the token is otherwise unused by CI and should
  be rotated on the same schedule as any other admin credential.

The check reports; it does not rotate. See
[Key rotation](self-hosting.md#key-rotation) for the procedure it points at.
