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

## Key expiry monitoring

A Cron Trigger inside this same Worker checks, weekly, every key the deployment
can currently sign with, and emails through a Cloudflare Email Service
`send_email` binding when one needs attention.

|             |                                                        |
| ----------- | ------------------------------------------------------ |
| Channel     | Email, through the `KEY_EXPIRY_ALERTS` binding         |
| Threshold   | `KEY_EXPIRY_WARN_DAYS`, default 60 days                |
| Schedule    | Weekly, plus `wrangler dev --test-scheduled` on demand |
| Credentials | **None**                                               |

The credential line is the point. The monitor reads the `KeyStorage` Durable
Object and the grant tables through the same modules the request path uses, so
it does not authenticate back into its own `/admin/*` API and holds neither
`ADMIN_TOKEN` nor `ADMIN_READONLY_TOKEN`. Email is a binding, not an API token
or an SMTP password. Nothing about this feature adds a credential to copy into
another system or to remember to rotate — which is what a monitor that outlives
its own credentials has to look like.

The binding is restricted in `wrangler.toml` by `destination_address` and
`allowed_sender_addresses`, so a compromised Worker cannot use it to mail
anyone else or to forge a sender. The two addresses are plain vars rather than
secrets; an address is not a credential, and the alternative is a deployment
whose operator cannot read where their own monitor reports to.

The monitored set is derived from live state rather than from a maintained
list: the deployment's `KEY_ID`, plus every key a live grant permits, minus
what no live grant reaches. Expiry and revocation are read out of the key
material. Two consequences worth stating: a grant added after a run is not
covered until the next one, and a key nothing can currently sign with is not
monitored at all — retaining it raises nothing, and so does forgetting it.

Reporting is not enforcement. Nothing in the sign path refuses a key that is
near expiry, revoked, or already lapsed; the monitor exists so that the first
sign of one is not every caller failing at once.

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
  `ADMIN_READONLY_TOKEN`, which is rotated by hand like the rest. Key _expiry_
  is monitored (above), but performing the rotation is manual: see
  [Key rotation](self-hosting.md#key-rotation);
- no enforcement of expiry in the sign path, so a key inside the warning window,
  revoked, or already lapsed is still signed with;
- a read-only admin credential that is narrower in _authority_ than
  `ADMIN_TOKEN` but not in _disclosure_: it still reads every key id,
  trust rule, token name and audit record;
- no audit retention or alert configuration;
- PGP-only behavior in the high-level CLI and Go wrapper; and
- Git history rewriting when a detached signature is attached after commit
  creation.

See [Self-hosting](self-hosting.md#before-production) for an operator checklist.
