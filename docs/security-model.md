# Security model

This document describes current behavior, including limitations. It is not a
security certification.

## Trust boundary

The deployment operator and Cloudflare infrastructure are trusted with:

- uploaded private-key material;
- `KEY_PASSPHRASE`, `ADMIN_TOKEN` and `ADMIN_READONLY_TOKEN`;
- `GITHUB_APP_PRIVATE_KEY` and `GITHUB_WEBHOOK_SECRET`, on a deployment that
  opts into the GitHub App webhook;
- data submitted for signing;
- generated signatures;
- audit records; and
- service-token hashes and metadata.

There is no HSM, external KMS, per-tenant vault, or operator role model.

This section is about the deployed service. The repository's CI carries a second
and unrelated trust boundary, between a job that executes a Dependabot pull
request and a job that can push to its branch. It is described in
[the Dependabot fix path](dependabot-fix-path.md).

A deployment that opts into the [GitHub App webhook](github-app.md) accepts a
third: `POST /github/webhook` takes an untrusted JSON payload from an
unauthenticated network peer, and `X-Hub-Signature-256` is the only thing that
makes it GitHub's. The endpoint is off unless `GITHUB_APP_ENABLED` is the
literal `"true"`, and a deployment that has not opted in answers it exactly as
it answers any unrouted path.

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
what no live grant reaches. Expiry is read out of the key material, as is
revocation **for PGP keys** — a revoked primary, or a signing subkey revoked
under a healthy one. The X.509 path reads the certificate's `notAfter` only:
there is no CRL or OCSP lookup, so a revoked-but-unexpired certificate is
reported `ok`. Two further consequences worth stating: a grant added after a run
is not covered until the next one, and a key nothing can currently sign with is
not monitored at all — retaining it raises nothing, and so does forgetting it.

A run that resolves no active key is reported, not treated as clean. It has
verified nothing, and a monitor whose green light can mean "I checked nothing"
is the failure this one exists to prevent.

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
- GitHub webhook deliveries are verified with HMAC-SHA-256 over the raw request
  bytes, compared in constant time. The parse happens after the verdict, so a
  re-serialised body is never what a signature is checked against. An enabled
  integration with no `GITHUB_WEBHOOK_SECRET` refuses every delivery rather than
  accepting unauthenticated ones.
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
| `POST /github/webhook`     | Client IP                          |
| Public routes              | No application rate limiter        |

Rate-limiter failure returns `503` rather than allowing the request.

The webhook bucket is keyed by address, not by installation: the installation id
is inside a body that has not been verified yet, so metering on it would let an
unsigned request choose its own bucket. It is metered before the HMAC is
checked, so the limit bounds unverified verification work, and it is a namespace
of its own so that a burst of deliveries cannot exhaust an operator's ability to
reach `/admin`.

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

There is no built-in retention, export, or tamper-evident log chain. Alerting is
available but optional; see below.

Accepted webhook deliveries are logged, not audited. `audit_logs` records
operations on keys and credentials, and the scaffold acts on no event, so a row
per acknowledged-and-discarded delivery would be a write per event nothing acted
on. See [GitHub App webhook](github-app.md#audit-records).

## What Sentry receives

Error reporting is **off unless `SENTRY_DSN` is set**. Unset — or set to
whitespace — the Worker builds its Sentry options with `enabled: false`, no DSN,
no tunnel, no debug logging, a trace sample rate of `0`, and no integrations at
all: nothing wraps `console`, nothing reads request bodies, nothing is sent, and
Workers Logs and `audit_logs` behave exactly as they do without the binding.
Self-hosting does not conscript you into a third-party processor.

That is a statement about what the Worker **emits**, not about its call stack.
The SDK's entry-point wrappers install before any option is read, so even with
no DSN the `env` bindings and Durable Object storage handles the Worker sees are
proxies, and prepared D1 statements carry span shims. They record into a client
that does not exist, so nothing is produced and nothing is kept. The whole test
suite runs on this branch — `wrangler.test.toml` sets no `SENTRY_DSN` — which is
what makes "an unset DSN changes nothing observable" a property every test
checks rather than an assertion in one of them.

Only the configured DSN decides where anything goes. `spotlight` and `tunnel`
are both pinned off in code, because each would otherwise be filled from a
`SENTRY_SPOTLIGHT` or `SENTRY_TUNNEL` variable and each can redirect events away
from the DSN — `spotlight` even without one.

With a DSN set, the boundary is `src/utils/sentry.ts`, and it is the only path
out. What is reported:

- uncaught exceptions and every `logger.error`, tagged with `requestId` and,
  where the code has them, `action` and `errorCode`;
- the two refusals worth alerting on as their own events — `KEY_NOT_ALLOWED`,
  and a revoked OIDC trust presented again (`errorCode: AUTH_INVALID`,
  `reason: revoked_trust_presented`);
- the two log-only refusals as **breadcrumbs**, not events. An unknown subject
  is reachable by any holder of any token a shared issuer will mint, so an event
  per occurrence would be a caller-controlled bill; a lapsed trust is routine
  maintenance. Both still ride along on whatever event is raised, which is what
  closes the retention gap the log-only refusals had.

What is never reported, redacted by property name _and_ by value shape,
recursively, across request data, extras, contexts, breadcrumbs, exception
messages and nested values:

- `KEY_PASSPHRASE`, `ADMIN_TOKEN`, `ADMIN_READONLY_TOKEN`,
  `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` — both under their own names
  and as literal values, wherever they appear;
- armored PGP or PEM private key material, including a block truncated
  mid-transit;
- raw OIDC JWTs, `gst_` service tokens, and `Bearer`/`Basic` credentials;
- the `Authorization` header, and cookies;
- request bodies, which are not collected at all: the SDK's body capture is
  pinned off and `request.data` is deleted on the way out regardless.

The deployment's own `KEY_PASSPHRASE`, `ADMIN_TOKEN`, `ADMIN_READONLY_TOKEN`,
`GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` and DSN are swept out of every
string **by literal value**, with no minimum length —
a short secret is still this deployment's secret, and that sweep is the only
rule that catches one arriving under a name nobody predicted. Only an empty or
all-whitespace value is skipped, because it is not a configured secret. The
credential rule is the same shape: `Bearer`/`Basic` redaction is decided by
credential syntax (RFC 7235 `token68`), not by length, so `Bearer x` is redacted
while `Bearer <token>` in a documentation hint and a `Bearer realm="…"`
challenge stay readable.

With a DSN set, the SDK also collects the following on its own. None of it is
requested by this service and none of it carries a secret past the scrubber, but
a document that enumerates what leaves the Worker should name it:

- **D1 query text**, as `query` breadcrumbs and `db.query` span names. Statements
  are parameterised, so values do not travel, but the schema does.
- **Durable Object storage operations**, as `durable_object_storage_*` spans —
  the operation and the object, not the stored value.
- **Outbound `fetch` calls** as spans: the OIDC JWKS fetches and the key-expiry
  mail delivery.
- **The inbound request URL and its full header set.** `Authorization` is
  redacted by name and cookies are dropped outright; the rest — `User-Agent`,
  `Content-Type`, `CF-Ray` and so on — travel.

Traces are sampled at `SENTRY_TRACES_SAMPLE_RATE`, default `0.1`. Setting it to
`0` keeps error events and drops all of the above.

`sendDefaultPii` is `false`, so no IP address or cookie-derived user is attached.
Key ids, fingerprints, issuers, subjects and subject-policy names _are_ reported:
each is already readable through `/public-key`, `GET /admin/subjects` or the
audit trail, and they are what makes an event worth having.

Sentry does not replace `audit_logs`. That table remains the durable record of
who signed what, it is queried by the admin API, and none of it moves to a third
party.

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
- no X.509 revocation checking: the monitor reads `notAfter` and performs no CRL
  or OCSP lookup, so a revoked-but-unexpired certificate raises nothing;
- a read-only admin credential that is narrower in _authority_ than
  `ADMIN_TOKEN` but not in _disclosure_: it still reads every key id,
  trust rule, token name and audit record;
- no audit retention, and no alerting unless the optional `SENTRY_DSN` is
  configured (see [What Sentry receives](#what-sentry-receives));
- a GitHub App webhook, when enabled, whose deliveries are logged but not
  recorded in `audit_logs`, and whose rate-limit bucket is shared by every
  caller reaching it from one address;
- PGP-only behavior in the high-level CLI and Go wrapper; and
- Git history rewriting when a detached signature is attached after commit
  creation.

See [Self-hosting](self-hosting.md#before-production) for an operator checklist.
