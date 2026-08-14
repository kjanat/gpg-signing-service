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
written as `AUTH_INVALID` with a `metadata.reason` of `revoked_trust_presented`.
Both writes are rate limited, so neither refusal can be used to flood the table
it is recorded in.

Invalid bodies, rate-limit rejections, and the remaining authentication failures
return before any audit is scheduled. An unknown subject and an expired trust are
logged only, the first because it is reachable by any holder of any token the
issuer will mint.

There is no built-in retention, export, alerting, or tamper-evident log chain.

## Browser access

`ALLOWED_ORIGINS` controls CORS. When it is empty, any supplied `Origin` is
treated as allowed and reflected with credentials enabled. Set an explicit
allowlist for deployments reachable from browsers.

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
- no automated passphrase, admin-token, or key rotation;
- no audit retention or alert configuration;
- PGP-only behavior in the high-level CLI and Go wrapper; and
- Git history rewriting when a detached signature is attached after commit
  creation.

See [Self-hosting](self-hosting.md#before-production) for an operator checklist.
