# ADR-004: Retirement and Revocation of Signing Key 62E75E54497815DD

## Status

Accepted (2026-09-09)

## Context

The passphrase-encrypted secret-key packet of production signing key
`62E75E54497815DD` was published in this repository's Git history, including
history reachable from the signed `v1.2.0` tag (#147). A passphrase the
repository does not hold was the only thing between a public tree and a usable
signing key.

The rotation is complete. What follows is the observed state, not a plan:

- Production signs with replacement key `AFD5E3EC68371856`, generated offline
  under a new passphrase, whose encrypted private half has never been committed
  here.
- The retired key was removed from the production `KeyStorage` Durable Object on
  2026-09-08. `GET /public-key?keyId=62E75E54497815DD` answers `404
  KEY_NOT_FOUND`, and the audit trail records a post-removal sign attempt under
  that key failing the same way.
- Every live OIDC subject grant and every unrevoked service token pins
  `AFD5E3EC68371856`. The tokens that pinned the retired key are revoked.
- The retired key is no longer registered on the GitHub account; the replacement
  is.
- Staging's `KEY_ID` named the retired key until 2026-09-09, but staging never
  held any key: its `KeyStorage` Durable Object has no stored data and its audit
  database has no applied migrations. Nothing signed there, with that key or any
  other. The reference was configuration drift, not exposure. It now names the
  replacement.

Two decisions were still open: whether to publish a revocation for the retired
key, and what to do about the published history.

## Decision

**1. The retired key SHOULD be formally revoked.** Its encrypted private half is
published and must be assumed recoverable. A published revocation is the only
signal that reaches a verifier who fetches the key rather than asking this
service. The revocation certificate lives with the operator's offline handoff
material and has to be published from there; nothing in this repository, in CI,
or in the Cloudflare account can produce or hold it. Until it is published, the
retired key's protection rests on removal from the signing path, which is
verified above.

**2. The retired key's public material is preserved regardless.** `v1.2.0` and
every historical signature made before 2026-09-08 verify only against it.
Revoking a key does not invalidate signatures it made while valid, and deleting
its public half would. Retention of the public key is not conditional on the
revocation decision.

**3. The published history stays.** The signed `v1.2.0` tag and its target are
not rewritten, recreated, or re-signed to reduce discoverability of the retired
ciphertext. Rotation was the security boundary; a history rewrite cannot make
already-copied ciphertext secret again, and it would destroy signed release
provenance that is being deliberately preserved. Old ciphertext reachable only
through immutable published release history is accepted historical exposure.

**4. The key-material guard keeps recognising the retired key.** `RETIRED_IDENTITIES`
in `scripts/key-material.py` is keyed on a digest over the retired key's public
material excluding its creation time, so a re-stamped copy does not clear it. The
entry is about what may never come back as a fixture, not about what is deployed,
and it stays after the key stops being deployed.

## Consequences

- A verifier who holds the retired public key and has not seen a revocation will
  still accept a signature made with it. That window closes when the operator
  publishes the revocation, and this is the reason to do so.
- Neither the retired nor the replacement key is currently on a public keyserver.
  Publishing the revocation implies publishing the retired public key to carry
  it, which is consistent with decision 2.
- Historical signature verification is unaffected by either the retirement or a
  later revocation, because the public key is retained.
- No further rotation is warranted by #147. Rotating again would invalidate the
  evidence above without addressing anything the rotation did not already close.

## References

- Issue #147 — post-rotation containment for the exposed signing key
- PR #148 — removal of current-tree copies and the key-material guard
- [ADR-002: Cryptography](ADR-002-cryptography.md)
- [Security model](../security-model.md)
