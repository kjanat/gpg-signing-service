# How it works

## Three separate layers

### Installer action

The root [`action.yml`](../action.yml) is a composite GitHub Action. It resolves
a GitHub release, downloads the binary for the runner, optionally verifies the
release checksum, and adds the binary directory to `PATH`.

It does not:

- authenticate to the signing service;
- configure Git or GPG;
- call `/sign`;
- attach a returned signature to a commit; or
- push a rewritten commit.

### CLI and Go client

The CLI in [`client/cmd/gpg-sign`](../client/cmd/gpg-sign) is an HTTP client.
`gpg-sign sign` reads bytes from standard input and writes a detached signature
to standard output. The high-level Go wrapper lives in
[`client/pkg/client`](../client/pkg/client).

### Signing service

The service is a Hono application running on Cloudflare Workers. It uses:

- a `KeyStorage` Durable Object for key records;
- a `RateLimiter` Durable Object for token buckets;
- D1 for audit records and service-token hashes; and
- KV for cached OIDC JSON Web Key Sets.

All key records share one named `KeyStorage` Durable Object. This is a
single-deployment service, not a multi-tenant key vault.

## Signing request flow

```text
caller
  │  Bearer OIDC JWT or gst_ service token
  ▼
POST /sign?keyId=0123456789ABCDEF
  │
  ├─ authenticate caller
  ├─ validate optional UUID request ID and non-empty body
  ├─ select requested key or the deployment's KEY_ID
  ├─ enforce a service-token key allowlist, when present
  ├─ consume the caller's rate-limit token
  ├─ load key material from the KeyStorage Durable Object
  ├─ create a detached OpenPGP or PKCS#7 signature
  └─ schedule an audit write and return the signature
```

Rate limiting and key lookup run in parallel, but signing does not begin unless
the rate-limit check succeeds.

## What is signed

`POST /sign` signs any non-empty text body. The service does not parse the body
as a Git object and does not compare OIDC repository, ref, or workflow claims
with that body.

The body is decoded as UTF-8 on arrival and re-encoded as UTF-8 before signing,
so the signed bytes are the request bytes for any UTF-8 payload — which every
Git commit object produced by a default `git` configuration is. A commit object
carrying non-UTF-8 bytes (an `encoding` header naming a legacy charset, say)
cannot round-trip through the text body and is not supported.

Access to `/sign` is therefore authority to request signatures over arbitrary
text with an accessible key. See [Authentication](authentication.md) and
[Security model](security-model.md) before exposing a deployment.

## Signature formats

| Stored key                       | Service response                          | Git mode                     |
| -------------------------------- | ----------------------------------------- | ---------------------------- |
| OpenPGP private key              | ASCII-armored detached PGP signature      | Default `gpg.format=openpgp` |
| PKCS#8 key and X.509 certificate | PEM-armored detached PKCS#7/CMS signature | `gpg.format=x509`            |

The current high-level Go client and `gpg-sign` CLI validate PGP response
markers and are therefore PGP-only. X.509 operations are available through the
HTTP API and generated raw Go client.

## OpenPGP packet format

The PGP signature is a **binary** signature — signature type `0x00` in
[RFC 9580 §5.2.1][rfc9580-sigtypes] — over the request body byte for byte. That
is what Git produces itself: `git commit -S` shells out to `gpg -bsa` with no
`--textmode`, and the resulting packet is `sigclass 0x00`.

The alternative, canonical text (`0x01`), is not interchangeable here. A
canonical-text signature rewrites every line ending to CRLF _before hashing_, so
a payload whose lines end in LF and the same payload with CRLF line endings hash
to the same value — one signature stays valid over two distinct commit objects,
and neither is pinned to the bytes Git actually stored. The service never
canonicalizes: the body is UTF-8 encoded and signed as-is.

To confirm the packet type on any signature this service returns:

```console
$ curl -sf "$GPG_SIGN_URL/public-key" | gpg --import
$ printf 'tree ...\n' > payload            # the unsigned commit object
$ curl -sf -H "Authorization: Bearer $TOKEN" --data-binary @payload \
    "$GPG_SIGN_URL/sign" > payload.sig
$ gpg --list-packets payload.sig | grep sigclass
	version 4, created ..., md5len 0, sigclass 0x00
$ gpg --verify payload.sig payload
gpg: Good signature from "..."
```

`sigclass 0x00` is the assertion. A `0x01` there is a defect, not a preference.

`scripts/test-gnupg-interop.sh` runs this end to end against real `gpg` and
`git` — it signs a genuine commit payload, checks the packet class against
git's own, verifies with `gpg --verify`, asserts the signature is _rejected_
over a CRLF-rewritten payload, and finally reassembles the commit object and
runs `git verify-commit` on it. `task test:gnupg-interop` runs it; it is part of
`task test` and skips itself where `gpg` is unavailable.

### Packet correctness is not the GitHub badge

Everything above is about the signature being cryptographically correct and
Git-compatible. Whether GitHub renders a green **Verified** badge is a separate,
account-level question — the key has to be registered to a GitHub account whose
verified email matches the committer address. A perfectly correct `0x00`
signature still shows as "Unverified" until that is done, and no change to the
packet can fix it. See
[GitHub will still say "Unverified"](cloud-session-signing.md#github-will-still-say-unverified)
for the prerequisites.

[rfc9580-sigtypes]: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-types

## From signature to signed commit

Git stores a signature inside the commit object. A signing client must:

1. obtain the exact unsigned commit payload;
2. request a detached signature over those bytes;
3. reconstruct the commit with a `gpgsig` header; and
4. update a ref to the newly created commit object.

Step 3 changes the commit object and therefore its SHA. Updating an existing
remote branch may require a force push and can invalidate descendant commits.
The installer action and `gpg-sign sign` stop after step 2.

See [CI integrations](integrations.md) for safe boundaries and examples.

## Release and install flow

```text
v*.*.* tag
  └─ release workflow cross-builds binaries
       ├─ linux: amd64, arm64
       ├─ macOS: amd64, arm64
       ├─ Windows: amd64, arm64
       └─ checksums.txt

consumer workflow
  └─ root composite action
       ├─ resolves latest release or requested tag
       ├─ selects an OS/architecture asset
       ├─ downloads and, when available, verifies it
       └─ adds gpg-sign to PATH for later steps
```

The action ref and its `version` input are independent selectors. See
[GitHub Action](github-action.md#pinning-and-trust-limits).
