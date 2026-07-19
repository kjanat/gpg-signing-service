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
