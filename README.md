# GPG Signing Service

An HTTP signing service for CI workloads, deployed as a Cloudflare Worker. It
can produce detached OpenPGP signatures or detached PKCS#7/CMS signatures for
Git's X.509 mode.

The repository contains three separate pieces:

- `action.yml` installs the released `gpg-sign` CLI in GitHub Actions.
- The CLI requests detached OpenPGP signatures from a deployed service.
- The Worker authenticates callers, stores keys, signs supplied bytes, and
  records selected audit events.

Installing the CLI does not grant signing access, and requesting a detached
signature does not attach it to a Git commit.

## Documentation

| Goal                                        | Guide                                               |
| ------------------------------------------- | --------------------------------------------------- |
| Understand the components and request flow  | [How it works](docs/how-it-works.md)                |
| Install the CLI in GitHub Actions           | [GitHub Action](docs/github-action.md)              |
| Learn who can access each operation         | [Authentication and access](docs/authentication.md) |
| Use the `gpg-sign` CLI                      | [CLI](docs/cli.md)                                  |
| Request signatures from GitHub or GitLab CI | [CI integrations](docs/integrations.md)             |
| Deploy an instance                          | [Self-hosting](docs/self-hosting.md)                |
| Review the trust boundary and known gaps    | [Security model](docs/security-model.md)            |
| Look up an endpoint                         | [API guide](docs/api.md)                            |
| Diagnose common failures                    | [Troubleshooting](docs/troubleshooting.md)          |

See the [documentation index](docs/README.md) for generated references and
design records.

## What it provides

- OpenPGP detached signatures
- X.509 detached PKCS#7/CMS signatures through the HTTP API
- GitHub Actions and GitLab CI OIDC authentication
- Revocable `gst_` service tokens with optional key allowlists
- Admin endpoints for key and token management
- Durable Object key storage and rate limiting
- D1 audit records and service-token hashes
- KV-backed OIDC JWKS caching
- Generated OpenAPI 3.0 contract and Go client

## Access summary

| Operation                                       | Credential                                |
| ----------------------------------------------- | ----------------------------------------- |
| Install a release with the GitHub Action        | GitHub API token for release access       |
| Read `/health`, `/public-key`, `/doc`, or `/ui` | None                                      |
| Call `/sign`                                    | Accepted OIDC JWT or `gst_` service token |
| Call `/admin/*`                                 | Deployment's static `ADMIN_TOKEN`         |

A verified OIDC token is not an authorized one. `ALLOWED_ISSUERS` is not a
repository allowlist — every repository on GitHub Actions gets a token from the
same issuer — so authorization is a separate table of trusted subjects managed
through `/admin/subjects`. An **OIDC** token is refused with
`AUTH_SUBJECT_UNTRUSTED` unless its issuer and `sub` match a live row, and each
row carries its own key allowlist, expiry, and revocation. The refusal echoes
the `subject` it saw and
links to [its own documentation](docs/errors.md#auth_subject_untrusted). **An empty table denies everyone**:
a fresh deployment cannot sign over OIDC until a subject is trusted.

That code is specific to verified OIDC identities. A `gst_` service token
carries its own grant rather than matching this table, so one that is unknown,
revoked or expired is refused `AUTH_INVALID` — never `AUTH_SUBJECT_UNTRUSTED`.

Trust is granted per issuer, subject prefix, and key. Within that grant a
trusted caller can request signatures over arbitrary non-empty text with any
key its row allows; the service does not further authorize workflow, ref,
environment, or project claims. Read the
[authentication](docs/authentication.md) and
[security](docs/security-model.md) guides before exposing a deployment.

## Quick start: install the CLI

Select the action implementation and downloaded binary independently. This
example fixes the action implementation to the commit that carries it:

```yaml
permissions:
  contents: read

steps:
  - uses: kjanat/gpg-signing-service@cbcb8600547bd6799cdca0b339e8dad044481435
    with:
      version: v1.2.0

  - env:
      GPG_SIGN_URL: ${{ vars.SIGNING_SERVICE_URL }}
    run: gpg-sign health
```

This only installs the CLI. Continue with
[Authentication](docs/authentication.md) and
[CI integrations](docs/integrations.md) to request a signature.

The binary release tag and its colocated checksum remain publisher-controlled.
See the [installer trust limits](docs/github-action.md#pinning-and-trust-limits)
when an independently fixed digest is required.

## API

The deployed service exposes:

| Path          | Purpose                              |
| ------------- | ------------------------------------ |
| `/doc`        | Generated OpenAPI 3.0 JSON           |
| `/ui`         | Swagger UI                           |
| `/health`     | Public dependency health             |
| `/public-key` | Public OpenPGP key retrieval         |
| `/sign`       | Authenticated detached signing       |
| `/admin/*`    | Key, token, and audit administration |

The checked-in schema is
[`client/openapi.json`](client/openapi.json). See the [API guide](docs/api.md)
for the complete endpoint table.

## Development

Project commands run through [Task](https://taskfile.dev/):

```bash
task install
task dev
task typecheck
task test
task generate:api
task format
```

Read [CLAUDE.md](CLAUDE.md) for repository command and verification rules.

## Architecture

```text
GitHub Actions / GitLab CI / other automation
                    │
                    │ OIDC JWT or gst_ token
                    ▼
          Cloudflare Worker (Hono)
             ├─ KV: OIDC JWKS cache
             ├─ D1: audit records and token hashes
             ├─ RateLimiter Durable Object
             └─ KeyStorage Durable Object
                    │
                    ▼
        detached OpenPGP or PKCS#7 signature
```

## License

The repository declares `AGPL-3.0-only OR MIT`. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0).
