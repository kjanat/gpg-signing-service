# Documentation

This directory describes the current implementation. The generated OpenAPI
contract and the source code remain the final authority when a guide and the
implementation disagree.

## Start here

| If you want to…                            | Read                                  |
| ------------------------------------------ | ------------------------------------- |
| Understand the components and signing flow | [How it works](how-it-works.md)       |
| Install `gpg-sign` in GitHub Actions       | [GitHub Action](github-action.md)     |
| Choose or configure credentials            | [Authentication](authentication.md)   |
| Use the command-line client                | [CLI](cli.md)                         |
| Integrate a CI job                         | [CI integrations](integrations.md)    |
| Deploy your own instance                   | [Self-hosting](self-hosting.md)       |
| Understand the trust boundary              | [Security model](security-model.md)   |
| Look up an endpoint                        | [API guide](api.md)                   |
| Diagnose a failure                         | [Troubleshooting](troubleshooting.md) |

## Components

The repository contains three related but independent components:

1. The root `action.yml` installs a released `gpg-sign` binary in a GitHub
   Actions job.
2. The `gpg-sign` CLI sends requests to a deployed signing service.
3. The Cloudflare Worker stores keys, authenticates callers, signs supplied
   bytes, and records selected audit events.

Installing the CLI does not grant access to a signing service. Requesting a
detached signature does not attach it to a Git commit.

## Access at a glance

| Operation                                       | Caller                                         |
| ----------------------------------------------- | ---------------------------------------------- |
| Install the public release in GitHub Actions    | Any workflow allowed to use this public action |
| Read `/health`, `/public-key`, `/doc`, or `/ui` | Anonymous                                      |
| Call `/sign`                                    | Accepted OIDC identity or `gst_` service token |
| Manage keys, tokens, and audit records          | Holder of the deployment's `ADMIN_TOKEN`       |
| Operate the service                             | Owner of a Cloudflare deployment               |

An operator controls availability and credentials for their deployment. This
repository does not promise public access, tenancy isolation, or a service-level
agreement for the example hosted URL.

## Other references

- Generated API contract: [`client/openapi.json`](../client/openapi.json)
- Go CLI and wrapper: [`client/README.md`](../client/README.md)
- High-level Go wrapper: [`client/pkg/client/README.md`](../client/pkg/client/README.md)
- Design history: [`docs/adr/`](adr/)
- Live deployment, when enabled: `/doc` for OpenAPI JSON and `/ui` for Swagger UI

The root `API.md`, `DOCUMENTATION.md`, `DEVELOPER_GUIDE.md`, generated
assessments, and older example prose predate parts of the current service. Use
the focused guides above for current behavior.
