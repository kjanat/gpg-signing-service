# API guide

The generated OpenAPI contract is the schema source of truth:

- deployed JSON: `GET /doc`
- deployed Swagger UI: `GET /ui`
- checked-in contract: [`client/openapi.json`](../client/openapi.json)

The service emits OpenAPI 3.0 because the Go generator does not yet consume
OpenAPI 3.1.

## Endpoints

| Method   | Path                         | Authentication        | Purpose                                   |
| -------- | ---------------------------- | --------------------- | ----------------------------------------- |
| `GET`    | `/health`                    | Public                | Service and storage health                |
| `GET`    | `/public-key`                | Public                | Default or selected PGP public key        |
| `GET`    | `/e/{code}`                  | Public                | Redirect to an error code's documentation |
| `POST`   | `/sign`                      | OIDC or service token | Sign the text body                        |
| `POST`   | `/admin/keys`                | Admin                 | Upload a PGP private key                  |
| `POST`   | `/admin/keys/x509`           | Admin                 | Upload a PKCS#8 key and X.509 certificate |
| `GET`    | `/admin/keys`                | Admin                 | List key metadata                         |
| `GET`    | `/admin/keys/{keyId}/public` | Admin                 | Get a PGP public key or X.509 certificate |
| `DELETE` | `/admin/keys/{keyId}`        | Admin                 | Delete a key                              |
| `GET`    | `/admin/audit`               | Admin                 | Query audit records                       |
| `POST`   | `/admin/tokens`              | Admin                 | Create a service token                    |
| `GET`    | `/admin/tokens`              | Admin                 | List service-token metadata               |
| `DELETE` | `/admin/tokens/{id}`         | Admin                 | Revoke a service token                    |
| `POST`   | `/admin/subjects`            | Admin                 | Trust an OIDC issuer and subject prefix   |
| `GET`    | `/admin/subjects`            | Admin                 | List trusted OIDC subjects                |
| `DELETE` | `/admin/subjects/{id}`       | Admin                 | Revoke a trusted OIDC subject             |

`/public-key` currently handles PGP keys only. Use
`/admin/keys/{keyId}/public` for X.509 certificate retrieval.

## Sign request

```http
POST /sign?keyId=62E75E54497815DD
Authorization: Bearer <OIDC-JWT-or-gst-token>
Content-Type: text/plain
X-Request-ID: 123e4567-e89b-42d3-a456-426614174000

tree ...
parent ...
author ...
committer ...

commit message
```

- Body: any non-empty text
- `keyId`: optional; defaults to deployment variable `KEY_ID`
- Key IDs: exactly 16 hexadecimal characters
- `X-Request-ID`: optional UUID; the service generates one when omitted
- Success: raw detached PGP or PKCS#7 signature

The service does not validate that the body is a Git commit.

## Authentication headers

```http
Authorization: Bearer <token>
```

Routing is prefix-based:

- a bearer beginning `gst_` is a service token;
- any other bearer on `/sign` is treated as an OIDC JWT;
- every `/admin/*` bearer is compared with `ADMIN_TOKEN`, and with
  `ADMIN_READONLY_TOKEN` if one is set — the latter is accepted on `GET` and
  `HEAD` only, and answers `403 AUTH_SCOPE_INSUFFICIENT` on every admin route
  that changes state.

See [Authentication](authentication.md) for token acquisition and policy.

## Response headers

| Header                          | On                    | Meaning                                     |
| ------------------------------- | --------------------- | ------------------------------------------- |
| `X-Request-ID`                  | every response        | Correlation id; quote it when reporting     |
| `X-RateLimit-Remaining`         | when a limiter ruled  | Signatures left in the bucket that answered |
| `X-RateLimit-Reset`             | when a limiter ruled  | Epoch seconds when that bucket has a token  |
| `Retry-After`                   | on `SERVICE_DEGRADED` | Whole seconds to wait before calling again  |
| `Access-Control-Expose-Headers` | every response        | The subset of the above a browser may read  |

A `429` carries the rate-limit pair too, describing the budget that refused —
which on `/sign` may be the per-row ceiling rather than the caller's own bucket.
`X-RateLimit-Reset` is then derived from the body's `retryAfter`, so the two
never disagree.

`X-RateLimit-Limit` is never sent; the bucket capacity is not published.

Browsers only see these on a cross-origin response when `ALLOWED_ORIGINS` grants
the requesting origin. See [Security model](security-model.md#browser-access).

## Error responses

Errors are JSON:

```json
{
  "error": "Subject is not trusted for signing",
  "code": "AUTH_SUBJECT_UNTRUSTED",
  "subject": "repo:kjanat/kjanat:ref:refs/heads/master",
  "hint": "No active trust rule matches this subject. …",
  "docs": "https://gpg.kajkowalski.nl/e/AUTH_SUBJECT_UNTRUSTED",
  "requestId": "628c9a74-c46d-403c-84c6-9c873298a17f"
}
```

| Field        | Present                                 | Meaning                                                        |
| ------------ | --------------------------------------- | -------------------------------------------------------------- |
| `error`      | always                                  | Prose. The service may reword these; branch on `code` instead. |
| `code`       | always                                  | Stable identifier. See the [error reference](errors.md).       |
| `docs`       | always                                  | `<service>/e/<CODE>`, redirecting to that code's section.      |
| `requestId`  | except a few early validation responses | Also the `X-Request-ID` header and `audit_logs.request_id`.    |
| `hint`       | where there is an action to name        | What to change.                                                |
| `subject`    | authorization `401`s                    | The `sub` claim the caller presented, echoed back.             |
| `retryAfter` | `429`                                   | Whole seconds to wait, at least one.                           |
| `issues`     | schema validation `400`s                | Per-field validation failures.                                 |

The `docs` link is a redirect served by the deployment rather than a deep link,
so it stays short enough to survive a wrapped CI log and keeps working if the
documentation moves. `GET /e/{code}` accepts either case and answers `404` for a
code the service does not define.

Every `401` also carries a `WWW-Authenticate: Bearer` challenge.

Common status codes:

| Status | Meaning                                                                           |
| ------ | --------------------------------------------------------------------------------- |
| `400`  | Invalid body, query, header, or identifier                                        |
| `401`  | Missing, invalid, or untrusted credential                                         |
| `403`  | Service token cannot use the selected key                                         |
| `404`  | Route, key, or token not found                                                    |
| `409`  | Duplicate service-token name                                                      |
| `429`  | Rate-limit bucket exhausted                                                       |
| `500`  | Key, signing, storage or database failure; or this deployment's own configuration |
| `503`  | Rate limiter or dependency unavailable                                            |

A `503` carrying `code: "SERVICE_DEGRADED"` is the one refusal a caller is
invited to repeat: the service could not reach the issuer's JWKS or its
authorization store, so nothing about the request was judged. It carries a
`Retry-After` header — a header, not an envelope field, since `ErrorResponse`
declares no `retryAfter` — and waiting is the whole fix. See
[`SERVICE_DEGRADED`](errors.md#service_degraded).

Its opposite number is [`SERVICE_MISCONFIGURED`](errors.md#service_misconfigured),
a `500`, and it is the one to **stop** on. Same "nothing about your request is
wrong", opposite answer: the cause is this deployment's configuration, so it
answers identically until an operator changes it. Branch on the `code`, not on
whether a `Retry-After` came back — a missing header means "no interval
offered", which plenty of retryable `5xx` also mean.

The two statuses are the version of that a proxy can read, since a proxy cannot
read the code: the transient one is a `503` **with** a `Retry-After`, the
permanent one a `500` **without**.

## Regeneration

After changing route or schema definitions:

```bash
task generate:api
```

This refreshes `client/openapi.json` and the generated Go API package.
