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

`/public-key` currently handles PGP keys only. Use
`/admin/keys/{keyId}/public` for X.509 certificate retrieval.

## Sign request

```http
POST /sign?keyId=D8BC04E534E7706F
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
- every `/admin/*` bearer is compared with `ADMIN_TOKEN`.

See [Authentication](authentication.md) for token acquisition and policy.

## Error responses

Errors are JSON and normally include:

```json
{
  "error": "Human-readable message",
  "code": "MACHINE_READABLE_CODE",
  "requestId": "optional-uuid"
}
```

Validation errors can also include an `issues` array. Not every early
authentication or validation response includes a request ID.

Common status codes:

| Status | Meaning                                               |
| ------ | ----------------------------------------------------- |
| `400`  | Invalid body, query, header, or identifier            |
| `401`  | Missing or invalid credential                         |
| `403`  | Service token cannot use the selected key             |
| `404`  | Route, key, or token not found                        |
| `409`  | Duplicate service-token name                          |
| `429`  | Rate-limit bucket exhausted                           |
| `500`  | Key processing, signing, storage, or database failure |
| `503`  | Rate limiter or dependency unavailable                |

## Regeneration

After changing route or schema definitions:

```bash
task generate:api
```

This refreshes `client/openapi.json` and the generated Go API package.
