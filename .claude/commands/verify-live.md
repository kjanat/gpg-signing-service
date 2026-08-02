---
description: Probe the live deployment and compare it against documented behavior
---

Verify the live gpg-signing-service deployment matches what the repo claims.
Base URL: use $GPG_SIGN_URL if set, otherwise https://gpg.kajkowalski.nl.

Probe each endpoint with WebFetch or `curl -sS -w '%{http_code}'` and compare
against `src/index.ts`, the OpenAPI config, and README.md:

1. `GET /health` — expect 200 with a healthy status body.
2. `GET /public-key` — expect 200, `application/pgp-keys`, an armored
   `PGP PUBLIC KEY BLOCK`.
3. `GET /doc` — expect 200 with a valid OpenAPI JSON document.
4. `GET /ui` — expect 200 AND a non-empty Swagger UI page: the HTML must
   actually reference the swagger-ui assets and render `/doc`. A 200 with a
   gutted/empty body is a FAILURE (see issue #25).
5. `POST /sign` without credentials — expect 401/403, NOT 500.
6. `GET /admin/...` without credentials — expect 401/403 and evidence the
   rate limiter is in front of auth.
7. Any endpoint the README or docs/ mention that is not covered above.

Then:

- Run `task t` to confirm the tree itself is green before blaming the deploy.
- Report a table: endpoint, expected, observed, verdict.
- For each mismatch, check open GitHub issues before filing: update the
  existing issue with fresh evidence instead of creating a duplicate. File a
  new issue only for undocumented drift, with curl output included.
