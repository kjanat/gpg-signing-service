# GitHub App webhook

An opt-in endpoint that lets a GitHub App deliver events to this service.

**It acts on nothing.** Every verified delivery is acknowledged and discarded.
This is the trust boundary and the credential exchange, shipped before anything
that uses them, because those are the parts that are hard to get right and easy
to get wrong quietly.

Off by default. A deployment that has not opted in answers `POST
/github/webhook` exactly the way it answers any path it does not route, so
shipping this code does not advertise the feature.

## What works today

|                        |                                                           |
| ---------------------- | --------------------------------------------------------- |
| `POST /github/webhook` | Verifies `X-Hub-Signature-256` and answers `202 Accepted` |
| App JWT minting        | RS256, from `GITHUB_APP_PRIVATE_KEY`                      |
| Installation tokens    | Minted on demand, cached in KV under a namespaced key     |

## What does not

Named in [#26](https://github.com/kjanat/gpg-signing-service/issues/26) and
deliberately absent: auto-signing pushed commits, publishing a "GPG verified"
check run, and dispatching `@claude`. All three need an authorization model
deciding which installation may cause which key to sign, and inventing that
inside a webhook handler is how a signing service acquires a second, weaker
front door. `getInstallationToken` has no caller in the request path for the
same reason.

## Setup

### 1. Register the App

Settings → Developer settings → GitHub Apps → New GitHub App.

- **Webhook URL**: `https://<your-deployment>/github/webhook`
- **Webhook secret**: generate one and keep it; you need it in step 3.
- **Permissions**: none are required by the scaffold. Grant only what the work
  you add later actually needs.
- **Subscribe to events**: nothing is required either. `ping` is delivered on
  registration regardless, which is enough to check the setup.

### 2. Get the private key

"Generate a private key" downloads a `.pem`. It is **PKCS#1** — the file opens
with `-----BEGIN RSA PRIVATE KEY-----`.

WebCrypto imports only PKCS#8, so this service converts the file for you and
either form is accepted. If you would rather convert it yourself:

```bash
openssl pkcs8 -topk8 -nocrypt -in downloaded.pem -out app-key.pem
```

### 3. Configure the deployment

```bash
wrangler secret put GITHUB_APP_PRIVATE_KEY   # paste the whole PEM, headers included
wrangler secret put GITHUB_WEBHOOK_SECRET    # the value from step 1
```

Then in `wrangler.toml`, under `[vars]`:

```toml
GITHUB_APP_ENABLED = "true"
GITHUB_APP_ID      = "123456"  # from the App's settings page
```

`GITHUB_APP_ENABLED` accepts the literal `"true"` and nothing else. `"TRUE"`,
`"1"` and `"yes"` all mean off. A flag guarding an inbound webhook is the wrong
place to be generous — every near-miss must read as off, because the
alternative is a deployment that is on by accident.

### 4. Check it

Redeliver the `ping` from the App's "Advanced" tab. A working deployment
answers:

```json
{
  "received": true,
  "event": "ping",
  "delivery": "…",
  "installation": false,
  "handled": false
}
```

`handled` is always `false` while this is a scaffold.

## What each answer means

| Status | Code                    | Meaning                                                       |
| ------ | ----------------------- | ------------------------------------------------------------- |
| `202`  | —                       | Signature verified. Acknowledged, not acted upon.             |
| `400`  | `INVALID_REQUEST`       | Signature verified, body was not JSON.                        |
| `401`  | `AUTH_MISSING`          | No `X-Hub-Signature-256`. The App has no webhook secret set.  |
| `401`  | `AUTH_INVALID`          | The signature did not verify. The two secrets differ.         |
| `404`  | `NOT_FOUND`             | `GITHUB_APP_ENABLED` is not `"true"`.                         |
| `413`  | `PAYLOAD_TOO_LARGE`     | Body over GitHub's 25 MiB cap. It was not read.               |
| `429`  | `RATE_LIMITED`          | Too many deliveries from this address. Not retried by GitHub. |
| `500`  | `SERVICE_MISCONFIGURED` | Enabled, but `GITHUB_WEBHOOK_SECRET` is unset.                |

The 404 is byte-identical to the one an unrouted path returns, on purpose: a
distinguishable answer would let anyone enumerate which deployments have the
integration configured. The 500 is deliberately _not_ hidden that way — an
operator who opted in and cannot receive deliveries needs to be able to tell
that apart from a deployment that never opted in, or the integration silently
receives nothing.

## How it is protected

The webhook URL is public by construction: it is typed into a settings form and
then reachable by anyone who guesses it. The HMAC is not one control among
several — it is the only one.

- **The bytes verified are the bytes that arrived.** GitHub signs the body octet
  by octet, so verification runs on the raw `ArrayBuffer` and the JSON parse
  happens strictly after the verdict. A verifier that parsed and re-serialised
  first would be checking a signature over bytes GitHub never sent, and would
  fail on honest traffic.
- **The comparison is constant-time.** `crypto.subtle.timingSafeEqual`, over two
  fixed-width 32-byte digests. A malformed candidate is rejected before the
  comparison, which is what guarantees the comparison always gets equal lengths.
- **The rate limiter runs before the HMAC**, in its own bucket, and fails closed
  — the same shape `/admin` uses. An accepted delivery with no limit in front of
  it is unbounded verification work for an anonymous caller. Note what failing
  closed costs: [GitHub does not automatically redeliver a failed
  delivery](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries),
  so a `429` or a `503` from this path drops the event until someone redelivers
  it from the App's "Advanced" tab or through
  `POST /app/hook/deliveries/{id}/attempts`. The bucket is also keyed by
  address, and GitHub delivers from a small published set of them, so every
  installation of the App shares a handful of buckets.
- **The feature gate runs before the limiter**, so a deployment that never opted
  in spends nothing at all on a request to this path.
- **The body is bounded before it is buffered.** The limiter caps request
  _count_; the MAC has to run over the whole body, and Workers will accept up to
  100 MB against a 128 MB isolate memory limit, so the bytes are capped
  separately at GitHub's own 25 MiB (26214400-byte) payload cap. Above that
  figure a delivery is not truncated by GitHub, it is [not sent](https://docs.github.com/en/webhooks/webhook-events-and-payloads#payload-cap)
  — so a larger body did not come from GitHub whatever signature it carries, and
  there is no signature worth the CPU to check.

  The ceiling is enforced twice, and neither half is redundant. A declared
  `Content-Length` over the cap is refused on the header alone, ahead of the
  rate limiter, because that costs one header read and the limiter costs a
  Durable Object round trip. The read then counts the octets that actually
  arrive and stops at the first chunk past the ceiling, because the header is
  written by the party whose body is in question and understating it is one line
  of client code. Both answer identically, so nothing reveals which one fired.

### Not yet: replay

A correctly signed delivery can be replayed indefinitely — nothing dedupes
`X-GitHub-Delivery`. That is harmless while the handler acts on nothing, and it
is a **prerequisite for the first handler that acts**: a `push` handler that
re-signs on every replay is exactly the second, weaker front door this design is
built to avoid. Whatever ships first has to bring delivery-id deduplication with
it.

## Talking to GitHub

`src/utils/github-app.ts` mints an App JWT and trades it for an installation
token.

- **The destination is pinned.** Everything goes to `api.github.com`, and
  `githubApiUrl` asserts the resolved origin rather than calling `validateUrl`.
  That guard exists to sift _caller-controlled_ URLs for private address space,
  and it answers the wrong question when the hostname is a constant — it would
  pass `https://api.github.com.evil.example` and every other public host.
- **Installation ids are validated before use.** A positive safe integer or
  nothing, because the value arrives inside a webhook payload and is
  interpolated into a URL path.
- **Cached tokens outlive nothing.** The KV entry's TTL is derived from GitHub's
  own `expires_at` with a five-minute margin subtracted, under
  `gh-app:<appId>:installation:<id>` — namespaced away from the `jwks:` entries
  sharing that namespace, and keyed by App id so that re-registering the App
  after a leak does not serve tokens the old one minted.
- **Nothing secret is logged.** The private key, the App JWT and the
  installation token never reach a log line, an error message or a response
  body; an error from this path carries an installation id and an HTTP status.
  Both new secrets are also in the Sentry scrubber's literal-value list.

## Audit records

There are none, and that is deliberate. `audit_logs` records operations on keys
and credentials; a row per acknowledged-and-discarded delivery would be a D1
write per event nothing acted on. Deliveries are logged at info instead. When a
handler starts acting on an event, the _action_ is what earns an audit record —
and that will need a new `AuditAction` value and the migration to widen the
table's `CHECK` constraint, alongside the delivery-id deduplication noted above.

## Not in the OpenAPI document

`POST /github/webhook` is registered with plain `app.post` rather than through
the OpenAPI router, for the same reason `/e/:code` is: the document exists to
generate clients, and the only caller of this route is GitHub, which does not
read it. Declaring it would put a method on the Go client — and on every other
generated one — for a caller that will never invoke it, and would require this
repository to publish a schema for a payload it does not model.
