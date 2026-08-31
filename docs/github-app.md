# GitHub App webhook

An opt-in endpoint that lets a GitHub App deliver events to this service.

**It acts on nothing.** Every verified delivery is acknowledged and discarded.
What is here is the trust boundary, the credential exchange, and the two checks
that have to stand between "this delivery is genuine" and "this delivery may
cause something" — shipped before anything that uses them, because those are the
parts that are hard to get right and easy to get wrong quietly.

Off by default. A deployment that has not opted in answers `POST
/github/webhook` exactly the way it answers any path it does not route, so
shipping this code does not advertise the feature.

## What works today

|                        |                                                               |
| ---------------------- | ------------------------------------------------------------- |
| `POST /github/webhook` | Verifies `X-Hub-Signature-256` and answers `202 Accepted`     |
| Authorization          | `<installation, repository>` pairs from an operator allowlist |
| Replay protection      | `X-GitHub-Delivery` claimed once, atomically, for four days   |
| App JWT minting        | RS256, from `GITHUB_APP_PRIVATE_KEY`                          |
| Installation tokens    | Minted on demand, cached in KV under a namespaced key         |

## What does not

Named in [#26](https://github.com/kjanat/gpg-signing-service/issues/26) and
deliberately absent: auto-signing pushed commits, publishing a "GPG verified"
check run, and dispatching `@claude`. What each still needs is the mapping from
an authorized repository to a _signing key_ — which key an installation may
cause to sign with — and inventing that inside a webhook handler is how a
signing service acquires a second, weaker front door. `getInstallationToken` has
no caller in the request path for the same reason.

What is here is everything that has to be right _before_ any of that can be
written: the trust boundary, the credential exchange, and the two checks
between "this delivery is genuine" and "this delivery may cause something" —
[authorization](#repository-and-installation-authorization) and
[replay protection](#replay-protection).

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

# Which <installation, repository> pairs a delivery may be about.
GITHUB_APP_ALLOWED_REPOSITORIES = "12345678:kjanat/gpg-signing-service"
```

The installation id is in the URL of the App's "Configure" page for that
account: `.../settings/installations/12345678`. It is also the `installation.id`
in any delivery the App makes, which the `ping` in step 4 will show you.

Leaving `GITHUB_APP_ALLOWED_REPOSITORIES` unset is a valid state and grants
nothing — the `ping` below still answers, so you can check the endpoint before
you have the installation id to write here.

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
  "scope": "none",
  "duplicate": false,
  "handled": false
}
```

`handled` is always `false` while this is a scaffold. `scope` is what the
allowlist granted this delivery — `none` for the App-level ping, which names
neither an installation nor a repository. `duplicate` marks a delivery id that
was already claimed; redeliver the same event from the Advanced tab and the
second answer is `200` with `"duplicate": true`.

## What each answer means

| Status | Code                     | Meaning                                                                      |
| ------ | ------------------------ | ---------------------------------------------------------------------------- |
| `202`  | —                        | Verified and authorized. Acknowledged, not acted upon.                       |
| `200`  | —                        | A delivery id already claimed. Acknowledged again, not acted upon again.     |
| `400`  | `INVALID_REQUEST`        | Signature verified; body was not JSON, or `X-GitHub-Delivery` is unusable.   |
| `401`  | `AUTH_MISSING`           | No `X-Hub-Signature-256`. The App has no webhook secret set.                 |
| `401`  | `AUTH_INVALID`           | The signature did not verify. The two secrets differ.                        |
| `401`  | `AUTH_SUBJECT_UNTRUSTED` | Verified, and the pair it names is not in `GITHUB_APP_ALLOWED_REPOSITORIES`. |
| `404`  | `NOT_FOUND`              | `GITHUB_APP_ENABLED` is not `"true"`.                                        |
| `413`  | `PAYLOAD_TOO_LARGE`      | Body over GitHub's 25 MiB cap. It was not read.                              |
| `429`  | `RATE_LIMITED`           | Too many deliveries from this address. Not retried by GitHub.                |
| `500`  | `SERVICE_MISCONFIGURED`  | Enabled, but `GITHUB_WEBHOOK_SECRET` is unset or the allowlist is malformed. |
| `503`  | `SERVICE_DEGRADED`       | The delivery ledger could not be reached, so replay could not be ruled out.  |

`AUTH_SUBJECT_UNTRUSTED` rather than `AUTH_INVALID` for an unauthorized pair,
and it is the same distinction the OIDC path draws: the credential is right and
the subject holds no grant, so the fix is to the allowlist and never to the
webhook secret. A caller that reads it as a credential fault rotates a secret
that is working exactly as provisioned.

The 404 is byte-identical to the one an unrouted path returns, on purpose: a
distinguishable answer would let anyone enumerate which deployments have the
integration configured. The 500 is deliberately _not_ hidden that way — an
operator who opted in and cannot receive deliveries needs to be able to tell
that apart from a deployment that never opted in, or the integration silently
receives nothing.

## How it is protected

The webhook URL is public by construction: it is typed into a settings form and
then reachable by anyone who guesses it. The HMAC is the only thing that makes a
request GitHub's — everything below it in this section rests on the HMAC being
right, and the two sections after it are about what a correct signature still
does not establish.

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

## Repository and installation authorization

A valid signature proves the **sender**. It says nothing about the **subject**.

One App has one webhook secret and as many installations as accept it, so a
delivery about a repository this deployment has no business touching carries
exactly the same valid HMAC as one about the repository it was set up for. On a
service whose purpose is to sign things, treating "authenticated" and
"authorized to make me sign for this repo" as one check is how a webhook secret
becomes authority over every repository the App is installed on.

So there is a second gate, against a list only an operator can write:

```toml
GITHUB_APP_ALLOWED_REPOSITORIES = "12345678:kjanat/gpg-signing-service, 12345678:kjanat/tools"
```

### Why the entries are pairs

Not two lists — allowed installations, allowed repositories — because two lists
authorize every _combination_ of their members, and most of those combinations
are grants nobody wrote. Installation A, which legitimately holds the App's
secret, could name repository R belonging to installation B and be waved through
by a repository list that never meant to give A anything. One entry binds the
two, so a repository is only ever authorized under the installation an operator
paired it with.

### What each delivery gets

| The delivery names                         | Scope          | May act on                |
| ------------------------------------------ | -------------- | ------------------------- |
| A pair on the list                         | `repository`   | That repository           |
| An installation on the list, no repository | `installation` | Nothing repository-shaped |
| Neither (the App-level `ping`)             | `none`         | Nothing                   |
| Anything else                              | —              | Refused, `401`            |

`ping` is accepted with no allowlist configured so that setup is checkable
before policy is written. It authorizes exactly what it names, which is nothing.

### Fail closed, in every direction

Each of these has an appealing permissive reading, and takes the strict one:

- **An unset or empty list grants nothing.** A missing policy is an empty
  policy, not an absent gate.
- **A malformed entry refuses every delivery** — a `500`, not a partial
  application of the entries that parsed. A typo must not silently drop a grant
  and must certainly not silently widen one. The offending entry is named in the
  log, never in the response.
- **An `installation` object whose id cannot be read is refused**, not treated
  as "no installation". The permissive reading accepts a delivery that was
  claiming an installation.
- **A `repository` object with no usable `full_name` is refused**, and so is a
  repository named without an installation to scope it to.
- **Comparison is case-insensitive**, because GitHub names are
  case-insensitive for uniqueness and `Kjanat/Repo` is not a second repository.

### The repository a handler acts on comes from the allowlist

The authorization decision carries the repository as **the operator's spelling**
from the matched entry, not the payload's. A handler reading
`payload.repository.full_name` would be back to letting the delivery name its
own subject, one layer further in — and doing so having passed a check, which is
worse than having no check. Taking it from the decision makes the safe path the
short one.

## Replay protection

A webhook signature covers the body and nothing else: no timestamp, no nonce, no
expiry. **A delivery that verified once verifies forever.** GitHub's own
"Redeliver" button does exactly that on purpose, and so can anyone who obtains a
copy of the bytes.

The only thing separating a repeat from a fresh event is `X-GitHub-Delivery`,
the GUID identifying the event, which a redelivery reuses. So the service
remembers the ids it has accepted and answers the second arrival without acting.

### Atomic, because the interesting case is simultaneous

Two copies of one delivery arriving at the same instant is what a double-click
on "Redeliver" produces and what an attacker sends deliberately. A
check-then-write across two round trips lets both observe "not seen" and both
proceed.

The ledger is a Durable Object — KV cannot do this at all, being eventually
consistent with no compare-and-set — and the read-modify-write runs inside
`blockConcurrencyWhile`, so the guarantee is stated in the code rather than
argued from the runtime's input-gate semantics. Twelve concurrent claims of one
id produce exactly one winner, and there is a test that says so.

### Bounded by GitHub's own redelivery window

Ids are retained for **four days**: [GitHub lists deliveries from the past
3 days](https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/viewing-webhook-deliveries)
and that listing _is_ the redelivery affordance, so three days is the window in
which a legitimate repeat can occur, plus a day for clock skew and the boundary
itself. Expiry is decided by each record's own timestamp, so a late sweep can
waste storage but never a refusal.

Stated plainly rather than buried: **an attacker who captured a delivery can
replay it successfully once the retention expires.** No TTL-based deduplication
can prevent that, because the signature carries no timestamp to age against and
this service cannot distinguish a five-day-old capture from a fresh delivery.
Bounding it to GitHub's own window covers every repeat GitHub itself can cause;
a handler whose action is destructive rather than idempotent needs a second
control — the event's own state, checked against GitHub — and not a longer TTL.

### Claimed last, and that is the security property

The claim is taken **after** the HMAC and **after** authorization, not between
them. Claiming an id is one-way: whoever claims it first makes every later
arrival of that id a no-op. A request that could consume an id before proving
both its origin and its grant could burn the id of a delivery it is not allowed
to cause, and so suppress the real one — which turns replay protection into a
denial-of-service primitive pointed at exactly the events it was built to
protect.

So an unsigned request, a wrongly signed one, one the allowlist refuses, one
over the payload ceiling, and one arriving at a deployment with the feature off
all leave the id unclaimed. Each is asserted by afterwards presenting the same
id as a legitimate delivery and requiring it to be accepted as a first arrival.

### A missing id is refused, not defaulted

A placeholder for a delivery with no `X-GitHub-Delivery` would be a _shared_
key: every id-less delivery would dedupe against every other, so the first one
claimed would silently suppress the rest — and one signed request with no id
does that on purpose. An id must be 8 to 200 characters of `[A-Za-z0-9._-]`,
starting with an alphanumeric. GitHub sends a GUID; the bound is wider than that
so a change in GitHub's id scheme is not an outage, and far narrower than "any
string" because the value becomes a storage key.

### If the ledger cannot be reached

The delivery is refused with `503`, like every other dependency on this path. A
claim that did not happen is not a claim, and reading an unreachable ledger as
"not seen before" removes the protection exactly when nothing can check it. That
costs the event, because GitHub does not redeliver on its own — redeliver it
by hand from the Advanced tab.

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
write per event nothing acted on. Deliveries are logged at info instead, with
the _authorized_ repository rather than the payload's, so a log line cannot be
made to name a repository nobody granted. When a handler starts acting on an
event, the _action_ is what earns an audit record — and that will need a new
`AuditAction` value and the migration to widen the table's `CHECK` constraint.

## Not in the OpenAPI document

`POST /github/webhook` is registered with plain `app.post` rather than through
the OpenAPI router, for the same reason `/e/:code` is: the document exists to
generate clients, and the only caller of this route is GitHub, which does not
read it. Declaring it would put a method on the Go client — and on every other
generated one — for a caller that will never invoke it, and would require this
repository to publish a schema for a payload it does not model.
