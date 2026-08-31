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
| Signing key binding    | One key per grant, from the same allowlist entry, or none     |
| Delivery semantics     | At-most-once: a claimed id is never released, even on failure |
| App JWT minting        | RS256, from `GITHUB_APP_PRIVATE_KEY`                          |
| Installation tokens    | Minted on demand, cached in KV under a namespaced key         |

## What does not

Named in [#26](https://github.com/kjanat/gpg-signing-service/issues/26) and
deliberately absent: auto-signing pushed commits, publishing a "GPG verified"
check run, and dispatching `@claude`. Each of those is a handler that _acts_,
and before one can be written the at-most-once question in
[Claimed before the handler runs](#claimed-before-the-handler-runs-at-most-once-not-at-least-once)
has to be answered for the action it performs. `getInstallationToken` and
`loadSigningKey` both have no caller in the request path for the same reason:
they are what an acting handler will use, shipped ahead of it so it inherits
their refusals rather than inventing its own.

What is here is everything that has to be right _before_ any of that can be
written: the trust boundary, the credential exchange, and the three checks
between "this delivery is genuine" and "this delivery may cause something" —
[authorization](#repository-and-installation-authorization),
[replay protection](#replay-protection) and
[which key it may sign with](#which-key-a-delivery-may-sign-with).

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

# Which <installation, repository> pairs a delivery may be about, and which
# key each of them may cause to sign with. The `=<keyId>` suffix is optional;
# without it the repository's events are received and may sign nothing.
GITHUB_APP_ALLOWED_REPOSITORIES = "12345678:kjanat/gpg-signing-service=62E75E54497815DD"
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
  "signingKey": false,
  "duplicate": false,
  "handled": false
}
```

`handled` is always `false` while this is a scaffold. `scope` is what the
allowlist granted this delivery — `none` for the App-level ping, which names
neither an installation nor a repository. `signingKey` says whether the matched
grant binds a key, not which one; the id itself is in the delivery's log line
rather than in the response, because the sender has no use for it. `duplicate`
marks a delivery id that was already claimed; redeliver the same event from the
Advanced tab and the second answer is `200` with `"duplicate": true`.

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
| `500`  | `SERVICE_MISCONFIGURED`  | Enabled, but `GITHUB_WEBHOOK_SECRET` is unset or the allowlist is unusable.  |
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

## Which key a delivery may sign with

Authorization says a delivery may be _about_ `owner/repo`. It does not say the
service will sign anything for it, and those are different grants: a repository
can be allowlisted so its events are received without being allowed to make a
signing service sign.

So an entry may bind exactly one key, in the same string:

```toml
GITHUB_APP_ALLOWED_REPOSITORIES = "12345678:kjanat/gpg-signing-service=62E75E54497815DD, 12345678:kjanat/tools"
```

`gpg-signing-service` may cause `62E75E54497815DD` to sign. `tools` may cause
nothing to sign; its deliveries are still received, authorized and logged.

### Why the key is in the entry and not in its own variable

A second variable is a second list, and two lists have to be kept in step by
hand. Anything that can drift can drift _open_ — a key entry for a pair nobody
authorized, or a pair whose authorization was edited and whose key entry was
not. With one entry there is nothing to reconcile, because there is only ever
one string to read, and the atomic unit of configuration is the whole grant:
installation, repository, key.

It is the same argument as [why the entries are pairs](#why-the-entries-are-pairs),
applied once more. Independent lists authorize combinations nobody wrote.

### There is no default key

Not `KEY_ID`, not the only key in storage, not the last key uploaded. A pair
with no `=<keyId>` suffix may not cause a signature, full stop.

`KEY_ID` is the default for `POST /sign`, and that is a different situation: a
caller there has authenticated with OIDC or a service token and had _its own_
key grant checked before the default is reached. A webhook delivery is a
different caller with a different grant, and letting it inherit the API's
default would mean every allowlisted repository silently acquired authority over
the service's own key the moment it was allowlisted.

The shape that would do it is `authorization.keyId ?? env.KEY_ID` — one
operator, one afternoon, one `??`. Which is why the nullable field is not the
interface: `requireSigningKey` in `src/utils/github-signing-key.ts` returns
either a key id or a reason, and the three situations in which there is no key —
a `none`-scope ping, an `installation`-scope event, and a `repository`-scope
pair with nothing bound — are refusals rather than a null a caller has to
remember to handle.

### The key comes from the entry, never from the payload

Same rule as the repository, and for the same reason. No function involved in
resolving a key takes a payload argument at all, so a delivery cannot name a key
it would like used, cannot add one at a level someone might later read, and
cannot widen the one its own grant gave it. A delivery that names a _different_
repository matches a different entry, or none — it does not borrow the key of
the one it was checked against.

### Canonicalisation

Key ids are 16 hexadecimal characters. Comparison and storage use the
upper-case spelling — `KeyIdSchema` normalises on the way in, so that is what
`KeyStorage` keys its records by — and an entry is normalised to match. An
operator who pastes `62e75e54497815dd` gets the key they meant rather than a
lookup that misses.

Repositories are matched case-insensitively, as before, and the key rides along
with whatever spelling the operator used for the pair.

### Fail closed, in every direction

- **An unusable key refuses the whole allowlist**, the same `500` a malformed
  pair produces. Not "drop the suffix and keep the pair": that turns a typo into
  a repository that is still authorized to receive deliveries and has quietly
  lost the binding an operator wrote, which is a policy change made by a
  keystroke. `=` with nothing after it is refused for the same reason — it is a
  binding someone started writing.
- **A pair may appear at most once.** A repeated pair refuses the whole list
  _even when the two entries agree_, because resolution takes the first match:
  a second entry is either dead configuration or a second opinion about which
  key a repository may use that nobody will notice being ignored. Compared
  case-insensitively, so the conflict cannot be hidden by spelling the
  repository differently the second time. One repository under two different
  installations is not a duplicate — the pair is the unit — and may bind two
  different keys.
- **A key id that is not shaped like one is refused at the point of use too**,
  not only at parse time. The value crosses a context boundary as a plain
  string, and re-checking is what lets the resolved id be a branded `KeyId`
  rather than a cast into a URL path.
- **A bound key this deployment does not hold is a refusal**, distinct from a
  key store that could not be reached. Different problems, different fixes: one
  is an allowlist to edit, the other is an outage to wait out, and collapsing
  them sends an operator to change configuration that is correct.

### Where key existence is checked

Not at parse time, and not as a pre-check. The allowlist is parsed per request,
so validating existence there would put a `KeyStorage` round trip in front of
every delivery — including the ones that were never going to sign, which today
is all of them — to answer a question that goes stale the moment a key is
deleted. The obvious repair for that cost is a cache, and a cache of "this key
exists" is a cache whose stale entries point at a key that is gone.

A pre-check immediately before use is no better: a separate "does it exist"
fetch followed by a "give me the key" fetch is two round trips with a window
between them, so the check establishes nothing the use does not and the code
still has to handle the missing key at the point of use.

So existence is established by **the fetch the signing action has to perform
anyway**. `loadSigningKey` resolves the binding and reads the key in one go, and
answers with the key or with `key_missing` / `key_storage_unavailable`. No
separate check, therefore no cache, no staleness and no window — the same
boundary `POST /sign` already uses.

### What is logged

An accepted delivery's log line carries the bound key id, and the reason when
there is none — `no_key_bound` is the one worth watching for, because it means
an allowlisted repository is missing its suffix and would be refused the moment
a handler tried to sign for it. A key id is not a secret: `/public-key` serves
the key it names. It is logged rather than returned because the sender has no
use for it, and both the id and the repository come from the matched entry, so
a log line cannot be made to name a key nobody granted.

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

### Claimed before the handler runs: at-most-once, not at-least-once

The id is claimed by the middleware and then `next()` is called, and **the claim
is never released**. So the delivery is consumed the instant it is accepted,
before any handler behind the guard has done anything, and it stays consumed
however that handler ends.

While the scaffold acts on nothing this costs nothing. The moment a handler
does act, it is a real trade and it points the wrong way from what the GitHub UI
suggests:

1. The handler acts, and fails partway through.
2. The service answers `5xx`, so GitHub marks the delivery failed and the
   operator sees a red row in **Recent Deliveries**.
3. They press **Redeliver** — the one recovery affordance this design is built
   around.
4. They get `200 {"duplicate": true}`. The event is never processed, and the
   answer looks like success.

That is **at-most-once** delivery: an event is acted on no more than once, and
possibly not at all. It is a deliberate choice for a signing service — acting
twice is worse than not acting — but it is the opposite of what a red delivery
row leads an operator to expect, and nothing about it is visible from the
response.

**A hard prerequisite for the first acting handler.** A handler that assumes a
failure can be recovered by redelivering is assuming semantics this ledger does
not provide, and it will be wrong quietly. Before one lands, this has to be
resolved one of these ways, in writing:

- **Make the handler's own action idempotent and recoverable from GitHub's
  state**, so a lost event is repaired by the next one rather than by a repeat
  of this one. Then at-most-once is simply correct and nothing changes.
- **Two-phase the ledger**: `reserve` under `blockConcurrencyWhile`, which is
  what keeps twelve simultaneous copies to one winner, and `commit` only after
  the handler succeeds; a reservation that is never committed expires in
  seconds. This keeps the concurrency property and makes a redelivery after a
  crash behave the way the operator expects.
- **Release on `5xx`**: delete the record when the handler produces a server
  error. Simpler, and strictly weaker — a handler that half-acted and then threw
  becomes replayable — but it does not reopen the concurrency window.

Not decided here, because the choice depends on what the first handler actually
does, and a scaffold that acts on nothing cannot make it well. What is decided
here is that it must be chosen deliberately rather than discovered in
production.

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
