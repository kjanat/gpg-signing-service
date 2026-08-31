# GitHub App webhook

An opt-in endpoint that lets a GitHub App deliver events to this service.

**Two events are acted on.** A `push` to an allowlisted repository whose grant
binds a signing key has the unsigned commits at its tip signed with that key,
and the branch moved to them. A deployment that opts into it separately also
publishes a check run saying what the resulting head's signature turned out to
be. An `issue_comment` invoking `@claude` — separately opt-in again — starts the
configured Claude workflow, once the comment's **author** has been shown to hold
write access to that repository. Every other event is acknowledged and
discarded.

Off by default, twice over. A deployment that has not set
`GITHUB_APP_ENABLED="true"` answers `POST /github/webhook` exactly the way it
answers any path it does not route, so shipping this code does not advertise the
feature — and a repository whose allowlist entry carries no `=<keyId>` suffix
receives its events and signs nothing. **Receiving events and causing signatures
are separate grants, and the key suffix is the opt-in for the second one.**

## What works today

|                        |                                                                          |
| ---------------------- | ------------------------------------------------------------------------ |
| `POST /github/webhook` | Verifies `X-Hub-Signature-256` and answers `202`, or `200` on a sign     |
| Authorization          | `<installation, repository>` pairs from an operator allowlist            |
| Replay protection      | `X-GitHub-Delivery` reserved once atomically, committed on action        |
| Signing key binding    | One key per grant, from the same allowlist entry, or none                |
| Delivery semantics     | Two-phase: released when nothing was published, else at-most-once        |
| `push` auto-signing    | The unsigned run at the tip, signed and force-updated                    |
| Signing budget         | Per `<installation, repository, key>`, one token per signature           |
| Signature check runs   | Opt-in: one converging check run per commit, off `GITHUB_APP_CHECK_RUNS` |
| Audit                  | One `push_sign` row per attempt that got as far as trying                |
|                        | One `check_report` row per check run published or attempted              |
| App JWT minting        | RS256, from `GITHUB_APP_PRIVATE_KEY`                                     |
| Installation tokens    | Minted on demand, cached in KV under a namespaced key                    |

## What does not

Only conversation comments dispatch. `pull_request_review_comment`,
`pull_request_review` and `issues` still reach the workflow through GitHub's own
Actions triggers; those three are not subscribed here and nothing about them
changed.

Absent, and more likely to surprise: **an unsigned commit underneath a signed
one is never signed.** See
[Only the unsigned run at the tip](#only-the-unsigned-run-at-the-tip).

## Signing commits on push

The whole operation, in the order it happens:

1. **Read** the branch the delivery names — from `payload.ref`, and then asked
   of GitHub, so the commit acted on is the one the repository holds rather than
   the one `payload.after` claims it holds.
2. **Walk** back from that head collecting unsigned commits, stopping at the
   first one that carries a signature, at a root commit, or at 20.
3. **Spend** one token per commit from the repository's signing budget.
4. **Sign** each commit payload and **create** each commit object, checking
   GitHub's returned object id against one computed locally.
5. **Re-read** the branch, require it to be where step 1 found it, and **move**
   it.

Steps 1–4 change nothing anyone can observe: a signature exists only in memory,
and a commit object no ref points at is unreachable and collected. Step 5 is the
one a person sees.

### Only the unsigned run at the tip

Replacing a commit changes its object id, which changes its children's ids,
which invalidates any signature those children carry. So the set this service
may touch is exactly the unsigned commits at the tip, and the walk stops at the
first signature — whoever made it.

The consequence is worth stating plainly rather than discovering: **an unsigned
commit below a signed one stays unsigned, forever.** The alternative is
destroying a signature somebody else made, which is not a trade this service
makes on its own.

A run longer than 20 commits is refused rather than rewritten. A push of two
hundred unsigned commits is a history event that wants a person looking at it.

Merges keep their shape: the walk follows first parents only, so a merge
commit's other parents are not rewritten and keep their ids and signatures.

### How the loop stops

Moving the branch raises another `push` delivery, for a head this service just
signed. The walk sees a signature immediately, the run is empty, and the plan is
`nothing_to_sign`.

The suppression is **the state of the object graph**, not a guess about who
pushed. `sender`, `pusher` and the event name are all fields in a document the
sender controls; a signature on the head commit is a fact about the repository.
A loop stopped by the second one stops whether or not the first says what was
expected.

### Why the object id is checked against GitHub's

GitHub's create-a-commit endpoint takes a `signature` and inserts it into the
object as the `gpgsig` header. It does not tell you what payload it assembled.
If its assembly differs from ours by one byte — a date offset normalised, a
header we did not model — the signature is over a different object than the one
that now exists, and the result is a commit that says it is signed and verifies
as broken. Nothing in the response announces that.

The object id does. The SHA-1 of the signed object is a total check on the whole
payload: equal ids mean identical bytes, and there is no way for them to be
equal and the signature to be wrong. The comparison happens **before** the ref
moves, so a mismatch costs a dangling object nobody can reach.

That check is only worth having if the two sides can actually disagree, which is
why the timezone offset below is recovered rather than echoed: while both sides
started from GitHub's already-normalised `Z`, they agreed on the same wrong
answer and the check could not see it.

### The timezone offset is recovered, not read

A commit object stores `<epoch> <±HHMM>` and the offset is part of the object —
change it and the commit gets a different id. **GitHub's API does not report
it.** `GET /git/commits/{sha}` renders both dates in UTC for a commit whose
object says `+0200`, and so does `GET /commits/{sha}`, and so does GraphQL's
`GitTimestamp` despite its schema documentation saying otherwise. A rewrite that
echoed that string back would quietly relocate every commit made outside UTC —
which is most commits made on a laptop — and `git log` would show a different
local time than the author committed at.

So the offset is worked out and then **proven**: the original object is
reconstructed under candidate offsets and the one whose SHA-1 equals the sha the
commit already has is kept. That sha was computed by Git over the real bytes, so
a match is proof rather than a guess, and it settles a second ambiguity with
it — the API also strips a trailing newline from the message, and only one of
the two variants can reproduce the id.

Both halves of that proof are carried forward, because they were proven
together: the reconstruction returns the offsets **and** the message
representation that matched, and it is that message which gets signed and handed
back to create-a-commit. Keeping only the offsets would rewrite every
`git commit`-made commit — they all end in a newline — into one whose message is
a byte shorter, and the object-id check could not see it either, both sides
having started from the same stripped string. GitHub stores the trailing newline
it is given; it is only the read path that strips it.

Author and committer offsets are searched together first, since a commit whose
two differ is the exception. When that fails, the **patch representation**
(`Accept: application/vnd.github.patch`) is fetched, because its RFC 2822
`Date:` header is the one rendering GitHub still shows the offset in; that pins
the author's, and the committer's is searched alone. A commit that nothing
reproduces is refused as `unreproducible_commit` rather than rewritten
approximately.

Going back out, the recovered offset is rendered into the ISO 8601 that
create-a-commit takes, and GitHub stores the offset it is given — verified
against the live API with an author at `+0545` and a committer at `-0330`, both
preserved in the created object. Which is what finally puts the object-id check
on both sides of a real disagreement.

### The signing budget

The rate limiter in front of the whole route counts **requests per source
address**. That is not a signing budget: one request can carry twenty
signatures, and what needs bounding is a repository's authority to cause them.

So there is a second meter, keyed
`github-push:<installation>:<owner>/<repo>:<keyId>` — every component from the
authorization decision, so a delivery cannot move itself into a fresh bucket by
varying a payload field — spending one token per signature, 120 a minute. A
refusal happens before the first signature, so it costs a read and nothing else,
and the delivery stays redeliverable.

### What is recorded

One `audit_logs` row per attempt that got as far as trying, `action =
push_sign`, `issuer = github-app`, `subject` the **authorized** repository and
`key_id` the bound key. The metadata carries the branch, the commit count and
the two head shas, or a failure reason.

Nothing secret rides along: no signature, no installation token, no key
material, and no GitHub response body.

## Reporting the signature as a check run

Off by default and switched on separately from the rest of the integration:

```toml
GITHUB_APP_CHECK_RUNS = "true"
```

With it on, every `push` this service handles for a repository whose grant binds
a key ends by publishing one check run — named `GPG signature`, attached to the
commit the branch actually points at — saying what that commit's signature turned
out to be.

### Why it needs a flag of its own

It is the one part of this integration that needs a permission the rest does
not: **`Checks: Read and write`**. That is a permission an installation has to
_approve_ after it is added to the App, so folding it into `GITHUB_APP_ENABLED`
would mean every deployment that upgraded started calling an endpoint its
installation had not granted, and answering `403` on each delivery.

With the flag unset, the reporter makes **no GitHub call at all** and push
signing behaves exactly as it does without this feature.

### And why it needs no new subscribed event

`push` is enough. A pull request's head branch lives in a repository, pushes to
it raise `push` there, and a check run is attached to a _commit_ — which is what
a pull request displays. Subscribing to `pull_request` as well would widen the
payload surface this service accepts to gain nothing it does not already have.

The consequence, stated plainly: **a pull request from a fork gets no check.**
Its commits are pushed to the fork, the App is not installed there, and the
allowlist pairs an installation with a repository. That is the same boundary
push signing has.

### The five states, and what each one claims

The sha is read back from the ref, never taken from `payload.after`. GitHub's
`verification.payload` and `verification.signature` for that commit are folded
back into a commit object and hashed; the result must equal the sha, which is
what makes the verdict a statement about _this commit_ rather than about bytes
an API reported. Then the signature is verified here, against the public half of
the key the allowlist bound.

| State               | Conclusion | What it says                                                                 |
| ------------------- | ---------- | ---------------------------------------------------------------------------- |
| `service_key_valid` | `success`  | An OpenPGP signature by the bound key, verified here over the commit's bytes |
| `invalid_signature` | `failure`  | A signature _naming the bound key_ that does not verify under it             |
| `other_signer`      | `neutral`  | Signed by somebody else. **No claim** about whether that signature is good   |
| `unsigned`          | `neutral`  | No signature at all                                                          |
| `unverifiable`      | `neutral`  | The reported bytes could not be tied to the commit, so nothing was shown     |

`failure` is reserved for the one state that is an accusation. An unsigned
commit is not a failure here — [an unsigned commit beneath a signed one is never
signed](#only-the-unsigned-run-at-the-tip), so failing it would be a permanent
red mark on a state this service declines to fix — and somebody else's signature
is somebody else's business. A branch protection rule that requires this check
should be written knowing that only `invalid_signature` fails it.

Two details worth knowing:

- **Attribution is to the key's own ids, primary and subkeys.** An OpenPGP key
  signs with its signing subkey, whose id is not the primary's, and a
  GnuPG-generated key almost always has one. Comparing against the allowlist's
  16 hex digits instead would report this service's own signatures as somebody
  else's.
- **A signature is judged as of when it was made.** Verifying at read time would
  flip every historical commit to `invalid_signature` on the day a key expires —
  an accusation of forgery about commits this service signed correctly.

`unverifiable` has a real cost, named rather than hidden: a commit whose object
carries a header this service does not model — a `mergetag`, most realistically
— will not fold back, and lands there with a perfectly good signature. It is the
right direction to be wrong in.

GitHub's own `verification` verdict is repeated in the check's summary, labelled
as GitHub's, and only after its `reason` has been matched against the documented
set. A value outside that set is shown as `unknown`: the summary is text this
service publishes under its own name, and a remote API does not get to choose
it.

### Retry and idempotency: converging, not at-most-once

A check run is **not** protected by the [delivery ledger](#replay-protection), and that is deliberate. Signing rewrites history,
so it is guarded by a one-way claim. A check run _states what is already true of
a commit_, so the same report published twice has to converge rather than be
prevented.

Both halves of a check's address are fixed before anything is written — the
name is a constant, and the sha was read back from the ref — so the write is a
**lookup, then update or create**:

1. List this App's check runs named `GPG signature` on that sha.
2. If one exists, update the earliest. Otherwise create one.

Which makes each of these safe:

| Situation                                      | What happens                                          |
| ---------------------------------------------- | ----------------------------------------------------- |
| The delivery is redelivered                    | The ledger answers it first; nothing is written       |
| A second delivery names the same head          | The existing run is updated                           |
| A create succeeded and the response was lost   | The next attempt finds that run and updates it        |
| Another app publishes a run with the same name | Ours is created beside it; theirs is never touched    |
| The report fails for any reason                | The signing outcome stands; the delivery is unchanged |

**The point after which replay is idempotent rather than suppressed is the
create.** Everything before it is a read. After it, the run exists, and every
later report — from a redelivery, a retry, or a fresh event about the same
commit — lands on that same run.

The residual, since GitHub's Checks API has no conditional create: two reports
for the _identical_ sha that are both in flight through the lookup can both
create a run. Nothing available over this API closes that window. What closes it
afterwards is the ordering rule — the runs are sorted by id and the **earliest**
is the one updated — so every later report converges on the same one rather than
alternating between them.

### It cannot change what the signing path did

A reporting failure is recorded and nothing more. It does not touch the
delivery's retryability, so a `403` from an installation that has not granted
`Checks: Read and write` cannot make a completed signing push redeliverable —
and cannot turn a signed branch into a `500`.

### What is recorded

One `audit_logs` row per report, `action = check_report`, `issuer =
github-app`, `subject` the **authorized** repository and `key_id` the bound key.
The metadata carries the sha, the state, the conclusion, the check run id and
whether it was created or updated — or a failure reason.

Nothing secret rides along: no signature, no installation token, no key
material, and no GitHub response body. The states and reasons are values from
closed sets in this repository, not text from an API response.

## Dispatching `@claude` from a comment

A comment on an issue or a pull request that invokes `@claude` used to start the
Claude workflow through GitHub's own `issue_comment` Actions trigger. It now
arrives here first: this service authenticates the delivery, authorizes the
repository, authorizes **the person who wrote the comment**, spends a budget,
claims the delivery id, and dispatches the workflow.

Off by default, and off separately from everything else:

```toml
GITHUB_APP_COMMENT_DISPATCH  = "true"
GITHUB_APP_DISPATCH_WORKFLOW = "claude.yml"
GITHUB_APP_DISPATCH_REF      = "master"
```

Unset — which is the shipped default — an `issue_comment` delivery is
acknowledged and dropped, and **no GitHub call is made at all**, not even the
permission lookup.

### An allowlisted repository is not an allowlisted commenter

This is the whole reason the slice exists. `githubWebhookAuthorize` establishes
that a delivery is about an `<installation, repository>` pair an operator wrote
down. It says nothing about who wrote the comment — and comments on a public
repository are written by anyone at all, arriving under the same installation,
about the same repository, with the same valid HMAC as the owner's.

So the author is authorized separately, against GitHub:

```http
GET /repos/{owner}/{repo}/collaborators/{login}/permission
```

and must come back `admin` or `write`. That field is GitHub's _legacy base
role_, which is deliberately the one to read: it collapses `maintain` into
`write`, `triage` into `read`, and every custom role onto whichever base role it
was built from — a closed set of four values with a defined meaning.
`role_name` is open-ended, and a check written against it would be a check
against strings an organisation admin can invent.

**`author_association` is not the check.** It reports `COLLABORATOR` for a
read-only collaborator, which is precisely the account that has to be excluded.

Everything that is not an unambiguous grant refuses:

| Answer                              | Result                                   |
| ----------------------------------- | ---------------------------------------- |
| `admin`, `write`                    | Dispatched                               |
| `read`, `none`                      | `actor_not_permitted`, nothing started   |
| `404` (not a collaborator)          | `actor_not_permitted`, nothing started   |
| `403`, `5xx`, a timeout             | `permission_lookup_failed`, fails closed |
| An answer about a _different_ login | `permission_lookup_failed`, fails closed |

The last row is worth naming: the login that comes back is compared against the
one that was asked about. An answer about somebody else is not an answer, and
taking it would authorize this comment with another account's access.

### Nothing here may become a loop

The session this starts finishes by writing a comment on the same issue, and
quoting the request it answered is the obvious thing for it to do. So the check
is on the identity GitHub attaches rather than on anything the text says:

- `comment.user.type` must be `User`. Bots are `Bot`.
- `sender.type` must be `User`, and must be the same login as the author.
- `comment.performed_via_github_app` must be absent or null.

The last one has a cost, stated rather than hidden: a maintainer whose client
posts through a GitHub App is refused too, and comments again from the web UI.
Erring the other way costs a session that starts sessions.

`action` must be `created`. An `edited` delivery is a comment somebody changed,
and accepting it would mean a year-old comment can be edited into a fresh
request — and edited again, each edit a new delivery id the replay ledger has no
reason to refuse.

### What the workflow is told, and what it is not

The dispatch carries four inputs and **no comment text**:

| Input          | Value                                                    |
| -------------- | -------------------------------------------------------- |
| `issue_number` | The issue or pull request the comment is on              |
| `comment_id`   | The comment. Its body is _fetched_ by the run            |
| `requested_by` | The author, already authorized here and re-checked there |
| `delivery_id`  | The webhook delivery, for correlation                    |

That is not a size precaution. A comment body arriving as a workflow input is a
comment body one `${{ }}` away from a command line, and the safest place for
untrusted text is a place it was never interpolated into. The run fetches it and
writes it to a file behind a grown fence — see
[`docs/claude-agent-harness.md`](claude-agent-harness.md).

The workflow and the ref are **operator configuration and nothing else**. The
ref decides which version of a privileged workflow a comment gets to start —
which prompt, which tool allowlist, which permissions — so a delivery able to
choose it would be able to choose the code that runs. Neither has a default:
a default workflow would be this service picking which of somebody's workflows a
comment may start.

`.github/scripts/claude-agent-harness.sh` then asks GitHub the _same_ permission
question again, on the other side of the dispatch, and refuses the run if the
answer is not `write` or `admin`, if the fetched comment was written by somebody
other than `requested_by`, if it belongs to a different issue, or if it never
contained the trigger phrase. Two answers either side of one hop, so the hop
itself is not the thing being trusted.

### Replay: at-most-once, on purpose

There is no idempotency key on GitHub's workflow-dispatch endpoint and a second
call starts a second run. Two agent sessions on one request is not a duplicate
log line — it is two sessions pushing to one branch. So the delivery id is
committed **before** the request leaves, and the ambiguous outcome resolves as
at-most-once.

| Outcome                                        | Delivery                                         |
| ---------------------------------------------- | ------------------------------------------------ |
| Budget refused, or the limiter was unreachable | Released — a real retry                          |
| The permission lookup could not be made        | Released                                         |
| `GITHUB_APP_DISPATCH_*` not set                | Released                                         |
| The author holds no write access               | Committed — a redelivery reaches the same answer |
| GitHub answered **4xx**                        | Released — it created nothing                    |
| GitHub answered **2xx**                        | Committed                                        |
| GitHub answered **5xx**, or never answered     | Committed                                        |

The 4xx row is the one exception and it is a narrow one: an unknown workflow, a
ref the workflow is not on, a permission the installation never granted. GitHub
answered, and its answer was that it did nothing — all operator-fixable, and a
redelivery afterwards is a real retry. A 5xx or a lost connection is not
distinguishable from a run that started, so it is not treated as one.

### The dispatch budget

A per-`<installation, repository>` bucket, ten a minute, spent **before** the
permission lookup — because the lookup is the first GitHub call an arbitrary
commenter can cause, one per `@claude`-containing comment on a repository where
anybody may comment. The bucket is built entirely from the authorization
decision, so a payload cannot move itself into a fresh one. It is disjoint from
the signing budget and from the per-IP meter in front of the whole route, which
counts GitHub's own delivery addresses and would never bound this.

### What is recorded

One `comment_dispatch` row per delivery that reached a decision, refusals
included — the Actions run list shows what ran and never what was turned away.
The metadata carries the workflow, the ref, the issue number, the comment id and
the actor: public facts, all of them visible to anyone who can read the comment.
No token, no key material, no GitHub response body. `key_id` is the sentinel
`none` rather than `unknown`, because dispatching involves no key at all.

## Setup

### 1. Register the App

Settings → Developer settings → GitHub Apps → New GitHub App.

- **Webhook URL**: `https://<your-deployment>/github/webhook`
- **Webhook secret**: generate one and keep it; you need it in step 3.
- **Permissions**: grant only what the feature you want actually needs.

  | Feature                                                         | Permissions                                                                        | Events          |
  | --------------------------------------------------------------- | ---------------------------------------------------------------------------------- | --------------- |
  | Nothing (setup check only)                                      | —                                                                                  | —               |
  | [Push signing](#signing-commits-on-push)                        | `Contents: Read and write`                                                         | `Push`          |
  | [Signature check runs](#reporting-the-signature-as-a-check-run) | `Checks: Read and write`                                                           | `Push`          |
  | [`@claude` dispatch](#dispatching-claude-from-a-comment)        | `Actions: Read and write`, `Issues: Read`, `Pull requests: Read`, `Metadata: Read` | `Issue comment` |

  `ping` is delivered on registration regardless, which is enough to check the
  setup without any of them.

- **Migrating an existing installation.** Adding a permission to an App that is
  already installed does **not** grant it: the installation has to approve the
  new permission before any of its deliveries can use it, and GitHub emails the
  account owner a link to do so. Until it is approved, the affected feature
  fails closed and says which one — a check run reports `403` in a
  `check_report` audit row, and a dispatch refuses with
  `permission_lookup_failed` rather than starting anything. Subscribing to a new
  _event_ needs no approval, but a delivery whose feature is unapproved is a
  delivery that does nothing.

  `Metadata: Read` is granted to every installation and needs no action; it is
  named above because it is what the collaborator-permission lookup reads.

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

# Publish a `GPG signature` check run on the head of every branch this service
# handles a push for. Needs `Checks: Read and write` on the App. Off by default;
# unset, no Checks API call is made at all.
GITHUB_APP_CHECK_RUNS = "true"

# Start the Claude workflow when a comment invokes it. Needs `Actions: Read and
# write`, `Issues: Read` and `Pull requests: Read` on the App, plus the workflow
# migration below. Off by default; unset, no Actions API call is made at all.
GITHUB_APP_COMMENT_DISPATCH  = "true"
GITHUB_APP_DISPATCH_WORKFLOW = "claude.yml"  # under .github/workflows/
GITHUB_APP_DISPATCH_REF      = "master"
```

**Before turning `GITHUB_APP_COMMENT_DISPATCH` on, migrate the workflow.** The
dispatched workflow has to accept `workflow_dispatch` _and_ stop subscribing to
`issue_comment` — GitHub raises that event for the same comment, so a workflow
that still listens for it starts a second session alongside the dispatched one.
In this repository that is one move:

```bash
git mv -f .github/workflows-pending/claude.yml .github/workflows/claude.yml
```

The file in `workflows-pending/` is the agent-mode harness with
`workflow_dispatch` declared and `issue_comment` deliberately absent; it lives
there because a GitHub App token has no `workflows` permission and cannot write
under `.github/workflows/`. `task test:agent-harness` asserts the absence, so a
change that puts the trigger back fails the suite with a message saying why.

To roll back: set `GITHUB_APP_COMMENT_DISPATCH = "false"` and add
`issue_comment: { types: [created] }` back to the workflow's triggers, in that
order. The harness still normalizes `issue_comment`, so nothing else changes.

The installation id is in the URL of the App's "Configure" page for that
account: `.../settings/installations/12345678`. It is also the `installation.id`
in any delivery the App makes, which the `ping` in step 4 will show you.

Leaving `GITHUB_APP_ALLOWED_REPOSITORIES` unset is a valid state and grants
nothing — the `ping` below still answers, so you can check the endpoint before
you have the installation id to write here.

`GITHUB_APP_ENABLED`, `GITHUB_APP_CHECK_RUNS` and `GITHUB_APP_COMMENT_DISPATCH`
all accept the literal `"true"` and nothing else. `"TRUE"`, `"1"` and `"yes"` all mean off. A flag guarding an inbound webhook is the wrong
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

`handled` is `true` only on a `push` that signed something; every other event
is received and dropped, and a ping is one of those. `scope` is what the
allowlist granted this delivery — `none` for the App-level ping, which names
neither an installation nor a repository. `signingKey` says whether the matched
grant binds a key, not which one; the id itself is in the delivery's log line
rather than in the response, because the sender has no use for it. `duplicate`
marks a delivery id that was already taken; redeliver the same event from the
Advanced tab and the second answer is `200` with `"duplicate": true`.

## What each answer means

| Status | Code                     | Meaning                                                                       |
| ------ | ------------------------ | ----------------------------------------------------------------------------- |
| `200`  | —                        | Either commits were signed and the branch moved, or the id was already taken. |
| `202`  | —                        | Verified and authorized. Acknowledged, not acted upon.                        |
| `400`  | `INVALID_REQUEST`        | Signature verified; body was not JSON, or `X-GitHub-Delivery` is unusable.    |
| `401`  | `AUTH_MISSING`           | No `X-Hub-Signature-256`. The App has no webhook secret set.                  |
| `401`  | `AUTH_INVALID`           | The signature did not verify. The two secrets differ.                         |
| `401`  | `AUTH_SUBJECT_UNTRUSTED` | Verified, and the pair it names is not in `GITHUB_APP_ALLOWED_REPOSITORIES`.  |
| `404`  | `NOT_FOUND`              | `GITHUB_APP_ENABLED` is not `"true"`.                                         |
| `413`  | `PAYLOAD_TOO_LARGE`      | Body over GitHub's 25 MiB cap. It was not read.                               |
| `429`  | `RATE_LIMITED`           | Too many deliveries from this address, or over the signing budget.            |
| `500`  | `SERVICE_MISCONFIGURED`  | Enabled, but `GITHUB_WEBHOOK_SECRET` is unset or the allowlist is unusable.   |
| `503`  | `SERVICE_DEGRADED`       | The delivery ledger could not be reached, so replay could not be ruled out.   |
| `503`  | —                        | The bound key is gone, key storage is down, or the budget could not be read.  |
| `500`  | `SIGN_ERROR`             | Signing or talking to GitHub failed. See `handled`/`skipped` in the body.     |

**No field in the body describes the check run**, because the response does not
wait for it. Reporting is handed to the runtime after the signing outcome is
decided and runs on after the acknowledgement has been sent, so that a slow or
unreachable Checks API cannot spend the ten seconds GitHub gives a receiver on a
write that changes nothing. What was published is in the delivery's log line and
in the `check_report` audit row; the commit itself is the other place to look. A
report that failed changes no status either: the answer is whatever the signing
path decided.

A delivery the **signing budget refused** publishes no check at all and makes no
Checks API call, which is the one case where the ordering is load-bearing rather
than incidental. A refusal is a decision that this service must stop acting on
that `<installation, repository, key>` for now, and a check run is four
authenticated calls against that repository — so publishing one after a refusal
would let a delivery loop keep spending GitHub API budget the refusal exists to
stop. A refusal is redeliverable; the redelivery that eventually signs reports
then.

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

A `202` body carries a `skipped` field naming why nothing was signed —
`nothing_to_sign` for a head that already carries a signature, `no_key_bound`
for a repository the operator granted events but no key, `not_a_branch`,
`branch_deleted`, `branch_moved`, `too_many_unsigned`,
`unreproducible_commit` for a commit whose exact bytes could not be
reconstructed from what the API reports, and `malformed` for a
payload that could not be shown to describe a signable push — no usable `ref`,
or a `deleted` flag that is not the literal `false` a non-deletion carries. A
`200` from a successful
sign carries `handled: true` and `signed: <count>`; a `200` from a repeat
carries `duplicate: true`.

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

The _storage fetch_ is what the two share, not the whole boundary: `/sign` also
meters its caller and writes an audit row, and `loadSigningKey` does neither.
A caller that acts on the key owes both, and the push handler provides them —
[the signing budget](#the-signing-budget) and
[what is recorded](#what-is-recorded).

### What is logged

An accepted delivery's log line carries the bound key id, and the reason when
there is none — `no_key_bound` is the one worth watching for, because it means
an allowlisted repository is missing its suffix and would sign nothing on push. A key id is not a secret: `/public-key` serves
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

### Two phases, and where the line is

The id is **reserved** before the handler runs and **settled** after it: kept
for the retention window when the delivery caused something, given back when it
caused nothing. The reservation is what keeps simultaneous copies to one winner,
so the concurrency property is unchanged — at every instant exactly one request
holds a given id.

Two phases rather than one because a one-way claim makes every failure
permanent, and it points the wrong way from what the GitHub UI suggests:

1. The handler fails before doing anything at all — the budget refused, the
   bound key is gone, key storage is down, GitHub would not mint a token.
2. The service answers `5xx`, so GitHub marks the delivery failed and the
   operator sees a red row in **Recent Deliveries**.
3. They press **Redeliver** — the one recovery affordance this design has.
4. Under a one-way claim they get `200 {"duplicate": true}`. The event is never
   processed, and the answer looks like success.

So the line the phases turn on is not "did the handler succeed" but **"has
anything left this service that cannot be taken back"**. For push signing that
is the ref update: a signature exists only in memory, a created commit object is
unreachable until a ref points at it, and moving the branch is the first step a
person can observe.

The delivery is marked **non-retryable immediately before** the update is
issued, not after it. That is deliberate and it is the asymmetric case: a
request that was sent and whose answer was lost may well have landed, and
repeating a force update on the assumption that it did not is how a branch gets
moved twice.

What sits in front of the update is the **decision**. The Durable Object write
happens afterwards, from the replay guard's `finally`, once the handler has
returned — the two are worth keeping apart because only one of them is where
at-most-once comes from. That comes from the reservation, which is held for the
whole request: no second copy of a delivery is handled while the first is still
running, wherever inside it the ledger write lands.

Two consequences of the write being last, both closed:

- A handler that dies between the ref update and the `finally` writes nothing.
  So `commit` **creates the record it does not find** rather than reporting
  `absent` and moving on: an irreversible delivery is recorded for the full
  retention window whether or not its reservation survived. The log line
  `Delivery committed after its reservation had lapsed` is that case.
- A ledger that cannot be reached at all is logged and leaves a reservation that
  lapses. That one is genuinely open, and it is why the handler's own
  idempotence — a head that is already signed is `nothing_to_sign` — is a second
  control rather than a nicety.

Everything before that point releases:

| Outcome                                      | Delivery  |
| -------------------------------------------- | --------- |
| Signed, branch moved                         | Committed |
| A commit in the run could not be reproduced  | Committed |
| Branch update failed after being issued      | Committed |
| No key bound to the pair                     | Released  |
| Bound key missing, or key storage down       | Released  |
| Over the signing budget, or budget unread    | Released  |
| GitHub refused a token, a read or a create   | Released  |
| Object id did not match what was signed      | Released  |
| Nothing to sign, tag, deletion, moved branch | Committed |
| Handler threw, state unknown                 | Committed |

The last two rows are the ones worth reading twice. A deterministic no-op stays
committed because a redelivery would reach the same answer, so handing the id
back would make it replayable for nothing. And an uncaught throw stays committed
because nothing is known about what it did — the default direction is
at-most-once, since acting twice is worse than not acting.

A reservation that is never settled — the isolate died mid-request — lapses on
its own after five minutes, after which a redelivery is allowed through and
meets the handler's own idempotence: a head this service already signed is
`nothing_to_sign`.

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
- **Response bodies are never quoted.** A `GitHubApiError` carries the
  operation and a status and nothing else, because a body from this API can echo
  back the request that produced it — which carried an installation token. What
  is parsed out of a response is picked by a schema; a document of an unexpected
  shape is reported as a count of bad fields, not as the document.

Every Checks API call goes through the same client, so it inherits all of the
above: the origin is pinned, the `owner/repo` in the path is the operator's
spelling out of the allowlist, and the token is minted for the installation that
allowlist paired with it. There is no function on that client that takes a
repository argument, and that absence is the mechanism.

## Audit records

Two actions are recorded, and only the two: `push_sign` for an attempt to sign,
`check_report` for a check run published or attempted. They are separate rows
because they are separate acts with different blast radii — one rewrites
history, one states a verdict about it — and because a delivery can do the
second without the first, which is exactly what the redelivery following a
signing push does.

**An acknowledged-and-discarded delivery is not audited**, and that is
deliberate: `audit_logs` records operations on keys and credentials, and a row
per event nothing acted on would be a D1 write for nothing. Those are logged at
info instead, with the _authorized_ repository rather than the payload's, so a
log line cannot be made to name a repository nobody granted. The _action_ is
what earns a record — and a new one costs an `AuditAction` value and a migration
widening the table's `CHECK` constraint, which is what `0005` and `0006` are.

## Not in the OpenAPI document

`POST /github/webhook` is registered with plain `app.post` rather than through
the OpenAPI router, for the same reason `/e/:code` is: the document exists to
generate clients, and the only caller of this route is GitHub, which does not
read it. Declaring it would put a method on the Go client — and on every other
generated one — for a caller that will never invoke it, and would require this
repository to publish a schema for a payload it does not model.
