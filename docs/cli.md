# `gpg-sign` CLI

The CLI is an HTTP client for a deployed signing service. It can check health,
retrieve PGP public keys, request detached PGP signatures, and perform PGP key
administration.

`sign` returns a detached signature and does not touch a commit. `sign-commit`
does attach one, by rewriting the commit objects in the current repository.

## Install

### GitHub Actions

```yaml
- uses: kjanat/gpg-signing-service@cbcb8600547bd6799cdca0b339e8dad044481435
  with:
    version: v1.2.0
```

See [GitHub Action](github-action.md) for pinning, inputs, and platform support.

### Release asset

```bash
GPG_SIGN_VERSION=v1.2.0
GPG_SIGN_SHA256='<digest recorded for that release>'

curl --fail --location --remote-name \
  "https://github.com/kjanat/gpg-signing-service/releases/download/$GPG_SIGN_VERSION/gpg-sign-linux-amd64"
printf '%s  %s\n' \
  "$GPG_SIGN_SHA256" \
  'gpg-sign-linux-amd64' |
  sha256sum --check
mkdir -p "$HOME/.local/bin"
install -m 0755 gpg-sign-linux-amd64 "$HOME/.local/bin/gpg-sign"
```

Choose the asset matching
`gpg-sign-{linux|darwin|windows}-{amd64|arm64}[.exe]`. The example above is for
Linux x64. Set `GPG_SIGN_SHA256` from the digest your own release policy
recorded for that tag. Reading it from the release's own `checksums.txt` checks
the download against the same publisher that produced it.

### Build from source

The Go module is under `client/`. The repository currently has root release
tags, not the `client/v*` module tags required by `go install ...@version`.
Build it from an explicitly selected checkout:

```bash
git clone https://github.com/kjanat/gpg-signing-service.git
cd gpg-signing-service
git checkout v1.2.0
cd client
go install ./cmd/gpg-sign
```

This requires the Go version declared in [`client/go.mod`](../client/go.mod).

## Configuration

Flags override environment variables. The service URL otherwise defaults to
`https://gpg.kajkowalski.nl`.

| Environment variable   | Flag            | Meaning                              |
| ---------------------- | --------------- | ------------------------------------ |
| `GPG_SIGN_URL`         | `--url`         | Signing service base URL             |
| `GPG_SIGN_TOKEN`       | `--token`       | OIDC JWT or `gst_` token for `/sign` |
| `GPG_SIGN_ADMIN_TOKEN` | `--admin-token` | Admin bearer for `/admin/*`          |
| —                      | `--timeout`     | Request timeout; default `30s`       |
| —                      | `--json`        | JSON output where supported          |

The default URL identifies one deployment; it is not a promise that the
deployment is public or suitable for your workload.

## Commands

| Command                                         | Authentication        | Purpose                                     |
| ----------------------------------------------- | --------------------- | ------------------------------------------- |
| `gpg-sign health`                               | None                  | Check service and storage health            |
| `gpg-sign public-key [--key-id ID]`             | None                  | Retrieve a PGP public key                   |
| `gpg-sign sign [--key-id ID]`                   | OIDC or service token | Sign stdin and print a detached signature   |
| `gpg-sign sign-commit [flags]`                  | OIDC or service token | Embed signatures in commits and move HEAD   |
| `gpg-sign repair-history [flags]`               | OIDC or service token | Rewrite a range's identity headers and sign |
| `gpg-sign admin upload --key-id ID --file FILE` | Admin                 | Upload an armored PGP private key           |
| `gpg-sign admin list`                           | Admin                 | List stored key metadata                    |
| `gpg-sign admin delete --key-id ID`             | Admin                 | Delete a key                                |
| `gpg-sign admin public-key --key-id ID`         | Admin                 | Retrieve public material for a key          |
| `gpg-sign admin audit [flags]`                  | Admin                 | Query audit records                         |

`sign-commit` flags: `--base`, `--default-branch`, `--allow-resign`,
`--sign-others`, `--scan-limit`, `--repo`, `--key-id`.

`repair-history` flags: `--base`, `--expected-tip`, `--identity`,
`--expect-identity` (repeatable), `--dry-run`, `--repo`, `--key-id`. All but
`--dry-run`, `--repo` and `--key-id` are required; see
[Repair manufactured provenance](#repair-manufactured-provenance).

Run `gpg-sign <command> --help` for all flags.

Key IDs must contain exactly 16 hexadecimal characters, for example
`62E75E54497815DD`.

## Examples

### Health

```bash
GPG_SIGN_URL="https://your-worker.example" gpg-sign health
```

### Public key

```bash
gpg-sign public-key --key-id 62E75E54497815DD > signing-key.asc
gpg --import signing-key.asc
```

### Request a detached signature

```bash
export GPG_SIGN_URL="https://your-worker.example"
export GPG_SIGN_TOKEN="gst_..."

printf 'data to sign' |
  gpg-sign sign --key-id 62E75E54497815DD > signature.asc
```

For Git:

```bash
git cat-file commit HEAD |
  gpg-sign sign --key-id 62E75E54497815DD > commit.sig
```

`commit.sig` is not yet part of the commit. See
[CI integrations](integrations.md#requesting-versus-applying-a-signature).

### Apply signatures to commits

```bash
export GPG_SIGN_URL="https://your-worker.example"
export GPG_SIGN_TOKEN="gst_..."

gpg-sign sign-commit --base origin/master --key-id 62E75E54497815DD
```

This rewrites every commit in `origin/master..HEAD` and moves the local `HEAD`
ref to the rewritten tip. It prints one line per commit:

```text
  signed   3f2a91c4 -> 7d84be10
  reparent a10ce7bb -> 2c9f4a55
  signed   9b1e0f37 -> 4e6dcb82
Signed 2 of 3 commit(s) in 8ab30c91..HEAD
HEAD now points at 4e6dcb82. Nothing was pushed; publishing this rewrite needs a force push.
```

`reparent` is a commit rewritten only to follow a rewritten parent; the middle
one here was committed by an identity this key does not cover.

#### What `--base` is

`--base` is the **exclusive** lower bound of the range to sign: the commit
_after_ which everything gets rewritten. `--base=X` signs `X..HEAD` and leaves
`X` itself alone. It takes anything `git rev-parse` accepts — a branch
(`origin/master`), a tag, a SHA, `HEAD~5`.

Getting it wrong is not a no-op. Too low a base rewrites history you did not
mean to touch, and every rewritten commit changes SHA.

You do not normally pass it. Without `--base` the range starts:

- at the last commit this key already verifies, when you are on
  `--default-branch` — the point the branch was last left in a good state; or
- at the merge base with `origin/<default-branch>`, on any other branch.

`--scan-limit` bounds that backward scan. It is ignored when `--base` pins the
range and when you are on another branch, because the scan does not run in
either case.

The scan can come up empty, which is when you have to pass it:

```text
Error: sign-commit failed: no verified commit in HEAD; pass base explicitly:
base is the exclusive lower bound of the range to sign, so --base=<sha> signs
every commit after that one — pick the commit just before the first one you
want signed, from `git log --oneline`. There is no branch point to use here:
master is the default branch, so origin/master is its own remote tip rather
than a fork point. Nothing this key signed was found in HEAD, which is expected
on a branch that has never been signed with it, and this ends the run before
any request is made
```

This is normal the first time a repository signs with a given key, and on any
branch whose history predates it. It ends the run **before any request is
made** — so if a `401` appears in the same job, the two are independent
failures, not cause and effect.

Pick the base by what you want rewritten. **`--base=<sha>` — the commit just
before the first one you want signed — is the general answer**, and it is the
only answer on this path: the scan only runs when you are standing on
`--default-branch`, where `origin/<default-branch>` is this branch's own remote
tip rather than a fork point. `origin/master..HEAD` there is whatever has not
been pushed yet, usually empty, which is a second round of guessing rather than
a fix.

`--base=origin/master` is the right shape one branch over: on a **topic**
branch it is the branch point, so it signs your commits and nothing already
published. That path never reaches the error above, because it takes the merge
base automatically and needs no `--base` at all.

#### Reading a failure

`gpg-sign` prints the service's own explanation underneath the error, one field
per line, instead of dumping the JSON envelope:

```text
Error: sign failed: authentication failed: AUTH_SUBJECT_UNTRUSTED: Subject is not trusted for signing (request 628c9a74-…)
  subject: repo:kjanat/kjanat:ref:refs/heads/master
  hint:    No active trust rule matches this subject. Trust rules exist for this issuer, but none of them both covers this subject and is currently active. …
  docs:    https://gpg.kajkowalski.nl/e/AUTH_SUBJECT_UNTRUSTED
  request: 628c9a74-c46d-403c-84c6-9c873298a17f
```

`docs` is a short redirect into the [error reference](errors.md); every code has
a section. Go callers read the same fields off `client.GuidanceFor(err)`, and
branch on `client.IsSubjectUntrusted(err)` to tell "this token is not
authorized" from "this token is broken".

A third case is neither: `client.IsServiceDegraded(err)` reports the `503` the
service answers when it could not reach the issuer or its own authorization
store, so the request was never judged. Those are retried automatically, and the
retrier waits the `Retry-After` the service sent instead of guessing.

`client.IsServiceMisconfigured(err)` is the fourth, and the one to stop on: the
same "nothing about your request is wrong", but the cause is the deployment's
own configuration, so it answers identically until an operator changes it. It
arrives as a `500` rather than its neighbour's `503` — `503` is the status the
proxies in between retry on their own account, and none of them can read a
`code`. It is the only `5xx` the retrier declines, and it declines it on the
`code`, not on the absent `Retry-After`, since a missing header is what plenty
of retryable failures also send.

The command refuses to rewrite commits that already carry a signature. It
prints what it would do to each and exits non-zero:

```text
  would re-sign a10ce7bb (signed by a key this service does not carry)
Error: signing 2 commit(s) would rewrite 1 already-signed commit(s) below the tip; move the base forward or re-run with --allow-resign (dispatch with allow_resign from CI)
```

`--allow-resign` proceeds anyway. A signed commit whose committer this key does
not cover loses its signature with nothing to replace it — that commit is marked
`stripped`, and the run warns about it. `--sign-others` signs those commits
instead of stripping them.

`--json` prints a machine-readable summary on stdout and sends progress to
stderr. A failed run prints a document too, so a scripted caller never has to
scrape the progress text:

```json
{
  "error": "signing 2 commit(s) would rewrite 1 already-signed commit(s) below the tip; ...",
  "result": {
    "branch": "feature",
    "base": "8ab30c91",
    "head": "4e6dcb8207f1a3c5d9e2b4f60817a9c3e5d7f901",
    "tip": "4e6dcb8207f1a3c5d9e2b4f60817a9c3e5d7f901",
    "commitsScanned": 2,
    "commitsSigned": 0,
    "refUpdated": false,
    "pushed": false
  },
  "resign": {
    "stale": 2,
    "commits": ["a10ce7bb2f0d4c8e9a1b3d5f7e9c0a2b4d6f8e01"],
    "report": [
      "  would re-sign a10ce7bb (signed by a key this service does not carry)"
    ]
  }
}
```

`resign` is present only when the run was blocked by an already-signed commit.
Every `result` field above is always present. `tip` is the commit `HEAD` would
be moved to, so on any run that did not get that far it still holds `head`;
`refUpdated` is what says whether the ref actually moved. `pushed` is always
`false` — the command has no push path.

### Repair manufactured provenance

`sign-commit` attests to what a commit already says. `repair-history` changes
what it says about who wrote it, and is a separate command for exactly that
reason.

It exists for one failure. Merging through GitHub's REST squash endpoint builds
the commit itself and stamps its own identities on it:

```text
author    claude[bot] <209825114+claude[bot]@users.noreply.github.com>
committer GitHub <noreply@github.com>
```

Neither wrote the code. Signing such a commit does not fix it — the signature
is valid and the provenance under it is still wrong, which is how a branch ends
up reported `Unverified` / `unknown_key` after a successful signing run. The
only correct repair is to rebuild the commits claiming the identity the signing
key actually represents.

Plan first. `--dry-run` validates the whole range and prints what it would do
without requesting a signature or writing an object:

```bash
gpg-sign repair-history --dry-run \
  --base a1cdfe318686cac582fc955243966d04236afb58 \
  --expected-tip 42e3400c7b10ee4fbdfc3638801d5776849d1353 \
  --identity "Kaj Kowalski <info@kajkowalski.nl>" \
  --expect-identity "209825114+claude[bot]@users.noreply.github.com" \
  --expect-identity "noreply@github.com"
```

Drop `--dry-run` to perform it. Every commit is rebuilt oldest-to-newest with
its parents remapped, its existing `gpgsig` stripped, its identity headers
replaced, and the reconstructed payload signed by the service. Each result is
read back out of the object store and checked before the walk continues.

```text
  plan     42e3400c claude[bot] <209825114+...> -> Kaj Kowalski <info@kajkowalski.nl>
  repaired 42e3400c -> 8c1d0a94
Repaired 20 commit(s) in a1cdfe31..42e3400c as Kaj Kowalski <info@kajkowalski.nl>.
Repaired tip 8c1d0a94... carries tree 6f2ab103, the same tree as 42e3400c.
No ref was moved and nothing was pushed. Publish with:
  git push origin 8c1d0a94...:refs/heads/<branch> --force-with-lease=<branch>:42e3400c...
```

#### What it preserves, and what it refuses

Preserved byte for byte: the tree, the message, each header's own timestamp and
timezone offset, unknown and multi-line headers, and the order and topology of
the range.

The run fails closed, before or during, on every one of these:

- `--base` or `--expected-tip` missing, or `--identity` not in `Name <address>`
  form, or no `--expect-identity` at all. None of them has a default.
- `HEAD` is not at `--expected-tip`. The tip is a lease, not a label: a branch
  that moved would leave the repaired chain built from commits the eventual
  force-with-lease is not replacing.
- `--base` is not an ancestor of `--expected-tip`. A base on a divergent branch
  still yields a non-empty range — one silently starting at their merge base —
  so a mistyped ref would widen the rewrite instead of being refused.
- The range is empty, or does not end at the expected tip.
- Any author or committer address in the range was not named with
  `--expect-identity`. The refusal lists them, because naming them is the
  remedy. The target identity's own address is always allowed.
- An identity header outside `Name <address> seconds ±hhmm`. Git tolerates
  shapes this command will not reproduce; guessing at one moves a commit's
  timestamp rather than failing.
- A rewritten commit that reads back with the wrong identity, a moved
  timestamp, a different tree, different message bytes, unremapped parents, or
  a signature the service key does not verify.
- A repaired tip whose tree differs from the tip it replaces.

`--expect-identity` is what stops a widened range from quietly reattributing a
commit nobody looked at, so it is required rather than defaulted.

#### It publishes nothing

`repair-history` writes objects and moves no ref. The repaired tip is printed —
and put in `tip` under `--json` — for a caller that has checked it to publish
under its own lease. `.github/scripts/repair-history.sh` is that caller in CI:
it runs the command, re-checks every commit in the range with `git` and `gpg`
rather than the CLI's own code
(`.github/scripts/assert-repaired-range.sh`), and only then performs one
`--force-with-lease` naming the exact object it replaces.

On a dry run `tip` is absent, so a caller that pushes whatever that field holds
cannot publish a plan.

Publishing is opt-in there too: `repair-history.sh` repairs, asserts and stops
unless it is given `PUSH=true`, and prints the exact push command instead.

The dispatch surface is `.github/workflows-pending/repair-history.yml` — a
separate workflow rather than a mode on Sign Commits, for the same reason this
is a separate command: a `mode:` dropdown would put a provenance rewrite one
mis-click away from a routine signing run. It defaults `dry_run` to true and
`push` to false, and `task test:repair-history` asserts both, because a YAML
default is one character away from its opposite.

#### Which `gpg-sign` runs it

`repair-history` is newer than any published release, so nothing should resolve
the name from `PATH` and hope. Both scripts take the binary from
`GPG_SIGN_BIN`, and `repair-history.sh` asks it for `repair-history --help`
before anything else — a released binary that predates the command is named as
such up front rather than discovered partway through a rewrite:

```bash
task client:build   # builds ./client/bin/gpg-sign from this checkout
GPG_SIGN_BIN=./client/bin/gpg-sign \
  BASE_REF=... EXPECTED_TIP=... IDENTITY=... EXPECT_IDENTITIES=... BRANCH=... \
  .github/scripts/repair-history.sh
```

`.github/scripts/test-repair-history.sh` builds the checked-out command the same
way, so the suite proves the orchestration against this tree rather than against
whatever release is installed. `sign-commits.sh` and
`.github/scripts/test-sign-commits.sh` do the same for `sign-commit`.

#### Landing order

The routine **Sign Commits** run is orchestrated by
`.github/scripts/sign-commits.sh`, which turns the dispatch inputs into
`gpg-sign sign-commit` flags and nothing else. It signs through the same CLI
`repair-history` lives in, so there is one implementation of the signing walk
rather than one in Go and a second in Python. The order is

1. merge the `repair-history` capability;
2. publish a `gpg-sign` release containing it and `sign-commit`;
3. point `.github/workflows/sign-commits.yml` at `sign-commits.sh`, drop the
   `NOT ACTIVE YET` header from the moved file, and drop the paragraph in
   `docs/integrations.md` that says the workflow is still pending;
4. delete the Python path once nothing invokes it (this is that step,
   together with 3);
5. run the production repair, with `PUSH=true`, from a checkout that has the
   released CLI — or, until one exists, with the repair workflow's
   `build_from_source` input, which is deliberate, named and off by default.

Step 3 needs a token with the `workflows` permission, which is why the one-line
workflow edit is applied by hand rather than in the change that removes the
script it replaces.

Until step 2 lands, the installed binary is a release that predates
`sign-commit`. That is not something to discover in the middle of a signing
run, so `sign-commits.sh` asks the binary for `sign-commit --help` first and
refuses by name if it has never heard of it — the same probe
`repair-history.sh` makes. `GPG_SIGN_BIN` points either script at a build of
this checkout in the meantime.

#### Stopping it happening again

`.github/scripts/check-commit-provenance.sh <range>` refuses commits whose
committer is `GitHub <noreply@github.com>` or whose author or committer name
ends in `[bot]`, in any case — `Renovate[Bot]` names the same mechanism as
`renovate[bot]`, and a display name is free text GitHub does not hold to the
lower-case spelling. Run it on pushes to the default branch, over the commits the
push added, so a merge that manufactures identities is a red build immediately
rather than twenty commits later. `PROVENANCE_ALLOW` takes addresses to permit
anyway, one per line.

It reads the message as well as the headers. A `Co-authored-by:` trailer is a
provenance claim too, and this branch had to be rewritten once because four
commits carried one that no one typed: correct `Kaj Kowalski` headers over
`Co-authored-by: Kaj Kowalski <6353477+kjanat@users.noreply.github.com>`, which
the header-only guard passed without comment. So a trailer whose name ends in
`[bot]`, or whose address is `noreply@github.com` or any
`users.noreply.github.com` alias, is refused — case-folded the same way —
for the same reason the headers are: it credits an account a tool had the id for, not a correspondent. An
ordinary human co-author at an address they write from is untouched, and
`PROVENANCE_ALLOW` reaches the trailers too. `Signed-off-by:` is a different
claim and is not read.

The job that runs it is gated on `github.event_name == 'push' &&
github.event.deleted == false`: deleting a branch is a push too, and one whose
`github.sha` is the default branch's tip, so `before..after` would span commits
the deletion never touched. `task test:commit-provenance` asserts that
condition against whichever of the patch or `ci.yml` currently carries the job.

The CI job that calls it arrives as
`.github/workflows-pending/ci-provenance-job.patch`, for the same reason the
Sign Commits replacement does: an App token cannot write under
`.github/workflows/`. Apply it with `git apply` and delete the patch.
`task test:commit-provenance` refuses a patch that has stopped applying, and
once the patch is gone it asserts that `ci.yml` still calls the guard.

All three staged files pin their external actions to full commit SHAs with the
version as a trailing comment, and each of the three suites asserts it. These
are the jobs that hold `contents: write`, mint OIDC tokens for real signatures,
and check the provenance of what lands on the default branch; an action
resolved through a tag is a step someone else can repoint into that position.
The rest of `.github/workflows/` still uses tags and is not this change's to
re-pin. Dependabot's `github-actions` ecosystem bumps a SHA-and-comment pin the
same way it bumps a tag.

### Upload a PGP key

```bash
export GPG_SIGN_URL="https://your-worker.example"
export GPG_SIGN_ADMIN_TOKEN="..."

gpg-sign admin upload \
  --key-id 62E75E54497815DD \
  --file .keys/private-key.asc
```

### Query audit records

```bash
gpg-sign --json admin audit \
  --limit 50 \
  --action sign \
  --start-date 2026-07-01T00:00:00Z
```

## Current boundaries

- `sign` and `public-key` require PGP-armored response markers. They do not
  support X.509/PKCS#7 end to end.
- The CLI has no commands for X.509 upload or service-token management. Use the
  HTTP API or generated raw Go client.
- Automatic retry behavior in the high-level client covers transport failures,
  not HTTP `429` or `5xx` responses.
- Supplying bytes to `sign` grants no Git-specific validation; the service signs
  any non-empty input.
- `sign-commit` rewrites commit SHAs. It stops at `git update-ref HEAD` and
  never pushes; publishing the result is a force push you perform yourself. It
  needs `git` on `PATH` — signatures are verified in-process, so no `gpg`
  installation is required — refuses a detached `HEAD`, and handles PGP only.
- `sign-commit` signs `sha1` and `sha256` repositories, writing the header Git
  names after the repository's hash algorithm — `gpgsig` or `gpgsig-sha256` —
  and reading that same spelling when it verifies. A repository in
  hash-algorithm compatibility mode is signed under one of the two headers Git
  wrote; the run warns that the other signature is dropped, because recreating
  it means signing the mirrored object the run never builds.
- `sign-commit` leaves a `mergetag` header alone when the commit it names is
  rewritten. The embedded tag is signed by its own tagger, so it cannot be
  repointed; the run warns, and `git log --show-signature` on that merge then
  describes a merged tag matching none of its parents.
- `sign-commit` refuses a commit whose object bytes are not valid UTF-8. The
  service reads the payload as text, so a message or identity written in a
  legacy charset — what git's `encoding` header records — would be signed with
  a replacement character in place of those bytes and the signature would not
  match the commit. Re-encode such commits before signing.
- `repair-history` rewrites the author and committer headers of published
  history. It is destructive, has no defaults, and is not a substitute for
  merging correctly in the first place; `check-commit-provenance.sh` is.
- `repair-history` moves no ref and never pushes. It writes objects and hands
  back a tip; publishing it is a force push the caller performs after checking
  it. A failed run therefore leaves only unreferenced objects behind.
- `repair-history` refuses an identity header outside
  `Name <address> seconds ±hhmm`, which is narrower than what Git accepts. The
  shapes it refuses are the ones released go-git reads back as a different
  timestamp, so reproducing them is not something this command can promise.
- `sign-commit` refuses to move `HEAD` if the branch changed while it was
  signing. The rewritten objects are left unreferenced and the branch is
  untouched; re-run once the branch is settled.
