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

| Command                                         | Authentication        | Purpose                                   |
| ----------------------------------------------- | --------------------- | ----------------------------------------- |
| `gpg-sign health`                               | None                  | Check service and storage health          |
| `gpg-sign public-key [--key-id ID]`             | None                  | Retrieve a PGP public key                 |
| `gpg-sign sign [--key-id ID]`                   | OIDC or service token | Sign stdin and print a detached signature |
| `gpg-sign sign-commit [flags]`                  | OIDC or service token | Embed signatures in commits and move HEAD |
| `gpg-sign admin upload --key-id ID --file FILE` | Admin                 | Upload an armored PGP private key         |
| `gpg-sign admin list`                           | Admin                 | List stored key metadata                  |
| `gpg-sign admin delete --key-id ID`             | Admin                 | Delete a key                              |
| `gpg-sign admin public-key --key-id ID`         | Admin                 | Retrieve public material for a key        |
| `gpg-sign admin audit [flags]`                  | Admin                 | Query audit records                       |

`sign-commit` flags: `--base`, `--default-branch`, `--allow-resign`,
`--sign-others`, `--scan-limit`, `--repo`, `--key-id`.

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
base is the exclusive lower bound of the range to sign, so --base=origin/master
signs every commit after the branch point, and --base=<sha> signs everything
after that commit (nothing this key signed was found in HEAD, which is expected
on a branch that has never been signed with it)
```

This is normal the first time a repository signs with a given key, and on any
branch whose history predates it. It ends the run **before any request is
made** — so if a `401` appears in the same job, the two are independent
failures, not cause and effect.

Pick the base by what you want rewritten. `--base=origin/master` on a topic
branch signs your commits and nothing already published. A `--base=<sha>` of the
oldest commit you want left alone is the general answer.

#### Reading a failure

`gpg-sign` prints the service's own explanation underneath the error, one field
per line, instead of dumping the JSON envelope:

```text
Error: sign failed: authentication failed: AUTH_SUBJECT_UNTRUSTED: Subject is not trusted for signing (request 628c9a74-…)
  subject: repo:kjanat/kjanat:ref:refs/heads/master
  hint:    No active trust rule matches this subject. Trust rules exist for this issuer, but none of them covers this subject. …
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
- `sign-commit` refuses to move `HEAD` if the branch changed while it was
  signing. The rewritten objects are left unreferenced and the branch is
  untouched; re-run once the branch is settled.
