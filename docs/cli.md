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

Without `--base`, the range starts at the last commit this key already verifies
when you are on `--default-branch`, and at the merge base with
`origin/<default-branch>` otherwise. `--scan-limit` bounds that backward scan.
It is ignored when `--base` pins the range and when you are on another branch,
because the scan does not run in either case.

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
    "commitsScanned": 2,
    "refUpdated": false
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
- `sign-commit` writes the `gpgsig` header, so it requires a `sha1` repository.
  A `sha256` repository names the header `gpgsig-sha256`; the command refuses
  one rather than writing a signature Git will not read.
- `sign-commit` leaves a `mergetag` header alone when the commit it names is
  rewritten. The embedded tag is signed by its own tagger, so it cannot be
  repointed; the run warns, and `git log --show-signature` on that merge then
  describes a merged tag matching none of its parents.
- `sign-commit` refuses to move `HEAD` if the branch changed while it was
  signing. The rewritten objects are left unreferenced and the branch is
  untouched; re-run once the branch is settled.
