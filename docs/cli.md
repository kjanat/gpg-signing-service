# `gpg-sign` CLI

The CLI is an HTTP client for a deployed signing service. It can check health,
retrieve PGP public keys, request detached PGP signatures, and perform PGP key
administration.

It does not attach a signature to a Git commit.

## Install

### GitHub Actions

```yaml
- uses: kjanat/gpg-signing-service@cbcb8600547bd6799cdca0b339e8dad044481435
  with:
    version: v1.1.2
```

See [GitHub Action](github-action.md) for pinning, inputs, and platform support.

### Release asset

```bash
GPG_SIGN_VERSION=v1.1.2
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
git checkout cbcb8600547bd6799cdca0b339e8dad044481435
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
| `gpg-sign admin upload --key-id ID --file FILE` | Admin                 | Upload an armored PGP private key         |
| `gpg-sign admin list`                           | Admin                 | List stored key metadata                  |
| `gpg-sign admin delete --key-id ID`             | Admin                 | Delete a key                              |
| `gpg-sign admin public-key --key-id ID`         | Admin                 | Retrieve public material for a key        |
| `gpg-sign admin audit [flags]`                  | Admin                 | Query audit records                       |

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
