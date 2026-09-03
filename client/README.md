# GPG Signing Service Go Client

A cross-platform Go client and CLI for the service's OpenPGP operations.

## Quick Start

### Installation

```bash
# From a checkout of the repository
cd client
go install ./cmd/gpg-sign
```

### CLI Usage

```bash
# 0. Check which build you have.
#    - A binary downloaded from a GitHub Release reports the released version,
#      plus the commit and build time Go stamped into it:
#        gpg-sign version 1.2.0 (commit 4918556..., built 2026-09-02T01:31:52Z)
#    - `task client:build` reports the same three from the local checkout.
#    - `go install`/`go run` reports "dev", plus the commit and build time when
#      it was built from a checkout. A tree with uncommitted or untracked files
#      marks the commit "+dirty", because the binary is not that commit.
gpg-sign --version

# 1. Set environment variables
export GPG_SIGN_URL="https://gpg.kajkowalski.nl"
export GPG_SIGN_TOKEN="<your-oidc-token>"

# 2. Check health
gpg-sign health

# 3. Sign a commit
echo "commit data" | gpg-sign sign
```

### Library Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/kjanat/gpg-signing-service/client/pkg/client"
)

func main() {
    // Initialize client with base URL
    c, err := client.New(
        "https://gpg.kajkowalski.nl",
        client.WithOIDCToken(os.Getenv("GPG_SIGN_TOKEN")),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Sign data
    result, err := c.Sign(context.Background(), "commit data", "")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(result.Signature)
}
```

## Features

- Health checks, OpenPGP public keys, signing, and PGP key administration
- OIDC JWT, `gst_` service-token, and admin-token authentication
- Typed errors and generated API models

The high-level wrapper and CLI are currently OpenPGP-only. Use the generated
raw client for X.509 and service-token administration endpoints.

## Documentation

For CLI commands, see [CLI]. For the current API surface, see [API].

[API]: ../docs/api.md
[CLI]: ../docs/cli.md

<!-- rumdl-disable-file MD013 -->
