# GPG Signing Service Go Client

A production-ready, cross-platform Go client and CLI for the GPG Signing Service API.

## Quick Start

### Installation

```bash
# Install the CLI
go install github.com/kjanat/gpg-signing-service/client/cmd/gpg-sign@latest
```

### CLI Usage

```bash
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
    signature, _, err := c.Sign(context.Background(), "commit data", "")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(signature)
}
```

## Features

- **Complete API Support**: Health, Public Keys, Signing, Admin operations.
- **Resilient**: Automatic retries with exponential backoff and jitter.
- **Type-Safe**: Comprehensive error handling with typed errors.
- **Secure**: OIDC and Admin token support.

## Documentation

For full documentation, see [DOCUMENTATION.md](../DOCUMENTATION.md).
For API details, see [API.md](../API.md).
