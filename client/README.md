# GPG Signing Service Go Client

A production-ready, cross-platform Go client and CLI for the GPG Signing Service
API.

## Features

- Complete API coverage (health, public keys, signing, admin operations)
- OIDC token authentication for signing
- Admin bearer token authentication for management
- Configurable timeouts and custom HTTP clients
- Comprehensive error handling with typed errors
- Rate limit detection with retry-after support
- JSON output mode for scripting
- Cross-platform builds (Linux, macOS, Windows)

## Installation

### From Source (Go)

```bash
go install github.com/kjanat/gpg-signing-service/client/cmd/gpg-sign@latest
```

<details>
<summary>From Source (git)</summary>

<!--### From Source-->

```bash
# Clone the repository
git clone https://github.com/kjanat/gpg-signing-service.git
cd gpg-signing-service/client

# Build the CLI
go build -o gpg-sign ./cmd/gpg-sign

# Or install to $GOPATH/bin
go install ./cmd/gpg-sign
```

</details>

<details>
<summary>Cross-Platform Builds</summary>

<!--### Cross-Platform Builds-->

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o gpg-sign-linux-amd64 ./cmd/gpg-sign

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o gpg-sign-linux-arm64 ./cmd/gpg-sign

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -o gpg-sign-darwin-amd64 ./cmd/gpg-sign

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o gpg-sign-darwin-arm64 ./cmd/gpg-sign

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o gpg-sign-windows-amd64.exe ./cmd/gpg-sign

# Windows ARM64
GOOS=windows GOARCH=arm64 go build -o gpg-sign-windows-arm64.exe ./cmd/gpg-sign
```

</details>

## CLI Usage

### Global Flags

```bash
--url string          API base URL (default: https://gpg.kajkowalski.nl)
--token string        OIDC token for signing
--admin-token string  Admin token for administrative operations
--timeout duration    Request timeout (default: 30s)
--json                Output as JSON
```

### Environment Variables

```bash
export GPG_SIGN_URL="https://gpg.kajkowalski.nl"
export GPG_SIGN_TOKEN="<your-oidc-token>"
export GPG_SIGN_ADMIN_TOKEN="<your-admin-token>"
```

### Commands

#### Health Check

```bash
# Check service health
gpg-sign health

# JSON output
gpg-sign health --json
```

#### Get Public Key

```bash
# Get default public key
gpg-sign public-key

# Get specific key
gpg-sign public-key --key-id=signing-key-v1

# Save to file
gpg-sign public-key --key-id=my-key > public.asc
```

#### Sign Data

```bash
# Sign data from stdin
echo "commit data" | gpg-sign sign

# Sign with specific key
cat commit.txt | gpg-sign sign --key-id=my-key

# Using OIDC token
echo "data" | gpg-sign sign --token="$OIDC_TOKEN"
```

#### Admin Operations

```bash
# List all keys
gpg-sign admin list --admin-token="$ADMIN_TOKEN"

# Upload a key
gpg-sign admin upload --key-id=new-key --file=private.asc

# Get public key (admin endpoint)
gpg-sign admin public-key --key-id=my-key

# Delete a key
gpg-sign admin delete --key-id=old-key

# Query audit logs
gpg-sign admin audit --limit=50
gpg-sign admin audit --action=sign --subject=myrepo
gpg-sign admin audit --start-date="2024-01-01T00:00:00Z" --end-date="2024-01-31T23:59:59Z"
```

## Library Usage

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/kjanat/gpg-signing-service/client/pkg/client"
)

func main() {
    // Create client
    c := client.New(
        client.WithBaseURL("https://gpg.kajkowalski.nl"),
        client.WithTimeout(30 * time.Second),
    )

    ctx := context.Background()

    // Health check
    health, err := c.GetHealth(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Status: %s\n", health.Status)

    // Get public key
    pubKey, err := c.GetPublicKey(ctx, "")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(pubKey)
}
```

### Signing with OIDC Token

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
    // Token from environment
    c := client.New(
        client.WithOIDCToken(os.Getenv("GITHUB_TOKEN")),
    )

    ctx := context.Background()

    commitData := []byte("tree abc123\nparent def456\n...")
    signature, rateLimit, err := c.Sign(ctx, commitData, "")
    if err != nil {
        // Check if rate limited
        if apiErr, ok := err.(*client.APIError); ok && apiErr.IsRateLimited() {
            fmt.Printf("Rate limited. Retry after %d seconds\n", apiErr.RetryAfter)
            return
        }
        log.Fatal(err)
    }

    fmt.Printf("Signature:\n%s\n", signature)
    fmt.Printf("Rate limit remaining: %d\n", rateLimit.Remaining)
}
```

### Admin Operations

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
    c := client.New(
        client.WithAdminToken(os.Getenv("GPG_SIGN_ADMIN_TOKEN")),
    )

    ctx := context.Background()

    // List keys
    keys, err := c.ListKeys(ctx)
    if err != nil {
        log.Fatal(err)
    }

    for _, key := range keys.Keys {
        fmt.Printf("Key: %s (%s)\n", key.KeyID, key.Fingerprint)
    }

    // Upload a new key
    armoredKey := `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`

    result, err := c.UploadKey(ctx, armoredKey, "new-signing-key")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Uploaded key: %s\n", result.Fingerprint)

    // Query audit logs
    logs, err := c.GetAuditLogs(ctx, client.AuditOptions{
        Limit:  50,
        Action: "sign",
    })
    if err != nil {
        log.Fatal(err)
    }

    for _, entry := range logs.Logs {
        fmt.Printf("[%s] %s: %s\n", entry.Timestamp, entry.Action, entry.Subject)
    }
}
```

### Error Handling

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"

    "github.com/kjanat/gpg-signing-service/client/pkg/client"
)

func main() {
    c := client.New()
    ctx := context.Background()

    _, err := c.GetPublicKey(ctx, "nonexistent-key")
    if err != nil {
        // Check for API errors
        var apiErr *client.APIError
        if errors.As(err, &apiErr) {
            fmt.Printf("API Error: %s (code: %s)\n", apiErr.Message, apiErr.Code)

            if apiErr.IsNotFound() {
                fmt.Println("Key not found")
            } else if apiErr.IsAuthError() {
                fmt.Println("Authentication failed")
            } else if apiErr.IsRateLimited() {
                fmt.Printf("Rate limited. Retry after %d seconds\n", apiErr.RetryAfter)
            }
            return
        }

        // Check for client errors
        var clientErr *client.ClientError
        if errors.As(err, &clientErr) {
            fmt.Printf("Client Error: %s\n", clientErr.Message)
            return
        }

        log.Fatal(err)
    }
}
```

### Custom HTTP Client

```go
package main

import (
    "crypto/tls"
    "net/http"
    "time"

    "github.com/kjanat/gpg-signing-service/client/pkg/client"
)

func main() {
    // Custom HTTP client with specific TLS config
    httpClient := &http.Client{
        Timeout: 60 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionTLS12,
            },
            MaxIdleConns:       10,
            IdleConnTimeout:    30 * time.Second,
            DisableCompression: true,
        },
    }

    c := client.New(
        client.WithHTTPClient(httpClient),
        client.WithUserAgent("my-app/1.0"),
    )

    // Use client...
    _ = c
}
```

## GitHub Actions Integration

```yaml
name: Sign Commits

on: push

jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write # Required for OIDC token
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.21"

      - name: Install gpg-sign
        run:
          go install
          github.com/kjanat/gpg-signing-service/client/cmd/gpg-sign@latest

      - name: Get OIDC token
        id: token
        run: |
          TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=gpg-signing-service" | jq -r '.value')
          echo "token=$TOKEN" >> $GITHUB_OUTPUT

      - name: Sign commit
        run: |
          git log -1 --format='%B' | gpg-sign sign --token="${{ steps.token.outputs.token }}"
```

## API Reference

### Client Options

| Option                   | Description            |
| ------------------------ | ---------------------- |
| `WithBaseURL(url)`       | Set API base URL       |
| `WithHTTPClient(client)` | Use custom HTTP client |
| `WithTimeout(duration)`  | Set request timeout    |
| `WithUserAgent(ua)`      | Set User-Agent header  |
| `WithOIDCToken(token)`   | Set OIDC token         |
| `WithAdminToken(token)`  | Set admin token        |

### Client Methods

| Method                          | Description            | Auth  |
| ------------------------------- | ---------------------- | ----- |
| `GetHealth(ctx)`                | Health check           | None  |
| `GetPublicKey(ctx, keyID)`      | Get public key         | None  |
| `Sign(ctx, data, keyID)`        | Sign data              | OIDC  |
| `UploadKey(ctx, key, keyID)`    | Upload key             | Admin |
| `ListKeys(ctx)`                 | List all keys          | Admin |
| `DeleteKey(ctx, keyID)`         | Delete key             | Admin |
| `GetAdminPublicKey(ctx, keyID)` | Get public key (admin) | Admin |
| `GetAuditLogs(ctx, opts)`       | Query audit logs       | Admin |

### Error Types

- `APIError` - Errors returned by the API
- `ClientError` - Client-side errors (network, parsing)

### Error Codes

| Code                   | Description                  |
| ---------------------- | ---------------------------- |
| `AUTH_MISSING`         | Authorization header missing |
| `AUTH_INVALID`         | Invalid or expired token     |
| `KEY_NOT_FOUND`        | Key not found                |
| `KEY_PROCESSING_ERROR` | Error processing key         |
| `KEY_UPLOAD_ERROR`     | Error uploading key          |
| `KEY_DELETE_ERROR`     | Error deleting key           |
| `SIGN_ERROR`           | Signing operation failed     |
| `RATE_LIMITED`         | Rate limit exceeded          |
| `INVALID_REQUEST`      | Malformed request            |
| `AUDIT_ERROR`          | Audit log retrieval failed   |
| `INTERNAL_ERROR`       | Server error                 |

## Testing

```bash
# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with race detector
go test -race ./...
```

## License

[MIT License](../LICENSE).

<!--    markdownlint-disable-file no-inline-html no-duplicate-heading -->
