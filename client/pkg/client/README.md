# GPG Signing Service Client Wrapper

A developer-friendly Go client library for the GPG Signing Service API.

## Overview

This package wraps the auto-generated API client (`pkg/api`) with a cleaner
interface that provides:

- **Simple API** - No pointer management, clean method signatures
- **Automatic retry** - Built-in exponential backoff with jitter
- **Type-safe errors** - Custom error types with helper functions
- **Rate limit aware** - Returns rate limit info in responses
- **Context support** - Proper timeout/cancellation handling
- **Production-ready** - Error handling, retries, timeouts built-in

## Installation

```bash
go get github.com/kjanat/gpg-signing-service/client/pkg/client
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/kjanat/gpg-signing-service/client/pkg/client"
)

func main() {
    // Create client with OIDC token
    c, err := client.New("https://gpg.kajkowalski.nl",
        client.WithOIDCToken(os.Getenv("OIDC_TOKEN")),
        client.WithTimeout(30*time.Second),
    )
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Sign commit data
    result, err := c.Sign(ctx, "commit data", "")
    if err != nil {
        if client.IsRateLimitError(err) {
            log.Printf("Rate limited: %v", err)
            return
        }
        log.Fatal(err)
    }

    fmt.Printf("Signature: %s\n", result.Signature)
    if result.RateLimitRemaining != nil {
        fmt.Printf("Rate limit remaining: %d\n", *result.RateLimitRemaining)
    }
}
```

## Comparison: Before vs. After

### Before (Raw Generated Client)

Complex pointer handling, manual error checking, verbose API:

```go
// Setup with manual auth injection
httpClient := &http.Client{Timeout: 30 * time.Second}
c, err := api.NewClientWithResponses(
    "https://gpg.kajkowalski.nl",
    api.WithHTTPClient(httpClient),
    api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
        req.Header.Set("Authorization", "Bearer "+token)
        return nil
    }),
)

// Sign with manual pointer management
keyID := "my-key"
params := &api.SignCommitParams{KeyId: &keyID}

resp, err := c.SignCommitWithBodyWithResponse(ctx, params, "text/plain", strings.NewReader(data))
if err != nil {
    return err
}

// Manual status code checking for each error type
if resp.JSON401 != nil {
    return fmt.Errorf("auth error: %s", resp.JSON401.Error)
}

if resp.JSON429 != nil {
    return fmt.Errorf("rate limited, retry after %d", resp.JSON429.RetryAfter)
}

if resp.JSON400 != nil {
    return fmt.Errorf("validation error: %s", resp.JSON400.Error)
}

if resp.StatusCode() != 200 {
    return fmt.Errorf("unexpected status: %d", resp.StatusCode())
}

signature := string(resp.Body)
```

### After (Wrapper Client)

Clean, simple API with automatic error handling:

```go
// Simple setup with builder pattern
c, err := client.New("https://gpg.kajkowalski.nl",
    client.WithOIDCToken(token),
    client.WithTimeout(30*time.Second),
)

// Clean method signature (no pointers)
result, err := c.Sign(ctx, data, "my-key")
if err != nil {
    // Type-safe error handling
    if client.IsRateLimitError(err) {
        // Automatic retry already attempted
        return err
    }
    return err
}

signature := result.Signature
remaining := result.RateLimitRemaining
```

## API Reference

### Client Creation

```go
c, err := client.New(baseURL string, opts ...Option)
```

### Options

| Option                    | Description                               |
| ------------------------- | ----------------------------------------- |
| `WithOIDCToken(token)`    | Set OIDC authentication token             |
| `WithAdminToken(token)`   | Set admin authentication token            |
| `WithTimeout(duration)`   | Set HTTP request timeout (default: 30s)   |
| `WithMaxRetries(n)`       | Set maximum retry attempts (default: 3)   |
| `WithRetryWait(min, max)` | Set retry backoff range (default: 1s-30s) |
| `WithoutRateLimitRetry()` | Disable automatic rate limit retry        |

### Public Methods

| Method                       | Description          | Auth  |
| ---------------------------- | -------------------- | ----- |
| `Health(ctx)`                | Check service health | None  |
| `PublicKey(ctx, keyID)`      | Get public key       | None  |
| `Sign(ctx, data, keyID)`     | Sign commit data     | OIDC  |
| `UploadKey(ctx, keyID, key)` | Upload signing key   | Admin |
| `ListKeys(ctx)`              | List all keys        | Admin |
| `DeleteKey(ctx, keyID)`      | Delete key           | Admin |
| `AuditLogs(ctx, filter)`     | Query audit logs     | Admin |

### Error Handling

#### Error Types

- `AuthError` - Authentication failures (carries the service's `Code`,
  `Message`, and `RequestID`)
- `RateLimitError` - Rate limit exceeded (carries the retry-after duration, read
  from the body's `retryAfter` or the `Retry-After` header, in either the
  delay-seconds or the HTTP-date form)
- `ValidationError` - Invalid request data
- `ServiceError` - API errors with codes

Every non-2xx response is reported with the service's own `error` and `code`
when the body carries them. The OpenAPI document declares a `401` on every
operation that takes a credential, so the code and message are decoded from the
typed response; anything the document does not describe is read from the error
envelope directly. A `401` on `Sign` therefore reads

```text
authentication failed: AUTH_INVALID: Subject is not trusted for signing (request 0e2a8f3c-6b41-4d7e-9a55-1c8d0f6b2e77)
```

rather than a bare status number — that particular message means the credential
verified but no trusted subject covers it.

`RequestID` is the id in the parenthesis, and the id to quote when asking what
happened: it is the key of the `audit_logs` row the refused request wrote. It is
taken from the body's `requestId`, or from the `X-Request-ID` response header
when the body has none. Every `401` this service emits carries it, so the
parenthesis is part of the message in practice; `AuthError.Error()` omits it
only for a locally constructed error or a peer that published neither.

`ErrUnexpectedStatus` is what remains: a response whose body is not a usable
error envelope. That means no `error` message, no `code` to branch on, or a
body that will not decode at all — an HTML challenge page from a proxy
labelled `application/json`, say. Such a body is detected before the generated
parser reaches it, so it reports as `unexpected status code: 401` rather than
as a JSON decoding error with no status in it.

#### Helper Functions

```go
client.IsAuthError(err)        // true if authentication error
client.IsRateLimitError(err)   // true if rate limited
client.IsKeyNotFound(err)      // true if key not found
client.IsValidationError(err)  // true if validation error
client.IsServiceError(err)     // true if 5xx error
```

#### Example

```go
result, err := c.Sign(ctx, data, keyID)
if err != nil {
    switch {
    case client.IsAuthError(err):
        // Handle authentication failure
    case client.IsRateLimitError(err):
        // Handle rate limiting (already retried automatically)
        var rateLimitErr *client.RateLimitError
        if errors.As(err, &rateLimitErr) {
            log.Printf("Retry after: %v", rateLimitErr.RetryAfter)
        }
    case client.IsKeyNotFound(err):
        // Handle missing key
    default:
        // Handle other errors
    }
    return err
}
```

## Admin Operations

```go
// Create admin client
admin, err := client.New("https://gpg.kajkowalski.nl",
    client.WithAdminToken(os.Getenv("ADMIN_TOKEN")),
)

// Upload key
keyData, _ := os.ReadFile("private-key.asc")
info, err := admin.UploadKey(ctx, "my-key-v2", string(keyData))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Uploaded: %s (%s)\n", info.KeyID, info.Fingerprint)

// List all keys
keys, err := admin.ListKeys(ctx)
for _, k := range keys {
    fmt.Printf("%s: %s (%s)\n", k.KeyID, k.Fingerprint, k.Algorithm)
}

// Delete key
err = admin.DeleteKey(ctx, "old-key")

// Query audit logs
logs, err := admin.AuditLogs(ctx, client.AuditFilter{
    Action: "sign",
    Limit:  50,
    StartDate: time.Now().Add(-7 * 24 * time.Hour),
})
fmt.Printf("Found %d audit entries\n", logs.Count)
```

## Retry Behavior

The client automatically retries:

- Rate limits (`429`)
- Transient service errors (`500`, `502`, `503`, `504`)
- Transport faults — a refused dial, a connection dropped mid-body

It never retries:

- Authentication errors (401)
- Validation errors (400)
- Not found errors (404)
- `501` and `505`, which describe what the server will never do
- A cancelled or expired context
- A response that arrived and failed to decode — the bytes are already in hand

Retry strategy:

- Exponential backoff with jitter
- Default: 3 retries, 1s-30s backoff range
- Respects context cancellation

Disable retries:

```go
c, _ := client.New(baseURL,
    client.WithMaxRetries(0), // Disable all retries
)
```

Disable only rate limit retry:

```go
c, _ := client.New(baseURL,
    client.WithoutRateLimitRetry(), // Fail fast on rate limits
)
```

### What is retried

A `429`, a `500`, `502`, `503` or `504`, and a transport fault — a state the
server or the network may be out of by the next attempt. Nothing else. A `501`
or a `505` describes what the server will never do, and every 4xx below `429`
describes something only the caller can change, so re-sending either spends the
timeout budget to arrive at the same answer. A cancelled or expired context is
not retried either: the next attempt fails the same way, immediately.

Three things worth knowing:

- `Health` never retries a status. Its `503` is `degraded`, a documented answer
  carrying a body you are meant to read, and a probe wants the current state
  rather than an eventually healthy one. Transport faults still retry there.
- The wait between attempts is the exponential backoff, not the server's
  `Retry-After`. The hint is not reachable from the generic response type the
  retry policy sees — but it is not discarded either: it reaches you on the
  `RateLimitError` returned once the attempts are spent.
- `Sign` and `UploadKey` are retried like everything else. Neither carries an
  idempotency key, so a retried attempt is a second request the service will
  act on: `Sign` produces another signature and another `sign` audit row,
  `UploadKey` rewrites `key:<keyId>` with the same bytes and appends another
  `key_upload` row. Both converge on the same state — a signature is a pure
  function of the request, and an overwrite with identical content is a no-op —
  so what a retry duplicates is the audit trail, which is a record of attempts
  and is meant to show them. If your deployment needs at-most-once semantics
  instead, run those calls with `WithMaxRetries(0)` and decide for yourself.

Retries are exhausted before an operation returns, so an error you receive is
final under the configured policy.

## Rate Limit Information

Signing operations return rate limit information:

```go
result, err := c.Sign(ctx, data, keyID)
if err != nil {
    return err
}

if result.RateLimitRemaining != nil {
    fmt.Printf("Remaining: %d requests\n", *result.RateLimitRemaining)
}

if result.RateLimitReset != nil {
    fmt.Printf("Reset at: %v\n", *result.RateLimitReset)
}
```

## Context Support

All methods support context for timeout/cancellation:

```go
// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

result, err := c.Sign(ctx, data, keyID)

// With cancellation
ctx, cancel := context.WithCancel(context.Background())
go func() {
    // Cancel after some condition
    cancel()
}()

result, err := c.Sign(ctx, data, keyID)
```

## License

Dual-licensed: [MIT][license:mit] or [AGPL-3.0][license:agpl]

See [LICENSE.md][license] for details.

[license]: ../../../LICENSE.md
[license:mit]: ../../../LICENSE-MIT
[license:agpl]: ../../../LICENSE-AGPL-3.0
