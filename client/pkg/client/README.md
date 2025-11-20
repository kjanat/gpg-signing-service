# GPG Signing Service Client Wrapper

A developer-friendly Go client library for the GPG Signing Service API.

## Overview

This package wraps the auto-generated API client (`pkg/api`) with a cleaner interface that provides:

- ✅ **Simple API** - No pointer management, clean method signatures
- ✅ **Automatic retry** - Built-in exponential backoff with jitter
- ✅ **Type-safe errors** - Custom error types with helper functions
- ✅ **Rate limit aware** - Returns rate limit info in responses
- ✅ **Context support** - Proper timeout/cancellation handling
- ✅ **Production-ready** - Error handling, retries, timeouts built-in

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

## Comparison: Before vs After

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
    retryAfter := 0
    if resp.JSON429.RetryAfter != nil {
        retryAfter = *resp.JSON429.RetryAfter
    }
    return fmt.Errorf("rate limited, retry after %d", retryAfter)
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

- `AuthError` - Authentication failures
- `RateLimitError` - Rate limit exceeded (includes retry-after duration)
- `ValidationError` - Invalid request data
- `ServiceError` - API errors with codes

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

- ✅ Rate limit errors (respects `Retry-After` header)
- ✅ Service errors (5xx status codes)
- ❌ Authentication errors (401)
- ❌ Validation errors (400)
- ❌ Not found errors (404)

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

[MIT License](../../../LICENSE)
