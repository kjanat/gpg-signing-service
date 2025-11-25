# Migration Guide: CLI to Wrapper Client

Guide for migrating `cmd/gpg-sign/main.go` from using the raw generated client
to the wrapper client.

## Benefits of Migration

- **70% less boilerplate** — No pointer management, cleaner error handling
- **Automatic retry** — Built-in exponential backoff
- **Type-safe errors** — Use helper functions instead of manual checks
- **Rate limit aware** — Extract rate limit info automatically
- **Maintainable** — Changes to wrapper benefit all consumers

## Example Migration

### Before (Current CLI Code)

```go
// cmd/gpg-sign/main.go - health command (current)
var healthCmd = &cobra.Command{
    RunE: func(cmd *cobra.Command, args []string) error {
        c, err := newClient()
        if err != nil {
            return fmt.Errorf("failed to create client: %w", err)
        }

        ctx, cancel := context.WithTimeout(context.Background(), timeout)
        defer cancel()

        resp, err := c.GetHealthWithResponse(ctx)
        if err != nil {
            return fmt.Errorf("health check failed: %w", err)
        }

        if resp.JSON200 == nil {
            return fmt.Errorf("health check failed: status %d", resp.StatusCode())
        }

        health := resp.JSON200

        if jsonOutput {
            return outputJSON(health)
        }

        fmt.Printf("Status: %s\n", health.Status)
        fmt.Printf("Version: %s\n", health.Version)
        // ... more output
    },
}
```

### After (Using Wrapper)

```go
// cmd/gpg-sign/main.go - health command (with wrapper)
var healthCmd = &cobra.Command{
    RunE: func(cmd *cobra.Command, args []string) error {
        c, err := newWrapperClient() // Use wrapper constructor
        if err != nil {
            return err
        }

        ctx, cancel := context.WithTimeout(context.Background(), timeout)
        defer cancel()

        health, err := c.Health(ctx) // Clean method call
        if err != nil {
            return err // Error already formatted
        }

        if jsonOutput {
            return outputJSON(health)
        }

        fmt.Printf("Status: %s\n", health.Status)
        fmt.Printf("Version: %s\n", health.Version)
        // ... more output
    },
}

// Helper to create wrapper client
func newWrapperClient() (*client.Client, error) {
    return client.New(getBaseURL(),
        client.WithTimeout(timeout),
    )
}

func newWrapperClientWithOIDC() (*client.Client, error) {
    return client.New(getBaseURL(),
        client.WithOIDCToken(getToken()),
        client.WithTimeout(timeout),
    )
}

func newWrapperClientWithAdmin() (*client.Client, error) {
    return client.New(getBaseURL(),
        client.WithAdminToken(getAdminToken()),
        client.WithTimeout(timeout),
    )
}
```

## Step-by-Step Migration

### 1. Add wrapper import

```go
import (
    "github.com/kjanat/gpg-signing-service/client/pkg/api"  // Keep for now
    "github.com/kjanat/gpg-signing-service/client/pkg/client" // Add wrapper
)
```

### 2. Create wrapper constructors

Replace `newClient()`, `newAdminClient()` with wrapper versions:

```go
// Before
func newClient() (*api.ClientWithResponses, error) {
    httpClient := &http.Client{Timeout: timeout}
    return api.NewClientWithResponses(getBaseURL(), api.WithHTTPClient(httpClient))
}

// After
func newWrapperClient() (*client.Client, error) {
    return client.New(getBaseURL(), client.WithTimeout(timeout))
}
```

### 3. Update sign command

```go
// Before (40+ lines)
resp, err := c.SignCommitWithBodyWithResponse(ctx, &api.SignCommitParams{KeyId: keyIDPtr}, "text/plain", strings.NewReader(string(data)))
if err != nil {
    return fmt.Errorf("signing failed: %w", err)
}

if resp.JSON401 != nil {
    return fmt.Errorf("authentication failed: %s", resp.JSON401.Error)
}

if resp.JSON429 != nil {
    return fmt.Errorf("rate limited, retry after %d seconds", *resp.JSON429.RetryAfter)
}

if resp.StatusCode() != 200 {
    return fmt.Errorf("signing failed: status %d", resp.StatusCode())
}

signature := string(resp.Body)

// After (5 lines)
result, err := c.Sign(ctx, string(data), keyID)
if err != nil {
    return err // Wrapper handles all error formatting
}

signature := result.Signature
```

### 4. Update admin commands

```go
// Before - upload
resp, err := c.UploadKeyWithResponse(ctx, body)
if err != nil {
    return fmt.Errorf("key upload failed: %w", err)
}
if resp.JSON401 != nil {
    return fmt.Errorf("authentication failed: %s", resp.JSON401.Error)
}
if resp.JSON201 == nil {
    return fmt.Errorf("key upload failed: status %d", resp.StatusCode())
}
result := resp.JSON201

// After - upload
info, err := c.UploadKey(ctx, keyID, string(keyData))
if err != nil {
    return err
}
```

### 5. Simplify error handling

```go
// Before
if resp.JSON401 != nil {
    return fmt.Errorf("authentication failed: %s", resp.JSON401.Error)
}

// After
if err != nil {
    if client.IsAuthError(err) {
        // Optional: add custom handling
    }
    return err // Already has descriptive message
}
```

## Expected Code Reduction

| Command      | Before (lines) | After (lines) | Reduction |
| ------------ | -------------- | ------------- | --------- |
| health       | 35             | 15            | 57%       |
| sign         | 55             | 18            | 67%       |
| admin upload | 50             | 20            | 60%       |
| admin list   | 40             | 22            | 45%       |
| admin delete | 45             | 15            | 67%       |
| admin audit  | 70             | 25            | 64%       |

**Total CLI reduction**: ~300 lines → ~115 lines (62% reduction)

## Rollout Strategy

1. **Phase 1**: Add wrapper alongside existing code (no breaking changes)
2. **Phase 2**: Migrate one command at a time (e.g., health → sign → admin)
3. **Phase 3**: Remove old raw client helpers once the migration is complete
4. **Phase 4**: Remove `pkg/api` import once fully migrated

## Testing Migration

Before each command migration:

```bash
# Test command still works
go build ./cmd/gpg-sign
./gpg-sign health
./gpg-sign sign < test-data.txt
./gpg-sign admin list
```

After all migrations:

```bash
# Verify no pkg/api usage remains (except in wrapper)
grep -r "pkg/api" cmd/
# Should return empty or only import comments
```
