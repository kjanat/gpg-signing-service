// Package client provides a high-level wrapper around the GPG Signing Service API.
//
// This package wraps the auto-generated API client (pkg/api) with a cleaner,
// more developer-friendly interface that handles common concerns like:
//   - Automatic retry with exponential backoff
//   - Rate limit detection and handling
//   - Type-safe error handling
//   - Simplified method signatures
//   - Context-aware operations
//
// # Basic Usage
//
// Create a client and perform operations:
//
//	c, err := client.New("https://gpg.kajkowalski.nl",
//	    client.WithOIDCToken(os.Getenv("OIDC_TOKEN")),
//	    client.WithTimeout(30*time.Second),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Sign commit data
//	result, err := c.Sign(ctx, "commit data", "")
//	if err != nil {
//	    if client.IsRateLimitError(err) {
//	        log.Printf("Rate limited: %v", err)
//	        return
//	    }
//	    log.Fatal(err)
//	}
//
//	fmt.Printf("Signature: %s\n", result.Signature)
//
// # Error Handling
//
// The client provides custom error types with helper functions:
//
//	result, err := c.Sign(ctx, data, keyID)
//	if err != nil {
//	    switch {
//	    case client.IsAuthError(err):
//	        // Handle authentication failure
//	    case client.IsRateLimitError(err):
//	        // Handle rate limiting
//	    case client.IsKeyNotFound(err):
//	        // Handle missing key
//	    default:
//	        // Handle other errors
//	    }
//	}
//
// # Admin Operations
//
// Admin operations require an admin token:
//
//	admin, err := client.New("https://gpg.kajkowalski.nl",
//	    client.WithAdminToken(os.Getenv("ADMIN_TOKEN")),
//	)
//
//	// Upload a key
//	keyData, _ := os.ReadFile("private-key.asc")
//	info, err := admin.UploadKey(ctx, "my-key", string(keyData))
//
//	// List all keys
//	keys, err := admin.ListKeys(ctx)
//
//	// Query audit logs
//	logs, err := admin.AuditLogs(ctx, client.AuditFilter{
//	    Action: "sign",
//	    Limit:  50,
//	})
package client
