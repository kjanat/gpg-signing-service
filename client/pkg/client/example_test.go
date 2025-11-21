package client_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

// Example demonstrates basic usage of the GPG Signing Service client.
func Example() {
	// Create a client with OIDC token
	c, err := client.New("https://gpg.kajkowalski.nl",
		client.WithOIDCToken(os.Getenv("OIDC_TOKEN")),
		client.WithTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Check service health
	health, err := c.Health(ctx)
	if err != nil {
		log.Printf("Health check failed: %v", err)
	} else if health.IsHealthy() {
		fmt.Printf("Service is healthy (v%s)\n", health.Version)
	}

	// Sign commit data
	commitData := "tree abc123\nparent def456\nauthor...\n"
	result, err := c.Sign(ctx, commitData, "")
	if err != nil {
		if client.IsRateLimitError(err) {
			log.Printf("Rate limited: %v", err)
			return
		}
		if client.IsAuthError(err) {
			log.Printf("Authentication failed: %v", err)
			return
		}
		log.Fatal(err)
	}

	fmt.Printf("Signature created\n")
	if result.RateLimitRemaining != nil {
		fmt.Printf("Rate limit remaining: %d\n", *result.RateLimitRemaining)
	}
}

// ExampleClient_adminOperations demonstrates admin operations.
func ExampleClient_adminOperations() {
	// Create admin client
	admin, err := client.New("https://gpg.kajkowalski.nl",
		client.WithAdminToken(os.Getenv("ADMIN_TOKEN")),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// List all keys
	keys, err := admin.ListKeys(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d keys\n", len(keys))
	for _, k := range keys {
		fmt.Printf("  %s: %s (%s)\n", k.KeyID, k.Fingerprint, k.Algorithm)
	}

	// Upload a new key
	keyData, _ := os.ReadFile("private-key.asc")
	info, err := admin.UploadKey(ctx, "my-key-v2", string(keyData))
	if err != nil {
		if client.IsKeyNotFound(err) {
			log.Printf("Key not found")
			return
		}
		log.Fatal(err)
	}

	fmt.Printf("Uploaded key: %s\n", info.Fingerprint)

	// Query audit logs
	logs, err := admin.AuditLogs(ctx, client.AuditFilter{
		Action:    "sign",
		Limit:     50,
		StartDate: time.Now().Add(-7 * 24 * time.Hour),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d audit entries\n", logs.Count)
	for _, entry := range logs.Logs {
		status := "✓"
		if !entry.Success {
			status = "✗"
		}
		fmt.Printf("%s %s: %s\n", status, entry.Action, entry.Subject)
	}
}

// ExampleClient_errorHandling demonstrates error handling patterns.
func ExampleClient_errorHandling() {
	c, _ := client.New("https://gpg.kajkowalski.nl",
		client.WithOIDCToken("token"),
	)

	ctx := context.Background()

	// Sign with error handling
	result, err := c.Sign(ctx, "commit data", "my-key")
	if err != nil {
		switch {
		case client.IsAuthError(err):
			fmt.Println("Authentication failed - check your token")
			return
		case client.IsRateLimitError(err):
			fmt.Println("Rate limited - wait before retrying")
			return
		case client.IsKeyNotFound(err):
			fmt.Println("Key 'my-key' not found")
			return
		case client.IsValidationError(err):
			fmt.Println("Invalid request data")
			return
		case client.IsServiceError(err):
			fmt.Println("Service error - try again later")
			return
		default:
			fmt.Printf("Unexpected error: %v\n", err)
			return
		}
	}

	fmt.Printf("Signature: %s\n", result.Signature)
}

// ExampleWithMaxRetries demonstrates retry configuration.
func ExampleWithMaxRetries() {
	c, _ := client.New("https://gpg.kajkowalski.nl",
		client.WithOIDCToken("token"),
		client.WithMaxRetries(5),
		client.WithRetryWait(1*time.Second, 60*time.Second),
	)

	ctx := context.Background()

	// This will automatically retry up to 5 times on transient failures
	_, err := c.Health(ctx)
	if err != nil {
		log.Fatal(err)
	}
}

// ExampleWithoutRateLimitRetry demonstrates disabling rate limit retry.
func ExampleWithoutRateLimitRetry() {
	c, _ := client.New("https://gpg.kajkowalski.nl",
		client.WithOIDCToken("token"),
		client.WithoutRateLimitRetry(),
	)

	ctx := context.Background()

	// This will fail immediately on rate limit instead of retrying
	_, err := c.Sign(ctx, "data", "")
	if client.IsRateLimitError(err) {
		fmt.Println("Rate limited - handle manually")
	}
}
