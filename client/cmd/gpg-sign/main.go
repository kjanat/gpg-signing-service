// Package main provides a CLI for the GPG Signing Service.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	apiURL     string
	token      string
	adminToken string
	timeout    time.Duration
	jsonOutput bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "gpg-sign",
	Short: "GPG Signing Service CLI",
	Long: `A command-line client for the GPG Signing Service API.

This tool allows you to:
  - Check service health
  - Retrieve public keys
  - Sign commit data
  - Manage keys (admin)
  - Query audit logs (admin)

Environment variables:
  GPG_SIGN_URL         - API base URL (default: https://gpg.kajkowalski.nl)
  GPG_SIGN_TOKEN       - OIDC token for signing operations
  GPG_SIGN_ADMIN_TOKEN - Admin token for administrative operations`,
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&apiURL, "url", "", "API base URL (default: https://gpg.kajkowalski.nl)")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "OIDC token for signing (or GPG_SIGN_TOKEN env)")
	rootCmd.PersistentFlags().StringVar(&adminToken, "admin-token", "", "Admin token (or GPG_SIGN_ADMIN_TOKEN env)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "Request timeout")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(publicKeyCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(adminCmd)
}

// getBaseURL returns the API base URL from flags or environment
func getBaseURL() string {
	if apiURL != "" {
		return apiURL
	}
	if url := os.Getenv("GPG_SIGN_URL"); url != "" {
		return url
	}
	return "https://gpg.kajkowalski.nl"
}

// getToken returns the OIDC token from flags or environment
func getToken() string {
	if token != "" {
		return token
	}
	return os.Getenv("GPG_SIGN_TOKEN")
}

// getAdminToken returns the admin token from flags or environment
func getAdminToken() string {
	if adminToken != "" {
		return adminToken
	}
	return os.Getenv("GPG_SIGN_ADMIN_TOKEN")
}

// newClient creates a new API client
func newClient() (*client.Client, error) {
	return client.New(getBaseURL(),
		client.WithOIDCToken(getToken()),
		client.WithTimeout(timeout),
	)
}

// newAdminClient creates a client with admin auth
func newAdminClient() (*client.Client, error) {
	return client.New(getBaseURL(),
		client.WithAdminToken(getAdminToken()),
		client.WithTimeout(timeout),
	)
}

// outputJSON prints the value as JSON
func outputJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Health command
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check service health",
	Long:  "Performs a health check on the GPG signing service.",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		health, err := c.Health(ctx)
		if err != nil {
			if client.IsServiceError(err) {
				// Even if degraded, we might have health info
				// But here we just return the error as the wrapper handles it
				return fmt.Errorf("health check failed: %w", err)
			}
			return fmt.Errorf("health check failed: %w", err)
		}

		if jsonOutput {
			return outputJSON(health)
		}

		fmt.Printf("Status: %s\n", health.Status)
		fmt.Printf("Version: %s\n", health.Version)
		fmt.Printf("Timestamp: %s\n", health.Timestamp)
		fmt.Printf("Checks:\n")
		fmt.Printf("  Key Storage: %v\n", health.KeyStorage)
		fmt.Printf("  Database: %v\n", health.Database)

		if health.Status != "healthy" {
			return fmt.Errorf("service is not healthy: %s", health.Status)
		}

		return nil
	},
}

// Public key command
var publicKeyCmd = &cobra.Command{
	Use:   "public-key",
	Short: "Get public key",
	Long:  "Retrieves the public signing key from the service.",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyID, _ := cmd.Flags().GetString("key-id")

		c, err := newClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		pubKey, err := c.PublicKey(ctx, keyID)
		if err != nil {
			if client.IsKeyNotFound(err) {
				return fmt.Errorf("key not found")
			}
			return fmt.Errorf("failed to get public key: %w", err)
		}

		if jsonOutput {
			return outputJSON(map[string]string{"publicKey": pubKey})
		}

		fmt.Print(pubKey)
		return nil
	},
}

func init() {
	publicKeyCmd.Flags().String("key-id", "", "Key identifier (uses default if not specified)")
}

// Sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign commit data",
	Long: `Signs commit data read from stdin using the specified key.

Example:
  echo "commit data" | gpg-sign sign --key-id=my-key
  git log -1 --format='%B' | gpg-sign sign`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keyID, _ := cmd.Flags().GetString("key-id")

		// Read data from stdin
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		if len(data) == 0 {
			return fmt.Errorf("no data provided on stdin")
		}

		c, err := newClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		result, err := c.Sign(ctx, string(data), keyID)
		if err != nil {
			if client.IsAuthError(err) {
				return fmt.Errorf("authentication failed: %w", err)
			}
			if client.IsRateLimitError(err) {
				// The wrapper already retried, so this is a final failure
				return fmt.Errorf("rate limit exceeded: %w", err)
			}
			return fmt.Errorf("signing failed: %w", err)
		}

		if jsonOutput {
			// Convert result to map for JSON output to match previous structure
			out := map[string]any{
				"signature": result.Signature,
			}
			if result.RateLimitRemaining != nil {
				out["rateLimitRemaining"] = *result.RateLimitRemaining
			}
			return outputJSON(out)
		}

		fmt.Print(result.Signature)
		return nil
	},
}

func init() {
	signCmd.Flags().String("key-id", "", "Key identifier (uses default if not specified)")
}

// Admin command group
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Administrative operations",
	Long:  "Administrative operations requiring ADMIN_TOKEN authentication.",
}

func init() {
	adminCmd.AddCommand(adminUploadCmd)
	adminCmd.AddCommand(adminListCmd)
	adminCmd.AddCommand(adminDeleteCmd)
	adminCmd.AddCommand(adminPublicKeyCmd)
	adminCmd.AddCommand(adminAuditCmd)
}

// Admin upload command
var adminUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a signing key",
	Long:  "Uploads an armored private key to the service.",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyID, _ := cmd.Flags().GetString("key-id")
		filePath, _ := cmd.Flags().GetString("file")

		if keyID == "" {
			return fmt.Errorf("--key-id is required")
		}
		if filePath == "" {
			return fmt.Errorf("--file is required")
		}

		// Read key file
		keyData, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}

		c, err := newAdminClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		result, err := c.UploadKey(ctx, keyID, string(keyData))
		if err != nil {
			if client.IsAuthError(err) {
				return fmt.Errorf("authentication failed: %w", err)
			}
			return fmt.Errorf("key upload failed: %w", err)
		}

		if jsonOutput {
			return outputJSON(result)
		}

		fmt.Printf("Key uploaded successfully\n")
		fmt.Printf("  Key ID: %s\n", result.KeyID)
		fmt.Printf("  Fingerprint: %s\n", result.Fingerprint)
		fmt.Printf("  Algorithm: %s\n", result.Algorithm)
		if result.UserID != "" {
			fmt.Printf("  User ID: %s\n", result.UserID)
		}

		return nil
	},
}

func init() {
	adminUploadCmd.Flags().String("key-id", "", "Key identifier (required)")
	adminUploadCmd.Flags().String("file", "", "Path to armored private key file (required)")
}

// Admin list command
var adminListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys",
	Long:  "Lists metadata for all stored signing keys.",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newAdminClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		keys, err := c.ListKeys(ctx)
		if err != nil {
			if client.IsAuthError(err) {
				return fmt.Errorf("authentication failed: %w", err)
			}
			return fmt.Errorf("failed to list keys: %w", err)
		}

		if jsonOutput {
			return outputJSON(map[string]any{"keys": keys})
		}

		if len(keys) == 0 {
			fmt.Println("No keys found")
			return nil
		}

		fmt.Printf("Keys (%d):\n", len(keys))
		for _, key := range keys {
			fmt.Printf("\n  Key ID: %s\n", key.KeyID)
			fmt.Printf("    Fingerprint: %s\n", key.Fingerprint)
			fmt.Printf("    Algorithm: %s\n", key.Algorithm)
			fmt.Printf("    Created: %s\n", key.CreatedAt)
		}

		return nil
	},
}

// Admin delete command
var adminDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a key",
	Long:  "Permanently deletes a signing key from the service.",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyID, _ := cmd.Flags().GetString("key-id")

		if keyID == "" {
			return fmt.Errorf("--key-id is required")
		}

		c, err := newAdminClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		err = c.DeleteKey(ctx, keyID)
		if err != nil {
			if client.IsAuthError(err) {
				return fmt.Errorf("authentication failed: %w", err)
			}
			if client.IsKeyNotFound(err) {
				fmt.Printf("Key '%s' was not found\n", keyID)
				if jsonOutput {
					return outputJSON(map[string]bool{"deleted": false})
				}
				return nil // Or should this be an error? Original code didn't error on not found for delete
			}
			return fmt.Errorf("failed to delete key: %w", err)
		}

		if jsonOutput {
			return outputJSON(map[string]bool{"deleted": true})
		}

		fmt.Printf("Key '%s' deleted successfully\n", keyID)
		return nil
	},
}

func init() {
	adminDeleteCmd.Flags().String("key-id", "", "Key identifier to delete (required)")
}

// Admin public key command
var adminPublicKeyCmd = &cobra.Command{
	Use:   "public-key",
	Short: "Get public key (admin)",
	Long:  "Retrieves the public key for a specific key ID via admin endpoint.",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyID, _ := cmd.Flags().GetString("key-id")

		if keyID == "" {
			return fmt.Errorf("--key-id is required")
		}

		c, err := newAdminClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Use the admin-specific endpoint to ensure admin auth is exercised
		pubKey, err := c.AdminPublicKey(ctx, keyID)
		if err != nil {
			if client.IsAuthError(err) {
				return fmt.Errorf("authentication failed: %w", err)
			}
			if client.IsKeyNotFound(err) {
				return fmt.Errorf("key not found")
			}
			return fmt.Errorf("failed to get public key: %w", err)
		}

		if jsonOutput {
			return outputJSON(map[string]string{"publicKey": pubKey})
		}

		fmt.Print(pubKey)
		return nil
	},
}

func init() {
	adminPublicKeyCmd.Flags().String("key-id", "", "Key identifier (required)")
}

// Admin audit command
var adminAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Query audit logs",
	Long:  "Retrieves audit log entries with optional filtering.",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		action, _ := cmd.Flags().GetString("action")
		subject, _ := cmd.Flags().GetString("subject")
		startDate, _ := cmd.Flags().GetString("start-date")
		endDate, _ := cmd.Flags().GetString("end-date")

		c, err := newAdminClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		filter := client.AuditFilter{
			Limit:   limit,
			Offset:  offset,
			Action:  action,
			Subject: subject,
		}

		if startDate != "" {
			t, err := time.Parse(time.RFC3339, startDate)
			if err != nil {
				return fmt.Errorf("invalid start-date format (use RFC3339): %w", err)
			}
			filter.StartDate = t
		}
		if endDate != "" {
			t, err := time.Parse(time.RFC3339, endDate)
			if err != nil {
				return fmt.Errorf("invalid end-date format (use RFC3339): %w", err)
			}
			filter.EndDate = t
		}

		result, err := c.AuditLogs(ctx, filter)
		if err != nil {
			if client.IsAuthError(err) {
				return fmt.Errorf("authentication failed: %w", err)
			}
			return fmt.Errorf("failed to get audit logs: %w", err)
		}

		if jsonOutput {
			// We need to match the structure of the original output if possible, or just dump the result
			// The wrapper returns AuditResult which has Logs []AuditLog
			// The original returned the raw JSON200 which had Logs *[]AuditLog
			// It should be close enough.
			return outputJSON(result)
		}

		if len(result.Logs) == 0 {
			fmt.Println("No audit logs found")
			return nil
		}

		fmt.Printf("Audit logs (%d entries):\n", result.Count)
		for _, log := range result.Logs {
			fmt.Printf("\n  ID: %s\n", log.ID)
			fmt.Printf("    Timestamp: %s\n", log.Timestamp)
			fmt.Printf("    Action: %s\n", log.Action)
			fmt.Printf("    Subject: %s\n", log.Subject)
			fmt.Printf("    Key ID: %s\n", log.KeyID)
			fmt.Printf("    Success: %v\n", log.Success)
			if log.ErrorCode != nil {
				fmt.Printf("    Error: %s\n", *log.ErrorCode)
			}
			if len(log.Metadata) > 0 {
				// Pretty print metadata if it's valid JSON
				var meta map[string]any
				if err := json.Unmarshal(log.Metadata, &meta); err == nil {
					parts := make([]string, 0, len(meta))
					for k, v := range meta {
						parts = append(parts, fmt.Sprintf("%s=%v", k, v))
					}
					fmt.Printf("    Metadata: %s\n", strings.Join(parts, ", "))
				} else {
					fmt.Printf("    Metadata: %s\n", string(log.Metadata))
				}
			}
		}

		return nil
	},
}

func init() {
	adminAuditCmd.Flags().Int("limit", 100, "Maximum number of entries (1-1000)")
	adminAuditCmd.Flags().Int("offset", 0, "Number of entries to skip")
	adminAuditCmd.Flags().String("action", "", "Filter by action (sign, key_upload, key_rotate)")
	adminAuditCmd.Flags().String("subject", "", "Filter by subject")
	adminAuditCmd.Flags().String("start-date", "", "Start date (RFC3339 format)")
	adminAuditCmd.Flags().String("end-date", "", "End date (RFC3339 format)")
}
