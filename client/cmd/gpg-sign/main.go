// Package main provides a CLI for the GPG Signing Service.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/api"
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
func newClient() (*api.ClientWithResponses, error) {
	httpClient := &http.Client{Timeout: timeout}
	return api.NewClientWithResponses(getBaseURL(), api.WithHTTPClient(httpClient))
}

// addOIDCAuth adds OIDC bearer token to request
func addOIDCAuth(ctx context.Context, req *http.Request) error {
	t := getToken()
	if t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	return nil
}

// addAdminAuth adds admin bearer token to request
func addAdminAuth(ctx context.Context, req *http.Request) error {
	t := getAdminToken()
	if t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	return nil
}

// outputJSON prints the value as JSON
func outputJSON(v interface{}) error {
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
		fmt.Printf("Timestamp: %s\n", health.Timestamp)
		fmt.Printf("Checks:\n")
		fmt.Printf("  Key Storage: %v\n", health.Checks.KeyStorage)
		fmt.Printf("  Database: %v\n", health.Checks.Database)

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

		var keyIDPtr *string
		if keyID != "" {
			keyIDPtr = &keyID
		}

		resp, err := c.GetPublicKeyWithResponse(ctx, &api.GetPublicKeyParams{KeyId: keyIDPtr})
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}

		if resp.StatusCode() == 404 {
			return fmt.Errorf("key not found")
		}

		if resp.StatusCode() != 200 {
			return fmt.Errorf("failed to get public key: status %d", resp.StatusCode())
		}

		pubKey := string(resp.Body)

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

		httpClient := &http.Client{Timeout: timeout}
		c, err := api.NewClientWithResponses(getBaseURL(),
			api.WithHTTPClient(httpClient),
			api.WithRequestEditorFn(addOIDCAuth))
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var keyIDPtr *string
		if keyID != "" {
			keyIDPtr = &keyID
		}

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

		if jsonOutput {
			result := map[string]interface{}{
				"signature": signature,
			}
			// Check for rate limit headers
			if remaining := resp.HTTPResponse.Header.Get("X-RateLimit-Remaining"); remaining != "" {
				result["rateLimitRemaining"] = remaining
			}
			return outputJSON(result)
		}

		fmt.Print(signature)
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

// newAdminClient creates a client with admin auth
func newAdminClient() (*api.ClientWithResponses, error) {
	httpClient := &http.Client{Timeout: timeout}
	return api.NewClientWithResponses(getBaseURL(),
		api.WithHTTPClient(httpClient),
		api.WithRequestEditorFn(addAdminAuth))
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

		body := api.UploadKeyJSONRequestBody{
			ArmoredPrivateKey: string(keyData),
			KeyId:             keyID,
		}

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

		if jsonOutput {
			return outputJSON(result)
		}

		fmt.Printf("Key uploaded successfully\n")
		fmt.Printf("  Key ID: %s\n", result.KeyId)
		fmt.Printf("  Fingerprint: %s\n", result.Fingerprint)
		fmt.Printf("  Algorithm: %s\n", result.Algorithm)
		if result.UserId != "" {
			fmt.Printf("  User ID: %s\n", result.UserId)
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

		resp, err := c.ListKeysWithResponse(ctx)
		if err != nil {
			return fmt.Errorf("failed to list keys: %w", err)
		}

		if resp.JSON401 != nil {
			return fmt.Errorf("authentication failed: %s", resp.JSON401.Error)
		}

		if resp.JSON200 == nil {
			return fmt.Errorf("failed to list keys: status %d", resp.StatusCode())
		}

		result := resp.JSON200

		if jsonOutput {
			return outputJSON(result)
		}

		if result.Keys == nil || len(*result.Keys) == 0 {
			fmt.Println("No keys found")
			return nil
		}

		keys := *result.Keys
		fmt.Printf("Keys (%d):\n", len(keys))
		for _, key := range keys {
			fmt.Printf("\n  Key ID: %s\n", key.KeyId)
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

		resp, err := c.DeleteKeyWithResponse(ctx, keyID, &api.DeleteKeyParams{})
		if err != nil {
			return fmt.Errorf("failed to delete key: %w", err)
		}

		if resp.JSON401 != nil {
			return fmt.Errorf("authentication failed: %s", resp.JSON401.Error)
		}

		if resp.JSON200 == nil {
			return fmt.Errorf("failed to delete key: status %d", resp.StatusCode())
		}

		result := resp.JSON200

		if jsonOutput {
			return outputJSON(result)
		}

		if result.Deleted != nil && *result.Deleted {
			fmt.Printf("Key '%s' deleted successfully\n", keyID)
		} else {
			fmt.Printf("Key '%s' was not found\n", keyID)
		}

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

		resp, err := c.GetAdminPublicKeyWithResponse(ctx, keyID)
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}

		if resp.JSON401 != nil {
			return fmt.Errorf("authentication failed: %s", resp.JSON401.Error)
		}

		if resp.StatusCode() == 404 {
			return fmt.Errorf("key not found")
		}

		if resp.StatusCode() != 200 {
			return fmt.Errorf("failed to get public key: status %d", resp.StatusCode())
		}

		pubKey := string(resp.Body)

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

		params := &api.GetAuditLogsParams{}
		if limit > 0 {
			params.Limit = &limit
		}
		if offset > 0 {
			params.Offset = &offset
		}
		if action != "" {
			actionParam := api.GetAuditLogsParamsAction(action)
			params.Action = &actionParam
		}
		if subject != "" {
			params.Subject = &subject
		}
		if startDate != "" {
			t, err := time.Parse(time.RFC3339, startDate)
			if err != nil {
				return fmt.Errorf("invalid start-date format (use RFC3339): %w", err)
			}
			params.StartDate = &t
		}
		if endDate != "" {
			t, err := time.Parse(time.RFC3339, endDate)
			if err != nil {
				return fmt.Errorf("invalid end-date format (use RFC3339): %w", err)
			}
			params.EndDate = &t
		}

		resp, err := c.GetAuditLogsWithResponse(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to get audit logs: %w", err)
		}

		if resp.JSON401 != nil {
			return fmt.Errorf("authentication failed: %s", resp.JSON401.Error)
		}

		if resp.JSON200 == nil {
			return fmt.Errorf("failed to get audit logs: status %d", resp.StatusCode())
		}

		result := resp.JSON200

		if jsonOutput {
			return outputJSON(result)
		}

		if result.Logs == nil || len(*result.Logs) == 0 {
			fmt.Println("No audit logs found")
			return nil
		}

		logs := *result.Logs
		fmt.Printf("Audit logs (%d entries):\n", result.Count)
		for _, log := range logs {
			fmt.Printf("\n  ID: %s\n", log.Id)
			fmt.Printf("    Timestamp: %s\n", log.Timestamp)
			fmt.Printf("    Action: %s\n", log.Action)
			fmt.Printf("    Subject: %s\n", log.Subject)
			fmt.Printf("    Key ID: %s\n", log.KeyId)
			fmt.Printf("    Success: %v\n", log.Success)
			if log.ErrorCode != nil {
				fmt.Printf("    Error: %s\n", *log.ErrorCode)
			}
			if len(log.Metadata) > 0 {
				// Pretty print metadata if it's valid JSON
				var meta map[string]interface{}
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
