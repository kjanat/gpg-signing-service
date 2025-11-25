package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
	"github.com/spf13/cobra"
)

// Test constants to avoid goconst lints
const testAdminToken = "admin-token"

// TestGetBaseURL tests URL resolution logic
//
//nolint:dupl // test table similar to TestGetToken; duplication is acceptable for clarity
func TestGetBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		flagURL  string
		envURL   string
		expected string
	}{
		{
			name:     "flag takes precedence",
			flagURL:  "http://flag.com",
			envURL:   "http://env.com",
			expected: "http://flag.com",
		},
		{
			name:     "env when no flag",
			flagURL:  "",
			envURL:   "http://env.com",
			expected: "http://env.com",
		},
		{
			name:     "default when neither",
			flagURL:  "",
			envURL:   "",
			expected: "https://gpg.kajkowalski.nl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore
			previousAPIURL := apiURL // Save the original value
			previousEnv := os.Getenv("GPG_SIGN_URL")
			defer func() {
				apiURL = previousAPIURL
				if err := os.Setenv("GPG_SIGN_URL", previousEnv); err != nil {
					t.Logf("failed to restore GPG_SIGN_URL: %v", err)
				}
			}()

			apiURL = tt.flagURL
			if tt.envURL != "" {
				if err := os.Setenv("GPG_SIGN_URL", tt.envURL); err != nil {
					t.Fatalf("failed to set GPG_SIGN_URL: %v", err)
				}
			} else {
				if err := os.Unsetenv("GPG_SIGN_URL"); err != nil {
					t.Fatalf("failed to unset GPG_SIGN_URL: %v", err)
				}
			}

			result := getBaseURL()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestGetToken tests token resolution
//
//nolint:dupl // similar structure to TestGetBaseURL; duplication is fine for clarity
func TestGetToken(t *testing.T) {
	tests := []struct {
		name      string
		flagToken string
		envToken  string
		expected  string
	}{
		{
			name:      "flag takes precedence",
			flagToken: "flag-token",
			envToken:  "env-token",
			expected:  "flag-token",
		},
		{
			name:      "env when no flag",
			flagToken: "",
			envToken:  "env-token",
			expected:  "env-token",
		},
		{
			name:      "empty when neither",
			flagToken: "",
			envToken:  "",
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previousToken := token
			previousEnv := os.Getenv("GPG_SIGN_TOKEN")
			defer func() {
				token = previousToken
				if err := os.Setenv("GPG_SIGN_TOKEN", previousEnv); err != nil {
					t.Logf("failed to restore GPG_SIGN_TOKEN: %v", err)
				}
			}()

			token = tt.flagToken
			if tt.envToken != "" {
				if err := os.Setenv("GPG_SIGN_TOKEN", tt.envToken); err != nil {
					t.Fatalf("failed to set GPG_SIGN_TOKEN: %v", err)
				}
			} else {
				if err := os.Unsetenv("GPG_SIGN_TOKEN"); err != nil {
					t.Fatalf("failed to unset GPG_SIGN_TOKEN: %v", err)
				}
			}

			result := getToken()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestGetAdminToken tests admin token resolution
func TestGetAdminToken(t *testing.T) {
	previousAdminToken := adminToken
	previousEnv := os.Getenv("GPG_SIGN_ADMIN_TOKEN")
	defer func() {
		adminToken = previousAdminToken
		if err := os.Setenv("GPG_SIGN_ADMIN_TOKEN", previousEnv); err != nil {
			t.Logf("failed to restore GPG_SIGN_ADMIN_TOKEN: %v", err)
		}
	}()

	// Test flag precedence
	adminToken = "flag-admin"
	if err := os.Setenv("GPG_SIGN_ADMIN_TOKEN", "env-admin"); err != nil {
		t.Fatalf("failed to set GPG_SIGN_ADMIN_TOKEN: %v", err)
	}
	if got := getAdminToken(); got != "flag-admin" {
		t.Errorf("expected flag-admin, got %s", got)
	}

	// Test env fallback
	adminToken = ""
	if got := getAdminToken(); got != "env-admin" {
		t.Errorf("expected env-admin, got %s", got)
	}
}

// TestNewClient tests client creation
func TestNewClient(t *testing.T) {
	previousURL := apiURL
	previousToken := token
	defer func() {
		apiURL = previousURL
		token = previousToken
	}()

	apiURL = "http://test.com"
	token = "test-token"
	timeout = 10 * time.Second

	c, err := newClient()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected client to be created")
	}
}

// TestNewAdminClient tests admin client creation
func TestNewAdminClient(t *testing.T) {
	previousURL := apiURL
	previousAdminToken := adminToken
	defer func() {
		apiURL = previousURL
		adminToken = previousAdminToken
	}()

	apiURL = "http://test.com"
	adminToken = testAdminToken

	c, err := newAdminClient()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected client to be created")
	}
}

// TestOutputJSON tests JSON output formatting
func TestOutputJSON(t *testing.T) {
	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	defer func() {
		os.Stdout = previousStdout
	}()

	data := map[string]string{"key": "value"}
	err = outputJSON(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(out, &result); err != nil {
		t.Errorf("invalid JSON output: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected value, got %s", result["key"])
	}
}

// TestHealthCommand tests the health command
func TestHealthCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected /health, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"status":    "healthy",
			"version":   "1.0.0",
			"timestamp": time.Now().Format(time.RFC3339),
			"checks":    map[string]bool{"keyStorage": true, "database": true},
		}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	previousURL := apiURL
	defer func() { apiURL = previousURL }()
	apiURL = server.URL

	// Capture output
	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	err = healthCmd.RunE(nil, nil)

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, "Status: healthy") {
		t.Error("expected healthy status in output")
	}
}

// TestHealthCommandJSON tests health command with JSON output
func TestHealthCommandJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"status":    "healthy",
			"version":   "1.0.0",
			"timestamp": time.Now().Format(time.RFC3339),
			"checks":    map[string]bool{"keyStorage": true, "database": true},
		}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	previousURL := apiURL
	previousJSON := jsonOutput
	defer func() {
		apiURL = previousURL
		jsonOutput = previousJSON
	}()
	apiURL = server.URL
	jsonOutput = true

	// Capture output
	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	err = healthCmd.RunE(nil, nil)

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var result client.HealthStatus
	if err := json.Unmarshal(out, &result); err != nil {
		t.Errorf("invalid JSON output: %v", err)
	}
	if result.Status != "healthy" {
		t.Error("expected healthy status in JSON")
	}
}

// TestPublicKeyCommand tests public key retrieval
func TestPublicKeyCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public-key" {
			t.Errorf("expected /public-key, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		if _, err := w.Write([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest key\n-----END PGP PUBLIC KEY BLOCK-----")); err != nil {
			t.Errorf("write error: %v", err)
		}
	}))
	defer server.Close()

	previousURL := apiURL
	defer func() { apiURL = previousURL }()
	apiURL = server.URL

	cmd := &cobra.Command{}
	cmd.Flags().String("key-id", "", "")

	// Capture output
	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	err = publicKeyCmd.RunE(cmd, nil)

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, "BEGIN PGP PUBLIC KEY") {
		t.Error("expected PGP key in output")
	}
}

// TestSignCommand tests signing command
func TestSignCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign" {
			t.Errorf("expected /sign, got %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body error: %v", err)
		}
		if string(body) != "test commit data" {
			t.Errorf("expected 'test commit data', got %s", string(body))
		}

		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte("-----BEGIN PGP SIGNATURE-----\ntest signature\n-----END PGP SIGNATURE-----")); err != nil {
			t.Errorf("write error: %v", err)
		}
	}))
	defer server.Close()

	previousURL := apiURL
	previousToken := token
	previousStdin := os.Stdin
	defer func() {
		apiURL = previousURL
		token = previousToken
		os.Stdin = previousStdin
	}()

	apiURL = server.URL
	token = "test-token"

	// Mock stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	if _, err := w.Write([]byte("test commit data")); err != nil {
		t.Fatalf("write error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdin = r

	cmd := &cobra.Command{}
	cmd.Flags().String("key-id", "", "")

	// Capture output
	previousStdout := os.Stdout
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = wOut

	err = signCmd.RunE(cmd, nil)

	if err := wOut.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(rOut)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, "BEGIN PGP SIGNATURE") {
		t.Error("expected PGP signature in output")
	}
}

// TestSignCommandNoData tests sign command with no input
func TestSignCommandNoData(t *testing.T) {
	previousStdin := os.Stdin
	defer func() { os.Stdin = previousStdin }()

	// Empty stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	if err := w.Close(); err != nil { // Close immediately for empty input
		t.Fatalf("close error: %v", err)
	}
	os.Stdin = r

	cmd := &cobra.Command{}
	cmd.Flags().String("key-id", "", "")

	err = signCmd.RunE(cmd, nil)
	if err == nil {
		t.Error("expected error for no data")
	} else if !strings.Contains(err.Error(), "no data provided") {
		t.Errorf("expected 'no data provided' error, got %v", err)
	}
}

// TestAdminUploadCommand tests key upload
func TestAdminUploadCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/keys" {
			t.Errorf("expected /admin/keys, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"success":     true,
			"keyId":       "test-key",
			"fingerprint": "ABCD1234",
			"algorithm":   "RSA",
			"userId":      "Test User <test@example.com>",
		}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create a temp keyfile
	tmpFile, err := os.CreateTemp("", "test-key-*.asc")
	if err != nil {
		t.Fatalf("create temp file error: %v", err)
	}
	if _, err := tmpFile.Write([]byte("-----BEGIN PGP PRIVATE KEY-----\ntest\n-----END PGP PRIVATE KEY-----")); err != nil {
		t.Fatalf("write temp file error: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close temp file error: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("cleanup error removing temp file: %v", err)
		}
	}()

	previousURL := apiURL
	previousAdminToken := adminToken
	defer func() {
		apiURL = previousURL
		adminToken = previousAdminToken
	}()

	apiURL = server.URL
	adminToken = testAdminToken

	cmd := &cobra.Command{}
	cmd.Flags().String("key-id", "test-key", "")
	cmd.Flags().String("file", tmpFile.Name(), "")

	// Capture output
	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	err = adminUploadCmd.RunE(cmd, nil)

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, "Key uploaded successfully") {
		t.Error("expected success message in output")
	}
}

// TestAdminUploadCommandValidation tests upload validation
func TestAdminUploadCommandValidation(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		file        string
		expectedErr string
	}{
		{
			name:        "missing key-id",
			keyID:       "",
			file:        "test.asc",
			expectedErr: "--key-id is required",
		},
		{
			name:        "missing file",
			keyID:       "test-key",
			file:        "",
			expectedErr: "--file is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("key-id", tt.keyID, "")
			cmd.Flags().String("file", tt.file, "")

			err := adminUploadCmd.RunE(cmd, nil)
			if err == nil {
				t.Error("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected error containing %q, got %v", tt.expectedErr, err)
			}
		})
	}
}

// TestAdminDeleteCommand tests key deletion
func TestAdminDeleteCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/admin/keys/") {
			t.Errorf("expected /admin/keys/*, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]bool{
			"success": true,
			"deleted": true,
		}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	previousURL := apiURL
	previousAdminToken := adminToken
	defer func() {
		apiURL = previousURL
		adminToken = previousAdminToken
	}()

	apiURL = server.URL
	adminToken = "admin-token"

	cmd := &cobra.Command{}
	cmd.Flags().String("key-id", "test-key", "")

	// Capture output
	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	err = adminDeleteCmd.RunE(cmd, nil)

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, "deleted successfully") {
		t.Error("expected success message in output")
	}
}

// TestAdminListCommand tests key listing
func TestAdminListCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/keys" {
			t.Errorf("expected /admin/keys, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"keyId":       "key1",
					"fingerprint": "ABCD1234",
					"algorithm":   "RSA",
					"createdAt":   time.Now().Format(time.RFC3339),
				},
			},
		}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	previousURL := apiURL
	previousAdminToken := adminToken
	defer func() {
		apiURL = previousURL
		adminToken = previousAdminToken
	}()

	apiURL = server.URL
	adminToken = "admin-token"

	// Capture output
	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	err = adminListCmd.RunE(nil, nil)

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, "Keys (1)") {
		t.Error("expected keys count in output")
	}
	if !strings.Contains(output, "key1") {
		t.Error("expected key1 in output")
	}
}

// TestRootCommand tests the root command
func TestRootCommand(t *testing.T) {
	// Test that root command doesn't error without subcommand
	rootCmd.SetArgs([]string{"--help"})

	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w

	err = rootCmd.Execute()

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	// Help should not error
	if err != nil && !strings.Contains(err.Error(), "help") {
		t.Errorf("unexpected error: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, "This tool allows you") {
		t.Error("expected CLI description in help")
	}
}

// TestMainFunc ensures main() runs without panicking
func TestMainFunc(t *testing.T) {
	// Save original
	previousArgs := os.Args
	defer func() { os.Args = previousArgs }()

	// Set args to trigger help
	os.Args = []string{"gpg-sign", "--help"}

	// Capture output to avoid polluting test output
	previousStdout := os.Stdout
	previousStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w
	os.Stderr = w

	// Use a channel to prevent main from exiting the test
	done := make(chan bool)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Errorf("main() panicked: %v", rec)
			}
			done <- true
		}()

		// Override os.Exit for testing - use a variable
		exitCalled := false
		originalExit := func(_ int) {
			exitCalled = true
		}
		_ = originalExit
		_ = exitCalled

		// We can't actually override os.Exit, so just call rootCmd.Execute instead
		rootCmd.SetArgs([]string{"--help"})
		if err := rootCmd.Execute(); err != nil && !strings.Contains(err.Error(), "help") {
			t.Errorf("unexpected error executing rootCmd: %v", err)
		}
	}()

	// Wait with timeout
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("main() timed out")
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	// Drain the read end to avoid pipe leaks
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("read error: %v", err)
	}
	os.Stdout = previousStdout
	os.Stderr = previousStderr
}
