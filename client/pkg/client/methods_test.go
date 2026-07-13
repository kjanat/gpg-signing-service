package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// runPublicKeyTest is a helper function to test public key retrieval methods
func runPublicKeyTest(
	t *testing.T,
	keyContent string,
	callMethod func(*Client, context.Context, string) (string, error),
	tests []struct {
		name         string
		keyID        string
		serverStatus int
		wantErr      bool
		validateResp func(t *testing.T, key string)
	},
) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if tt.serverStatus == 200 {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(w, keyContent)
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.serverStatus)
					_ = json.NewEncoder(w).Encode(map[string]string{
						fieldCode:  "KEY_NOT_FOUND",
						fieldError: testMsgKeyNotFound,
					})
				}
			}))
			defer server.Close()

			client, _ := New(server.URL)
			key, err := callMethod(client, context.Background(), tt.keyID)

			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validateResp != nil {
				tt.validateResp(t, key)
			}
		})
	}
}

// TestHealth tests the Health() method
func TestHealth(t *testing.T) {
	tests := []struct {
		name         string
		serverStatus int
		responseBody any
		wantErr      bool
		validateResp func(t *testing.T, status *HealthStatus)
	}{
		{
			name:         "healthy service",
			serverStatus: 200,
			responseBody: map[string]any{
				fieldStatus:    StatusHealthy,
				fieldVersion:   testVersion,
				fieldTimestamp: time.Now().Format(time.RFC3339),
				fieldChecks: map[string]any{
					fieldKeyStorage: true,
					fieldDatabase:   true,
				},
			},
			wantErr: false,
			validateResp: func(t *testing.T, status *HealthStatus) {
				if status == nil {
					t.Fatal("health status is nil")
				}
				if status.Status != StatusHealthy {
					t.Errorf("expected status 'healthy', got %q", status.Status)
				}
				if status.Version != testVersion {
					t.Errorf("expected version '1.0.0', got %q", status.Version)
				}
				if !status.KeyStorage {
					t.Error("expected KeyStorage true")
				}
				if !status.Database {
					t.Error("expected Database true")
				}
				if !status.IsHealthy() {
					t.Error("expected IsHealthy() to return true")
				}
			},
		},
		{
			name:         "degraded service (503)",
			serverStatus: 503,
			responseBody: map[string]any{
				fieldStatus:    "degraded",
				fieldVersion:   testVersion,
				fieldTimestamp: time.Now().Format(time.RFC3339),
				fieldChecks: map[string]any{
					fieldKeyStorage: false,
					fieldDatabase:   true,
				},
			},
			wantErr: true,
			validateResp: func(t *testing.T, status *HealthStatus) {
				if status == nil {
					t.Fatal("health status is nil")
				}
				if status.Status != "degraded" {
					t.Errorf("expected status 'degraded', got %q", status.Status)
				}
				if status.IsHealthy() {
					t.Error("expected IsHealthy() to return false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_ = json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			client, _ := New(server.URL)
			status, err := client.Health(context.Background())

			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validateResp != nil {
				tt.validateResp(t, status)
			}
		})
	}
}

// TestPublicKey tests the PublicKey() method
func TestPublicKey(t *testing.T) {
	publicKeyPEM := `-----BEGIN PGP PUBLIC KEY BLOCK-----
test-key-data
-----END PGP PUBLIC KEY BLOCK-----`

	tests := []struct {
		name         string
		keyID        string
		serverStatus int
		wantErr      bool
		validateResp func(t *testing.T, key string)
	}{
		{
			name:         "get default public key",
			keyID:        "",
			serverStatus: 200,
			wantErr:      false,
			validateResp: func(t *testing.T, key string) {
				if key != publicKeyPEM {
					t.Errorf("expected key %q, got %q", publicKeyPEM, key)
				}
			},
		},
		{
			name:         "get specific public key",
			keyID:        testKeyID,
			serverStatus: 200,
			wantErr:      false,
			validateResp: func(t *testing.T, key string) {
				if key != publicKeyPEM {
					t.Errorf("expected key %q, got %q", publicKeyPEM, key)
				}
			},
		},
		{
			name:         testMsgKeyNotFound,
			keyID:        testKeyIDMissing,
			serverStatus: 404,
			wantErr:      true,
		},
		{
			name:         testMsgServerError,
			keyID:        testKeyID,
			serverStatus: 500,
			wantErr:      true,
		},
	}

	runPublicKeyTest(t, publicKeyPEM, (*Client).PublicKey, tests)
}

// TestUploadKey tests the UploadKey() method
func TestUploadKey(t *testing.T) {
	tests := []struct {
		name         string
		keyID        string
		privateKey   string
		serverStatus int
		wantErr      bool
		validateResp func(t *testing.T, info *KeyInfo)
	}{
		{
			name:       "empty keyID",
			keyID:      "",
			privateKey: "test-key",
			wantErr:    true,
		},
		{
			name:       "empty private key",
			keyID:      testKeyID,
			privateKey: "",
			wantErr:    true,
		},
		{
			name:         "successful upload",
			keyID:        testKeyID,
			privateKey:   "-----BEGIN PGP PRIVATE KEY-----\ntest\n-----END PGP PRIVATE KEY-----",
			serverStatus: 201,
			wantErr:      false,
			validateResp: func(t *testing.T, info *KeyInfo) {
				if info == nil {
					t.Fatal("KeyInfo is nil")
				}
				if info.KeyID != testKeyID {
					t.Errorf("expected KeyID 'key-123', got %q", info.KeyID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_ = json.NewEncoder(w).Encode(map[string]string{
					fieldKeyID:       testKeyID,
					fieldFingerprint: "ABC123",
					fieldAlgorithm:   testAlgorithmRSA,
					"userId":         "test@example.com",
				})
			}))
			defer server.Close()

			client, _ := New(server.URL)
			info, err := client.UploadKey(context.Background(), tt.keyID, tt.privateKey)

			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validateResp != nil {
				tt.validateResp(t, info)
			}
		})
	}
}

// TestListKeys tests the ListKeys() method
func TestListKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					fieldKeyID:       testKeyID1,
					fieldFingerprint: "AAAA",
					fieldAlgorithm:   testAlgorithmRSA,
					"createdAt":      time.Now().Format(time.RFC3339),
				},
				{
					fieldKeyID:       "key-2",
					fieldFingerprint: "BBBB",
					fieldAlgorithm:   "ED25519",
					"createdAt":      time.Now().Format(time.RFC3339),
				},
			},
		})
	}))
	defer server.Close()

	client, _ := New(server.URL)
	keys, err := client.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].KeyID != testKeyID1 {
		t.Errorf("expected first key 'key-1', got %q", keys[0].KeyID)
	}
	if keys[1].Algorithm != "ED25519" {
		t.Errorf("expected second key algorithm 'ED25519', got %q", keys[1].Algorithm)
	}
}

// TestDeleteKey tests the DeleteKey() method
func TestDeleteKey(t *testing.T) {
	tests := []struct {
		name         string
		keyID        string
		serverStatus int
		deleted      bool
		wantErr      bool
	}{
		{
			name:         "successful delete",
			keyID:        testKeyID,
			serverStatus: 200,
			deleted:      true,
			wantErr:      false,
		},
		{
			name:         testMsgKeyNotFound,
			keyID:        testKeyIDMissing,
			serverStatus: 200,
			deleted:      false,
			wantErr:      true,
		},
		{
			name:         testMsgServerError,
			keyID:        testKeyID,
			serverStatus: 500,
			deleted:      false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE, got %s", r.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_ = json.NewEncoder(w).Encode(map[string]bool{
					"deleted": tt.deleted,
				})
			}))
			defer server.Close()

			client, _ := New(server.URL)
			err := client.DeleteKey(context.Background(), tt.keyID)

			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestAuditLogs tests the AuditLogs() method
func TestAuditLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		// Verify filter parameters are passed
		if limit := r.URL.Query().Get("limit"); limit != "" {
			if limit != "10" {
				t.Errorf("expected limit '10', got %q", limit)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			fieldLogs: []map[string]any{
				{
					"id":           testRequestID,
					fieldTimestamp: time.Now().Format(time.RFC3339),
					"requestId":    "550e8400-e29b-41d4-a716-446655440001",
					"action":       testOpSignLower,
					"issuer":       "user@example.com",
					"subject":      testKeyID1,
					fieldKeyID:     testKeyID1,
					fieldSuccess:   true,
				},
			},
			fieldCount: 1,
		})
	}))
	defer server.Close()

	client, _ := New(server.URL)

	filter := AuditFilter{
		Limit: 10,
	}
	result, err := client.AuditLogs(context.Background(), filter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("audit result is nil")
	}
	if len(result.Logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(result.Logs))
	}
	if result.Count != 1 {
		t.Errorf("expected count 1, got %d", result.Count)
	}
	if result.Logs[0].Action != testOpSignLower {
		t.Errorf("expected action 'sign', got %q", result.Logs[0].Action)
	}
}

// TestAdminPublicKey tests the AdminPublicKey() method
func TestAdminPublicKey(t *testing.T) {
	publicKey := `-----BEGIN PGP PUBLIC KEY-----
test-key
-----END PGP PUBLIC KEY BLOCK-----`

	tests := []struct {
		name         string
		keyID        string
		serverStatus int
		wantErr      bool
		validateResp func(t *testing.T, key string)
	}{
		{
			name:         "empty keyID returns error",
			keyID:        "",
			serverStatus: 200,
			wantErr:      true,
		},
		{
			name:         "successful retrieval",
			keyID:        testKeyID,
			serverStatus: 200,
			wantErr:      false,
			validateResp: func(t *testing.T, key string) {
				if key != publicKey {
					t.Errorf("expected key %q, got %q", publicKey, key)
				}
			},
		},
		{
			name:         testMsgKeyNotFound,
			keyID:        testKeyIDMissing,
			serverStatus: 404,
			wantErr:      true,
		},
	}

	runPublicKeyTest(t, publicKey, (*Client).AdminPublicKey, tests)
}

// TestAuditFilterWithAllFields tests AuditFilter with all fields populated
func TestAuditFilterWithAllFields(t *testing.T) {
	startDate := time.Now().Add(-24 * time.Hour)
	endDate := time.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			fieldLogs:  []map[string]any{},
			fieldCount: 0,
		})
	}))
	defer server.Close()

	client, _ := New(server.URL)

	filter := AuditFilter{
		Limit:     20,
		Offset:    10,
		Action:    testOpSignLower,
		Subject:   "user-123",
		StartDate: startDate,
		EndDate:   endDate,
	}

	result, err := client.AuditLogs(context.Background(), filter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("audit result is nil")
	}
}

// BenchmarkHealth benchmarks Health() method
func BenchmarkHealth(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			fieldStatus:    StatusHealthy,
			fieldVersion:   testVersion,
			fieldTimestamp: time.Now().Format(time.RFC3339),
			fieldChecks: map[string]any{
				fieldKeyStorage: true,
				fieldDatabase:   true,
			},
		})
	}))
	defer server.Close()

	client, _ := New(server.URL)

	for b.Loop() {
		_, _ = client.Health(context.Background())
	}
}

// BenchmarkPublicKey benchmarks PublicKey() method
func BenchmarkPublicKey(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "-----BEGIN PGP PUBLIC KEY-----\ntest\n-----END PGP PUBLIC KEY-----")
	}))
	defer server.Close()

	client, _ := New(server.URL)

	for b.Loop() {
		_, _ = client.PublicKey(context.Background(), "")
	}
}
