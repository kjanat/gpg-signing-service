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
				"status":    "healthy",
				"version":   "1.0.0",
				"timestamp": time.Now().Format(time.RFC3339),
				"checks": map[string]any{
					"keyStorage": true,
					"database":   true,
				},
			},
			wantErr: false,
			validateResp: func(t *testing.T, status *HealthStatus) {
				if status == nil {
					t.Fatal("health status is nil")
				}
				if status.Status != "healthy" {
					t.Errorf("expected status 'healthy', got %q", status.Status)
				}
				if status.Version != "1.0.0" {
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
				"status":    "degraded",
				"version":   "1.0.0",
				"timestamp": time.Now().Format(time.RFC3339),
				"checks": map[string]any{
					"keyStorage": false,
					"database":   true,
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
			keyID:        "key-123",
			serverStatus: 200,
			wantErr:      false,
			validateResp: func(t *testing.T, key string) {
				if key != publicKeyPEM {
					t.Errorf("expected key %q, got %q", publicKeyPEM, key)
				}
			},
		},
		{
			name:         "key not found",
			keyID:        "nonexistent",
			serverStatus: 404,
			wantErr:      true,
		},
		{
			name:         "server error",
			keyID:        "key-123",
			serverStatus: 500,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if tt.serverStatus == 200 {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(w, publicKeyPEM)
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.serverStatus)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"code":  "KEY_NOT_FOUND",
						"error": "key not found",
					})
				}
			}))
			defer server.Close()

			client, _ := New(server.URL)
			key, err := client.PublicKey(context.Background(), tt.keyID)

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
			keyID:      "key-123",
			privateKey: "",
			wantErr:    true,
		},
		{
			name:         "successful upload",
			keyID:        "key-123",
			privateKey:   "-----BEGIN PGP PRIVATE KEY-----\ntest\n-----END PGP PRIVATE KEY-----",
			serverStatus: 201,
			wantErr:      false,
			validateResp: func(t *testing.T, info *KeyInfo) {
				if info == nil {
					t.Fatal("KeyInfo is nil")
				}
				if info.KeyID != "key-123" {
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
					"keyId":       "key-123",
					"fingerprint": "ABC123",
					"algorithm":   "RSA",
					"userId":      "test@example.com",
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
					"keyId":       "key-1",
					"fingerprint": "AAAA",
					"algorithm":   "RSA",
					"createdAt":   time.Now().Format(time.RFC3339),
				},
				{
					"keyId":       "key-2",
					"fingerprint": "BBBB",
					"algorithm":   "ED25519",
					"createdAt":   time.Now().Format(time.RFC3339),
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
	if keys[0].KeyID != "key-1" {
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
			keyID:        "key-123",
			serverStatus: 200,
			deleted:      true,
			wantErr:      false,
		},
		{
			name:         "key not found",
			keyID:        "nonexistent",
			serverStatus: 200,
			deleted:      false,
			wantErr:      true,
		},
		{
			name:         "server error",
			keyID:        "key-123",
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
			"logs": []map[string]any{
				{
					"id":        "log-1",
					"timestamp": time.Now().Format(time.RFC3339),
					"requestId": "req-123",
					"action":    "sign",
					"issuer":    "user@example.com",
					"subject":   "key-1",
					"keyId":     "key-1",
					"success":   true,
				},
			},
			"count": 1,
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
	if result.Logs[0].Action != "sign" {
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
			keyID:        "key-123",
			serverStatus: 200,
			wantErr:      false,
			validateResp: func(t *testing.T, key string) {
				if key != publicKey {
					t.Errorf("expected key %q, got %q", publicKey, key)
				}
			},
		},
		{
			name:         "key not found",
			keyID:        "nonexistent",
			serverStatus: 404,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if tt.serverStatus == 200 {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(w, publicKey)
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.serverStatus)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"code":  "KEY_NOT_FOUND",
						"error": "key not found",
					})
				}
			}))
			defer server.Close()

			client, _ := New(server.URL)
			key, err := client.AdminPublicKey(context.Background(), tt.keyID)

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

// TestAuditFilterWithAllFields tests AuditFilter with all fields populated
func TestAuditFilterWithAllFields(t *testing.T) {
	startDate := time.Now().Add(-24 * time.Hour)
	endDate := time.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"logs":  []map[string]any{},
			"count": 0,
		})
	}))
	defer server.Close()

	client, _ := New(server.URL)

	filter := AuditFilter{
		Limit:     20,
		Offset:    10,
		Action:    "sign",
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "healthy",
			"version":   "1.0.0",
			"timestamp": time.Now().Format(time.RFC3339),
			"checks": map[string]any{
				"keyStorage": true,
				"database":   true,
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
