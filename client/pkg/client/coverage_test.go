package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestUnexpectedStatusResponses tests all methods handle unexpected status codes
func TestUnexpectedStatusResponses(t *testing.T) {
	unexpectedCodes := []int{418, 501, 502, 504, 506}

	for _, code := range unexpectedCodes {
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer server.Close()

			client, _ := New(server.URL, WithAdminToken("test"))
			ctx := context.Background()

			// Test Health
			_, err := client.Health(ctx)
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("Health: expected unexpected status error for code %d", code)
			}

			// Test PublicKey
			_, err = client.PublicKey(ctx, "")
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("PublicKey: expected unexpected status error for code %d", code)
			}

			// Test Sign
			_, err = client.Sign(ctx, "commit data", "")
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("Sign: expected unexpected status error for code %d", code)
			}

			// Test UploadKey
			_, err = client.UploadKey(ctx, "id", "key")
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("UploadKey: expected unexpected status error for code %d", code)
			}

			// Test ListKeys
			_, err = client.ListKeys(ctx)
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("ListKeys: expected unexpected status error for code %d", code)
			}

			// Test DeleteKey
			err = client.DeleteKey(ctx, "keyid")
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("DeleteKey: expected unexpected status error for code %d", code)
			}

			// Test AuditLogs
			_, err = client.AuditLogs(ctx, AuditFilter{})
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("AuditLogs: expected unexpected status error for code %d", code)
			}

			// Test AdminPublicKey
			_, err = client.AdminPublicKey(ctx, "keyid")
			if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("AdminPublicKey: expected unexpected status error for code %d", code)
			}
		})
	}
}

// TestMalformedJSONResponses tests handling of invalid JSON
func TestMalformedJSONResponses(t *testing.T) {
	testCases := []struct {
		name   string
		method string
		body   string
	}{
		{"Health", "GET", `{"status": "healthy", INVALID}`},
		{"Sign", "POST", `{"signature": "sig", BROKEN`},
		{"UploadKey", "POST", `{"success": true MISSING_BRACE`},
		{"ListKeys", "GET", `{"keys": [`},
		{"AuditLogs", "GET", `{"logs": [{"id": "not-a-uuid"}]}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.name == "Sign" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("invalid signature format"))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client, err := New(server.URL, WithAdminToken("test"))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}
			ctx := context.Background()

			switch tc.name {
			case "Health":
				_, err := client.Health(ctx)
				if err == nil {
					t.Error("expected JSON unmarshal error")
				}
			case "Sign":
				// Sign returns text content directly, not JSON,
				// so this test is not applicable, skip it
				return
			case "UploadKey":
				_, err := client.UploadKey(ctx, "id", "key")
				if err == nil {
					t.Error("expected JSON unmarshal error")
				}
			case "ListKeys":
				_, err := client.ListKeys(ctx)
				if err == nil {
					t.Error("expected JSON unmarshal error")
				}
			case "AuditLogs":
				_, err := client.AuditLogs(ctx, AuditFilter{})
				if err == nil {
					t.Error("expected invalid UUID error")
				}
			}
		})
	}
}

// TestSignMethodEdgeCases tests uncovered paths in Sign
func TestSignMethodEdgeCases(t *testing.T) {
	t.Run("401 with malformed error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`not json`))
		}))
		defer server.Close()

		client, err := New(server.URL)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		_, err = client.Sign(context.Background(), "data", "")
		if err == nil {
			t.Error("expected auth error")
		}
	})

	t.Run("429 with invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{invalid`))
		}))
		defer server.Close()

		client, err := New(server.URL)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		_, err = client.Sign(context.Background(), "data", "")
		if err == nil {
			t.Error("expected rate limit error")
		}
	})

	t.Run("200 with empty signature", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Return an empty body
		}))
		defer server.Close()

		client, err := New(server.URL)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		result, err := client.Sign(context.Background(), "data", "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil || result.Signature != "" {
			t.Error("expected empty signature in result")
		}
	})
}

// TestUploadKeyEdgeCases tests uncovered paths in UploadKey
func TestUploadKeyEdgeCases(t *testing.T) {
	t.Run("202 Accepted status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"keyId":   "test",
			})
		}))
		defer server.Close()

		client, err := New(server.URL, WithAdminToken("test"))
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		result, err := client.UploadKey(context.Background(), "id", "key")
		if err == nil {
			t.Error("expected unexpected status error for 202")
		}
		if result != nil {
			t.Error("expected nil result for error case")
		}
	})
}

// TestAuditLogsComplexFilters tests all filter combinations
func TestAuditLogsComplexFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify all query parameters are passed correctly
		query := r.URL.Query()
		expectedParams := []string{"limit", "offset", "action", "subject", "startDate", "endDate"}

		for _, param := range expectedParams {
			if val := query.Get(param); val == "" {
				t.Errorf("missing expected parameter: %s", param)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"logs":  []map[string]any{},
			"count": 0,
		})
	}))
	defer server.Close()

	client, err := New(server.URL, WithAdminToken("test"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	now := time.Now()
	filter := AuditFilter{
		Limit:     100,
		Offset:    50,
		Action:    "sign",
		Subject:   "test-subject",
		StartDate: now.Add(-24 * time.Hour),
		EndDate:   now,
	}

	_, err = client.AuditLogs(context.Background(), filter)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
