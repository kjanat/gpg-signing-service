package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSignMethodAllPaths tests all branches in Sign method
func TestSignMethodAllPaths(t *testing.T) {
	t.Run("400 with JSON error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "bad request",
				"code":  "INVALID_REQUEST",
			})
		}))
		defer server.Close()

		client, _ := New(server.URL)
		_, err := client.Sign(context.Background(), "data", "")
		if err == nil {
			t.Error("expected validation error")
		}
		validationError := &ValidationError{}
		if !errors.As(err, &validationError) {
			t.Errorf("expected ValidationError, got %T", err)
		}
	})

	t.Run("400 without JSON error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("plain text error"))
		}))
		defer server.Close()

		client, _ := New(server.URL)
		_, err := client.Sign(context.Background(), "data", "")
		if err == nil {
			t.Error("expected validation error")
		}
	})

	t.Run("500 with JSON error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":     "internal error",
				"code":      "INTERNAL_ERROR",
				"requestId": "550e8400-e29b-41d4-a716-446655440000",
			})
		}))
		defer server.Close()

		client, _ := New(server.URL)
		_, err := client.Sign(context.Background(), "data", "")
		if err == nil {
			t.Error("expected service error")
		}
		se := &ServiceError{}
		if errors.As(err, &se) {
			if se.RequestID != "550e8400-e29b-41d4-a716-446655440000" {
				t.Errorf("expected request ID 550e8400-e29b-41d4-a716-446655440000, got %s", se.RequestID)
			}
		} else {
			t.Errorf("expected ServiceError, got %T", err)
		}
	})

	t.Run("503 without JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client, _ := New(server.URL)
		_, err := client.Sign(context.Background(), "data", "")
		if err == nil {
			t.Error("expected service error")
		}
	})
}

// TestUploadKeyAllPaths tests all branches in the UploadKey method
func TestUploadKeyAllPaths(t *testing.T) {
	t.Run("200 fallback (non-standard success)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Return 200 instead of 201 to test the fallback path
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":     true,
				"keyId":       "test-key",
				"fingerprint": "ABCD1234",
				"algorithm":   "RSA",
				"userId":      "test@example.com",
			})
		}))
		defer server.Close()

		client, _ := New(server.URL, WithAdminToken("test"))
		_, err := client.UploadKey(context.Background(), "id", "key")
		// Should get unexpected status error since 200 is not expected
		if err == nil {
			t.Error("expected unexpected status error for 200")
		}
	})

	t.Run("400 with error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid key",
				"code":  "INVALID_KEY",
			})
		}))
		defer server.Close()

		client, _ := New(server.URL, WithAdminToken("test"))
		_, err := client.UploadKey(context.Background(), "id", "key")
		if err == nil {
			t.Error("expected validation error")
		}
	})

	t.Run("500 without JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client, _ := New(server.URL, WithAdminToken("test"))
		_, err := client.UploadKey(context.Background(), "id", "key")
		if err == nil {
			t.Error("expected service error")
		}
	})
}

// TestAuditLogsAllPaths tests all branches in the AuditLogs method
func TestAuditLogsAllPaths(t *testing.T) {
	t.Run("206 Partial Content (unexpected)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Return 206 to test unexpected status
			w.WriteHeader(http.StatusPartialContent)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"logs":  []any{},
				"count": 0,
			})
		}))
		defer server.Close()

		client, _ := New(server.URL, WithAdminToken("test"))
		_, err := client.AuditLogs(context.Background(), AuditFilter{})
		if err == nil {
			t.Error("expected unexpected status error for 206")
		}
	})

	t.Run("400 with error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid filter",
				"code":  "INVALID_REQUEST",
			})
		}))
		defer server.Close()

		client, _ := New(server.URL, WithAdminToken("test"))
		_, err := client.AuditLogs(context.Background(), AuditFilter{})
		if err == nil {
			t.Error("expected validation error")
		}
	})

	t.Run("500 without JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client, _ := New(server.URL, WithAdminToken("test"))
		_, err := client.AuditLogs(context.Background(), AuditFilter{})
		if err == nil {
			t.Error("expected service error")
		}
	})
}

// TestNewClientEdgeCases tests edge cases in client creation
func TestNewClientEdgeCases(t *testing.T) {
	t.Run("URL with trailing slash", func(t *testing.T) {
		client, err := New("http://example.com/")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client == nil {
			t.Error("expected valid client")
		}
	})

	t.Run("HTTPS URL", func(t *testing.T) {
		client, err := New("https://example.com")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client == nil {
			t.Error("expected valid client")
		}
	})
}
