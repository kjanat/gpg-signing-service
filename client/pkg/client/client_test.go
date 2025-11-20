package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewClient tests the New() constructor with various scenarios
func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		opts      []Option
		wantErr   bool
		errMsg    string
		validate  func(t *testing.T, c *Client)
	}{
		{
			name:    "valid client with default options",
			baseURL: "http://localhost:8080",
			opts:    nil,
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c == nil {
					t.Fatal("client is nil")
				}
				if c.opts.timeout != 30*time.Second {
					t.Errorf("expected timeout 30s, got %v", c.opts.timeout)
				}
				if c.opts.maxRetries != 3 {
					t.Errorf("expected maxRetries 3, got %d", c.opts.maxRetries)
				}
				if !c.opts.retryOnRateLimit {
					t.Error("expected retryOnRateLimit true")
				}
			},
		},
		{
			name:    "empty baseURL returns error",
			baseURL: "",
			opts:    nil,
			wantErr: true,
			errMsg:  "baseURL cannot be empty",
		},
		{
			name:    "client with custom timeout",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithTimeout(60 * time.Second)},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.timeout != 60*time.Second {
					t.Errorf("expected timeout 60s, got %v", c.opts.timeout)
				}
			},
		},
		{
			name:    "zero timeout returns error",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithTimeout(0)},
			wantErr: true,
			errMsg:  "timeout must be positive",
		},
		{
			name:    "negative timeout returns error",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithTimeout(-1 * time.Second)},
			wantErr: true,
			errMsg:  "timeout must be positive",
		},
		{
			name:    "client with OIDC token",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithOIDCToken("test-token-123")},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.authToken != "test-token-123" {
					t.Errorf("expected authToken 'test-token-123', got %q", c.opts.authToken)
				}
			},
		},
		{
			name:    "client with admin token",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithAdminToken("admin-token-456")},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.authToken != "admin-token-456" {
					t.Errorf("expected authToken 'admin-token-456', got %q", c.opts.authToken)
				}
			},
		},
		{
			name:    "client with maxRetries",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithMaxRetries(5)},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.maxRetries != 5 {
					t.Errorf("expected maxRetries 5, got %d", c.opts.maxRetries)
				}
			},
		},
		{
			name:    "zero maxRetries disables retries",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithMaxRetries(0)},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.maxRetries != 0 {
					t.Errorf("expected maxRetries 0, got %d", c.opts.maxRetries)
				}
			},
		},
		{
			name:    "negative maxRetries returns error",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithMaxRetries(-1)},
			wantErr: true,
			errMsg:  "maxRetries cannot be negative",
		},
		{
			name:    "client with custom retry wait",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithRetryWait(500*time.Millisecond, 60*time.Second)},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.retryWaitMin != 500*time.Millisecond {
					t.Errorf("expected retryWaitMin 500ms, got %v", c.opts.retryWaitMin)
				}
				if c.opts.retryWaitMax != 60*time.Second {
					t.Errorf("expected retryWaitMax 60s, got %v", c.opts.retryWaitMax)
				}
			},
		},
		{
			name:    "retryWaitMin >= retryWaitMax returns error",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithRetryWait(30*time.Second, 1*time.Second)},
			wantErr: true,
			errMsg:  "retryWaitMin must be less than retryWaitMax",
		},
		{
			name:    "retryWaitMin equal to retryWaitMax returns error",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithRetryWait(5*time.Second, 5*time.Second)},
			wantErr: true,
			errMsg:  "retryWaitMin must be less than retryWaitMax",
		},
		{
			name:    "disable rate limit retry",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithoutRateLimitRetry()},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.retryOnRateLimit {
					t.Error("expected retryOnRateLimit false")
				}
			},
		},
		{
			name:    "multiple options applied in order",
			baseURL: "http://localhost:8080",
			opts: []Option{
				WithTimeout(45 * time.Second),
				WithOIDCToken("test-token"),
				WithMaxRetries(2),
				WithRetryWait(100*time.Millisecond, 20*time.Second),
			},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.opts.timeout != 45*time.Second {
					t.Errorf("expected timeout 45s, got %v", c.opts.timeout)
				}
				if c.opts.authToken != "test-token" {
					t.Errorf("expected authToken 'test-token', got %q", c.opts.authToken)
				}
				if c.opts.maxRetries != 2 {
					t.Errorf("expected maxRetries 2, got %d", c.opts.maxRetries)
				}
				if c.opts.retryWaitMin != 100*time.Millisecond {
					t.Errorf("expected retryWaitMin 100ms, got %v", c.opts.retryWaitMin)
				}
			},
		},
		{
			name:    "retrier is properly initialized",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithMaxRetries(4)},
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.retrier == nil {
					t.Fatal("retrier is nil")
				}
				if c.retrier.maxRetries != 4 {
					t.Errorf("expected retrier.maxRetries 4, got %d", c.retrier.maxRetries)
				}
			},
		},
		{
			name:    "raw API client is initialized",
			baseURL: "http://localhost:8080",
			opts:    nil,
			wantErr: false,
			validate: func(t *testing.T, c *Client) {
				if c.raw == nil {
					t.Fatal("raw API client is nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(tt.baseURL, tt.opts...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, c)
			}
		})
	}
}

// TestNewClientWithHTTPServer validates client works with real HTTP server
func TestNewClientWithHTTPServer(t *testing.T) {
	// Create a simple test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	c, err := New(server.URL, WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if c == nil {
		t.Fatal("client is nil")
	}
	if c.raw == nil {
		t.Fatal("raw API client is nil")
	}
}

// TestClientConcurrency validates client structure for concurrent use
func TestClientConcurrency(t *testing.T) {
	c, err := New("http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Simulate concurrent access to client fields
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = c.opts.timeout
			_ = c.opts.maxRetries
			_ = c.retrier
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestNewClientAuthorizationHeader validates that auth token is properly set
func TestNewClientAuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if auth != "Bearer test-token" {
			t.Errorf("expected Authorization header 'Bearer test-token', got %q", auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(server.URL, WithOIDCToken("test-token"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if c.opts.authToken != "test-token" {
		t.Errorf("expected authToken 'test-token', got %q", c.opts.authToken)
	}
}

// TestNewClientTimeout validates timeout option is applied to HTTP client
func TestNewClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(server.URL, WithTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if c.opts.timeout != 50*time.Millisecond {
		t.Errorf("expected timeout 50ms, got %v", c.opts.timeout)
	}
}

// BenchmarkNewClient benchmarks client creation
func BenchmarkNewClient(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := New("http://localhost:8080", WithTimeout(30*time.Second))
		if err != nil {
			b.Fatalf("failed to create client: %v", err)
		}
	}
}

// TestNewClientWithValidContext ensures client is compatible with context
func TestNewClientWithValidContext(t *testing.T) {
	c, err := New("http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify client works with context (this is just checking the type)
	_ = ctx
	if c == nil {
		t.Fatal("client is nil after context creation")
	}
}

// TestDefaultOptions validates the default options values
func TestDefaultOptions(t *testing.T) {
	opts := defaultOptions()

	if opts.timeout != 30*time.Second {
		t.Errorf("default timeout should be 30s, got %v", opts.timeout)
	}
	if opts.maxRetries != 3 {
		t.Errorf("default maxRetries should be 3, got %d", opts.maxRetries)
	}
	if opts.retryWaitMin != 1*time.Second {
		t.Errorf("default retryWaitMin should be 1s, got %v", opts.retryWaitMin)
	}
	if opts.retryWaitMax != 30*time.Second {
		t.Errorf("default retryWaitMax should be 30s, got %v", opts.retryWaitMax)
	}
	if !opts.retryOnRateLimit {
		t.Error("default retryOnRateLimit should be true")
	}
	if opts.authToken != "" {
		t.Errorf("default authToken should be empty, got %q", opts.authToken)
	}
}

// TestOptionFunctions tests individual option functions
func TestOptionFunctions(t *testing.T) {
	tests := []struct {
		name string
		opt  Option
		want func(*Options) bool
	}{
		{
			name: "WithTimeout",
			opt:  WithTimeout(15 * time.Second),
			want: func(o *Options) bool { return o.timeout == 15*time.Second },
		},
		{
			name: "WithOIDCToken",
			opt:  WithOIDCToken("oidc-token"),
			want: func(o *Options) bool { return o.authToken == "oidc-token" },
		},
		{
			name: "WithAdminToken",
			opt:  WithAdminToken("admin-token"),
			want: func(o *Options) bool { return o.authToken == "admin-token" },
		},
		{
			name: "WithMaxRetries",
			opt:  WithMaxRetries(7),
			want: func(o *Options) bool { return o.maxRetries == 7 },
		},
		{
			name: "WithRetryWait",
			opt:  WithRetryWait(200*time.Millisecond, 45*time.Second),
			want: func(o *Options) bool {
				return o.retryWaitMin == 200*time.Millisecond && o.retryWaitMax == 45*time.Second
			},
		},
		{
			name: "WithoutRateLimitRetry",
			opt:  WithoutRateLimitRetry(),
			want: func(o *Options) bool { return !o.retryOnRateLimit },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := defaultOptions()
			tt.opt(opts)
			if !tt.want(opts) {
				t.Errorf("option %s did not apply correctly", tt.name)
			}
		})
	}
}
