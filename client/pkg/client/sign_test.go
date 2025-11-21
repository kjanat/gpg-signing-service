package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSignValidation tests Sign() input validation
func TestSignValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "signature")
	}))
	defer server.Close()

	client, _ := New(server.URL)

	tests := []struct {
		name       string
		commitData string
		keyID      string
		wantErr    bool
	}{
		{
			name:       "empty commitData",
			commitData: "",
			keyID:      "",
			wantErr:    true,
		},
		{
			name:       "valid commitData",
			commitData: "test commit",
			keyID:      "",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Sign(context.Background(), tt.commitData, tt.keyID)
			if tt.wantErr && err == nil {
				t.Errorf("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// TestSignSuccessResponse tests Sign() with successful response
func TestSignSuccessResponse(t *testing.T) {
	signature := "test-signature-data"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, signature)
	}))
	defer server.Close()

	client, _ := New(server.URL)
	result, err := client.Sign(context.Background(), "commit data", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Signature != signature {
		t.Errorf("expected signature %q, got %q", signature, result.Signature)
	}
}

// TestSignWithRateLimitHeaders tests Sign() rate limit header parsing
func TestSignWithRateLimitHeaders(t *testing.T) {
	resetTime := time.Now().Add(time.Hour).Unix()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-RateLimit-Remaining", "95")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "signature")
	}))
	defer server.Close()

	client, _ := New(server.URL)
	result, err := client.Sign(context.Background(), "commit data", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RateLimitRemaining == nil || *result.RateLimitRemaining != 95 {
		t.Errorf("expected RateLimitRemaining 95, got %v", result.RateLimitRemaining)
	}
	if result.RateLimitReset == nil {
		t.Errorf("expected RateLimitReset, got nil")
	}
}

// TestSignWithKeyID tests Sign() with specific keyID
func TestSignWithKeyID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "signature")
	}))
	defer server.Close()

	client, _ := New(server.URL)
	result, err := client.Sign(context.Background(), "commit data", "test-key-123")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

// TestSignContextCancellation tests Sign() with cancelled context
func TestSignContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "signature")
	}))
	defer server.Close()

	client, err := New(server.URL, WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.Sign(ctx, "commit data", "")
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

// TestSignContextDeadline tests Sign() with deadline exceeded
func TestSignContextDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "signature")
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = client.Sign(ctx, "commit data", "")
	if err == nil {
		t.Fatal("expected context deadline exceeded error")
	}
}

// TestRetrier tests the retry logic
func TestRetrier(t *testing.T) {
	tests := []struct {
		name         string
		maxRetries   int
		attempts     int
		returnErr    func(int) error
		wantErr      bool
		wantAttempts int
	}{
		{
			name:         "success on first attempt",
			maxRetries:   3,
			attempts:     0,
			returnErr:    func(i int) error { return nil },
			wantErr:      false,
			wantAttempts: 1,
		},
		{
			name:       "success after retry",
			maxRetries: 3,
			attempts:   0,
			returnErr: func(i int) error {
				if i < 1 {
					return &ServiceError{Code: "ERROR", Message: "test", StatusCode: 500}
				}
				return nil
			},
			wantErr:      false,
			wantAttempts: 2,
		},
		{
			name:       "fails with max retries exceeded",
			maxRetries: 2,
			attempts:   0,
			returnErr: func(i int) error {
				return &ServiceError{Code: "ERROR", Message: "test", StatusCode: 500}
			},
			wantErr:      true,
			wantAttempts: 3,
		},
		{
			name:       "no retry on validation error",
			maxRetries: 3,
			attempts:   0,
			returnErr: func(i int) error {
				return &ValidationError{Code: "INVALID", Message: "invalid"}
			},
			wantErr:      true,
			wantAttempts: 1,
		},
		{
			name:       "zero max retries",
			maxRetries: 0,
			attempts:   0,
			returnErr: func(i int) error {
				if i == 0 {
					return &ServiceError{Code: "ERROR", Message: "test", StatusCode: 500}
				}
				return nil
			},
			wantErr:      true,
			wantAttempts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrier := &Retrier{
				maxRetries:       tt.maxRetries,
				retryWaitMin:     1 * time.Millisecond,
				retryWaitMax:     5 * time.Millisecond,
				retryOnRateLimit: true,
			}

			attempts := 0
			err := retrier.Do(context.Background(), func() error {
				defer func() { attempts++ }()
				return tt.returnErr(attempts)
			})

			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if attempts != tt.wantAttempts {
				t.Errorf("expected %d attempts, got %d", tt.wantAttempts, attempts)
			}
		})
	}
}

// TestRetrierRateLimitRetry tests rate limit retry logic
func TestRetrierRateLimitRetry(t *testing.T) {
	tests := []struct {
		name             string
		retryOnRateLimit bool
		returnErr        func(int) error
		wantErr          bool
		wantAttempts     int
	}{
		{
			name:             "retry on rate limit when enabled",
			retryOnRateLimit: true,
			returnErr: func(i int) error {
				if i < 1 {
					return &RateLimitError{
						Message:    "rate limit exceeded",
						RetryAfter: 1 * time.Millisecond,
					}
				}
				return nil
			},
			wantErr:      false,
			wantAttempts: 2,
		},
		{
			name:             "no retry on rate limit when disabled",
			retryOnRateLimit: false,
			returnErr: func(i int) error {
				return &RateLimitError{
					Message:    "rate limit exceeded",
					RetryAfter: 1 * time.Millisecond,
				}
			},
			wantErr:      true,
			wantAttempts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrier := &Retrier{
				maxRetries:       3,
				retryWaitMin:     1 * time.Millisecond,
				retryWaitMax:     5 * time.Millisecond,
				retryOnRateLimit: tt.retryOnRateLimit,
			}

			attempts := 0
			err := retrier.Do(context.Background(), func() error {
				defer func() { attempts++ }()
				return tt.returnErr(attempts)
			})

			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if attempts != tt.wantAttempts {
				t.Errorf("expected %d attempts, got %d", tt.wantAttempts, attempts)
			}
		})
	}
}

// TestRetrierContextCancellation tests that retrier respects context cancellation
func TestRetrierContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	retrier := &Retrier{
		maxRetries:       5,
		retryWaitMin:     100 * time.Millisecond,
		retryWaitMax:     500 * time.Millisecond,
		retryOnRateLimit: true,
	}

	attempts := 0
	// Cancel context after first failure to prevent retry
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := retrier.Do(ctx, func() error {
		attempts++
		return &ServiceError{Code: "ERROR", Message: "test", StatusCode: 500}
	})

	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context error, got: %v", err)
	}
}

// TestRetrierBackoff validates exponential backoff calculation
func TestRetrierBackoff(t *testing.T) {
	retrier := &Retrier{
		maxRetries:       10,
		retryWaitMin:     1 * time.Second,
		retryWaitMax:     60 * time.Second,
		retryOnRateLimit: true,
	}

	// Test that backoff increases exponentially
	prev := time.Duration(0)
	for attempt := 1; attempt <= 5; attempt++ {
		backoff := retrier.backoff(attempt)
		if backoff <= prev || backoff > retrier.retryWaitMax {
			t.Errorf("backoff attempt %d: expected > %v and <= %v, got %v",
				attempt, prev, retrier.retryWaitMax, backoff)
		}
		prev = backoff
	}
}

// TestRetrierBackoffMax validates that backoff respects maximum
func TestRetrierBackoffMax(t *testing.T) {
	retrier := &Retrier{
		maxRetries:       10,
		retryWaitMin:     1 * time.Second,
		retryWaitMax:     10 * time.Second,
		retryOnRateLimit: true,
	}

	// After enough attempts, backoff should hit max
	for attempt := 1; attempt <= 20; attempt++ {
		backoff := retrier.backoff(attempt)
		if backoff > retrier.retryWaitMax {
			t.Errorf("attempt %d: backoff %v exceeds max %v", attempt, backoff, retrier.retryWaitMax)
		}
	}
}

// BenchmarkSign benchmarks signing operation
func BenchmarkSign(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "signature")
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Sign(context.Background(), "commit data", "")
	}
}
