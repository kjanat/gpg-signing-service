package client

import (
	"context"
	"errors"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "-----BEGIN PGP SIGNATURE-----\n\ntest-sig\n-----END PGP SIGNATURE-----")
	}))
	defer server.Close()

	client := newMappingClient(t, server.URL)

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
	signature := "-----BEGIN PGP SIGNATURE-----\n\ntest-signature-data\n-----END PGP SIGNATURE-----"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, signature)
	}))
	defer server.Close()

	client := newMappingClient(t, server.URL)
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-RateLimit-Remaining", "95")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "-----BEGIN PGP SIGNATURE-----\n\ntest-sig\n-----END PGP SIGNATURE-----")
	}))
	defer server.Close()

	client := newMappingClient(t, server.URL)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "-----BEGIN PGP SIGNATURE-----\n\ntest-sig\n-----END PGP SIGNATURE-----")
	}))
	defer server.Close()

	client := newMappingClient(t, server.URL)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "-----BEGIN PGP SIGNATURE-----\n\ntest-sig\n-----END PGP SIGNATURE-----")
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "-----BEGIN PGP SIGNATURE-----\n\ntest-sig\n-----END PGP SIGNATURE-----")
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
			returnErr:    func(_ int) error { return nil },
			wantErr:      false,
			wantAttempts: 1,
		},
		{
			name:       "success after retry",
			maxRetries: 3,
			attempts:   0,
			returnErr: func(i int) error {
				if i < 1 {
					return &ServiceError{Code: testCodeError, Message: testMsgTest, StatusCode: 500}
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
			returnErr: func(_ int) error {
				return &ServiceError{Code: testCodeError, Message: testMsgTest, StatusCode: 500}
			},
			wantErr:      true,
			wantAttempts: 3,
		},
		{
			name:       "no retry on validation error",
			maxRetries: 3,
			attempts:   0,
			returnErr: func(_ int) error {
				return &ValidationError{Code: testCodeInvalid, Message: "invalid"}
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
					return &ServiceError{Code: testCodeError, Message: testMsgTest, StatusCode: 500}
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
						Message:    testMsgRateLimited,
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
			returnErr: func(_ int) error {
				return &RateLimitError{
					Message:    testMsgRateLimited,
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
	// Cancel context after the first failure to prevent retry
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := retrier.Do(ctx, func() error {
		attempts++
		return &ServiceError{Code: testCodeError, Message: testMsgTest, StatusCode: 500}
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "-----BEGIN PGP SIGNATURE-----\n\ntest-sig\n-----END PGP SIGNATURE-----")
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}

	for b.Loop() {
		_, _ = client.Sign(context.Background(), "commit data", "")
	}
}

// TestSignKeyNotAllowed checks that a 403 scope denial keeps the server's error
// code instead of collapsing to "unexpected status code". The code exists so a
// caller can tell a scope denial from any other refusal; discarding it here
// would make that pointless.
func TestSignKeyNotAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"Token is not allowed to sign with key BBBBBBBBBBBBBBBB",`+
			`"code":"KEY_NOT_ALLOWED","requestId":"`+testErrRequestID+`"}`)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL)
	_, err := c.Sign(context.Background(), "commit data", "BBBBBBBBBBBBBBBB")
	if err == nil {
		t.Fatal("expected an error for a 403 response")
	}
	if !IsKeyNotAllowed(err) {
		t.Errorf("expected IsKeyNotAllowed, got %v", err)
	}
	// A scope denial is not an auth failure: the credential was accepted.
	if IsAuthError(err) {
		t.Error("a key scope denial must not report as an auth error")
	}
	var se *ServiceError
	if !errors.As(err, &se) {
		t.Fatalf("expected a *ServiceError, got %T", err)
	}
	if se.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", se.StatusCode)
	}
	if !strings.Contains(se.Message, "not allowed to sign") {
		t.Errorf("server message was discarded: %q", se.Message)
	}
	if se.RequestID != testErrRequestID {
		t.Errorf("request id was discarded: %q", se.RequestID)
	}
}

// TestSignUntrustedSubject checks that a 401 reaches the caller with the
// service's own message. Without the declared 401 the generated client has no
// typed field to decode into and the response collapses to "unexpected status
// code: 401" — the exact failure an operator cannot debug, because a CI-only
// OIDC token cannot be replayed from a laptop to read the body by hand.
func TestSignUntrustedSubject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":"Subject is not trusted for signing",`+
			`"code":"AUTH_INVALID","requestId":"`+testErrRequestID+`"}`)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL)
	_, err := c.Sign(context.Background(), "commit data", "")
	if err == nil {
		t.Fatal("expected an error for a 401 response")
	}
	if !IsAuthError(err) {
		t.Errorf("expected IsAuthError, got %v", err)
	}
	if errors.Is(err, ErrUnexpectedStatus) {
		t.Error("a 401 carrying an error body must not report as an unexpected status")
	}

	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected an *AuthError, got %T", err)
	}
	if ae.Message != "Subject is not trusted for signing" {
		t.Errorf("server message was discarded: %q", ae.Message)
	}
	if ae.Code != testCodeAuthInvalid {
		t.Errorf("error code was discarded: %q", ae.Code)
	}
	if ae.RequestID != testErrRequestID {
		t.Errorf("request id was discarded: %q", ae.RequestID)
	}
	if !strings.Contains(err.Error(), "Subject is not trusted for signing") {
		t.Errorf("message missing from rendered error: %q", err.Error())
	}
}

// TestSignAuthErrorWithoutBody keeps the fallback honest: a 401 with nothing to
// read still has to produce an error, and the sentinel is all that is left.
func TestSignAuthErrorWithoutBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL)
	_, err := c.Sign(context.Background(), "commit data", "")
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("expected the unexpected-status sentinel, got %v", err)
	}
	if IsAuthError(err) {
		t.Error("an empty body carries no auth detail to report")
	}
}

// TestSignUndocumentedStatusWithBody covers the non-401 half of the same gap: a
// status the document does not declare still carries a usable envelope.
func TestSignUndocumentedStatusWithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = fmt.Fprint(w, `{"error":"brewing refused","code":"INTERNAL_ERROR"}`)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL)
	_, err := c.Sign(context.Background(), "commit data", "")

	var se *ServiceError
	if !errors.As(err, &se) {
		t.Fatalf("expected a *ServiceError, got %T (%v)", err, err)
	}
	if se.StatusCode != http.StatusTeapot {
		t.Errorf("expected status 418, got %d", se.StatusCode)
	}
	if se.Message != "brewing refused" {
		t.Errorf("server message was discarded: %q", se.Message)
	}
}

// TestSignRetriesRealStatusResponses drives the retry policy through an actual
// HTTP server rather than a synthetic closure.
//
// The unit tests around Retrier hand it functions that return errors directly,
// which is why a gap sat here unseen: a 429 or a 500 is a *successful* round
// trip, so the closure the client used to pass reported a nil error and the
// retrier saw nothing to retry. shouldRetry's RateLimitError and 5xx branches
// were unreachable against a real server and WithoutRateLimitRetry() toggled
// nothing. Only a test that counts requests arriving at a server can tell the
// difference. TestSignRetriesTransportFaults covers the other half: the faults
// that did reach shouldRetry were dropped by its fallthrough.
func TestSignRetriesRealStatusResponses(t *testing.T) {
	const signature = "-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----"

	tests := []struct {
		name string
		// failures is how many attempts answer with status before one succeeds;
		// a count above maxRetries means every attempt fails.
		failures     int
		status       int
		body         string
		opts         []Option
		wantRequests int
		wantErr      bool
	}{
		{
			name:         "rate limit is retried and then succeeds",
			failures:     2,
			status:       http.StatusTooManyRequests,
			body:         `{"error":"rate limit exceeded","code":"RATE_LIMITED","retryAfter":1}`,
			wantRequests: 3,
		},
		{
			name:         "server error is retried and then succeeds",
			failures:     1,
			status:       http.StatusInternalServerError,
			body:         `{"error":"boom","code":"INTERNAL_ERROR"}`,
			wantRequests: 2,
		},
		{
			name:         "retries are bounded by maxRetries",
			failures:     99,
			status:       http.StatusInternalServerError,
			body:         `{"error":"boom","code":"INTERNAL_ERROR"}`,
			wantRequests: 3,
			wantErr:      true,
		},
		{
			name:         "WithoutRateLimitRetry stops after the first 429",
			failures:     99,
			status:       http.StatusTooManyRequests,
			body:         `{"error":"rate limit exceeded","code":"RATE_LIMITED","retryAfter":1}`,
			opts:         []Option{WithoutRateLimitRetry()},
			wantRequests: 1,
			wantErr:      true,
		},
		{
			name:         "a refusal the caller cannot fix is not retried",
			failures:     99,
			status:       http.StatusUnauthorized,
			body:         `{"error":"Subject is not trusted for signing","code":"AUTH_INVALID"}`,
			wantRequests: 1,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				if requests > tt.failures {
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(w, signature)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			// Waits are held to milliseconds: the point is how many requests
			// arrive, not how long the backoff sleeps between them.
			opts := append([]Option{
				WithMaxRetries(2),
				WithRetryWait(time.Millisecond, 5*time.Millisecond),
			}, tt.opts...)

			c, err := New(server.URL, opts...)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			_, err = c.Sign(context.Background(), "commit data", "")
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if requests != tt.wantRequests {
				t.Errorf("expected %d requests, got %d", tt.wantRequests, requests)
			}
		})
	}
}

// TestSignRateLimitKeepsRetryAfter checks that the hint survives the retries.
// The retrier's own waits are exponential, but what the caller is finally handed
// must still say how long the service asked it to wait.
func TestSignRateLimitKeepsRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"rate limit exceeded","code":"RATE_LIMITED","retryAfter":42}`)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL)
	_, err := c.Sign(context.Background(), "commit data", "")
	if !IsRateLimitError(err) {
		t.Fatalf("expected a rate limit error, got %T: %v", err, err)
	}

	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("expected a *RateLimitError, got %T", err)
	}
	if re.RetryAfter != 42*time.Second {
		t.Errorf("expected the envelope's 42s hint, got %v", re.RetryAfter)
	}
}

// TestAdminUndeclaredRateLimit covers a 429 on an operation the document does
// not declare one for. It reaches the caller through the envelope fallback, and
// must still arrive as a rate limit: IsRateLimitError, the retry policy and the
// CLI's throttling message all key off the type, not the status.
func TestAdminUndeclaredRateLimit(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"too many requests","code":"RATE_LIMITED"}`)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL)
	_, err := c.ListKeys(context.Background())
	if !IsRateLimitError(err) {
		t.Fatalf("expected a rate limit error, got %T: %v", err, err)
	}

	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("expected a *RateLimitError, got %T", err)
	}
	// No `retryAfter` in the body, so the header is the only source left.
	if re.RetryAfter != 3*time.Second {
		t.Errorf("expected the header's 3s hint, got %v", re.RetryAfter)
	}
	if requests != 1 {
		t.Errorf("expected 1 request with retries off, got %d", requests)
	}
}
