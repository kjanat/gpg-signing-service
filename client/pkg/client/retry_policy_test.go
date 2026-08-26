package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signature is what a stub answers a successful /sign with.
const testSignature = "-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----"

// TestWaitBeforePrefersTheServersHint covers the decision that used to live in
// Do as unreachable code.
//
// The retrier held a Retry-After branch that nothing could reach: every
// response path runs through executeWithRetry, whose signal carried a zero
// RetryAfter because the hint was not reachable from the generic response type.
// So a 429 asking for one second cost the full exponential backoff instead —
// on the shipped defaults, roughly fifteen seconds for a limit that had already
// cleared. Held to the arithmetic here; the end-to-end test below pays for a
// real wait once.
func TestWaitBeforePrefersTheServersHint(t *testing.T) {
	r := &Retrier{
		maxRetries:       3,
		retryWaitMin:     5 * time.Second,
		retryWaitMax:     30 * time.Second,
		retryOnRateLimit: true,
	}
	// backoff(1) is 2*retryWaitMin plus jitter, so anything the hint decides is
	// unambiguously below it.
	const floor = 10 * time.Second

	tests := []struct {
		name             string
		retryOnRateLimit bool
		err              error
		want             time.Duration
		wantBackoff      bool
	}{
		{
			name:             "a hint shorter than the backoff is what the server asked for",
			retryOnRateLimit: true,
			err:              &RateLimitError{Message: testMsgRateLimited, RetryAfter: time.Second},
			want:             time.Second,
		},
		{
			name:             "the signal the status path builds carries it too",
			retryOnRateLimit: true,
			err:              &retrySignalError{inner: &RateLimitError{RetryAfter: 2 * time.Second}},
			want:             2 * time.Second,
		},
		{
			name:             "a hint past the configured ceiling is clamped to it",
			retryOnRateLimit: true,
			err:              &RateLimitError{Message: testMsgRateLimited, RetryAfter: time.Hour},
			want:             30 * time.Second,
		},
		{
			name:             "a 429 with no hint falls back to the backoff",
			retryOnRateLimit: true,
			err:              &RateLimitError{Message: testMsgRateLimited},
			wantBackoff:      true,
		},
		{
			name:             "a 5xx has no hint to prefer",
			retryOnRateLimit: true,
			err:              &ServiceError{Code: testCodeError, StatusCode: 503},
			wantBackoff:      true,
		},
		{
			name:             "WithoutRateLimitRetry leaves the backoff in charge",
			retryOnRateLimit: false,
			err:              &RateLimitError{Message: testMsgRateLimited, RetryAfter: time.Second},
			wantBackoff:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := *r
			policy.retryOnRateLimit = tt.retryOnRateLimit

			got := policy.waitBefore(1, tt.err)
			if tt.wantBackoff {
				if got < floor || got > policy.retryWaitMax {
					t.Errorf("expected a backoff in [%v, %v], got %v", floor, policy.retryWaitMax, got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("waitBefore = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRecordRetryHint covers the transport half of the same fix: the hint has
// two sources and the retry policy can see neither.
//
// `Retry-After` is a header and this service's own hint is a body field, while
// executeWithRetry works with a response type exposing StatusCode() alone. The
// transport is the one place both are in hand at once.
func TestRecordRetryHint(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		header     http.Header
		want       time.Duration
	}{
		{
			name:       "the envelope this service actually sends",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error":"slow down","code":"RATE_LIMITED","retryAfter":7}`,
			want:       7 * time.Second,
		},
		{
			name:       "the header, for a throttle that sent no envelope",
			statusCode: http.StatusTooManyRequests,
			header:     http.Header{headerRetryAfter: []string{"12"}},
			want:       12 * time.Second,
		},
		{
			name:       "a half-envelope still carries its hint",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error":"slow down","retryAfter":3}`,
			want:       3 * time.Second,
		},
		{
			name:       "a 429 with neither leaves the backoff in charge",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error":"slow down","code":"RATE_LIMITED"}`,
		},
		{
			// 503 is the only other status that may carry Retry-After, and it
			// is deliberately not read: the retrier has no hint type for it and
			// WithoutRateLimitRetry does not govern it.
			name:       "a 503 is not a rate limit",
			statusCode: http.StatusServiceUnavailable,
			header:     http.Header{headerRetryAfter: []string{"12"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := tt.header
			if header == nil {
				header = http.Header{}
			}

			sink := &retryHint{}
			ctx := withRetryHint(context.Background(), sink)
			recordRetryHint(ctx, tt.statusCode, []byte(tt.body), header)

			if sink.retryAfter != tt.want {
				t.Errorf("recorded %v, want %v", sink.retryAfter, tt.want)
			}
		})
	}
}

// TestRecordRetryHintWithoutASink pins that a call outside executeWithRetry —
// every request Health makes — records nothing rather than panicking.
func TestRecordRetryHintWithoutASink(_ *testing.T) {
	recordRetryHint(context.Background(), http.StatusTooManyRequests, nil, http.Header{
		headerRetryAfter: []string{"5"},
	})
}

// TestRateLimitWaitFollowsTheHintEndToEnd walks the hint the whole way: the
// service's envelope, through the transport, into the wait the retrier takes.
//
// The one test here that pays for a real wait, because Retry-After is measured
// in whole seconds and there is no sub-second way to state it. The backoff it
// replaces would be 10s or more, so a second is the cheapest honest assertion.
func TestRateLimitWaitFollowsTheHintEndToEnd(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"error":"rate limit exceeded","code":"RATE_LIMITED","retryAfter":1}`)
			return
		}
		_, _ = fmt.Fprint(w, testSignature)
	}))
	defer server.Close()

	// backoff(1) here is at least 10s, so a run that ignores the hint cannot
	// finish inside the assertion below by luck.
	c, err := New(server.URL,
		WithMaxRetries(2),
		WithRetryWait(5*time.Second, 30*time.Second),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	start := time.Now()
	result, err := c.Sign(context.Background(), "commit data", "")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if result.Signature != testSignature {
		t.Errorf("unexpected signature: %q", result.Signature)
	}
	if requests != 2 {
		t.Errorf("expected 2 requests, got %d", requests)
	}
	if elapsed < time.Second {
		t.Errorf("expected the call to honour the server's 1s hint, took %v", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("expected the 1s hint rather than the backoff, took %v", elapsed)
	}
}

// TestDeadlineKeepsTheAnswerAlreadyInHand covers what a caller-side deadline
// costs once statuses are retried.
//
// Do returns ctx.Err() from the backoff sleep, which is reached only *after* a
// response arrived and was classified retryable — so the response that caused
// the wait was in hand, unmapped, and thrown away for a timeout. The CLI hands
// the same --timeout to WithTimeout and to its context, so any limit shorter
// than one backoff turned "you are being throttled" into "context deadline
// exceeded" and IsRateLimitError into false. Retries are an optimisation over
// the response, not a precondition for it.
func TestDeadlineKeepsTheAnswerAlreadyInHand(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		check  func(*testing.T, error)
	}{
		{
			name:   "a 429 stays a rate limit",
			status: http.StatusTooManyRequests,
			body:   `{"error":"rate limit exceeded","code":"RATE_LIMITED","retryAfter":30}`,
			check: func(t *testing.T, err error) {
				t.Helper()
				var re *RateLimitError
				if !errors.As(err, &re) {
					t.Fatalf("expected a *RateLimitError, got %T: %v", err, err)
				}
				if re.RetryAfter != 30*time.Second {
					t.Errorf("expected the server's 30s hint to survive, got %v", re.RetryAfter)
				}
			},
		},
		{
			name:   "a 503 stays a service error",
			status: http.StatusServiceUnavailable,
			body:   `{"error":"unavailable","code":"INTERNAL_ERROR"}`,
			check: func(t *testing.T, err error) {
				t.Helper()
				if !IsServiceError(err) {
					t.Fatalf("expected a service error, got %T: %v", err, err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			// The wait is an order of magnitude past the deadline either way,
			// so the sleep is always what the deadline interrupts.
			c, err := New(server.URL,
				WithMaxRetries(3),
				WithRetryWait(2*time.Second, 10*time.Second),
			)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()

			_, err = c.Sign(ctx, "commit data", "")
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("the deadline outranked the answer the server gave: %v", err)
			}
			tt.check(t, err)
		})
	}
}

// TestDeadlineBeforeAnyAnswerStaysADeadline is the other side of it. With no
// response in hand there is nothing to prefer over the timeout, and reporting
// one anyway would be an invention.
func TestDeadlineBeforeAnyAnswerStaysADeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	c, err := New(server.URL, WithMaxRetries(3), WithRetryWait(time.Millisecond, 5*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.Sign(ctx, "commit data", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the deadline to stand, got %T: %v", err, err)
	}
}

// TestCancellationOutranksTheAnswer pins the asymmetry above deliberately.
//
// A caller whose deadline lapsed asked for an answer within N seconds and one
// exists. A caller who cancelled asked to stop, and handing them a rate limit
// error for a call they abandoned would report work rather than the abandoning.
func TestCancellationOutranksTheAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, `{"error":"unavailable","code":"INTERNAL_ERROR"}`)
	}))
	defer server.Close()

	c, err := New(server.URL, WithMaxRetries(3), WithRetryWait(2*time.Second, 10*time.Second))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	if _, err := c.Sign(ctx, "commit data", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("expected the cancellation to stand, got %T: %v", err, err)
	}
}

// TestRateLimitCarriesTheRequestID covers the id a 429 used to lose.
//
// newStatusError threads a request id onto every other status. The 429 branch
// sits above the line that reads it — deliberately, because a 429 needs no
// envelope to be understood — and RateLimitError had no field to put one on.
// Admin's rate limiter sends no `requestId` in the body at all, so the echoed
// header is the only source, which is precisely the case requestIDFrom's
// fallback exists for and precisely what troubleshooting.md asks operators to
// quote.
func TestRateLimitCarriesTheRequestID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(headerRequestID, testErrRequestID)
		w.WriteHeader(http.StatusTooManyRequests)
		// The shape adminRateLimit sends: no requestId in the body.
		_, _ = fmt.Fprint(w, `{"error":"rate limit exceeded","code":"RATE_LIMITED","retryAfter":3}`)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL, WithAdminToken(testMsgTest))

	// The undeclared path, through newStatusError's hand-parsed envelope.
	_, err := c.ListKeys(context.Background())
	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("ListKeys: expected a *RateLimitError, got %T: %v", err, err)
	}
	if re.RequestID != testErrRequestID {
		t.Errorf("ListKeys: RequestID = %q, want %q", re.RequestID, testErrRequestID)
	}
	if !strings.Contains(re.Error(), testErrRequestID) {
		t.Errorf("ListKeys: the id is not in the error text: %q", re.Error())
	}

	// The declared path, through /sign's typed JSON429. RateLimitErrorSchema
	// declares no requestId, so this one can only come from the header.
	_, err = c.Sign(context.Background(), "commit data", "")
	re = nil
	if !errors.As(err, &re) {
		t.Fatalf("Sign: expected a *RateLimitError, got %T: %v", err, err)
	}
	if re.RequestID != testErrRequestID {
		t.Errorf("Sign: RequestID = %q, want %q", re.RequestID, testErrRequestID)
	}
}

// TestDeleteKeyRetriedPastACommitReportsSuccess covers the one retried mutation
// whose *answer* does not converge even though its state does.
//
// The handler reports whether the key was there when that attempt ran, so a
// delete that committed and then lost its response — the audit write after it
// throws, the connection drops mid-body — is answered `deleted:false` by the
// next attempt. Mapped naively that is KEY_NOT_FOUND for a key this call
// removed, and the CLI treats not-found as an idempotent no-op: it prints
// {"deleted":false} and exits 0 for work it did do.
func TestDeleteKeyRetriedPastACommitReportsSuccess(t *testing.T) {
	requests := 0
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			// The delete committed; the audit write that follows it did not.
			deleted = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"error":"Failed to delete key","code":"INTERNAL_ERROR"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"success":true,"deleted":%t}`, !deleted)
	}))
	defer server.Close()

	c, err := New(server.URL,
		WithAdminToken(testMsgTest),
		WithMaxRetries(2),
		WithRetryWait(time.Millisecond, 5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if err := c.DeleteKey(context.Background(), testKeyID); err != nil {
		t.Fatalf("expected the delete to be reported as done, got %T: %v", err, err)
	}
	if requests != 2 {
		t.Errorf("expected 2 requests, got %d", requests)
	}
}

// TestDeleteKeyNotFoundOnTheFirstAttemptStaysNotFound pins the other half: with
// no earlier attempt, `deleted:false` means what it says and the narrowing
// above must not swallow it.
func TestDeleteKeyNotFoundOnTheFirstAttemptStaysNotFound(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"deleted":false}`)
	}))
	defer server.Close()

	c, err := New(server.URL,
		WithAdminToken(testMsgTest),
		WithMaxRetries(2),
		WithRetryWait(time.Millisecond, 5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	err = c.DeleteKey(context.Background(), testKeyIDMissing)
	if !IsKeyNotFound(err) {
		t.Fatalf("expected KEY_NOT_FOUND, got %T: %v", err, err)
	}
	if requests != 1 {
		t.Errorf("expected 1 request, got %d", requests)
	}
}
