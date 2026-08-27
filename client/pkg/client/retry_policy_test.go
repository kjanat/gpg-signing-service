package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
		wantCode   string
	}{
		{
			name:       "the envelope this service actually sends",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error":"slow down","code":"RATE_LIMITED","retryAfter":7}`,
			want:       7 * time.Second,
			wantCode:   "RATE_LIMITED",
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
			wantCode:   "RATE_LIMITED",
		},
		{
			// A 503 is the other status that carries Retry-After, and it used to
			// be dropped here on the reasoning that the retrier had no hint type
			// for it. It has had one since ServiceError grew RetryAfter, and
			// dropping it left the wait reaching the mapped error but never the
			// pause between attempts.
			name:       "a 503's wait is read too",
			statusCode: http.StatusServiceUnavailable,
			header:     http.Header{headerRetryAfter: []string{"12"}},
			body:       `{"error":"issuer away","code":"SERVICE_DEGRADED"}`,
			want:       12 * time.Second,
			wantCode:   "SERVICE_DEGRADED",
		},
		{
			// The code is the whole reason a 5xx body is read at all: it is what
			// tells shouldRetry that this one will never clear.
			name:       "a permanent 503 carries its code and no wait",
			statusCode: http.StatusServiceUnavailable,
			body:       `{"error":"SSRF protection: private address","code":"SERVICE_MISCONFIGURED"}`,
			wantCode:   "SERVICE_MISCONFIGURED",
		},
		{
			// No body form of the code exists, so an unreadable one leaves it
			// empty — and empty is the retrying answer, which is the safe way
			// round for an intermediary's bare 502.
			name:       "an unreadable 5xx records nothing to branch on",
			statusCode: http.StatusBadGateway,
			body:       "<html>502</html>",
		},
		{
			// Nothing below 500 that is not a 429 is a status the policy will
			// consider, so nothing is recorded for one.
			name:       "a 404 is not the policy's business",
			statusCode: http.StatusNotFound,
			header:     http.Header{headerRetryAfter: []string{"12"}},
			body:       `{"error":"nope","code":"NOT_FOUND"}`,
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
			if sink.code != tt.wantCode {
				t.Errorf("recorded code %q, want %q", sink.code, tt.wantCode)
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

// TestPerAttemptTimeoutIsNotAnAnswer pins the boundary of the branch
// TestDeadlineKeepsTheAnswerAlreadyInHand and its siblings cover from the
// other side.
//
// executeWithRetry reports a response rather than a deadline when the caller's
// context ran out mid-policy, on the reasoning that the answer was already in
// hand and the retry was only an optimisation over it. That reasoning is about
// ctx.Err() returned from Do's backoff sleep — but a WithTimeout that expires
// on a later attempt arrives as a *url.Error wrapping "context deadline
// exceeded (Client.Timeout exceeded while awaiting headers)", which satisfies
// errors.Is against DeadlineExceeded identically. Testing the error alone
// therefore swallowed a real timeout and answered with whatever status an
// earlier attempt had returned: measured here before the ctx.Err() test was
// added, a call whose second attempt never got a reply came back as attempt
// one's 503, with a nil error from executeWithRetry and no trace of the
// timeout anywhere.
//
// The caller's context is untouched here, so nothing about this call ran out
// of the budget the caller set — only one attempt did, and that is what
// WithTimeout bounds. See TestTimeoutBoundsOneAttemptNotTheCall.
func TestPerAttemptTimeoutIsNotAnAnswer(t *testing.T) {
	var requests atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"attempt one said this","code":"INTERNAL_ERROR"}`))
			return
		}
		// Never answers, so a passing run costs one timeout rather than a fixed
		// sleep. Released at teardown the way TestExpiredTimeoutEndsTheCall
		// does it: r.Context() alone is not enough to unblock Close.
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	c, err := New(server.URL,
		WithMaxRetries(3),
		WithTimeout(150*time.Millisecond),
		WithRetryWait(10*time.Millisecond, 20*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, signErr := c.Sign(context.Background(), "commit data", "")
	if signErr == nil {
		t.Fatal("expected the expired per-request timeout to be reported, got no error")
	}
	if !errors.Is(signErr, context.DeadlineExceeded) {
		t.Errorf("expected a deadline error, got %T: %v", signErr, signErr)
	}
	var serviceErr *ServiceError
	if errors.As(signErr, &serviceErr) {
		t.Errorf("attempt one's %d was reported in place of the timeout: %v",
			serviceErr.StatusCode, signErr)
	}
	// Asserted last and separately from the error: without it the test passes
	// on the unfixed code whenever attempt *one* is what runs out of time,
	// which a loaded runner can produce out of a 150ms budget. That call never
	// reaches the branch under test — attempted is false, the deadline is
	// returned as itself, and every assertion above holds for the wrong
	// reason. Two requests is what puts a response in hand for the timeout to
	// be swallowed by.
	if got := requests.Load(); got < 2 {
		t.Fatalf("attempt one did not answer within the per-request timeout, so "+
			"the branch under test was never reached: %d request(s)", got)
	}
}

// TestDeadlineMidAttemptKeepsTheAnswer covers the second way the caller's
// deadline reaches the branch TestDeadlineKeepsTheAnswerAlreadyInHand pins.
//
// That test sets the wait an order of magnitude past the deadline on purpose,
// so the sleep is always what the deadline interrupts and Do returns ctx.Err()
// itself. A deadline that lapses while an attempt is *in flight* never reaches
// the sleep: net/http aborts the round trip and returns a *url.Error wrapping
// context.DeadlineExceeded, shouldRetry declines it, and Do hands that back as
// the last error rather than ctx.Err(). Same branch, different error, and no
// test went in that way — which is how "Do returns ctx.Err() from the backoff
// sleep" came to stand as a description of the only route in, and how
// TestPerAttemptTimeoutIsNotAnAnswer's sibling half went unpinned while its own
// half was being fixed.
//
// The precedence is the same either way and is asserted here so it stays that
// way: an answer is in hand and it is the caller's own budget that ran out, so
// the answer is what they get. What distinguishes this from
// TestPerAttemptTimeoutIsNotAnAnswer above is not where the error came from
// but whose deadline lapsed, which is exactly what the ctx.Err() test asks.
func TestDeadlineMidAttemptKeepsTheAnswer(t *testing.T) {
	var requests atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"error":"unavailable","code":"INTERNAL_ERROR"}`)
			return
		}
		// Parked until the caller's deadline kills the round trip, the way
		// TestDeadlineBeforeAnyAnswerStaysADeadline does it.
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	// The per-attempt budget is two orders of magnitude past the caller's, so
	// the deadline that lands is unambiguously the context's; the wait is three
	// orders below it, so it lands on an attempt and not on the sleep.
	c, err := New(server.URL,
		WithMaxRetries(3),
		WithTimeout(10*time.Second),
		WithRetryWait(time.Millisecond, 2*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, signErr := c.Sign(ctx, "commit data", "")
	if signErr == nil {
		t.Fatal("expected attempt one's 503 to be reported, got no error")
	}
	if errors.Is(signErr, context.DeadlineExceeded) {
		t.Errorf("the deadline outranked the answer already in hand: %v", signErr)
	}
	if !IsServiceError(signErr) {
		t.Errorf("expected attempt one's service error, got %T: %v", signErr, signErr)
	}
	// The precondition, asserted separately for the same reason
	// TestPerAttemptTimeoutIsNotAnAnswer asserts its own: with one request the
	// deadline landed on attempt one, attempted is false, and every check above
	// holds without the branch under test being reached at all.
	if got := requests.Load(); got < 2 {
		t.Fatalf("the deadline landed on attempt one, so no answer was ever in "+
			"hand and the branch under test was never reached: %d request(s)", got)
	}
}
