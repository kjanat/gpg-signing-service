package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestSignRetriesTransportFaults covers the half of the retry policy that never
// worked in either direction.
//
// shouldRetry fell through to false for everything it did not recognise, and a
// transport fault is recognised by nothing above that fallthrough — it arrives
// as a bare *url.Error. So a dropped connection, the textbook case for another
// attempt, came back to the caller on attempt one while README and the Health
// comment both said it retried. The server hangs up mid-handshake once and then
// answers normally; a working policy sees the signature.
func TestSignRetriesTransportFaults(t *testing.T) {
	const signature = "-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----"

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			// Hijack and close without writing a response: the client sees EOF,
			// which is the shape a dropped connection actually has.
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack failed: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = fmt.Fprint(w, signature)
	}))
	defer server.Close()

	c, err := New(server.URL,
		WithMaxRetries(2),
		WithRetryWait(time.Millisecond, 5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := c.Sign(context.Background(), "commit data", "")
	if err != nil {
		t.Fatalf("transport fault was not retried: %v", err)
	}
	if result.Signature != signature {
		t.Errorf("unexpected signature: %q", result.Signature)
	}
	if requests != 2 {
		t.Errorf("expected 2 requests, got %d", requests)
	}
}

// TestSignDoesNotRetryCancelledContext pins the one error the transport-fault
// default must not swallow. Retrying a dead context burns the whole budget on
// attempts that fail identically and instantly.
func TestSignDoesNotRetryCancelledContext(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(server.URL, WithMaxRetries(5), WithRetryWait(time.Millisecond, 5*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.Sign(ctx, "commit data", ""); err == nil {
		t.Fatal("expected an error")
	}
	if requests != 0 {
		t.Errorf("expected the cancelled context to stop before any request, got %d", requests)
	}
}

// TestOpaqueRateLimitIsStillRateLimited covers the 429 this service did not
// write: an edge throttle answering with a page and a Retry-After header.
//
// It is not a usable error envelope, so the parse gate used to turn it into the
// bare "unexpected status code: 429" sentinel — IsRateLimitError false, the
// CLI's throttling message unreachable, and the header hint discarded by the
// one function added to read it. It is also the only 429 that ever reaches that
// header fallback, since this service always sends `retryAfter` alongside a
// body.
func TestOpaqueRateLimitIsStillRateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, "<html><body>error 1015</body></html>")
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL, WithAdminToken(testMsgTest))

	_, err := c.ListKeys(context.Background())
	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("expected a *RateLimitError, got %T: %v", err, err)
	}
	if re.RetryAfter != 60*time.Second {
		t.Errorf("expected the header's 60s hint, got %v", re.RetryAfter)
	}
	// Without a body to quote, the status text stands in — an empty Message
	// would print as a dangling "rate limited: ".
	if re.Message != http.StatusText(http.StatusTooManyRequests) {
		t.Errorf("expected the status text as the message, got %q", re.Message)
	}

	if _, err := c.Sign(context.Background(), "commit data", ""); !IsRateLimitError(err) {
		t.Errorf("Sign: expected a rate limit error, got %T: %v", err, err)
	}
}

// TestSignRetrySendsTheBodyAgain pins the invariant executeWithRetry rests on:
// the closure must build the request body afresh on every attempt.
//
// Sign's reader is constructed inside the closure, which is correct and was
// load-bearing the moment a status became retryable — a reader hoisted out is
// drained by attempt one and every attempt after it POSTs an empty body. The
// existing tests count requests and read the final response, so they pass
// either way; nothing looked at what arrived. This does.
func TestSignRetrySendsTheBodyAgain(t *testing.T) {
	const commitData = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@example.com>"
	const signature = "-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----"

	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
			return
		}
		bodies = append(bodies, string(body))
		if len(bodies) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"error":"unavailable","code":"SERVICE_UNAVAILABLE"}`)
			return
		}
		_, _ = fmt.Fprint(w, signature)
	}))
	defer server.Close()

	c, err := New(server.URL,
		WithMaxRetries(2),
		WithRetryWait(time.Millisecond, 5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if _, err := c.Sign(context.Background(), commitData, ""); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(bodies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(bodies))
	}
	for i, body := range bodies {
		if body != commitData {
			t.Errorf("request %d carried %q, want the commit data", i+1, body)
		}
	}
}

// TestSignRetriesBodyTruncatedMidRead covers the transport fault that does not
// look like one.
//
// The generated client reads the body with io.ReadAll inside Parse…Response,
// well past the *url.Error the round trip returned, so a connection dropped
// after the headers arrived comes back as a bare io.ErrUnexpectedEOF. Testing
// only for *url.Error missed it, while README listed "a connection dropped
// mid-body" among the faults this retries — the same shape of gap this file
// exists to close, one layer further in.
func TestSignRetriesBodyTruncatedMidRead(t *testing.T) {
	const signature = "-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----"

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			// Promise more than is sent, then hang up: the client reads the
			// status and headers, then runs out of body.
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "512")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("-----BEGIN PGP SIG"))
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack failed: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = fmt.Fprint(w, signature)
	}))
	defer server.Close()

	c, err := New(server.URL,
		WithMaxRetries(2),
		WithRetryWait(time.Millisecond, 5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := c.Sign(context.Background(), "commit data", "")
	if err != nil {
		t.Fatalf("truncated body was not retried: %v", err)
	}
	if result.Signature != signature {
		t.Errorf("unexpected signature: %q", result.Signature)
	}
	if requests != 2 {
		t.Errorf("expected 2 requests, got %d", requests)
	}
}

// TestMalformedBodyIsNotRetried pins the other side of that line.
//
// A response that arrived whole and failed to decode is not a transport fault:
// the bytes are in hand and the next attempt parses exactly as badly. json
// reports a truncated document as *json.SyntaxError and never wraps
// io.ErrUnexpectedEOF, so recognising the truncated *read* must not drag the
// truncated *document* along with it.
func TestMalformedBodyIsNotRetried(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"keys":[`)
	}))
	defer server.Close()

	c, err := New(server.URL,
		WithAdminToken(testMsgTest),
		WithMaxRetries(3),
		WithRetryWait(time.Millisecond, 5*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if _, err := c.ListKeys(context.Background()); err == nil {
		t.Fatal("expected a decode error")
	}
	if requests != 1 {
		t.Errorf("expected the malformed body to be final, got %d requests", requests)
	}
}

// TestHalfEnvelopeRateLimitKeepsItsBody covers a 429 whose body parsed cleanly
// but is not an envelope: `error` and `retryAfter` with no `code`, which is
// what an intermediary that knows the shape but not the vocabulary emits.
//
// The 429 branch sits above the parse gate, so it reads a value the gate
// rejected. Zeroing that value on rejection threw away a message and a hint
// that had both survived json.Unmarshal — the hoist survived the type of the
// body but not its contents.
func TestHalfEnvelopeRateLimitKeepsItsBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"Too many requests, slow down","retryAfter":7}`)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL, WithAdminToken(testMsgTest))

	_, err := c.ListKeys(context.Background())
	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("expected a *RateLimitError, got %T: %v", err, err)
	}
	if re.Message != "Too many requests, slow down" {
		t.Errorf("expected the body's message, got %q", re.Message)
	}
	if re.RetryAfter != 7*time.Second {
		t.Errorf("expected the body's 7s hint, got %v", re.RetryAfter)
	}
}

// TestParseRetryAfter covers both forms RFC 9110 permits for the header.
func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "delay seconds", value: "30", want: 30 * time.Second},
		{name: "surrounding space", value: "  30  ", want: 30 * time.Second},
		{name: "zero seconds is no hint", value: "0"},
		{name: "negative seconds is no hint", value: "-5"},
		{name: "empty is no hint", value: ""},
		{name: "prose is no hint", value: "soon"},
		{
			name:  "IMF-fixdate",
			value: "Wed, 26 Aug 2026 12:01:00 GMT",
			want:  time.Minute,
		},
		{
			name:  "RFC 850, which a recipient must still understand",
			value: "Wednesday, 26-Aug-26 12:00:30 GMT",
			want:  30 * time.Second,
		},
		{name: "a date already past is no hint", value: "Wed, 26 Aug 2026 11:00:00 GMT"},
		// Atoi accepts it, time.Duration does not: the multiply wraps to -775ms.
		{name: "seconds past what a Duration holds is no hint", value: "9223372036854"},
		{name: "seconds past int64 is no hint", value: "99999999999999999999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseRetryAfter(tt.value, now); got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestRetryAfterHeaderDateReachesTheCaller walks a date-form header the whole
// way through the client, since parseRetryAfter being right is only half of it.
func TestRetryAfterHeaderDateReachesTheCaller(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Retry-After", time.Now().Add(90*time.Second).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, "throttled")
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL, WithAdminToken(testMsgTest))

	_, err := c.ListKeys(context.Background())
	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("expected a *RateLimitError, got %T: %v", err, err)
	}
	// A lower bound in seconds would be a stalled-runner flake whose failure
	// message teaches nothing. What the test is about is that a date-form
	// header produces a hint at all, and one no larger than the delay sent.
	if re.RetryAfter <= 0 || re.RetryAfter > 90*time.Second {
		t.Errorf("expected a positive hint of at most 90s from the date-form header, got %v", re.RetryAfter)
	}
}

// TestNegativeMaxRetriesIsRejected pins where a negative budget is caught.
//
// Do's loop runs while `attempt <= maxRetries`, so a negative value would skip
// it entirely and return a nil error having called nothing, leaving every
// operation to dereference a nil response. New refuses to build such a client,
// which is why no operation has to defend against one.
func TestNegativeMaxRetriesIsRejected(t *testing.T) {
	c, err := New("http://example.invalid", WithMaxRetries(-1))
	if err == nil {
		t.Fatalf("expected New to reject a negative retry budget, got %#v", c)
	}
	if c != nil {
		t.Errorf("expected a nil client alongside the error, got %#v", c)
	}
}

// TestTimeoutBoundsOneAttemptNotTheCall pins what WithTimeout actually bounds.
//
// http.Client applies its Timeout per request, so each attempt is handed a
// fresh one — and a server answering promptly with a retryable status never
// trips it at all. Connecting the retry policy to statuses is what made that
// visible: before it, a 503 ended the call on attempt one and the configured
// timeout was the only clock. It is now four attempts plus the backoff between
// them, which on the defaults is a WithTimeout(30s) call of up to 2m15s. A
// caller who wants one budget for the operation passes a context deadline,
// which Do checks before every wait — TestSignDoesNotRetryCancelledContext
// covers that side.
//
// Held to milliseconds, with an order of magnitude between the handler's delay
// and the timeout, so the arithmetic is the only thing under test.
func TestTimeoutBoundsOneAttemptNotTheCall(t *testing.T) {
	// The two numbers are set apart deliberately. The timeout has to be far
	// enough above the handler's 20ms that a stalled runner cannot trip it —
	// that would turn the *ServiceError assertion into a *url.Error and read as
	// a logic bug rather than a slow machine — while the backoffs have to add
	// up to more than the timeout for the point of the test to hold at all.
	// 20ms per attempt under a 400ms timeout, against 3 x 200ms of backoff.
	const perCall = 400 * time.Millisecond

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, `{"error":"unavailable","code":"INTERNAL_ERROR"}`)
	}))
	defer server.Close()

	c, err := New(server.URL,
		WithTimeout(perCall),
		WithMaxRetries(3),
		WithRetryWait(150*time.Millisecond, 200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	start := time.Now()
	_, err = c.Sign(context.Background(), "commit data", "")
	elapsed := time.Since(start)

	var se *ServiceError
	if !errors.As(err, &se) {
		t.Fatalf("expected a *ServiceError, got %T: %v", err, err)
	}
	if requests != 4 {
		t.Errorf("expected 4 attempts, got %d", requests)
	}
	if elapsed <= perCall {
		t.Errorf("expected the call to outlast WithTimeout(%v), took %v", perCall, elapsed)
	}
}

// TestExpiredTimeoutEndsTheCall pins the other half of what WithTimeout does.
//
// The test above covers a timeout that never fires — a server answering
// promptly with a retryable status. This one covers a timeout that does fire,
// and the rule is the opposite: an attempt that ran out of time is final,
// because the next one is handed the same duration and the same slow server.
//
// It rests entirely on an ordering inside shouldRetry. net/http renders an
// exceeded Client.Timeout as a *url.Error wrapping "context deadline exceeded
// (Client.Timeout exceeded while awaiting headers)", which also satisfies
// errors.Is against context.DeadlineExceeded — so both the context branch and
// the *url.Error branch below it match, and only the fact that the context one
// is written first ends the call. Nothing asserted that: moving the context
// branch below the transport branch left `task c:t` green while turning a
// WithTimeout(30s) call against an unresponsive server into four of them plus
// backoff. The comment above the branch and README's "It never retries: a
// cancelled or expired context" both describe this; now something checks it.
//
// The handler parks until the client hangs up rather than sleeping a fixed
// span, so a passing run costs one timeout instead of one sleep, and a
// regression costs four timeouts rather than hanging. That also makes this the
// one test here whose handler is still running when the call returns, which is
// why the counter is atomic where the rest of the file uses a plain int: every
// other handler has written its response by then, and the round trip is the
// happens-before this one does not get.
func TestExpiredTimeoutEndsTheCall(t *testing.T) {
	const perCall = 100 * time.Millisecond

	var requests atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		// Never answers. Returns when the client gives up, or at teardown.
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
		WithTimeout(perCall),
		WithMaxRetries(3),
		WithRetryWait(60*time.Millisecond, 120*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = c.Sign(context.Background(), "commit data", "")
	if err == nil {
		t.Fatal("expected the expired timeout to surface as an error")
	}
	// The caller still learns it was a timeout rather than a status.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected an error satisfying context.DeadlineExceeded, got %T: %v", err, err)
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("expected an expired timeout to be final after 1 attempt, got %d", got)
	}
}
