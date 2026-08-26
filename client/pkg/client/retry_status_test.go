package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	// The header carries whole seconds and the round trip eats some of them.
	if re.RetryAfter <= 80*time.Second || re.RetryAfter > 90*time.Second {
		t.Errorf("expected roughly 90s from the date-form header, got %v", re.RetryAfter)
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
