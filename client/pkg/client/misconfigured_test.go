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

const misconfiguredBody = `{"error":"SSRF protection: URL resolves to a private address",` +
	`"code":"SERVICE_MISCONFIGURED",` +
	`"hint":"This deployment refuses to fetch from the URL that issuer's discovery points at, so no token from it ` +
	`can ever be verified here. Retrying will get this same answer every time.",` +
	`"docs":"https://gpg.example/e/SERVICE_MISCONFIGURED"}`

// The whole point of the code existing: a 5xx that is not worth retrying.
//
// The service used to say "permanent" by omitting Retry-After, which no client
// reads as a signal — shouldRetry attempts every 5xx — so an ALLOWED_ISSUERS
// entry pointing at a URL the service will never fetch cost four requests and
// the whole backoff budget to be told the same thing four times. Omitting the
// header only removed the interval.
func TestMisconfiguredIsNotRetried(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		// Deliberately no Retry-After: the code is the signal, and this asserts
		// the policy does not need the header's absence to reach the same answer.
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, misconfiguredBody)
	}))
	defer server.Close()

	c, err := New(server.URL, WithMaxRetries(3), WithRetryWait(time.Millisecond, 10*time.Millisecond))
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	_, signErr := c.Sign(context.Background(), "commit data", "")
	if signErr == nil {
		t.Fatal("expected an error")
	}

	if attempts != 1 {
		t.Errorf("a permanent 503 was attempted %d times; it must be attempted once", attempts)
	}
	if !IsServiceMisconfigured(signErr) {
		t.Errorf("expected IsServiceMisconfigured, got %v", signErr)
	}
	// Still a service error, and still not the caller's fault to fix: the
	// classification narrows what to do about it, it does not move the blame.
	if !IsServiceError(signErr) {
		t.Error("a misconfigured 503 is a service error")
	}
	if IsServiceDegraded(signErr) {
		t.Error("SERVICE_MISCONFIGURED is not SERVICE_DEGRADED; the two answer 'retry?' oppositely")
	}
	if IsAuthError(signErr) {
		t.Error("a misconfigured 503 is not an authentication failure")
	}

	guidance, ok := GuidanceFor(signErr)
	if !ok {
		t.Fatalf("guidance was dropped: %v", signErr)
	}
	if guidance.Docs != "https://gpg.example/e/SERVICE_MISCONFIGURED" {
		t.Errorf("docs: got %q", guidance.Docs)
	}
	if guidance.Hint == "" {
		t.Error("the hint names the operator's knob and is the only actionable part")
	}
}

// The neighbouring 503 must be unaffected. A policy that read "no Retry-After"
// as "do not retry" would also stop retrying every intermediary's bare 502, so
// this pins that the distinction is the code and nothing else.
func TestDegradedWithoutARetryAfterIsStillRetried(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, degradedBody)
	}))
	defer server.Close()

	c, err := New(server.URL, WithMaxRetries(2), WithRetryWait(time.Millisecond, 10*time.Millisecond))
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	if _, signErr := c.Sign(context.Background(), "commit data", ""); signErr == nil {
		t.Fatal("expected an error")
	}

	if attempts != 3 {
		t.Errorf("a transient 503 carrying no hint should still be retried; got %d attempt(s)", attempts)
	}
}

// A 5xx this client cannot read a code off must keep retrying.
//
// recordRetryHint takes the code from the body alone — it has no header form —
// so an intermediary's bare 502, an oversized body, a text/plain page all leave
// it empty. Empty is not ErrCodeMisconfigured, and the fallback has to be the
// retrying one: a client that treated "unknown" as permanent would refuse the
// exact transport-level faults retries exist for.
func TestUnreadable5xxIsStillRetried(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, "<html><body>502 Bad Gateway</body></html>")
	}))
	defer server.Close()

	c, err := New(server.URL, WithMaxRetries(2), WithRetryWait(time.Millisecond, 10*time.Millisecond))
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	if _, signErr := c.Sign(context.Background(), "commit data", ""); signErr == nil {
		t.Fatal("expected an error")
	}

	if attempts != 3 {
		t.Errorf("a 5xx with no readable code must still be retried; got %d attempt(s)", attempts)
	}
}

// shouldRetry reads the code, not the missing header. Asserted directly so the
// policy holds for a caller driving the retrier with its own mapped error, and
// not only for the signal executeWithRetry synthesises.
func TestShouldRetryReadsThePermanentCode(t *testing.T) {
	r := &Retrier{maxRetries: 3, retryWaitMin: time.Millisecond, retryWaitMax: time.Second}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"permanent 503", &ServiceError{Code: ErrCodeMisconfigured, StatusCode: 503}, false},
		{"transient 503", &ServiceError{Code: ErrCodeDegraded, StatusCode: 503}, true},
		// The header says nothing either way: a permanent fault carrying one is
		// still permanent, and a transient one carrying none is still transient.
		{"permanent 503 that carried a wait anyway", &ServiceError{Code: ErrCodeMisconfigured, StatusCode: 503, RetryAfter: time.Minute}, false},
		{"500", &ServiceError{Code: ErrCodeInternalError, StatusCode: 500}, true},
		{"no code at all", &ServiceError{StatusCode: 502}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.shouldRetry(tc.err); got != tc.want {
				t.Errorf("shouldRetry = %v, want %v", got, tc.want)
			}
		})
	}
}

// The other half of the plumbing this needed.
//
// recordRetryHint only ever recorded a 429, so a 503's Retry-After reached the
// mapped error the operation returned and never the wait *between* attempts:
// retryStatusSignal built a ServiceError with no interval on it, and
// waitBefore's ServiceError branch was unreachable during the loop. The client
// backed off blind against the one failure that had told it what to do.
func TestDegradedRetryAfterGovernsTheWaitBetweenAttempts(t *testing.T) {
	attempts := 0
	var gaps []time.Duration
	last := time.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		if attempts > 0 {
			gaps = append(gaps, now.Sub(last))
		}
		last = now
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, degradedBody)
	}))
	defer server.Close()

	// The server asks for a second and the ceiling clamps that to 100ms. The
	// backoff this has to be distinguishable from is 2^1 x 1ms plus up to 1ms of
	// jitter, so anything at or past the ceiling could only have come from the
	// hint. The gap between the two is what makes the assertion mean something:
	// picking a retryWaitMin whose backoff already reaches retryWaitMax would
	// pass whether or not the hint was ever read.
	c, err := New(server.URL, WithMaxRetries(1), WithRetryWait(time.Millisecond, 100*time.Millisecond))
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	if _, signErr := c.Sign(context.Background(), "commit data", ""); signErr == nil {
		t.Fatal("expected an error")
	}

	if len(gaps) != 1 {
		t.Fatalf("expected one retry, saw %d", len(gaps))
	}
	if gaps[0] < 100*time.Millisecond {
		t.Errorf("waited %v; the server's clamped hint is 100ms and the backoff would be ~3ms, "+
			"so the hint was not read", gaps[0])
	}
}

// retryStatusSignal is where the body's code has to survive into the policy.
// Tested directly because the value it builds is skeletal by design, and what
// makes it useful is precisely the two fields carried onto it.
func TestRetryStatusSignalCarriesTheCode(t *testing.T) {
	signal := retryStatusSignal(http.StatusServiceUnavailable, retryHint{
		code:       ErrCodeMisconfigured,
		retryAfter: 5 * time.Second,
	})
	if signal == nil {
		t.Fatal("a 503 is a failure whether or not it is retried")
	}

	var svcErr *ServiceError
	if !errors.As(signal, &svcErr) {
		t.Fatalf("expected a *ServiceError, got %T", signal)
	}
	if svcErr.Code != ErrCodeMisconfigured {
		t.Errorf("Code = %q, want %q", svcErr.Code, ErrCodeMisconfigured)
	}
	if svcErr.RetryAfter != 5*time.Second {
		t.Errorf("RetryAfter = %v, want 5s", svcErr.RetryAfter)
	}
}
