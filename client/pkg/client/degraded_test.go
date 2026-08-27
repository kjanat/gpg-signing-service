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

const degradedBody = `{"error":"Could not reach the OIDC configuration at https://issuer.example/.well-known/openid-configuration: ` +
	`Request to https://issuer.example timed out after 10000ms","code":"SERVICE_DEGRADED",` +
	`"hint":"This deployment could not reach the issuer to verify the token.",` +
	`"docs":"https://gpg.example/e/SERVICE_DEGRADED"}`

// The failure this code was split out for: the service could not reach the
// issuer, so the token was never judged. It used to arrive as 401 AUTH_INVALID
// — an *AuthError, which shouldRetry refuses — so the one authentication-path
// failure a retry fixes was the one the client would not retry.
func TestDegradedIsRetriedAndCarriesItsGuidance(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, degradedBody)
	}))
	defer server.Close()

	c, err := New(server.URL, WithMaxRetries(1), WithRetryWait(time.Millisecond, 10*time.Millisecond))
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	_, signErr := c.Sign(context.Background(), "commit data", "")
	if signErr == nil {
		t.Fatal("expected an error")
	}

	if attempts != 2 {
		t.Errorf("expected the 503 to be retried once, got %d attempt(s)", attempts)
	}
	if !IsServiceDegraded(signErr) {
		t.Errorf("expected IsServiceDegraded, got %v", signErr)
	}
	// Still a service error and still not an auth error: the credential was
	// never the subject of this refusal.
	if !IsServiceError(signErr) {
		t.Error("a degraded 503 is a service error")
	}
	if IsAuthError(signErr) {
		t.Error("a degraded 503 is not an authentication failure")
	}

	guidance, ok := GuidanceFor(signErr)
	if !ok {
		t.Fatalf("guidance was dropped: %v", signErr)
	}
	if guidance.Docs != "https://gpg.example/e/SERVICE_DEGRADED" {
		t.Errorf("docs: got %q", guidance.Docs)
	}

	var svcErr *ServiceError
	if !errors.As(signErr, &svcErr) {
		t.Fatalf("expected a *ServiceError, got %T", signErr)
	}
	// Read off the header, because ErrorResponse declares no retryAfter field.
	if svcErr.RetryAfter != time.Second {
		t.Errorf("expected the Retry-After header carried onto the error, got %v", svcErr.RetryAfter)
	}
}

// A 503 is the one refusal whose wait this client could not have guessed: a
// rate limit refills on a schedule, an outage clears when it clears.
func TestWaitBeforeHonoursAServiceRetryAfter(t *testing.T) {
	r := &Retrier{retryWaitMin: time.Second, retryWaitMax: time.Minute}

	degraded := &ServiceError{Code: ErrCodeDegraded, StatusCode: 503, RetryAfter: 4 * time.Second}
	if got := r.waitBefore(0, degraded); got != 4*time.Second {
		t.Errorf("expected the server's hint, got %v", got)
	}

	// Clamped, so a hostile or mistaken hint cannot park a caller for hours.
	tooLong := &ServiceError{Code: ErrCodeDegraded, StatusCode: 503, RetryAfter: time.Hour}
	if got := r.waitBefore(0, tooLong); got != time.Minute {
		t.Errorf("expected the ceiling, got %v", got)
	}

	// Nothing to honour falls back to backoff, which is never zero.
	plain := &ServiceError{Code: ErrCodeInternalError, StatusCode: 500}
	if got := r.waitBefore(0, plain); got <= 0 {
		t.Errorf("expected a backoff, got %v", got)
	}
}

// WithoutRateLimitRetry turns off *throttling* retries. An outage's wait hint
// is a different thing and must survive it.
func TestServiceRetryAfterSurvivesRateLimitRetryBeingOff(t *testing.T) {
	r := &Retrier{retryWaitMin: time.Second, retryWaitMax: time.Minute, retryOnRateLimit: false}

	degraded := &ServiceError{Code: ErrCodeDegraded, StatusCode: 503, RetryAfter: 2 * time.Second}
	if got := r.waitBefore(0, degraded); got != 2*time.Second {
		t.Errorf("expected the server's hint, got %v", got)
	}
}
