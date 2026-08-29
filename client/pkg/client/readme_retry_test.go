package client

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// retrySections pulls the three places README.md states the retry policy.
//
// Keyed on the headings rather than on line numbers so a rewrite of the prose
// does not break the test; a rewrite that *deletes* one of the headings does,
// which is the right answer — the claim has to live somewhere.
func retrySections(t *testing.T) map[string]string {
	t.Helper()

	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(raw)

	bounds := []struct {
		name  string
		start string
		end   string
	}{
		{"automatically retries", "The client automatically retries:", "It never retries:"},
		{"never retries", "It never retries:", "Retry strategy:"},
		{"what is retried", "### What is retried", "Retries are exhausted"},
	}

	sections := make(map[string]string, len(bounds))
	for _, b := range bounds {
		from := strings.Index(readme, b.start)
		if from < 0 {
			t.Fatalf("README.md no longer contains %q; the retry policy has to be stated somewhere", b.start)
		}
		to := strings.Index(readme[from:], b.end)
		if to < 0 {
			t.Fatalf("README.md: no %q after %q", b.end, b.start)
		}
		sections[b.name] = readme[from : from+to]
	}
	return sections
}

// The README's retry lists have to name the one 5xx this client refuses.
//
// The lists read "transient service errors (500, 502, 503, 504)" and "a 429, a
// 500, 502, 503 or 504 … Nothing else", which is the policy minus its only
// exception — and the exception is the whole reason the code exists. A caller
// reading those lists writes a handler that expects a SERVICE_MISCONFIGURED 500
// to have been retried four times, and then cannot explain why the call
// returned in under a second.
//
// Asserted alongside the behaviour rather than on its own, so the test fails
// when the two disagree rather than when the prose is merely reworded.
func TestReadmeNamesTheOneUnretried5xx(t *testing.T) {
	r := &Retrier{maxRetries: 3, retryWaitMin: time.Millisecond, retryWaitMax: time.Second}

	if r.shouldRetry(&ServiceError{Code: ErrCodeMisconfigured, StatusCode: 500}) {
		t.Fatal("shouldRetry now retries SERVICE_MISCONFIGURED; the README says it does not")
	}
	// The neighbours it has to stay distinguishable from, so a test that starts
	// passing because *everything* stopped being retried still fails.
	for _, retryable := range []*ServiceError{
		{Code: ErrCodeDegraded, StatusCode: 503},
		{Code: ErrCodeInternalError, StatusCode: 500},
		{StatusCode: 502},
	} {
		if !r.shouldRetry(retryable) {
			t.Fatalf("shouldRetry declined %+v, which the README lists as retried", retryable)
		}
	}

	for name, section := range retrySections(t) {
		if !strings.Contains(section, ErrCodeMisconfigured) {
			t.Errorf("README.md %q section does not name %s, so it documents the 5xx policy without its only exception:\n%s",
				name, ErrCodeMisconfigured, section)
		}
	}
}

// The wait between attempts comes from more than a 429.
//
// waitBefore honours a ServiceError's Retry-After too — a SERVICE_DEGRADED 503
// carries one, and unlike a rate limit's it is not something this client could
// have estimated. The README used to describe the hint as a 429-only affair,
// which understates what the retrier does with an outage that told it how long
// to wait.
func TestReadmeDescribesTheDegradedWaitHint(t *testing.T) {
	r := &Retrier{maxRetries: 3, retryWaitMin: time.Millisecond, retryWaitMax: time.Minute}

	degraded := &ServiceError{Code: ErrCodeDegraded, StatusCode: 503, RetryAfter: 2 * time.Second}
	if got := r.waitBefore(1, degraded); got != 2*time.Second {
		t.Fatalf("waitBefore for a degraded 503 = %v, want the server's 2s hint", got)
	}
	// RATE_LIMIT_ERROR is the retryable 503 that sends no interval, which is why
	// the README may not say "a 503 carries a Retry-After" without qualifying it.
	//
	// Asserted as "fell through to the backoff" rather than as "not 2s": the
	// latter passes for every wait the retrier could have invented except one,
	// so it would not have caught a hint read off the wrong field. At
	// retryWaitMin=1ms the first backoff is 2^1*1ms plus up to 1ms of jitter.
	noHint := &ServiceError{Code: "RATE_LIMIT_ERROR", StatusCode: 503}
	if got := r.waitBefore(1, noHint); got < 2*time.Millisecond || got >= 3*time.Millisecond {
		t.Fatalf("waitBefore for a 503 that carried no interval = %v, want the backoff (2-3ms)", got)
	}

	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(raw)

	for _, claim := range []string{ErrCodeDegraded, "RATE_LIMIT_ERROR"} {
		if !strings.Contains(readme, claim) {
			t.Errorf("README.md does not mention %s, so its account of the wait hint is incomplete", claim)
		}
	}
}

// The README says where a 429's wait hint comes from, and the two sources are
// not interchangeable.
//
// This service puts the hint in the body, as `retryAfter`; it sends no
// `Retry-After` header on a 429 at all — the denial carries only the two
// X-RateLimit headers, and the limiter's own header never leaves the Durable
// Object. The client still reads the header, because a 429 that carries one was
// authored by an edge throttle in front of the service and is otherwise the
// response whose hint is lost. Writing that as "`retryAfter`/`Retry-After` on a
// 429" described the two as one thing and left a reader expecting a header this
// service never sends.
func TestReadmeAttributesThe429WaitHint(t *testing.T) {
	// The envelope is preferred, which is what makes it the service's channel.
	if got := retryAfterFrom(3, http.Header{headerRetryAfter: []string{"9"}}); got != 3*time.Second {
		t.Fatalf("retryAfterFrom with both = %v, want the envelope's 3s", got)
	}
	// The header is the fallback, for the 429 this service did not write.
	if got := retryAfterFrom(0, http.Header{headerRetryAfter: []string{"9"}}); got != 9*time.Second {
		t.Fatalf("retryAfterFrom with a header only = %v, want 9s", got)
	}
	if got := retryAfterFrom(0, http.Header{}); got != 0 {
		t.Fatalf("retryAfterFrom with neither = %v, want no hint", got)
	}

	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	// Reflowed to one line first: the formatter wraps this prose at 80 columns,
	// so a phrase this test looks for can land either side of a newline for
	// reasons that have nothing to do with what it says.
	readme := strings.Join(strings.Fields(string(raw)), " ")

	// Both sources have to be named, and the body one attributed to this service
	// rather than listed as an alternative spelling of the header.
	for _, claim := range []string{"body's `retryAfter`", "`Retry-After` header"} {
		if !strings.Contains(readme, claim) {
			t.Errorf("README.md does not contain %q, so it no longer says where a 429's hint comes from", claim)
		}
	}
	if strings.Contains(readme, "`retryAfter`/`Retry-After` on a `429`") {
		t.Error("README.md still describes the body field and the header as one source on a 429")
	}
}
