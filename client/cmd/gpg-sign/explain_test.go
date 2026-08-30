package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

// The failure from the issue, rendered the way the operator sees it.
func TestReportFailurePrintsEachFieldOnItsOwnLine(t *testing.T) {
	var out bytes.Buffer
	err := &client.AuthError{
		Subject:   "repo:kjanat/kjanat:ref:refs/heads/master",
		Hint:      "No active trust rule matches this subject.",
		Docs:      "https://gpg.kajkowalski.nl/e/AUTH_SUBJECT_UNTRUSTED",
		Code:      client.ErrCodeAuthSubjectUntrusted,
		Message:   "Subject is not trusted for signing",
		RequestID: "628c9a74-c46d-403c-84c6-9c873298a17f",
	}

	reportFailure(&out, err)

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected one line per field, got %d:\n%s", len(lines), out.String())
	}
	for i, want := range []string{"subject:", "hint:", "docs:", "request:"} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d: expected %q, got %q", i, want, lines[i])
		}
	}
	// The whole point is that none of this is JSON any more.
	if strings.Contains(out.String(), "{") {
		t.Errorf("expected no raw envelope in the output:\n%s", out.String())
	}
}

// The reporter runs after cobra has printed the error, and it sees whatever
// wrapping the command applied on the way out.
func TestReportFailureSeesThroughWrapping(t *testing.T) {
	var out bytes.Buffer
	inner := &client.ServiceError{
		Docs:       "https://gpg.kajkowalski.nl/e/KEY_NOT_ALLOWED",
		Code:       client.ErrCodeKeyNotAllowed,
		StatusCode: 403,
		RequestID:  "11111111-2222-3333-4444-555555555555",
	}

	reportFailure(&out, fmt.Errorf("sign-commit failed: %w", inner))

	if !strings.Contains(out.String(), "e/KEY_NOT_ALLOWED") {
		t.Errorf("expected the docs link, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "11111111-2222-3333-4444-555555555555") {
		t.Errorf("expected the request id, got:\n%s", out.String())
	}
}

// Silence rather than an empty frame: a network failure, or a service too old
// to send the fields, has nothing to add underneath cobra's line.
func TestReportFailureStaysQuietWithNothingToAdd(t *testing.T) {
	for name, err := range map[string]error{
		"transport":    errors.New("dial tcp: connection refused"),
		"bare refusal": &client.AuthError{Code: client.ErrCodeAuthMissing, Message: "Missing authorization header"},
	} {
		var out bytes.Buffer
		reportFailure(&out, err)
		if out.Len() != 0 {
			t.Errorf("%s: expected no output, got:\n%s", name, out.String())
		}
	}
}

// An error can carry an id and nothing else — an intermediary's refusal, or a
// deployment older than the release that added the guidance fields. The id is
// still the thing the operator is asked to quote, so it prints on its own.
func TestReportFailurePrintsRequestIDWithoutGuidance(t *testing.T) {
	var out bytes.Buffer
	reportFailure(&out, &client.AuthError{
		Code:      client.ErrCodeAuthInvalid,
		Message:   "Invalid token signature",
		RequestID: "628c9a74-c46d-403c-84c6-9c873298a17f",
	})

	got := strings.TrimRight(out.String(), "\n")
	if got != "  request: 628c9a74-c46d-403c-84c6-9c873298a17f" {
		t.Errorf("unexpected output %q", got)
	}
}

// A hint alone is enough to print; the other fields are skipped rather than
// rendered as empty labels.
func TestReportFailureSkipsAbsentFields(t *testing.T) {
	var out bytes.Buffer
	reportFailure(&out, &client.RateLimitError{
		Hint:    "Wait for the bucket to refill.",
		Message: "Rate limit exceeded",
	})

	got := strings.TrimRight(out.String(), "\n")
	if got != "  hint:    Wait for the bucket to refill." {
		t.Errorf("unexpected output %q", got)
	}
}

// A rate limit carries its id on the echoed header and nowhere else, so the
// block prints it from RateLimitError rather than only from the two envelope
// types that declare a `requestId`.
func TestReportFailurePrintsRateLimitRequestID(t *testing.T) {
	var out bytes.Buffer
	reportFailure(&out, &client.RateLimitError{
		Hint:      "Wait for the bucket to refill.",
		Message:   "Rate limit exceeded",
		RequestID: "0e2a8f3c-6b41-4d7e-9a55-1c8d0f6b2e77",
	})

	got := out.String()
	if !strings.Contains(got, "request: 0e2a8f3c-6b41-4d7e-9a55-1c8d0f6b2e77") {
		t.Errorf("request id missing from %q", got)
	}
}
