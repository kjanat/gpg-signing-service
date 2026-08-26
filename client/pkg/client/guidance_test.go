package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kjanat/gpg-signing-service/client/pkg/api"
)

func strptr(s string) *string { return &s }

// The refusal from the issue: a valid token whose subject nobody trusted. The
// point of the test is that all three actionable fields survive the trip into
// a typed error, because the old client dropped every one of them and left the
// caller with "authentication failed" and a request id.
func TestAuthErrorCarriesGuidance(t *testing.T) {
	body := &api.ErrorResponse{
		Error:   testMsgUntrusted,
		Code:    api.AUTHSUBJECTUNTRUSTED,
		Subject: strptr("repo:kjanat/kjanat:ref:refs/heads/master"),
		Hint:    strptr("No active trust rule matches this subject."),
		Docs:    strptr("https://gpg.example/e/AUTH_SUBJECT_UNTRUSTED"),
	}

	err := newAuthErrorFromResponse(body, http.Header{})

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected an *AuthError, got %T", err)
	}
	if authErr.Code != ErrCodeAuthSubjectUntrusted {
		t.Errorf("expected the untrusted-subject code, got %q", authErr.Code)
	}
	if authErr.Subject != "repo:kjanat/kjanat:ref:refs/heads/master" {
		t.Errorf("expected the presented subject echoed back, got %q", authErr.Subject)
	}
	if authErr.Hint == "" || authErr.Docs == "" {
		t.Errorf("expected a hint and a docs link, got hint=%q docs=%q", authErr.Hint, authErr.Docs)
	}

	// A token problem and an authorization problem take opposite fixes, so the
	// predicate that separates them is the one callers branch on.
	if !IsSubjectUntrusted(err) {
		t.Error("expected IsSubjectUntrusted to recognise the code")
	}
	if !IsAuthError(err) {
		t.Error("expected it to remain an auth error")
	}
	if IsSubjectUntrusted(&AuthError{Code: ErrCodeAuthInvalid}) {
		t.Error("a refused credential is not an untrusted subject")
	}
}

// Error() stays one line. Callers wrap it, log it and compare it; the guidance
// is read off the fields or printed by the CLI, never folded into the string.
func TestAuthErrorStringStaysOneLine(t *testing.T) {
	err := &AuthError{
		Guidance:  Guidance{Hint: "a hint", Docs: "https://gpg.example/e/X", Subject: "repo:a/b"},
		Code:      ErrCodeAuthSubjectUntrusted,
		Message:   testMsgUntrusted,
		RequestID: "628c9a74-c46d-403c-84c6-9c873298a17f",
	}

	got := err.Error()
	want := "authentication failed: AUTH_SUBJECT_UNTRUSTED: Subject is not trusted for signing " +
		"(request 628c9a74-c46d-403c-84c6-9c873298a17f)"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestGuidanceForFindsWrappedErrors(t *testing.T) {
	inner := &ServiceError{
		Guidance:   Guidance{Hint: "add a trust rule", Docs: "https://gpg.example/e/KEY_NOT_ALLOWED"},
		Code:       ErrCodeKeyNotAllowed,
		StatusCode: 403,
	}

	guidance, ok := GuidanceFor(fmt.Errorf("sign-commit failed: %w", inner))
	if !ok {
		t.Fatal("expected guidance to survive wrapping")
	}
	if guidance.Hint != "add a trust rule" {
		t.Errorf("unexpected hint %q", guidance.Hint)
	}
}

// Nothing to say is reported as nothing, so a caller never prints an empty
// frame around empty strings.
func TestGuidanceForReportsAbsence(t *testing.T) {
	for name, err := range map[string]error{
		"plain error":     errors.New("connection refused"),
		"no fields":       &AuthError{Code: ErrCodeAuthMissing, Message: "Missing authorization header"},
		"older service":   newAuthErrorFromResponse(&api.ErrorResponse{Error: "nope", Code: api.AUTHMISSING}, http.Header{}),
		"unparseable 401": newStatusError(401, []byte("not json"), http.Header{}),
	} {
		if _, ok := GuidanceFor(err); ok {
			t.Errorf("%s: expected no guidance", name)
		}
	}
}

// The fallback path, for a body the document does not describe per-operation.
// It has to agree with the typed path about what is worth surfacing, or the
// same refusal reads differently depending on which endpoint answered it.
func TestUntypedBodyCarriesGuidance(t *testing.T) {
	body := []byte(`{"error":"Subject is not trusted for signing","code":"AUTH_SUBJECT_UNTRUSTED",` +
		`"subject":"repo:kjanat/kjanat:ref:refs/heads/master","hint":"No active trust rule matches this subject.",` +
		`"docs":"https://gpg.example/e/AUTH_SUBJECT_UNTRUSTED","requestId":"628c9a74-c46d-403c-84c6-9c873298a17f"}`)

	err := newStatusError(http.StatusUnauthorized, body, http.Header{})

	guidance, ok := GuidanceFor(err)
	if !ok {
		t.Fatal("expected guidance from the hand-parsed envelope")
	}
	if guidance.Subject != "repo:kjanat/kjanat:ref:refs/heads/master" {
		t.Errorf("unexpected subject %q", guidance.Subject)
	}
	if guidance.Docs != "https://gpg.example/e/AUTH_SUBJECT_UNTRUSTED" {
		t.Errorf("unexpected docs link %q", guidance.Docs)
	}
	if !IsSubjectUntrusted(err) {
		t.Error("expected the code to survive the fallback path")
	}
}

// Every status the sign path maps has to carry the guidance through, not just
// the 401. A caller told "rate limited" with no hint and no link is in the same
// position the untrusted-subject 401 used to leave them in.
func TestSignPathCarriesGuidanceOnEveryStatus(t *testing.T) {
	cases := map[string]struct {
		status   int
		body     string
		wantHint string
		wantDocs string
	}{
		"403 key scope": {
			status: http.StatusForbidden,
			body: `{"error":"Token is not allowed to sign with key AAAA","code":"KEY_NOT_ALLOWED",` +
				`"hint":"Widen the credential's keyIds grant.","docs":"https://gpg.example/e/KEY_NOT_ALLOWED"}`,
			wantHint: "Widen the credential's keyIds grant.",
			wantDocs: "https://gpg.example/e/KEY_NOT_ALLOWED",
		},
		"404 key missing": {
			status: http.StatusNotFound,
			body: `{"error":"Key not found","code":"KEY_NOT_FOUND","hint":"Check gpg-sign admin list.",` +
				`"docs":"https://gpg.example/e/KEY_NOT_FOUND"}`,
			wantHint: "Check gpg-sign admin list.",
			wantDocs: "https://gpg.example/e/KEY_NOT_FOUND",
		},
		"429 rate limited": {
			status: http.StatusTooManyRequests,
			body: `{"error":"Rate limit exceeded","code":"RATE_LIMITED","retryAfter":3,` +
				`"hint":"Two tiers meter this call.","docs":"https://gpg.example/e/RATE_LIMITED"}`,
			wantHint: "Two tiers meter this call.",
			wantDocs: "https://gpg.example/e/RATE_LIMITED",
		},
		"400 bad body": {
			status: http.StatusBadRequest,
			body: `{"error":"No commit data provided","code":"INVALID_REQUEST","hint":"Send the commit object.",` +
				`"docs":"https://gpg.example/e/INVALID_REQUEST"}`,
			wantHint: "Send the commit object.",
			wantDocs: "https://gpg.example/e/INVALID_REQUEST",
		},
		"500 signing failed": {
			status: http.StatusInternalServerError,
			body: `{"error":"Signing failed","code":"SIGN_ERROR","hint":"Check KEY_PASSPHRASE.",` +
				`"docs":"https://gpg.example/e/SIGN_ERROR"}`,
			wantHint: "Check KEY_PASSPHRASE.",
			wantDocs: "https://gpg.example/e/SIGN_ERROR",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer server.Close()

			// One attempt: the retrying transport would otherwise sit out the
			// 429's retryAfter before handing the error back.
			c, err := New(server.URL, WithMaxRetries(0), WithoutRateLimitRetry())
			if err != nil {
				t.Fatalf("client: %v", err)
			}

			_, signErr := c.Sign(context.Background(), "commit data", "")
			if signErr == nil {
				t.Fatal("expected an error")
			}

			guidance, ok := GuidanceFor(signErr)
			if !ok {
				t.Fatalf("guidance was dropped: %v", signErr)
			}
			if guidance.Hint != tc.wantHint {
				t.Errorf("hint: want %q, got %q", tc.wantHint, guidance.Hint)
			}
			if guidance.Docs != tc.wantDocs {
				t.Errorf("docs: want %q, got %q", tc.wantDocs, guidance.Docs)
			}
		})
	}
}

// The undeclared 429. `retryAfter` is the only field the document declares a
// typed body for on /sign, so every other operation's 429 is hand-parsed —
// and that branch sits above the envelope gate, where it would be easy to
// build the error from the status alone and drop the fields beside it.
func TestGuidanceSurvivesAnUndeclaredRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "0e2a8f3c-6b41-4d7e-9a55-1c8d0f6b2e77")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"Rate limit exceeded","code":"RATE_LIMITED","retryAfter":3,`+
			`"hint":"Two tiers meter this call.","docs":"https://gpg.example/e/RATE_LIMITED"}`)
	}))
	defer server.Close()

	c, err := New(server.URL, WithMaxRetries(0), WithoutRateLimitRetry())
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	_, keyErr := c.PublicKey(context.Background(), "")
	if keyErr == nil {
		t.Fatal("expected an error")
	}

	guidance, ok := GuidanceFor(keyErr)
	if !ok {
		t.Fatalf("guidance was dropped: %v", keyErr)
	}
	if guidance.Hint != "Two tiers meter this call." {
		t.Errorf("hint: got %q", guidance.Hint)
	}
	if guidance.Docs != "https://gpg.example/e/RATE_LIMITED" {
		t.Errorf("docs: got %q", guidance.Docs)
	}

	var rateErr *RateLimitError
	if !errors.As(keyErr, &rateErr) {
		t.Fatalf("want a RateLimitError, got %T", keyErr)
	}
	if rateErr.RequestID != "0e2a8f3c-6b41-4d7e-9a55-1c8d0f6b2e77" {
		t.Errorf("request id: got %q", rateErr.RequestID)
	}
}
