package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unauthorizedStub answers every request with a 401 carrying the given body,
// labelled `application/json` — the label is the point, since it is what sends
// the response down the generated client's typed branch whether or not the body
// can be decoded there.
func unauthorizedStub(t *testing.T, body string, extra map[string]string) *Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range extra {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

// TestUnauthorizedWithoutCodeFallsBackToSentinel is the second half of the
// usable-envelope rule.
//
// ErrorResponse declares `code` required, and the reason this client reads the
// declared 401 at all is that callers are told to branch on the code rather
// than on prose the service is free to reword. An AuthError with an empty Code
// cannot be branched on — it is a sentinel wearing a type — and
// parseAPIErrorBody already rejects the same body on the fallback path.
func TestUnauthorizedWithoutCodeFallsBackToSentinel(t *testing.T) {
	client := unauthorizedStub(t, `{"error":"Unauthorized"}`, nil)

	if _, err := client.ListKeys(context.Background()); !errors.Is(err, ErrUnexpectedStatus) {
		t.Errorf("ListKeys: a 401 with no code must report as an unexpected status, got %T (%v)", err, err)
	}
	if _, err := client.Sign(context.Background(), "commit data", ""); !errors.Is(err, ErrUnexpectedStatus) {
		t.Errorf("Sign: a 401 with no code must report as an unexpected status, got %T (%v)", err, err)
	}
}

// TestUndecodableErrorBodyKeepsTheStatus is the regression the declared 401
// introduced and errorBodyTransport closes.
//
// The generated parser dispatches on Content-Type before it knows the body is
// well formed, and answers a decode failure with `return nil, err`. That loses
// the response: the caller gets "unexpected end of JSON input" — no status, no
// sentinel, nothing errors.Is can classify — which is strictly worse than the
// "unexpected status code: 401" this client series exists to replace.
func TestUndecodableErrorBodyKeepsTheStatus(t *testing.T) {
	bodies := map[string]string{
		"empty":           ``,
		"truncated":       `{"error": "nope"`,
		"not json at all": `<html><body>401</body></html>`,
		"wrong types":     `{"error": 42, "code": []}`,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			client := unauthorizedStub(t, body, nil)

			_, err := client.ListKeys(context.Background())
			if !errors.Is(err, ErrUnexpectedStatus) {
				t.Fatalf("expected the sentinel, got %T (%v)", err, err)
			}
			// The status is the only thing left to report, so it has to survive.
			if got := err.Error(); got != "unexpected status code: 401" {
				t.Errorf("status lost from the message: %q", got)
			}
		})
	}
}

// TestOffSchemaRequestIDStillYieldsAnAuthError covers a body that is valid JSON
// and a perfectly readable envelope, but fails the document's schema:
// `requestId` is declared a UUID and typed *openapi_types.UUID in the generated
// struct, so a free-text id takes the whole decode down with it.
//
// This service cannot produce that — getRequestId only honours a
// caller-supplied id when it parses as a UUID, precisely so one free-text value
// cannot make a page undecodable — but nothing constrains an intermediary. The
// hand-rolled fallback parser types the field as a string, so once the response
// reaches it the caller gets the message, the code and the id intact.
func TestOffSchemaRequestIDStillYieldsAnAuthError(t *testing.T) {
	client := unauthorizedStub(t, `{"error":"`+testMsgBadAdmin+`","code":"AUTH_INVALID","requestId":"req-123"}`, nil)

	_, err := client.ListKeys(context.Background())

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected an *AuthError, got %T (%v)", err, err)
	}
	if authErr.Code != testCodeAuthInvalid {
		t.Errorf("code was discarded: %q", authErr.Code)
	}
	if authErr.Message != testMsgBadAdmin {
		t.Errorf("message was discarded: %q", authErr.Message)
	}
	if authErr.RequestID != "req-123" {
		t.Errorf("request id was discarded: %q", authErr.RequestID)
	}
}

// TestRequestIDFallsBackToTheHeader pins the id an operator needs against a
// service that does not put it in the body.
//
// Every 401 this service emits now carries `requestId` in its envelope, but a
// client is not deployed in lockstep with the Worker it talks to, and the id is
// the key to the audit_logs row — the one thing a failed CI run leaves behind
// that a laptop cannot reproduce. It is echoed on X-Request-ID either way.
func TestRequestIDFallsBackToTheHeader(t *testing.T) {
	t.Run("declared 401", func(t *testing.T) {
		client := unauthorizedStub(t, `{"error":"`+testMsgBadAdmin+`","code":"AUTH_INVALID"}`,
			map[string]string{"X-Request-ID": testRequestID})

		_, err := client.ListKeys(context.Background())

		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected an *AuthError, got %T (%v)", err, err)
		}
		if authErr.RequestID != testRequestID {
			t.Errorf("request id not recovered from the header: %q", authErr.RequestID)
		}
	})

	t.Run("envelope wins when both are present", func(t *testing.T) {
		// They are the same id in practice; if they ever differ, the body is the
		// value the handler recorded.
		client := unauthorizedStub(t,
			`{"error":"`+testMsgBadAdmin+`","code":"AUTH_INVALID","requestId":"`+testRequestID+`"}`,
			map[string]string{"X-Request-ID": "00000000-0000-4000-8000-000000000000"})

		_, err := client.ListKeys(context.Background())

		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected an *AuthError, got %T (%v)", err, err)
		}
		if authErr.RequestID != testRequestID {
			t.Errorf("header overrode the envelope: %q", authErr.RequestID)
		}
	})
}

// TestSuccessBodiesAreNotBuffered guards the transport's own boundary: it reads
// error bodies to check them, and must leave everything else alone.
func TestSuccessBodiesAreNotBuffered(t *testing.T) {
	const armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pgp-keys")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(armored))
	}))
	defer server.Close()

	client, _ := New(server.URL)

	key, err := client.PublicKey(context.Background(), "")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if key != armored {
		t.Errorf("body altered in transit: %q", key)
	}
}

// TestOversizedErrorBodyIsDroppedNotBuffered pins the ceiling on the error-body
// read.
//
// errorBodyTransport buffers the body so a broken one can be caught before the
// generated parser dies on it, and the parser then reads the same bytes back
// out — so an unbounded read here lets the peer pick the client's allocation,
// twice over. A body past the ceiling carries nothing a caller can act on that
// the status code does not, so it is dropped and the status survives alone.
func TestOversizedErrorBodyIsDroppedNotBuffered(t *testing.T) {
	// A well-formed envelope, padded past the ceiling. Well-formed on purpose:
	// the ceiling has to bite before decodability is consulted, or the size of
	// the allocation is still the peer's to choose.
	padding := strings.Repeat("A", maxErrorBodyBytes)
	body := `{"error":"` + padding + `","code":"AUTH_INVALID"}`
	if len(body) <= maxErrorBodyBytes {
		t.Fatalf("test body is not oversized: %d bytes", len(body))
	}

	client := unauthorizedStub(t, body, nil)

	_, err := client.ListKeys(context.Background())
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("expected the sentinel, got %T (%v)", err, err)
	}
	if got := err.Error(); got != "unexpected status code: 401" {
		t.Errorf("status lost from the message: %q", got)
	}
	// The point of the ceiling: the padding must not have reached an AuthError.
	if strings.Contains(err.Error(), padding[:64]) {
		t.Error("the oversized body was surfaced to the caller after all")
	}
}

// TestErrorBodyAtTheCeilingStillDecodes is the other side of the boundary: a
// body that fits must be reported in full, so the ceiling cannot quietly become
// a truncation that costs callers their message.
func TestErrorBodyAtTheCeilingStillDecodes(t *testing.T) {
	message := strings.Repeat("B", maxErrorBodyBytes-len(`{"error":"","code":"AUTH_INVALID"}`))
	body := `{"error":"` + message + `","code":"AUTH_INVALID"}`
	if len(body) != maxErrorBodyBytes {
		t.Fatalf("test body is not exactly at the ceiling: %d bytes", len(body))
	}

	client := unauthorizedStub(t, body, nil)

	_, err := client.ListKeys(context.Background())
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected an *AuthError, got %T (%v)", err, err)
	}
	if authErr.Message != message {
		t.Errorf("message truncated: got %d bytes, want %d", len(authErr.Message), len(message))
	}
}
