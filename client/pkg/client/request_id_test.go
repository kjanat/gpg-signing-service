package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The typed 403 and 404 disagreed with the 400 beside them about where a
// request id comes from: the 403 read the envelope alone and the 404 read
// nothing at all. Both statuses are ones an operator opens a ticket about —
// "this credential cannot use that key", "that key does not exist" — and
// docs/troubleshooting.md asks them to quote the id when they do, so a response
// carrying one only on X-Request-ID left them with nothing to quote.
//
// Envelope first, header second, on both statuses: the pair of ids in each
// envelope-present case are deliberately different so preferring the envelope
// is provable rather than merely consistent.
func TestTypedSignErrorsKeepTheRequestID(t *testing.T) {
	const envelopeID = "9c1e0f4a-7b3d-4e21-8f60-5a2c7d9b1e34"
	const headerID = "2d7f8a15-0c46-4b93-a1e7-6f3b8c05d29a"

	cases := map[string]struct {
		status      int
		body        string
		header      string
		wantID      string
		wantCode    string
		wantMessage string
	}{
		"403 envelope id": {
			status: http.StatusForbidden,
			body: fmt.Sprintf(`{"error":"Token is not allowed to sign with key AAAA",`+
				`"code":"KEY_NOT_ALLOWED","requestId":%q}`, envelopeID),
			header:      headerID,
			wantID:      envelopeID,
			wantCode:    ErrCodeKeyNotAllowed,
			wantMessage: "Token is not allowed to sign with key AAAA",
		},
		"403 header only": {
			status:      http.StatusForbidden,
			body:        `{"error":"Token is not allowed to sign with key AAAA","code":"KEY_NOT_ALLOWED"}`,
			header:      headerID,
			wantID:      headerID,
			wantCode:    ErrCodeKeyNotAllowed,
			wantMessage: "Token is not allowed to sign with key AAAA",
		},
		"404 envelope id": {
			status: http.StatusNotFound,
			body: fmt.Sprintf(`{"error":"Key not found","code":"KEY_NOT_FOUND","requestId":%q}`,
				envelopeID),
			header:      headerID,
			wantID:      envelopeID,
			wantCode:    ErrCodeKeyNotFound,
			wantMessage: "Key not found",
		},
		"404 header only": {
			status:      http.StatusNotFound,
			body:        `{"error":"Key not found","code":"KEY_NOT_FOUND"}`,
			header:      headerID,
			wantID:      headerID,
			wantCode:    ErrCodeKeyNotFound,
			wantMessage: "Key not found",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tc.header != "" {
					w.Header().Set("X-Request-ID", tc.header)
				}
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer server.Close()

			c := newMappingClient(t, server.URL)

			_, signErr := c.Sign(context.Background(), "commit data", "AAAA")
			if signErr == nil {
				t.Fatal("expected an error")
			}

			var svcErr *ServiceError
			if !errors.As(signErr, &svcErr) {
				t.Fatalf("expected a *ServiceError, got %T (%v)", signErr, signErr)
			}
			if svcErr.RequestID != tc.wantID {
				t.Errorf("RequestID = %q, want %q", svcErr.RequestID, tc.wantID)
			}
			// The id is only useful where the operator reads it, and that is the
			// rendered error rather than the struct field.
			if want := "(status " + fmt.Sprint(tc.status) + ", request " + tc.wantID + ")"; !strings.HasSuffix(svcErr.Error(), want) {
				t.Errorf("Error() = %q, want it to end with %q", svcErr.Error(), want)
			}
			// Everything else the two branches map has to be exactly what it was.
			if svcErr.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", svcErr.StatusCode, tc.status)
			}
			if svcErr.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", svcErr.Code, tc.wantCode)
			}
			if svcErr.Message != tc.wantMessage {
				t.Errorf("Message = %q, want %q", svcErr.Message, tc.wantMessage)
			}
		})
	}
}

// A 403 or 404 with neither source prints no id, and no empty "(request )".
func TestTypedSignErrorsWithoutAnIDPrintNone(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"error":"Key not found","code":"KEY_NOT_FOUND"}`)
			}))
			defer server.Close()

			c := newMappingClient(t, server.URL)

			_, signErr := c.Sign(context.Background(), "commit data", "AAAA")

			var svcErr *ServiceError
			if !errors.As(signErr, &svcErr) {
				t.Fatalf("expected a *ServiceError, got %T (%v)", signErr, signErr)
			}
			if svcErr.RequestID != "" {
				t.Errorf("RequestID = %q, want empty", svcErr.RequestID)
			}
			want := fmt.Sprintf("KEY_NOT_FOUND: Key not found (status %d)", status)
			if svcErr.Error() != want {
				t.Errorf("Error() = %q, want %q", svcErr.Error(), want)
			}
		})
	}
}
