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
// Envelopes reused across the cases below, with no requestId field: the shape a
// deployment older than the release that added it sends, and the one that has
// only the echoed header left to fall back on.
const (
	bodyKeyNotFound   = `{"error":"Key not found","code":"KEY_NOT_FOUND"}`
	bodyKeyNotAllowed = `{"error":"Token is not allowed to sign with key AAAA","code":"KEY_NOT_ALLOWED"}`
	bodyInternalError = `{"error":"Internal error","code":"INTERNAL_ERROR"}`
)

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
			body:        bodyKeyNotAllowed,
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
			body:        bodyKeyNotFound,
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
//
// Each status is fed the body it actually sends — sign.ts answers 403 with
// KEY_NOT_ALLOWED and 404 with KEY_NOT_FOUND — so the rendered string these
// assert is one the service can produce rather than a fixture that only
// happens to exercise the branch.
func TestTypedSignErrorsWithoutAnIDPrintNone(t *testing.T) {
	cases := []struct {
		status   int
		body     string
		wantText string
	}{
		{http.StatusForbidden, bodyKeyNotAllowed, "KEY_NOT_ALLOWED: Token is not allowed to sign with key AAAA"},
		{http.StatusNotFound, bodyKeyNotFound, "KEY_NOT_FOUND: Key not found"},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
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
			want := fmt.Sprintf("%s (status %d)", tc.wantText, tc.status)
			if svcErr.Error() != want {
				t.Errorf("Error() = %q, want %q", svcErr.Error(), want)
			}
		})
	}
}

// The same defect, on the branches the sign path's fix did not reach: every
// other error this client returns either read the envelope alone (the admin
// audit 400/500) or read nothing at all (PublicKey, AdminPublicKey, UploadKey,
// ListKeys, DeleteKey, and the two envelope-less errors at the end of the
// table), so a response carrying its id only on X-Request-ID left the caller
// with nothing to quote there either. requestIdMiddleware stamps the header on
// every response the service sends, which is what makes it a fallback worth
// having on all of them.
func TestNonSignErrorsKeepTheRequestID(t *testing.T) {
	const headerID = "2d7f8a15-0c46-4b93-a1e7-6f3b8c05d29a"

	cases := map[string]struct {
		status int
		body   string
		call   func(*Client) error
	}{
		"public key 404": {
			status: http.StatusNotFound,
			body:   bodyKeyNotFound,
			call: func(c *Client) error {
				_, err := c.PublicKey(context.Background(), "AAAA")
				return err
			},
		},
		"public key 500": {
			status: http.StatusInternalServerError,
			body:   bodyInternalError,
			call: func(c *Client) error {
				_, err := c.PublicKey(context.Background(), "AAAA")
				return err
			},
		},
		"admin public key 404": {
			status: http.StatusNotFound,
			body:   bodyKeyNotFound,
			call: func(c *Client) error {
				_, err := c.AdminPublicKey(context.Background(), "AAAA")
				return err
			},
		},
		"upload key 400": {
			status: http.StatusBadRequest,
			body:   `{"error":"Invalid key","code":"INVALID_REQUEST"}`,
			call: func(c *Client) error {
				_, err := c.UploadKey(context.Background(), "AAAA", "-----BEGIN PGP PRIVATE KEY BLOCK-----")
				return err
			},
		},
		"list keys 500": {
			status: http.StatusInternalServerError,
			body:   bodyInternalError,
			call: func(c *Client) error {
				_, err := c.ListKeys(context.Background())
				return err
			},
		},
		"delete key 500": {
			status: http.StatusInternalServerError,
			body:   bodyInternalError,
			call: func(c *Client) error {
				return c.DeleteKey(context.Background(), "AAAA")
			},
		},
		"audit 500": {
			status: http.StatusInternalServerError,
			body:   bodyInternalError,
			call: func(c *Client) error {
				_, err := c.AuditLogs(context.Background(), AuditFilter{})
				return err
			},
		},
		// The last two have no error envelope to read at all, so the echoed
		// header is not a fallback there but the only source: HealthResponse
		// declares no requestId, and the delete not-found is synthesized from a
		// 200 whose body says nothing happened. Both are still responses an
		// operator reports — a service calling itself degraded, a delete that
		// says the key was never there.
		"health 503 degraded": {
			status: http.StatusServiceUnavailable,
			body: `{"status":"degraded","version":"1.0.0",` +
				`"timestamp":"2026-01-01T00:00:00Z",` +
				`"checks":{"keyStorage":false,"database":true}}`,
			call: func(c *Client) error {
				_, err := c.Health(context.Background())
				return err
			},
		},
		"delete key reported not found": {
			status: http.StatusOK,
			body:   `{"success":true,"deleted":false,"keyId":"AAAA"}`,
			call: func(c *Client) error {
				return c.DeleteKey(context.Background(), "AAAA")
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-ID", headerID)
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer server.Close()

			c := newMappingClient(t, server.URL, WithAdminToken("test-token"))

			err := tc.call(c)

			var svcErr *ServiceError
			if !errors.As(err, &svcErr) {
				t.Fatalf("expected a *ServiceError, got %T (%v)", err, err)
			}
			if svcErr.RequestID != headerID {
				t.Errorf("RequestID = %q, want %q", svcErr.RequestID, headerID)
			}
			if !strings.Contains(svcErr.Error(), "request "+headerID) {
				t.Errorf("Error() = %q, want it to mention the request id", svcErr.Error())
			}
		})
	}
}

// The envelope still wins where the service does send one, on the branch that
// used to be the only non-sign reader of it.
func TestAuditErrorPrefersTheEnvelopeID(t *testing.T) {
	const envelopeID = "9c1e0f4a-7b3d-4e21-8f60-5a2c7d9b1e34"
	const headerID = "2d7f8a15-0c46-4b93-a1e7-6f3b8c05d29a"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", headerID)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"Invalid filter","code":"INVALID_REQUEST","requestId":%q}`, envelopeID)
	}))
	defer server.Close()

	c := newMappingClient(t, server.URL, WithAdminToken("test-token"))

	_, err := c.AuditLogs(context.Background(), AuditFilter{})

	var svcErr *ServiceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected a *ServiceError, got %T (%v)", err, err)
	}
	if svcErr.RequestID != envelopeID {
		t.Errorf("RequestID = %q, want the envelope id %q", svcErr.RequestID, envelopeID)
	}
}
