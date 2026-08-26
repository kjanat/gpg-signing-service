package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/api"
)

// Error codes returned by the service in the `code` field of an error response.
//
// AuthError.Code carries one of the two AUTH_ values on every 401 the document
// declares, and the pair is the whole reason the code is surfaced rather than
// the prose: AUTH_MISSING means no usable credential was presented and retrying
// with the same configuration cannot help, while AUTH_INVALID means one was
// presented and refused — a rotated admin token, an unlisted issuer, a subject
// holding no trusted row. Exported so callers branch on these rather than on
// string literals the service is free to reword.
const (
	ErrCodeAuthMissing    = "AUTH_MISSING"
	ErrCodeAuthInvalid    = "AUTH_INVALID"
	ErrCodeDegraded       = "SERVICE_DEGRADED"
	ErrCodeKeyNotFound    = "KEY_NOT_FOUND"
	ErrCodeKeyNotAllowed  = "KEY_NOT_ALLOWED"
	ErrCodeInvalidRequest = "INVALID_REQUEST"
	ErrCodeInternalError  = "INTERNAL_ERROR"
)

// ErrUnexpectedStatus is a sentinel error returned when the server responds with an unexpected status code.
var (
	ErrUnexpectedStatus = errors.New("unexpected status code")
)

// ServiceError represents an API error response.
type ServiceError struct {
	Code       string
	Message    string
	StatusCode int
	RequestID  string
}

func (e *ServiceError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("%s: %s (status %d, request %s)", e.Code, e.Message, e.StatusCode, e.RequestID)
	}
	return fmt.Sprintf("%s: %s (status %d)", e.Code, e.Message, e.StatusCode)
}

// AuthError represents authentication failures.
type AuthError struct {
	Code    string
	Message string
	// RequestID is the server's request identifier when the response carried
	// one. Empty for locally constructed errors.
	RequestID string
}

func (e *AuthError) Error() string {
	msg := e.Message
	// Both halves are required for the separator to mean anything. An AuthError
	// built from a response always has both, but the type is exported and a
	// caller's own value need not — and "AUTH_MISSING: " reads as a message the
	// service failed to send rather than one it never had.
	if e.Code != "" && msg != "" {
		msg = e.Code + ": " + msg
	} else if msg == "" {
		msg = e.Code
	}
	if e.RequestID != "" {
		return fmt.Sprintf("authentication failed: %s (request %s)", msg, e.RequestID)
	}
	return fmt.Sprintf("authentication failed: %s", msg)
}

// RateLimitError represents the rate limit having been exceeded.
type RateLimitError struct {
	Message    string
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("rate limited: %s (retry after %v)", e.Message, e.RetryAfter)
	}
	return fmt.Sprintf("rate limited: %s", e.Message)
}

// ValidationError represents invalid request data.
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s", e.Message)
}

// IsKeyNotFound returns true if the error indicates a key was not found.
func IsKeyNotFound(err error) bool {
	var se *ServiceError
	return errors.As(err, &se) && se.Code == ErrCodeKeyNotFound
}

// IsKeyNotAllowed returns true if the error indicates the caller's credential is
// valid but its grant does not cover the requested key. Distinct from
// IsAuthError: the credential was accepted, the key was not.
func IsKeyNotAllowed(err error) bool {
	var se *ServiceError
	return errors.As(err, &se) && se.Code == ErrCodeKeyNotAllowed
}

// IsAuthError returns true if the error is authentication-related.
func IsAuthError(err error) bool {
	var ae *AuthError
	return errors.As(err, &ae)
}

// IsRateLimitError returns true if the error indicates rate limit exceeded.
func IsRateLimitError(err error) bool {
	var re *RateLimitError
	return errors.As(err, &re)
}

// IsValidationError returns true if the error indicates invalid request data.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// IsServiceError returns true if the error is a service-side error (5xx).
func IsServiceError(err error) bool {
	var se *ServiceError
	return errors.As(err, &se) && se.StatusCode >= 500
}

// headerRequestID is the response header the service echoes its request id on.
const headerRequestID = "X-Request-ID"

// requestIDFrom returns the id the caller should quote when asking what
// happened, preferring the envelope's field and falling back to the header.
//
// Both carry the same value: requestIdMiddleware derives one id per request,
// hands it to the handlers and echoes it on the way out. The fallback is not
// redundancy for its own sake — it covers a service older than the release that
// started putting the id in error bodies, and every response body this client
// cannot parse into a typed envelope at all.
func requestIDFrom(envelope string, header http.Header) string {
	if envelope != "" {
		return envelope
	}
	return header.Get(headerRequestID)
}

// retryAfterFrom returns how long a 429 asks the caller to wait, preferring the
// envelope's `retryAfter` seconds and falling back to the `Retry-After` header.
//
// The header matters more than its rarity suggests. This service's limiter
// always emits `retryAfter` in the body when it emits a body at all, so the
// only 429 that reaches the fallback is one this service did not author — an
// edge throttle in front of it, which answers with a page rather than an
// envelope. That is exactly the response whose hint is otherwise lost.
func retryAfterFrom(envelopeSeconds int, header http.Header) time.Duration {
	if envelopeSeconds > 0 {
		return time.Duration(envelopeSeconds) * time.Second
	}
	return parseRetryAfter(header.Get("Retry-After"), time.Now())
}

// parseRetryAfter reads both forms RFC 9110 §10.2.3 permits: delay-seconds, and
// an absolute HTTP-date, which is reported as the delay remaining at now.
//
// The date form is not hypothetical — intermediaries and CDNs emit IMF-fixdate
// freely, and reading only integers turned one into "no hint". A value already
// in the past, or one that parses as neither form, yields zero, which callers
// read as "no hint" rather than "no wait": the retrier falls back to its own
// backoff and the error simply carries nothing to show.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}

	// http.ParseTime accepts IMF-fixdate and the two obsolete formats RFC 9110
	// still requires a recipient to understand.
	deadline, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	if wait := deadline.Sub(now); wait > 0 {
		return wait
	}
	return 0
}

// newAuthErrorFromResponse turns the service's 401 envelope into an AuthError.
//
// The document declares a 401 on every operation that requires a credential, so
// this is the mapped path — newStatusError below only ever sees a 401 the
// document does not cover (an unauthenticated endpoint behind a proxy that
// challenges, say).
//
// Two bodies decode but are not usable envelopes, and both fall back to the
// sentinel rather than becoming a threadbare AuthError:
//
//   - No message — `{}`, or `null`. It says nothing the status code did not,
//     and an AuthError built from it prints as a bare "authentication failed:".
//   - No code. ErrorResponse declares `code` required, and the whole reason
//     this client reads the field is that callers are told to branch on it
//     instead of on prose the service may reword. An AuthError with an empty
//     Code cannot be branched on, so it is not one.
//
// parseAPIErrorBody applies the same two rules on the fallback path. Neither
// this service nor the document can produce such a body; an intermediary can,
// and the two paths must not disagree about what a usable envelope is.
func newAuthErrorFromResponse(body *api.ErrorResponse, header http.Header) error {
	if body == nil || body.Error == "" || body.Code == "" {
		return newUnexpectedStatusError(http.StatusUnauthorized)
	}

	envelopeID := ""
	if body.RequestId != nil {
		envelopeID = body.RequestId.String()
	}
	return &AuthError{
		Code:      string(body.Code),
		Message:   body.Error,
		RequestID: requestIDFrom(envelopeID, header),
	}
}

func newUnexpectedStatusError(code int) error {
	return fmt.Errorf("%w: %d", ErrUnexpectedStatus, code)
}

// apiErrorBody is the service's error envelope. The generated client only
// exposes typed fields for statuses the OpenAPI document declares per
// operation, so a response the document omits arrives with its body intact but
// no field to read it from.
type apiErrorBody struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
	// RetryAfter is the delay in seconds a 429 asks for. Declared by
	// RateLimitErrorSchema; absent, and so zero, on every other status.
	RetryAfter int `json:"retryAfter"`
}

// newStatusError builds the richest error the response supports.
//
// The service answers every refusal with a precise message — `AUTH_MISSING`,
// `Issuer not allowed: <iss>`, `Subject is not trusted for signing` — and
// collapsing that to "unexpected status code: 401" throws away the one thing
// that tells an operator which of those it hit. A CI-only OIDC token cannot be
// replayed from a laptop to recover it, so the body is read here or not at all.
//
// Every status the document declares is mapped before a call reaches this
// point; what is left is whatever the document does not describe — a proxy's
// 502, a gateway's 401 challenge — so the envelope is parsed by hand. Falls
// back to the bare sentinel when the body is not a usable error envelope, which
// keeps text responses and empty bodies behaving as before.
func newStatusError(statusCode int, body []byte, header http.Header) error {
	parsed, ok := parseAPIErrorBody(body)

	// Deliberately above the envelope gate. A 429 needs no body to be
	// understood: the status *is* the whole meaning, and IsRateLimitError —
	// with it the retry policy and the CLI's "you are being throttled"
	// message — keys off the type. An edge throttle sitting in front of this
	// service answers 429 with an HTML page and a Retry-After header, which is
	// not a usable envelope but is unambiguously a rate limit; gating this
	// branch on one collapsed it to the bare sentinel and threw the hint away,
	// leaving retryAfterFrom's header fallback unreachable in the single case
	// it was written for. A rate limit the document does not declare is still a
	// rate limit, and so is one this service did not write.
	if statusCode == http.StatusTooManyRequests {
		message := parsed.Error
		if message == "" {
			// Otherwise Error() prints a bare "rate limited: ".
			message = http.StatusText(statusCode)
		}
		return &RateLimitError{
			Message:    message,
			RetryAfter: retryAfterFrom(parsed.RetryAfter, header),
		}
	}

	if !ok {
		return newUnexpectedStatusError(statusCode)
	}

	requestID := requestIDFrom(parsed.RequestID, header)

	if statusCode == http.StatusUnauthorized {
		return &AuthError{
			Code:      parsed.Code,
			Message:   parsed.Error,
			RequestID: requestID,
		}
	}

	return &ServiceError{
		Code:       parsed.Code,
		Message:    parsed.Error,
		StatusCode: statusCode,
		RequestID:  requestID,
	}
}

// parseAPIErrorBody reports whether body is an error envelope a caller can act
// on: a message to show and a code to branch on. A body missing either says
// nothing the status code did not, so it is treated as unparseable rather than
// surfaced as an error with empty fields — the same two rules
// newAuthErrorFromResponse applies on the typed path.
func parseAPIErrorBody(body []byte) (apiErrorBody, bool) {
	var parsed apiErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return apiErrorBody{}, false
	}
	if parsed.Error == "" || parsed.Code == "" {
		return apiErrorBody{}, false
	}
	return parsed, true
}
