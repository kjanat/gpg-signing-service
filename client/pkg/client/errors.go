package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	if e.Code != "" {
		msg = e.Code + ": " + msg
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

// newAuthErrorFromResponse turns the service's 401 envelope into an AuthError.
//
// The document declares a 401 on every operation that requires a credential, so
// this is the mapped path — newStatusError below only ever sees a 401 the
// document does not cover (an unauthenticated endpoint behind a proxy that
// challenges, say).
//
// A body that decodes but carries no message — `{}`, or `null` — says nothing
// the status code did not, and an `AuthError` built from it prints as a bare
// "authentication failed: ". parseAPIErrorBody rejects that same body on the
// fallback path, so this returns the same sentinel rather than letting the two
// paths disagree about what a usable envelope is.
func newAuthErrorFromResponse(body *api.ErrorResponse) error {
	if body == nil || body.Error == "" {
		return newUnexpectedStatusError(http.StatusUnauthorized)
	}

	authErr := &AuthError{
		Code:    string(body.Code),
		Message: body.Error,
	}
	if body.RequestId != nil {
		authErr.RequestID = body.RequestId.String()
	}
	return authErr
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
func newStatusError(statusCode int, body []byte) error {
	parsed, ok := parseAPIErrorBody(body)
	if !ok {
		return newUnexpectedStatusError(statusCode)
	}

	if statusCode == http.StatusUnauthorized {
		return &AuthError{
			Code:      parsed.Code,
			Message:   parsed.Error,
			RequestID: parsed.RequestID,
		}
	}

	return &ServiceError{
		Code:       parsed.Code,
		Message:    parsed.Error,
		StatusCode: statusCode,
		RequestID:  parsed.RequestID,
	}
}

// parseAPIErrorBody reports whether body is an error envelope carrying a
// message. A body without `error` says nothing the status code did not, so it
// is treated as unparseable rather than surfaced as an empty message.
func parseAPIErrorBody(body []byte) (apiErrorBody, bool) {
	var parsed apiErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return apiErrorBody{}, false
	}
	if parsed.Error == "" {
		return apiErrorBody{}, false
	}
	return parsed, true
}
