package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/api"
)

// Error codes returned by the service in the `code` field of an error response.
//
// AuthError.Code carries one of the three AUTH_ values on every 401 the
// document declares, and the set is the whole reason the code is surfaced
// rather than the prose. Each names a different fix: AUTH_MISSING means no
// usable credential was presented and retrying with the same configuration
// cannot help; AUTH_INVALID means one was presented and the credential was
// refused — a rotated admin token, an unlisted issuer, a stale token;
// AUTH_SUBJECT_UNTRUSTED means the credential was fine and the identity is not
// authorized. Exported so callers branch on these rather than on string
// literals the service is free to reword.
const (
	ErrCodeAuthMissing = "AUTH_MISSING"
	ErrCodeAuthInvalid = "AUTH_INVALID"
	// ErrCodeAuthSubjectUntrusted means the credential verified and the identity
	// it proves is not authorized to sign. Split out of AUTH_INVALID because the
	// fixes have nothing in common: AUTH_INVALID is answered by mending the
	// token, this one by adding a trust rule for the subject. A caller that
	// cannot tell them apart retries the first fix for both, which is how a
	// missing trust rule reads as a broken OIDC setup.
	ErrCodeAuthSubjectUntrusted = "AUTH_SUBJECT_UNTRUSTED"
	ErrCodeDegraded             = "SERVICE_DEGRADED"
	ErrCodeKeyNotFound          = "KEY_NOT_FOUND"
	ErrCodeKeyNotAllowed        = "KEY_NOT_ALLOWED"
	ErrCodeInvalidRequest       = "INVALID_REQUEST"
	ErrCodeInternalError        = "INTERNAL_ERROR"
)

// Guidance is the actionable half of an error response: not what went wrong,
// which the message already says, but what to change and where to read more.
//
// Carried by every error type in this package rather than formatted into the
// message, because the two are consumed differently. `Error()` has to stay one
// line — it gets wrapped by callers, logged, compared in tests — while a hint
// worth reading is a sentence or two and a docs link is only useful whole. The
// CLI prints these on their own lines; a library caller reads the fields.
type Guidance struct {
	// Hint is what to change, in prose. Empty when the service offered none.
	Hint string
	// Docs links to the reference section for this error's code. Short by
	// construction (`<service>/e/<CODE>`) so it survives a wrapped CI log.
	Docs string
	// Subject is the `sub` claim the caller presented, echoed back on an
	// authorization refusal. Empty on every other kind of error.
	Subject string
}

// guidanceOf satisfies the interface GuidanceFor looks for. Unexported: the
// data is reached through the embedded struct's fields, and the method exists
// only so errors.As can find a wrapped error that carries any.
func (g Guidance) guidanceOf() Guidance { return g }

// GuidanceFor digs the guidance out of err, however deeply it is wrapped.
//
// Reports false when the error carries none — a transport failure, a locally
// constructed error, or a service too old to send the fields.
func GuidanceFor(err error) (Guidance, bool) {
	var carrier interface{ guidanceOf() Guidance }
	if !errors.As(err, &carrier) {
		return Guidance{}, false
	}
	guidance := carrier.guidanceOf()
	if guidance == (Guidance{}) {
		return Guidance{}, false
	}
	return guidance, true
}

// ErrUnexpectedStatus is a sentinel error returned when the server responds with an unexpected status code.
var (
	ErrUnexpectedStatus = errors.New("unexpected status code")
)

// ServiceError represents an API error response.
type ServiceError struct {
	Guidance
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
	Guidance
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
	Guidance
	Message string
	// RequestID is the server's request identifier when the response carried
	// one. On a 429 that is usually the echoed X-Request-ID header and nothing
	// else: RateLimitErrorSchema declares no `requestId`, and none of the three
	// bodies this service answers a 429 with sends one — so a rate limit was
	// the one refusal whose id an operator could not quote, which is exactly
	// what docs/troubleshooting.md asks them to do.
	RequestID  string
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	msg := "rate limited: " + e.Message
	if e.RetryAfter > 0 {
		msg += fmt.Sprintf(" (retry after %v)", e.RetryAfter)
	}
	if e.RequestID != "" {
		msg += fmt.Sprintf(" (request %s)", e.RequestID)
	}
	return msg
}

// ValidationError represents invalid request data.
type ValidationError struct {
	Guidance
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

// IsSubjectUntrusted returns true if the credential was accepted and the
// identity it proves holds no active trust rule.
//
// The distinction IsAuthError cannot make, and the one that decides what to do
// next: nothing about the token or the workflow's OIDC configuration will
// change this answer, only a trust rule for the subject will.
func IsSubjectUntrusted(err error) bool {
	var ae *AuthError
	return errors.As(err, &ae) && ae.Code == ErrCodeAuthSubjectUntrusted
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

// Response headers this client reads.
const (
	// headerRequestID is the one the service echoes its request id on.
	headerRequestID = "X-Request-ID"
	// headerRetryAfter is the RFC 9110 hint, in either of the two forms
	// parseRetryAfter accepts.
	headerRetryAfter = "Retry-After"
)

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
	if hint := retryAfterSeconds(envelopeSeconds); hint > 0 {
		return hint
	}
	return parseRetryAfter(header.Get(headerRetryAfter), time.Now())
}

// maxRetryAfterSeconds is the largest delay-seconds a time.Duration can hold.
// A Duration is an int64 of nanoseconds, so the conversion wraps somewhere past
// 292 years and a header meaning "wait forever" would arrive as a negative wait.
const maxRetryAfterSeconds = int64(math.MaxInt64) / int64(time.Second)

// retryAfterSeconds converts a delay-seconds hint to a Duration, reporting zero
// — "no hint" — for anything a Duration cannot hold.
//
// Both sources are outside this client's control: the header is written by
// whatever answered, and `retryAfter` in the envelope is an unbounded JSON
// integer whatever wrote the body chose. The multiply wraps silently, so
// 9223372036854 arrives as -775ms: a wait that is not merely wrong but reads as
// one already past.
func retryAfterSeconds(seconds int) time.Duration {
	if seconds <= 0 || int64(seconds) > maxRetryAfterSeconds {
		return 0
	}
	return time.Duration(seconds) * time.Second
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
		return retryAfterSeconds(seconds)
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
		Guidance:  guidanceFromResponse(body),
		Code:      string(body.Code),
		Message:   body.Error,
		RequestID: requestIDFrom(envelopeID, header),
	}
}

// deref reads an optional document field, absent meaning "nothing to say".
func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// guidanceOfBody reads the actionable fields off a hand-parsed envelope, for
// the statuses the document does not declare a typed body for.
func guidanceOfBody(body apiErrorBody) Guidance {
	return Guidance{Hint: body.Hint, Docs: body.Docs, Subject: body.Subject}
}

// guidanceFromResponse reads the actionable fields off a typed envelope.
//
// All three are optional in the document: an older deployment sends none of
// them, and an intermediary's error carries whatever it likes. Absent fields
// become empty strings, which every consumer treats as "nothing to say" rather
// than printing an empty line.
func guidanceFromResponse(body *api.ErrorResponse) Guidance {
	guidance := Guidance{}
	if body == nil {
		return guidance
	}
	guidance.Hint = deref(body.Hint)
	guidance.Docs = deref(body.Docs)
	guidance.Subject = deref(body.Subject)
	return guidance
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
	Hint      string `json:"hint"`
	Docs      string `json:"docs"`
	Subject   string `json:"subject"`
	// RetryAfter is the delay in seconds a 429 asks for. Declared by
	// RateLimitErrorSchema; absent, and so zero, on every other status.
	RetryAfter int `json:"retryAfter"`
}

// newRateLimitError builds the RateLimitError a 429 deserves, from whichever of
// its sources carries anything.
//
// Both paths that answer a 429 go through here so they cannot disagree about
// what one means. The declared path — /sign's typed JSON429 — built the value
// inline from the envelope alone, which cost it both fallbacks the undeclared
// path has. An intermediary that answers 429 with a JSON body reaches the typed
// path whenever that body happens to decode, and it is exactly the responder
// whose body carries neither field: no `error`, so Error() printed a bare
// "rate limited: ", and no `retryAfter`, so a Retry-After header sitting on the
// same response was discarded.
func newRateLimitError(envelopeMessage string, envelopeSeconds int, envelopeRequestID string, guidance Guidance, header http.Header) *RateLimitError {
	message := envelopeMessage
	if message == "" {
		// Otherwise Error() prints a bare "rate limited: ".
		message = http.StatusText(http.StatusTooManyRequests)
	}
	return &RateLimitError{
		// A 429 carries the same actionable fields every other refusal does —
		// the middleware fills `docs` in on the way out for any body with a
		// `code` — so the guidance is threaded through here rather than being
		// the one error type that drops it.
		Guidance:   guidance,
		Message:    message,
		RequestID:  requestIDFrom(envelopeRequestID, header),
		RetryAfter: retryAfterFrom(envelopeSeconds, header),
	}
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
		return newRateLimitError(parsed.Error, parsed.RetryAfter, parsed.RequestID, guidanceOfBody(parsed), header)
	}

	if !ok {
		return newUnexpectedStatusError(statusCode)
	}

	requestID := requestIDFrom(parsed.RequestID, header)

	guidance := guidanceOfBody(parsed)

	if statusCode == http.StatusUnauthorized {
		return &AuthError{
			Guidance:  guidance,
			Code:      parsed.Code,
			Message:   parsed.Error,
			RequestID: requestID,
		}
	}

	return &ServiceError{
		Guidance:   guidance,
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
		// The value still goes back. Only newStatusError's 429 branch, which sits
		// above the gate because a 429 needs no envelope to be understood, reads
		// it when ok is false — a half-envelope carrying `error` and `retryAfter`
		// but no `code` parsed cleanly and has both of the things that branch
		// wants. Every other path discards it and reports the status alone.
		return parsed, false
	}
	return parsed, true
}
