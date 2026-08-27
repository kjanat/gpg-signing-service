package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/kjanat/gpg-signing-service/client/pkg/api"
)

// errorBodyTransport keeps an undecodable error body from destroying the
// response that carried it.
//
// The generated parsers dispatch on Content-Type before they know whether the
// body is well formed:
//
//	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 401:
//		var dest ErrorResponse
//		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
//			return nil, err
//		}
//
// That `return nil, err` discards the whole response. The caller gets
// "unexpected end of JSON input" — no status code, no sentinel, nothing
// errors.Is or IsAuthError can classify — which is strictly less useful than
// the "unexpected status code: 401" this client exists to improve on. Before
// any status was declared there was no case to hit, so such a body reached
// newStatusError untouched; declaring the 401 moved it onto the typed path and
// made the regression possible.
//
// Two bodies reach that branch and lose:
//
//   - Not JSON at all, despite the header. An intermediary that answers with an
//     HTML challenge page under `Content-Type: application/json`.
//   - JSON, but off-schema. `requestId` is `*openapi_types.UUID`, so
//     {"error":"nope","code":"AUTH_INVALID","requestId":"req-123"} fails to
//     decode. This service cannot emit that — getRequestId only honours a
//     caller-supplied id when it parses as a UUID, precisely so one free-text
//     value cannot make a page undecodable — but a proxy in front of it is
//     under nobody's control.
//
// So the body is checked here, where the status and headers are still in hand.
// A body that will not decode has its Content-Type replaced, the generated
// parser skips its typed branch, and the response arrives at newStatusError
// with everything intact — which then falls back to the sentinel, the
// behaviour these statuses had before they were declared.
type errorBodyTransport struct {
	base http.RoundTripper
}

// contentTypeUndecodable is what an error body that fails to decode is
// relabelled as. Any value the generated parsers do not treat as JSON works;
// this one says what happened.
const contentTypeUndecodable = "application/octet-stream"

// maxErrorBodyBytes bounds what this transport will hold for one error
// response.
//
// Reading an error body here is what lets a broken one be caught before the
// generated parser dies on it, but io.ReadAll with no ceiling lets the peer
// choose the client's allocation — and on this path the body is held twice,
// once here and once in the `bodyBytes` the parser reads back out. A 4 GiB
// "401" is not a credential problem the caller can act on; it is a way to take
// the process down.
//
// The envelope this bounds is four short fields. A megabyte is already three
// orders of magnitude more than the largest one the service emits (a 400
// carrying a Zod `issues` array), so nothing real is truncated, and a body that
// does exceed it is dropped rather than kept: the status is the only part of
// such a response worth reporting.
const maxErrorBodyBytes = 1 << 20

func (t *errorBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	// Only error responses: a success body belongs to the operation's own
	// schema, which this has no business second-guessing, and buffering it here
	// would defeat streaming for every call.
	if resp.StatusCode < http.StatusBadRequest {
		return resp, nil
	}
	// Recorded before the body is read, so a response this transport declines
	// to buffer still contributes its header, and refreshed below once the
	// envelope — where this service actually puts the hint — is in hand.
	recordRetryHint(req.Context(), resp.StatusCode, nil, resp.Header)

	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return resp, nil
	}

	// One byte past the ceiling, so an oversized body is detected rather than
	// silently truncated into something that might still decode.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if len(body) > maxErrorBodyBytes {
		// Deliberately not drained first: draining is what would make the
		// connection reusable, and paying an unbounded read for one pooled
		// connection is the trade this ceiling exists to refuse.
		resp.Body = http.NoBody
		resp.ContentLength = 0
		resp.Header.Set("Content-Type", contentTypeUndecodable)
		return resp, nil
	}
	// Put it back regardless: the generated code reads it again, and so does
	// newStatusError via resp.Body on the fallback path.
	resp.Body = io.NopCloser(bytes.NewReader(body))

	recordRetryHint(req.Context(), resp.StatusCode, body, resp.Header)

	if !decodesAsErrorEnvelope(resp.StatusCode, body) {
		resp.Header.Set("Content-Type", contentTypeUndecodable)
	}
	return resp, nil
}

// decodesAsErrorEnvelope reports whether body is what the generated parsers
// will successfully unmarshal for a declared error status.
//
// Deliberately the same target types the generated code uses, so this cannot
// drift into accepting a body the parser then rejects. `{}` and `null` decode
// and are left alone — they are handled downstream, where an envelope carrying
// no message is turned into the sentinel rather than an error with an empty
// message.
//
// There is more than one target type, which is why the status matters here.
// ErrorResponse covers most of them, but a 429 is unmarshalled into
// RateLimitError and /health's 503 into HealthResponse, and each carries a
// field ErrorResponse does not: `retryAfter` is an int, `timestamp` a
// time.Time. Checking ErrorResponse alone therefore passed bodies the real
// parser rejects — `{"error":"…","code":"…","retryAfter":"60"}`, a service that
// stringifies its numbers, decoded here and died there — which is the exact
// `return nil, err` this transport exists to keep away from the caller.
//
// The transport cannot know which operation a response belongs to, so a status
// answered by two schemas has to satisfy both. That costs nothing: every field
// is optional to encoding/json, so a genuine ErrorResponse decodes into a
// HealthResponse as a zero value and vice versa. Only a type conflict fails.
func decodesAsErrorEnvelope(statusCode int, body []byte) bool {
	switch statusCode {
	case http.StatusTooManyRequests:
		var rateLimit api.RateLimitError
		if json.Unmarshal(body, &rateLimit) != nil {
			return false
		}
	case http.StatusServiceUnavailable:
		var health api.HealthResponse
		if json.Unmarshal(body, &health) != nil {
			return false
		}
	}

	var dest api.ErrorResponse
	return json.Unmarshal(body, &dest) == nil
}

// recordRetryHint leaves the server's retry-after where the retry policy can
// read it.
//
// See retryHint: this transport is the only point in a call where the status,
// the headers and the body are in hand at once, and the retry policy sees none
// of the three — it works with a generic response type exposing StatusCode()
// alone. A no-op when no sink is on the context, which is every request Health
// makes and every request a caller drives through the raw client.
//
// A 429 and every 5xx are recorded; nothing else is, because nothing else is a
// status the policy will consider retrying.
//
// Only the 429 used to be, on the reasoning that it was the one status this
// service attaches a delay to. That stopped being true in the release that
// added SERVICE_DEGRADED, and it left both halves of a 503 unreadable from
// where they are acted on: the interval, so the retrier backed off blind
// against the one failure that had told it how long to wait, and the code, so
// SERVICE_MISCONFIGURED — which the service sends precisely to say "this will
// not clear" — was indistinguishable from any other 503 and got retried four
// times.
//
// The code is taken from the body alone. Unlike the interval it has no header
// form, so a response this transport declined to buffer contributes none — and
// that is the safe direction: an unreadable body leaves the code empty, and an
// empty code is not ErrCodeMisconfigured, so the policy falls back to retrying.
func recordRetryHint(ctx context.Context, statusCode int, body []byte, header http.Header) {
	sink := retryHintFrom(ctx)
	if sink == nil || (statusCode != http.StatusTooManyRequests && statusCode < http.StatusInternalServerError) {
		return
	}

	envelopeSeconds := 0
	if len(body) > 0 {
		// The `ok` is deliberately dropped: a half-envelope carrying
		// `retryAfter` but no `code` still carries the hint, and reading it
		// anyway is the same call newStatusError's 429 branch makes.
		parsed, _ := parseAPIErrorBody(body)
		envelopeSeconds = parsed.RetryAfter
		sink.code = parsed.Code
	}
	sink.retryAfter = retryAfterFrom(envelopeSeconds, header)
}
