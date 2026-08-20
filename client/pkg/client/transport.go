package client

import (
	"bytes"
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
	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return resp, nil
	}

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	// Put it back regardless: the generated code reads it again, and so does
	// newStatusError via resp.Body on the fallback path.
	resp.Body = io.NopCloser(bytes.NewReader(body))

	if !decodesAsErrorEnvelope(body) {
		resp.Header.Set("Content-Type", contentTypeUndecodable)
	}
	return resp, nil
}

// decodesAsErrorEnvelope reports whether body is what the generated parsers
// will successfully unmarshal for a declared error status.
//
// Deliberately the same target type the generated code uses, so this cannot
// drift into accepting a body the parser then rejects. `{}` and `null` decode
// and are left alone — they are handled downstream, where an envelope carrying
// no message is turned into the sentinel rather than an error with an empty
// message.
func decodesAsErrorEnvelope(body []byte) bool {
	var dest api.ErrorResponse
	return json.Unmarshal(body, &dest) == nil
}
