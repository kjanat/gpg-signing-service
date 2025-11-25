package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	openapiTypes "github.com/oapi-codegen/runtime/types"
)

// stubDoer implements HttpRequestDoer for tests and captures the last request
type stubDoer struct {
	resp    *http.Response
	err     error
	lastReq *http.Request
}

func (s *stubDoer) Do(req *http.Request) (*http.Response, error) {
	s.lastReq = req
	if s.resp == nil {
		return &http.Response{StatusCode: 204, Status: http.StatusText(http.StatusNoContent), Body: io.NopCloser(strings.NewReader(""))}, s.err
	}
	return s.resp, s.err
}

func newResp(status int, body string, contentType string) *http.Response {
	if contentType == "" {
		contentType = "application/json"
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{contentType}},
	}
}

func TestWithBaseURL(t *testing.T) {
	c, err := NewClient("https://example.com")
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}
	if c.Server != "https://example.com/" {
		t.Fatalf("unexpected initial server: %s", c.Server)
	}
	// Apply option
	opt := WithBaseURL("https://api.test.local/base")
	if err := opt(c); err != nil {
		t.Fatalf("WithBaseURL error: %v", err)
	}
	if c.Server != "https://api.test.local/base" {
		t.Fatalf("server not updated: %s", c.Server)
	}
}

func TestNewGetPublicKeyRequest(t *testing.T) {
	u := "https://svc.local/root"
	// with keyId
	key := "abc123"
	req, err := NewGetPublicKeyRequest(u, &GetPublicKeyParams{KeyId: &key})
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Errorf("method: %s", req.Method)
	}
	// Path should contain /public-key
	if !strings.Contains(req.URL.String(), "/public-key") {
		t.Errorf("url path not correct: %s", req.URL.String())
	}
	q := req.URL.Query()
	if got := q.Get("keyId"); got != key {
		t.Errorf("expected keyId=%s, got %s", key, got)
	}

	// without params
	req2, err := NewGetPublicKeyRequest(u, nil)
	if err != nil {
		t.Fatalf("build req2: %v", err)
	}
	if req2.URL.RawQuery != "" {
		t.Errorf("expected empty query, got %q", req2.URL.RawQuery)
	}
}

func TestNewPostSignRequestWithTextBody(t *testing.T) {
	base := "https://svc.local"
	text := PostSignTextRequestBody("to-sign")
	key := "k1"
	reqID := openapiTypes.UUID{}
	params := &PostSignParams{KeyId: &key, XRequestID: &reqID}
	req, err := NewPostSignRequestWithTextBody(base, params, text)
	if err != nil {
		t.Fatalf("build sign req: %v", err)
	}
	if req.Method != http.MethodPost {
		t.Errorf("method: %s", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("content-type: %s", ct)
	}
	if req.Header.Get("X-Request-ID") == "" {
		t.Errorf("expected X-Request-ID header to be set")
	}
	if got := req.URL.Query().Get("keyId"); got != key {
		t.Errorf("keyId query missing: %s", got)
	}
	// Body should contain the text
	b, _ := io.ReadAll(req.Body)
	if string(b) != text {
		t.Errorf("body mismatch: %q", string(b))
	}
}

func TestClientEditorsAndDoer(t *testing.T) {
	// Prepare an editor which injects a header
	var editorCalled, perCallCalled bool
	ed1 := func(_ context.Context, req *http.Request) error {
		editorCalled = true
		req.Header.Set("X-Test", "client-editor")
		return nil
	}
	ed2 := func(_ context.Context, req *http.Request) error {
		perCallCalled = true
		req.Header.Set("X-Call", "req-editor")
		return nil
	}

	// The response body returned by the client call is closed below; suppress bodyclose here.
	doer := &stubDoer{resp: newResp(200, `{"status":"ok","checks":{"database":true,"keyStorage":true},"timestamp":"2020-01-01T00:00:00Z","version":"v"}`, "application/json")} //nolint:bodyclose // closed after GetHealth returns
	c, err := NewClient("https://host", WithHTTPClient(doer), WithRequestEditorFn(ed1))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Call a simple endpoint
	rsp, err := c.GetHealth(context.Background(), ed2)
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	// Ensure body is properly closed to satisfy bodyclose linter
	if rsp != nil && rsp.Body != nil {
		defer func() { _ = rsp.Body.Close() }()
	}
	if rsp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", rsp.StatusCode)
	}
	if !editorCalled || !perCallCalled {
		t.Fatalf("editors not called: client=%v perCall=%v", editorCalled, perCallCalled)
	}
	if doer.lastReq == nil {
		t.Fatalf("doer did not receive request")
	}
	if doer.lastReq.Header.Get("X-Test") != "client-editor" || doer.lastReq.Header.Get("X-Call") != "req-editor" {
		t.Errorf("headers not propagated: %+v", doer.lastReq.Header)
	}
}

func TestParseGetHealthResponse(t *testing.T) {
	// Successful 200
	payload := HealthResponse{Status: HealthStatus("ok")}
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(payload)
	r := newResp(200, buf.String(), "application/json")

	parsed, err := ParseGetHealthResponse(r)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if r.Body != nil {
		if err := r.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
	}
	if parsed.StatusCode() != 200 || parsed.Status() == "" {
		t.Errorf("status helpers incorrect: %d %q", parsed.StatusCode(), parsed.Status())
	}
	if parsed.JSON200 == nil || string(parsed.JSON200.Status) != "ok" {
		t.Errorf("JSON200 not decoded: %+v", parsed.JSON200)
	}

	// 503 should decode into JSON503
	payload2 := HealthResponse{Status: HealthStatus("degraded")}
	buf2 := new(bytes.Buffer)
	_ = json.NewEncoder(buf2).Encode(payload2)
	r2 := newResp(503, buf2.String(), "application/json")
	parsed2, err := ParseGetHealthResponse(r2)
	if err != nil {
		t.Fatalf("parse2 error: %v", err)
	}
	if r2.Body != nil {
		if err := r2.Body.Close(); err != nil {
			t.Fatalf("close body2: %v", err)
		}
	}
	if parsed2.JSON503 == nil || string(parsed2.JSON503.Status) != "degraded" {
		t.Errorf("JSON503 not decoded: %+v", parsed2.JSON503)
	}
}

func TestNewClientWithResponses(t *testing.T) {
	cwr, err := NewClientWithResponses("https://h")
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	if cwr == nil {
		t.Fatal("nil client with responses")
	}
}

func TestPathToRawSpecAndGetSwagger(t *testing.T) {
	// Ensure we can access the embedded spec helpers without errors.
	m := PathToRawSpec("spec.json")
	if len(m) == 0 {
		t.Fatalf("expected non-empty spec map")
	}
	getter, ok := m["spec.json"]
	if !ok {
		t.Fatalf("expected key in spec map")
	}
	bb, err := getter()
	if err != nil || len(bb) == 0 {
		t.Fatalf("getter failed: %v len=%d", err, len(bb))
	}
	// decodeSpecCached returns a memoized function; call twice
	f := decodeSpecCached()
	b1, err := f()
	if err != nil || len(b1) == 0 {
		t.Fatalf("decodeSpecCached first call failed: %v, len=%d", err, len(b1))
	}
	b2, err := f()
	if err != nil || len(b2) == 0 {
		t.Fatalf("decodeSpecCached second call failed: %v, len=%d", err, len(b2))
	}
	// Validate GetSwagger can parse
	sw, err := GetSwagger()
	if err != nil {
		t.Fatalf("GetSwagger error: %v", err)
	}
	if sw == nil || sw.Paths == nil {
		t.Fatalf("swagger not loaded")
	}
}

func TestNewGetHealthRequest_BuildsURL(t *testing.T) {
	base := "https://example.com/base"
	req, err := NewGetHealthRequest(base)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	if req.URL == nil {
		t.Fatal("nil URL")
	}
	// Ensure URL is valid and parsable
	if _, err := url.Parse(req.URL.String()); err != nil {
		t.Fatalf("invalid url: %v", err)
	}
}
