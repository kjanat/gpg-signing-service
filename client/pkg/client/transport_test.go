package client

import (
	"io"
	"net/http"
	"testing"
)

// endlessBody is an error body that never ends, counting what was taken from
// it. A peer that streams is the case a ceiling has to survive: nothing about
// Content-Length is trustworthy, so the only real bound is on the read itself.
type endlessBody struct {
	read   int64
	budget int64
}

func (b *endlessBody) Read(p []byte) (int, error) {
	if b.read >= b.budget {
		// A test must fail rather than hang, so the stream is finite in the
		// large. Reaching this at all means the ceiling did not hold.
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'A'
	}
	b.read += int64(len(p))
	return len(p), nil
}

func (b *endlessBody) Close() error { return nil }

type stubRoundTripper struct{ resp *http.Response }

func (s stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return s.resp, nil }

// TestRoundTripBoundsTheErrorBodyRead pins the ceiling on the read, not just on
// what survives it.
//
// This transport exists to buffer an error body before the generated parser can
// die on it, and the parser then reads the same bytes back out — so an
// io.ReadAll with no limit hands the peer the size of two client allocations
// for the price of one refusal. Checking the length after reading everything
// would still have read everything.
func TestRoundTripBoundsTheErrorBodyRead(t *testing.T) {
	body := &endlessBody{budget: 64 * maxErrorBodyBytes}
	transport := &errorBodyTransport{base: stubRoundTripper{resp: &http.Response{
		StatusCode:    http.StatusUnauthorized,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          body,
		ContentLength: -1,
	}}}

	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/admin/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if body.read > maxErrorBodyBytes+1 {
		t.Errorf("read %d bytes of an unbounded body, ceiling is %d", body.read, maxErrorBodyBytes)
	}
	// What the parser sees afterwards: nothing to decode, and a label that keeps
	// it off the typed branch, so the status reaches newStatusError intact.
	if got := resp.Header.Get("Content-Type"); got != contentTypeUndecodable {
		t.Errorf("Content-Type = %q, want %q", got, contentTypeUndecodable)
	}
	left, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the replaced body: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("an oversized body was handed on anyway: %d bytes", len(left))
	}
	// ContentLength has to agree with the body that is actually there; leaving
	// the peer's number on a response whose body was dropped is a lie a caller
	// reading resp.HTTPResponse would act on.
	if resp.ContentLength != 0 {
		t.Errorf("ContentLength = %d, want 0", resp.ContentLength)
	}
}
