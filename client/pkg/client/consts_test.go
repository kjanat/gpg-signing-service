package client

import "testing"

// Shared fixtures for the client test suite. Extracted so repeated literals
// have a single definition (and a single place to change them).
const (
	// JSON field names used when building stub API responses.
	fieldCode        = "code"
	fieldError       = "error"
	fieldKeyID       = "keyId"
	fieldFingerprint = "fingerprint"
	fieldLogs        = "logs"
	fieldCount       = "count"
	fieldChecks      = "checks"
	fieldKeyStorage  = "keyStorage"
	fieldDatabase    = "database"
	fieldSuccess     = "success"
	fieldAlgorithm   = "algorithm"
	fieldStatus      = "status"
	fieldVersion     = "version"
	fieldTimestamp   = "timestamp"
	fieldRequestID   = "requestId"

	// Stub server and request fixtures.
	testBaseURL   = "http://localhost:8080"
	testRequestID = "550e8400-e29b-41d4-a716-446655440000"
	// The id the stub servers embed in error envelopes.
	testErrRequestID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
	testVersion      = "1.0.0"
	testTimestamp    = "2023-11-20T10:30:45Z"

	// Key fixtures.
	testKeyID        = "key-123"
	testKeyID1       = "key-1"
	testKeyIDMissing = "nonexistent"
	testAlgorithmRSA = "RSA"

	// Error codes and messages returned by stub responses.
	testCodeInvalid     = "INVALID"
	testCodeError       = "ERROR"
	testCodeTest        = "TEST"
	testCodeAuthInvalid = "AUTH_INVALID"
	testMsgBadRequest   = "bad request"
	testMsgKeyNotFound  = "key not found"
	testMsgTest         = "test"
	testMsgRateLimited  = "rate limit exceeded"
	testMsgServerError  = "server error"
	testMsgExpired      = "token expired"
	testMsgBadAdmin     = "Invalid admin token"
	testMsgUntrusted    = "Subject is not trusted for signing"

	// Table-driven test case names and operations.
	testOpSign           = "Sign"
	testOpUploadKey      = "UploadKey"
	testOpListKeys       = "ListKeys"
	testOpAuditLogs      = "AuditLogs"
	testOpSignLower      = "sign"
	testNameNilError     = "nil error"
	testNameValidation   = "validation error"
	testNameOtherErrType = "other error type"
)

// newMappingClient builds a client for a test that asserts how a response is
// *reported* rather than whether it is re-attempted.
//
// Retries are off. A 429 or a transient 5xx is now genuinely retried against a
// real server, so a stub answering one of those on every request would put the
// default 1s–30s backoff between the test and the answer it is checking —
// several minutes across the suite, to reach exactly the same error. Retry
// behaviour has its own tests, which count requests instead of inspecting one.
func newMappingClient(tb testing.TB, baseURL string, opts ...Option) *Client {
	tb.Helper()

	c, err := New(baseURL, append([]Option{WithMaxRetries(0)}, opts...)...)
	if err != nil {
		tb.Fatalf("failed to create client: %v", err)
	}
	return c
}
