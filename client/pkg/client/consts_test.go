package client

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

	// Stub server and request fixtures.
	testBaseURL   = "http://localhost:8080"
	testRequestID = "550e8400-e29b-41d4-a716-446655440000"
	testVersion   = "1.0.0"
	testTimestamp = "2023-11-20T10:30:45Z"

	// Key fixtures.
	testKeyID        = "key-123"
	testKeyID1       = "key-1"
	testKeyIDMissing = "nonexistent"
	testAlgorithmRSA = "RSA"

	// Error codes and messages returned by stub responses.
	testCodeInvalid    = "INVALID"
	testCodeError      = "ERROR"
	testCodeTest       = "TEST"
	testMsgBadRequest  = "bad request"
	testMsgKeyNotFound = "key not found"
	testMsgTest        = "test"
	testMsgRateLimited = "rate limit exceeded"
	testMsgServerError = "server error"

	// Table-driven test case names and operations.
	testOpSign           = "Sign"
	testOpSignLower      = "sign"
	testNameNilError     = "nil error"
	testNameValidation   = "validation error"
	testNameOtherErrType = "other error type"
)
