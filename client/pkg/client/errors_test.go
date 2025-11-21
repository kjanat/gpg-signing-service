package client

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestServiceError tests ServiceError type
func TestServiceError(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		message    string
		statusCode int
		requestID  string
		wantError  string
	}{
		{
			name:       "service error with request ID",
			code:       "INTERNAL_ERROR",
			message:    "internal server error",
			statusCode: 500,
			requestID:  "req-123",
			wantError:  "INTERNAL_ERROR: internal server error (status 500, request req-123)",
		},
		{
			name:       "service error without request ID",
			code:       "SERVICE_UNAVAILABLE",
			message:    "service unavailable",
			statusCode: 503,
			requestID:  "",
			wantError:  "SERVICE_UNAVAILABLE: service unavailable (status 503)",
		},
		{
			name:       "service error with empty code",
			code:       "",
			message:    "error occurred",
			statusCode: 500,
			requestID:  "",
			wantError:  ": error occurred (status 500)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ServiceError{
				Code:       tt.code,
				Message:    tt.message,
				StatusCode: tt.statusCode,
				RequestID:  tt.requestID,
			}

			errStr := err.Error()
			if errStr != tt.wantError {
				t.Errorf("expected error %q, got %q", tt.wantError, errStr)
			}
		})
	}
}

// TestAuthError tests AuthError type
func TestAuthError(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		message   string
		wantError string
	}{
		{
			name:      "auth error with message",
			code:      "INVALID_TOKEN",
			message:   "token expired",
			wantError: "authentication failed: token expired",
		},
		{
			name:      "auth error empty message",
			code:      "NO_CREDENTIALS",
			message:   "",
			wantError: "authentication failed: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &AuthError{
				Code:    tt.code,
				Message: tt.message,
			}

			errStr := err.Error()
			if errStr != tt.wantError {
				t.Errorf("expected error %q, got %q", tt.wantError, errStr)
			}
		})
	}
}

// TestRateLimitError tests RateLimitError type
func TestRateLimitError(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		retryAfter time.Duration
		wantError  string
	}{
		{
			name:       "rate limit with retry-after",
			message:    "too many requests",
			retryAfter: 60 * time.Second,
			wantError:  "rate limited: too many requests (retry after 1m0s)",
		},
		{
			name:       "rate limit without retry-after",
			message:    "rate limit exceeded",
			retryAfter: 0,
			wantError:  "rate limited: rate limit exceeded",
		},
		{
			name:       "rate limit with short retry",
			message:    "slow down",
			retryAfter: 5 * time.Second,
			wantError:  "rate limited: slow down (retry after 5s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &RateLimitError{
				Message:    tt.message,
				RetryAfter: tt.retryAfter,
			}

			errStr := err.Error()
			if errStr != tt.wantError {
				t.Errorf("expected error %q, got %q", tt.wantError, errStr)
			}
		})
	}
}

// TestValidationError tests ValidationError type
func TestValidationError(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		message   string
		wantError string
	}{
		{
			name:      "validation error",
			code:      "INVALID_REQUEST",
			message:   "invalid request data",
			wantError: "validation error: invalid request data",
		},
		{
			name:      "validation error empty message",
			code:      "INVALID",
			message:   "",
			wantError: "validation error: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ValidationError{
				Code:    tt.code,
				Message: tt.message,
			}

			errStr := err.Error()
			if errStr != tt.wantError {
				t.Errorf("expected error %q, got %q", tt.wantError, errStr)
			}
		})
	}
}

// TestIsKeyNotFound tests IsKeyNotFound helper
func TestIsKeyNotFound(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		match bool
	}{
		{
			name: "key not found error",
			err: &ServiceError{
				Code:       ErrCodeKeyNotFound,
				Message:    "key not found",
				StatusCode: 200,
			},
			match: true,
		},
		{
			name: "other service error",
			err: &ServiceError{
				Code:       "OTHER_ERROR",
				Message:    "something else",
				StatusCode: 500,
			},
			match: false,
		},
		{
			name:  "nil error",
			err:   nil,
			match: false,
		},
		{
			name:  "other error type",
			err:   errors.New("some error"),
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKeyNotFound(tt.err)
			if result != tt.match {
				t.Errorf("expected IsKeyNotFound %v, got %v", tt.match, result)
			}
		})
	}
}

// TestIsAuthError tests IsAuthError helper
func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		match bool
	}{
		{
			name: "auth error",
			err: &AuthError{
				Code:    "INVALID_TOKEN",
				Message: "token expired",
			},
			match: true,
		},
		{
			name:  "validation error",
			err:   &ValidationError{Code: "INVALID", Message: "bad request"},
			match: false,
		},
		{
			name:  "nil error",
			err:   nil,
			match: false,
		},
		{
			name:  "other error type",
			err:   errors.New("some error"),
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAuthError(tt.err)
			if result != tt.match {
				t.Errorf("expected IsAuthError %v, got %v", tt.match, result)
			}
		})
	}
}

// TestIsRateLimitError tests IsRateLimitError helper
func TestIsRateLimitError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		match bool
	}{
		{
			name: "rate limit error",
			err: &RateLimitError{
				Message:    "too many requests",
				RetryAfter: 60 * time.Second,
			},
			match: true,
		},
		{
			name:  "validation error",
			err:   &ValidationError{Code: "INVALID", Message: "bad request"},
			match: false,
		},
		{
			name:  "nil error",
			err:   nil,
			match: false,
		},
		{
			name:  "other error type",
			err:   errors.New("some error"),
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRateLimitError(tt.err)
			if result != tt.match {
				t.Errorf("expected IsRateLimitError %v, got %v", tt.match, result)
			}
		})
	}
}

// TestIsValidationError tests IsValidationError helper
func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		match bool
	}{
		{
			name: "validation error",
			err: &ValidationError{
				Code:    "INVALID_REQUEST",
				Message: "invalid request data",
			},
			match: true,
		},
		{
			name:  "service error",
			err:   &ServiceError{Code: "ERROR", Message: "error", StatusCode: 500},
			match: false,
		},
		{
			name:  "nil error",
			err:   nil,
			match: false,
		},
		{
			name:  "other error type",
			err:   errors.New("some error"),
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationError(tt.err)
			if result != tt.match {
				t.Errorf("expected IsValidationError %v, got %v", tt.match, result)
			}
		})
	}
}

// TestIsServiceError tests IsServiceError helper
func TestIsServiceError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		match bool
	}{
		{
			name: "500 service error",
			err: &ServiceError{
				Code:       "INTERNAL_ERROR",
				Message:    "server error",
				StatusCode: 500,
			},
			match: true,
		},
		{
			name: "503 service error",
			err: &ServiceError{
				Code:       "UNAVAILABLE",
				Message:    "unavailable",
				StatusCode: 503,
			},
			match: true,
		},
		{
			name: "400 client error",
			err: &ServiceError{
				Code:       "BAD_REQUEST",
				Message:    "bad request",
				StatusCode: 400,
			},
			match: false,
		},
		{
			name: "404 not found",
			err: &ServiceError{
				Code:       "NOT_FOUND",
				Message:    "not found",
				StatusCode: 404,
			},
			match: false,
		},
		{
			name:  "validation error",
			err:   &ValidationError{Code: "INVALID", Message: "bad request"},
			match: false,
		},
		{
			name:  "nil error",
			err:   nil,
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsServiceError(tt.err)
			if result != tt.match {
				t.Errorf("expected IsServiceError %v, got %v", tt.match, result)
			}
		})
	}
}

// TestErrorCodes tests error code constants
func TestErrorCodes(t *testing.T) {
	if ErrCodeDegraded != "SERVICE_DEGRADED" {
		t.Errorf("expected ErrCodeDegraded 'SERVICE_DEGRADED', got %q", ErrCodeDegraded)
	}
	if ErrCodeKeyNotFound != "KEY_NOT_FOUND" {
		t.Errorf("expected ErrCodeKeyNotFound 'KEY_NOT_FOUND', got %q", ErrCodeKeyNotFound)
	}
}

// TestErrUnexpectedStatus tests ErrUnexpectedStatus constant
func TestErrUnexpectedStatus(t *testing.T) {
	if ErrUnexpectedStatus.Error() != "unexpected status code" {
		t.Errorf("expected 'unexpected status code', got %q", ErrUnexpectedStatus.Error())
	}
}

// TestErrorWrapping tests error wrapping in errors.As
func TestErrorWrapping(t *testing.T) {
	// Test that errors can be properly unwrapped with errors.As
	serviceErr := &ServiceError{
		Code:       "TEST",
		Message:    "test error",
		StatusCode: 500,
	}

	var err error = serviceErr
	var unwrapped *ServiceError
	if !errors.As(err, &unwrapped) {
		t.Fatal("failed to unwrap ServiceError with errors.As")
	}
	if unwrapped.Code != "TEST" {
		t.Errorf("expected Code 'TEST', got %q", unwrapped.Code)
	}
}

// TestErrorTypeAssertions tests type assertions for all error types
func TestErrorTypeAssertions(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		errType any
	}{
		{
			name:    "ServiceError",
			err:     &ServiceError{Code: "TEST", Message: "test", StatusCode: 500},
			errType: (*ServiceError)(nil),
		},
		{
			name:    "AuthError",
			err:     &AuthError{Code: "TEST", Message: "test"},
			errType: (*AuthError)(nil),
		},
		{
			name:    "RateLimitError",
			err:     &RateLimitError{Message: "test", RetryAfter: 60 * time.Second},
			errType: (*RateLimitError)(nil),
		},
		{
			name:    "ValidationError",
			err:     &ValidationError{Code: "TEST", Message: "test"},
			errType: (*ValidationError)(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if fmt.Sprintf("%T", tt.err) != fmt.Sprintf("%T", tt.errType) {
				t.Errorf("error type mismatch")
			}
		})
	}
}

// TestStatusCodeInServiceError validates status codes are properly stored
func TestStatusCodeInServiceError(t *testing.T) {
	statusCodes := []int{400, 401, 403, 404, 500, 502, 503, 504}

	for _, code := range statusCodes {
		err := &ServiceError{
			StatusCode: code,
		}

		if err.StatusCode != code {
			t.Errorf("expected StatusCode %d, got %d", code, err.StatusCode)
		}
	}
}

// TestErrorMessageFormatting tests error message formatting
func TestErrorMessageFormatting(t *testing.T) {
	err := &ServiceError{
		Code:       "TEST_ERROR",
		Message:    "This is a test error message",
		StatusCode: 500,
	}

	errStr := err.Error()
	if len(errStr) == 0 {
		t.Fatal("error message is empty")
	}

	// Verify all components are in the message
	if !contains(errStr, "TEST_ERROR") {
		t.Errorf("error message missing code: %s", errStr)
	}
	if !contains(errStr, "This is a test error message") {
		t.Errorf("error message missing message: %s", errStr)
	}
	if !contains(errStr, "500") {
		t.Errorf("error message missing status code: %s", errStr)
	}
}

// Helper function for string checking
func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkIsServiceError benchmarks error type checking
func BenchmarkIsServiceError(b *testing.B) {
	err := &ServiceError{
		Code:       "TEST",
		Message:    "test",
		StatusCode: 500,
	}

	for b.Loop() {
		_ = IsServiceError(err)
	}
}

// BenchmarkIsValidationError benchmarks error type checking
func BenchmarkIsValidationError(b *testing.B) {
	err := &ValidationError{
		Code:    "TEST",
		Message: "test",
	}

	for b.Loop() {
		_ = IsValidationError(err)
	}
}
