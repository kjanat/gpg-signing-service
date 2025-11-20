package client

import (
	"errors"
	"fmt"
	"time"
)

// Error codes
const (
	ErrCodeDegraded    = "SERVICE_DEGRADED"
	ErrCodeKeyNotFound = "KEY_NOT_FOUND"
)

// Common errors
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
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authentication failed: %s", e.Message)
}

// RateLimitError represents rate limit exceeded.
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

func newUnexpectedStatusError(code int) error {
	return fmt.Errorf("%w: %d", ErrUnexpectedStatus, code)
}
