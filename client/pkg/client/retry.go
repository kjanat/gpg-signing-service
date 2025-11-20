package client

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"time"
)

// Retrier handles retry logic with exponential backoff.
// It is safe for concurrent use by multiple goroutines.
type Retrier struct {
	maxRetries       int
	retryWaitMin     time.Duration
	retryWaitMax     time.Duration
	retryOnRateLimit bool
}

func newRetrier(opts *Options) *Retrier {
	return &Retrier{
		maxRetries:       opts.maxRetries,
		retryWaitMin:     opts.retryWaitMin,
		retryWaitMax:     opts.retryWaitMax,
		retryOnRateLimit: opts.retryOnRateLimit,
	}
}

// Do executes fn with retry logic.
func (r *Retrier) Do(ctx context.Context, fn func() error) error {
	var lastErr error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		// Exponential backoff before retry (skip on first attempt)
		if attempt > 0 {
			wait := r.backoff(attempt)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Check if we should retry
		if !r.shouldRetry(lastErr) {
			return lastErr
		}

		// Handle rate limit with explicit wait
		var rateLimitErr *RateLimitError
		if errors.As(lastErr, &rateLimitErr) && r.retryOnRateLimit {
			if rateLimitErr.RetryAfter > 0 {
				timer := time.NewTimer(rateLimitErr.RetryAfter)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}

	return lastErr
}

func (r *Retrier) shouldRetry(err error) bool {
	// Always retry rate limits if enabled
	var rateLimitErr *RateLimitError
	if errors.As(err, &rateLimitErr) {
		return r.retryOnRateLimit
	}

	// Retry service errors (5xx)
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) && serviceErr.StatusCode >= 500 {
		return true
	}

	// Don't retry auth, validation, or not found errors
	var authErr *AuthError
	var validationErr *ValidationError
	if errors.As(err, &authErr) || errors.As(err, &validationErr) {
		return false
	}

	// Check for key not found
	if IsKeyNotFound(err) {
		return false
	}

	return false
}

func (r *Retrier) backoff(attempt int) time.Duration {
	// Cap attempt to prevent overflow
	if attempt > 10 {
		attempt = 10
	}

	// Exponential backoff with jitter
	mult := math.Pow(2, float64(attempt))
	wait := time.Duration(mult) * r.retryWaitMin

	// Add jitter (0-100% of retryWaitMin) - using math/rand/v2 (goroutine-safe)
	jitter := time.Duration(rand.Int64N(int64(r.retryWaitMin)))
	wait += jitter

	if wait > r.retryWaitMax {
		wait = r.retryWaitMax
	}

	return wait
}
