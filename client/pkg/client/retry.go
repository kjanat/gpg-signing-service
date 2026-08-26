package client

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
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
		// Exponential backoff before retry (skip on the first attempt)
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
				select {
				case <-timer.C:
					// Timer fired normally, no cleanup needed
				case <-ctx.Done():
					stopTimer(timer)
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

	// Check for keys not found
	if IsKeyNotFound(err) {
		return false
	}

	// A cancelled or expired context is not worth another attempt: the next one
	// fails the same way, immediately, and the caller's deadline is the answer
	// either way. Checked before the transport branch below, because a context
	// that expires mid-flight surfaces wrapped in a *url.Error like any other.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// A round trip that never completed is the textbook case for trying again,
	// and used to be the case this function dropped: statuses never reached the
	// retrier, and the transport faults that did fell through to false, so
	// retryWaitMin/Max governed nothing at all.
	//
	// net/http reports every one of those as a *url.Error — a refused dial, a
	// connection closed mid-body, a failed handshake, a per-request timeout —
	// which is why this tests for the type rather than defaulting to true. A
	// response that arrived and then failed to decode is not a transport fault:
	// the body is already in hand and the next attempt parses exactly as badly,
	// so a blanket default would spend the whole backoff budget re-reading a
	// malformed 200.
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

func (r *Retrier) backoff(attempt int) time.Duration {
	// Cap attempt to prevent overflow in exponential calculation
	// Note: attempts > 10 will use maximum backoff duration
	if attempt > 10 {
		attempt = 10
	}

	// Defensive: normalize minWait to prevent Int64N panic
	minWait := r.retryWaitMin
	if minWait <= 0 {
		// If retryWaitMax is also invalid, use safe default (1 second)
		if r.retryWaitMax <= 0 {
			return time.Second
		}
		return r.retryWaitMax
	}

	// Exponential backoff with jitter
	mult := math.Pow(2, float64(attempt))
	wait := time.Duration(mult) * minWait

	// Add jitter (0-100% of minWait) - using math/rand/v2 (goroutine-safe)
	// #nosec G404 - using weak RNG is acceptable for backoff jitter (non-cryptographic use)
	jitter := time.Duration(rand.Int64N(int64(minWait)))
	wait += jitter

	if wait > r.retryWaitMax {
		wait = r.retryWaitMax
	}

	return wait
}

func stopTimer(t *time.Timer) {
	if t == nil {
		return
	}

	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// statusCoder is satisfied by every generated `…Response` type.
type statusCoder interface {
	StatusCode() int
}

// retrySignalError marks an error as the retrier's business and nobody else's.
//
// It exists because "should this be attempted again?" and "what is this failure
// called?" have different answers here. The first is asked of a bare status
// code, before any operation-specific mapping has run; the second is answered
// by that mapping, which knows the endpoint's declared bodies and builds the
// RateLimitError, ServiceError or AuthError a caller branches on. Signalling
// the first with a throwaway wrapper leaves the second untouched:
// executeWithRetry discards the signal once the attempts are spent, and the
// final response is mapped exactly as it would have been.
//
// shouldRetry uses errors.As throughout, so the wrapper is transparent to it —
// including Do's RateLimitError branch, which reads RetryAfter through the same
// unwrap.
type retrySignalError struct {
	inner error
}

func (s *retrySignalError) Error() string { return s.inner.Error() }
func (s *retrySignalError) Unwrap() error { return s.inner }

// retryStatusSignal classifies a completed round trip for the retrier.
//
// A 429 or a 5xx is a *successful* HTTP exchange: the generated client returns
// a nil error and puts the status on the response. A closure reporting only
// that error therefore told the retrier nothing was wrong, which left
// shouldRetry's RateLimitError and 5xx-ServiceError branches unreachable
// against a real server, and WithoutRateLimitRetry() toggling nothing. The
// transport faults that did reach shouldRetry fell through to false, so
// retryWaitMin/Max governed nothing at all. Returning the classification here
// is what connects the policy to responses.
//
// The values are skeletal by design; they are read for their type and nothing
// else. The wait between attempts is the retrier's exponential backoff rather
// than the server's `Retry-After` hint: the hint is not reachable from the
// generic response type, and a bounded, jittered backoff is a well-behaved
// policy to fall back to. Callers still receive the hint — it survives on the
// mapped RateLimitError the operation returns once the attempts are spent.
//
// Not every 5xx qualifies. shouldRetry's ServiceError branch tests `>= 500`
// because a caller reaching it has already decided the error is worth another
// go; deciding it here from a bare status has to be narrower, because 501 and
// 505 describe what the server will never do rather than what it could not do
// this time. Repeating those only spends the caller's timeout budget.
func retryStatusSignal(statusCode int) error {
	switch statusCode {
	case http.StatusTooManyRequests:
		return &retrySignalError{inner: &RateLimitError{Message: "rate limited"}}
	case http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return &retrySignalError{inner: &ServiceError{StatusCode: statusCode}}
	}
	return nil
}

// executeWithRetry runs one API call under the retry policy and returns the
// final response.
//
// A retryable status is attempted again; everything else — including the last
// attempt of a retryable one — is handed back with a nil error, so the caller's
// own mapping decides what the failure is called. Only a transport error or a
// cancelled context escapes as an error from here.
func executeWithRetry[T statusCoder](
	ctx context.Context,
	r *Retrier,
	call func() (T, error),
) (T, error) {
	var resp T
	err := r.Do(ctx, func() error {
		var execErr error
		resp, execErr = call()
		if execErr != nil {
			return execErr
		}
		return retryStatusSignal(resp.StatusCode())
	})

	var signal *retrySignalError
	if err != nil && !errors.As(err, &signal) {
		return resp, err
	}
	return resp, nil
}
