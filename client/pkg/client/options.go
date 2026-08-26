package client

import (
	"time"
)

// Options configures the client behavior.
type Options struct {
	timeout          time.Duration
	authToken        string
	maxRetries       int
	retryWaitMin     time.Duration
	retryWaitMax     time.Duration
	retryOnRateLimit bool
}

func defaultOptions() *Options {
	return &Options{
		timeout:          30 * time.Second,
		maxRetries:       3,
		retryWaitMin:     1 * time.Second,
		retryWaitMax:     30 * time.Second,
		retryOnRateLimit: true,
	}
}

// Option configures the client.
type Option func(*Options)

// WithTimeout sets the per-attempt HTTP request timeout. The default is 30s.
//
// It bounds one attempt, not the call. http.Client applies its timeout per
// request, so every retry is handed a fresh one — WithTimeout(30s) under the
// default policy is four attempts of up to 30s plus roughly 15s of backoff. An
// attempt that does run out of time ends the call and is reported as the
// timeout it is, never as the status an earlier attempt happened to return.
//
// Pass a context with a deadline when you want one budget for the whole call.
// That one is checked before every wait, and a deadline lapsing with an answer
// already in hand costs the retry rather than the answer — see the retry
// section of the package README.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.timeout = d
	}
}

// WithOIDCToken sets the OIDC authentication token for signing operations.
func WithOIDCToken(token string) Option {
	return func(o *Options) {
		o.authToken = token
	}
}

// WithAdminToken sets the admin authentication token for administrative operations.
func WithAdminToken(token string) Option {
	return func(o *Options) {
		o.authToken = token
	}
}

// WithMaxRetries sets the maximum number of retry attempts.
// The default is 3. Set to 0 to disable retries.
func WithMaxRetries(n int) Option {
	return func(o *Options) {
		o.maxRetries = n
	}
}

// WithRetryWait sets the min/max retry backoff duration.
// Default is 1 s minWait, 30s maxWait.
func WithRetryWait(minWait, maxWait time.Duration) Option {
	return func(o *Options) {
		o.retryWaitMin = minWait
		o.retryWaitMax = maxWait
	}
}

// WithoutRateLimitRetry makes a 429 final on the first response.
//
// By default a 429 is attempted again under the same budget as any other
// retryable status, and the wait between attempts is the server's retry-after
// hint when the response carries one — from the body's `retryAfter` or the
// Retry-After header — falling back to the exponential backoff when it does
// not. A hint longer than WithRetryWait's maximum is clamped to it, so a
// misconfigured responder cannot park the call; the untruncated value still
// reaches the caller on the RateLimitError returned once the attempts are
// spent. Set this when a throttled call should fail fast rather than spend
// that budget.
func WithoutRateLimitRetry() Option {
	return func(o *Options) {
		o.retryOnRateLimit = false
	}
}
