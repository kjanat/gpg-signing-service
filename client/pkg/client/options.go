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

// WithTimeout sets the HTTP request timeout.
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
// retryable status. The wait between attempts is the exponential backoff, not
// the server's retry-after hint — the hint is not reachable from the generic
// response type the retry policy sees — but it is not lost either: it reaches
// the caller on the RateLimitError returned once the attempts are spent. Set
// this when a throttled call should fail fast rather than spend that budget.
func WithoutRateLimitRetry() Option {
	return func(o *Options) {
		o.retryOnRateLimit = false
	}
}
