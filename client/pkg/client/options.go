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
// Default is 3. Set to 0 to disable retries.
func WithMaxRetries(n int) Option {
	return func(o *Options) {
		o.maxRetries = n
	}
}

// WithRetryWait sets the min/max retry backoff duration.
// Default is 1s min, 30s max.
func WithRetryWait(min, max time.Duration) Option {
	return func(o *Options) {
		o.retryWaitMin = min
		o.retryWaitMax = max
	}
}

// WithoutRateLimitRetry disables automatic retry on rate limit errors.
// By default, rate limit errors are automatically retried after the
// retry-after duration specified by the server.
func WithoutRateLimitRetry() Option {
	return func(o *Options) {
		o.retryOnRateLimit = false
	}
}
