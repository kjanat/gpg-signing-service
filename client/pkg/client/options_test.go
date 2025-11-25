package client

import (
	"testing"
	"time"
)

// TestOptionChaining tests that options can be chained together
func TestOptionChaining(t *testing.T) {
	opts := defaultOptions()

	// Apply multiple options in sequence
	WithTimeout(45 * time.Second)(opts)
	WithMaxRetries(5)(opts)
	WithRetryWait(100*time.Millisecond, 45*time.Second)(opts)
	WithOIDCToken("test-token")(opts)
	WithoutRateLimitRetry()(opts)

	if opts.timeout != 45*time.Second {
		t.Errorf("expected timeout 45s, got %v", opts.timeout)
	}
	if opts.maxRetries != 5 {
		t.Errorf("expected maxRetries 5, got %d", opts.maxRetries)
	}
	if opts.retryWaitMin != 100*time.Millisecond {
		t.Errorf("expected retryWaitMin 100ms, got %v", opts.retryWaitMin)
	}
	if opts.retryWaitMax != 45*time.Second {
		t.Errorf("expected retryWaitMax 45s, got %v", opts.retryWaitMax)
	}
	if opts.authToken != "test-token" {
		t.Errorf("expected authToken 'test-token', got %q", opts.authToken)
	}
	if opts.retryOnRateLimit {
		t.Error("expected retryOnRateLimit false")
	}
}

// TestOptionOverwriting tests that later options overwrite earlier ones
func TestOptionOverwriting(t *testing.T) {
	// Create options with the first value
	opts := defaultOptions()
	WithTimeout(10 * time.Second)(opts)

	// Overwrite with the second value
	WithTimeout(20 * time.Second)(opts)

	if opts.timeout != 20*time.Second {
		t.Errorf("expected timeout 20s, got %v", opts.timeout)
	}
}

// TestOptionTokenOverwriting tests that token options overwrite
func TestOptionTokenOverwriting(t *testing.T) {
	opts := defaultOptions()
	WithOIDCToken("first-token")(opts)

	if opts.authToken != "first-token" {
		t.Errorf("expected authToken 'first-token', got %q", opts.authToken)
	}

	// Overwrite with the admin token
	WithAdminToken("admin-token")(opts)

	if opts.authToken != "admin-token" {
		t.Errorf("expected authToken 'admin-token', got %q", opts.authToken)
	}
}

// TestOptionRetryWaitValidation tests retry wait time relationships
func TestOptionRetryWaitValidation(t *testing.T) {
	tests := []struct {
		name  string
		min   time.Duration
		max   time.Duration
		valid bool
	}{
		{
			name:  "min less than max",
			min:   1 * time.Second,
			max:   30 * time.Second,
			valid: true,
		},
		{
			name:  "min equal to max",
			min:   5 * time.Second,
			max:   5 * time.Second,
			valid: false, // Client validation should reject this
		},
		{
			name:  "min greater than max",
			min:   60 * time.Second,
			max:   10 * time.Second,
			valid: false, // Client validation should reject this
		},
		{
			name:  "very small durations",
			min:   1 * time.Millisecond,
			max:   10 * time.Millisecond,
			valid: true,
		},
		{
			name:  "very large durations",
			min:   1 * time.Hour,
			max:   24 * time.Hour,
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := defaultOptions()
			WithRetryWait(tt.min, tt.max)(opts)

			if tt.valid {
				if opts.retryWaitMin != tt.min {
					t.Errorf("expected retryWaitMin %v, got %v", tt.min, opts.retryWaitMin)
				}
				if opts.retryWaitMax != tt.max {
					t.Errorf("expected retryWaitMax %v, got %v", tt.max, opts.retryWaitMax)
				}
			} else if opts.retryWaitMin != tt.min {
				// For invalid options, the values should still be set at the Options level,
				// but client creation will reject them
				t.Errorf("expected retryWaitMin %v, got %v", tt.min, opts.retryWaitMin)
			}
		})
	}
}

// TestWithTimeoutVariations tests different timeout values
func TestWithTimeoutVariations(t *testing.T) {
	timeouts := []time.Duration{
		1 * time.Millisecond,
		100 * time.Millisecond,
		1 * time.Second,
		10 * time.Second,
		1 * time.Minute,
		10 * time.Minute,
	}

	for _, timeout := range timeouts {
		t.Run(timeout.String(), func(t *testing.T) {
			opts := defaultOptions()
			WithTimeout(timeout)(opts)

			if opts.timeout != timeout {
				t.Errorf("expected timeout %v, got %v", timeout, opts.timeout)
			}
		})
	}
}

// TestWithMaxRetriesVariations tests different retry counts
func TestWithMaxRetriesVariations(t *testing.T) {
	retries := []int{0, 1, 2, 5, 10, 100}

	for _, retryCount := range retries {
		t.Run("retries-"+string(rune(retryCount)), func(t *testing.T) {
			opts := defaultOptions()
			WithMaxRetries(retryCount)(opts)

			if opts.maxRetries != retryCount {
				t.Errorf("expected maxRetries %d, got %d", retryCount, opts.maxRetries)
			}
		})
	}
}

// TestWithoutRateLimitRetryToggle tests toggling rate limit retry on and off
func TestWithoutRateLimitRetryToggle(t *testing.T) {
	opts := defaultOptions()

	// Verify default is true
	if !opts.retryOnRateLimit {
		t.Error("expected default retryOnRateLimit true")
	}

	// Disable rate limit retry
	WithoutRateLimitRetry()(opts)

	if opts.retryOnRateLimit {
		t.Error("expected retryOnRateLimit false after WithoutRateLimitRetry")
	}

	// Note: There's no WithRateLimitRetry function, so we can't re-enable it
	// This is by design - once disabled, it stays disabled in the same Options object
}

// TestTokenOptionEmptyString tests setting tokens to empty string
func TestTokenOptionEmptyString(t *testing.T) {
	opts := defaultOptions()

	// Set a token
	WithOIDCToken("test-token")(opts)
	if opts.authToken != "test-token" {
		t.Fatal("failed to set token")
	}

	// Set to empty string
	WithOIDCToken("")(opts)
	if opts.authToken != "" {
		t.Error("expected empty authToken")
	}
}

// TestRetryWaitWithZeroDuration tests retry wait with zero/negative durations
func TestRetryWaitWithZeroDuration(t *testing.T) {
	tests := []struct {
		name string
		min  time.Duration
		max  time.Duration
	}{
		{
			name: "zero min",
			min:  0,
			max:  10 * time.Second,
		},
		{
			name: "negative max",
			min:  1 * time.Second,
			max:  -5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := defaultOptions()
			WithRetryWait(tt.min, tt.max)(opts)

			// Options accept any value; validation happens at client creation
			if opts.retryWaitMin != tt.min {
				t.Errorf("expected retryWaitMin %v, got %v", tt.min, opts.retryWaitMin)
			}
		})
	}
}

// BenchmarkOptionApplication benchmarks applying options
func BenchmarkOptionApplication(b *testing.B) {
	opts := []Option{
		WithTimeout(30 * time.Second),
		WithMaxRetries(3),
		WithRetryWait(1*time.Second, 30*time.Second),
		WithOIDCToken("test-token"),
	}

	for b.Loop() {
		options := defaultOptions()
		for _, opt := range opts {
			opt(options)
		}
	}
}

// BenchmarkDefaultOptions benchmarks creating default options
func BenchmarkDefaultOptions(b *testing.B) {
	for b.Loop() {
		_ = defaultOptions()
	}
}
