package client

import (
	"context"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"net"
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
	var wait time.Duration

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		// Skipped on the first attempt; otherwise this is what the previous
		// failure asked for, decided by waitBefore below.
		if attempt > 0 {
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

		wait = r.waitBefore(attempt+1, lastErr)
	}

	return lastErr
}

// waitBefore is how long to hold off before the given attempt.
//
// The exponential backoff, unless the failure carried the server's own
// retry-after hint. Preferring the hint is not politeness: this service floors
// `retryAfter` at one second and its limiter refills a single token in well
// under that, so a client that ignores it turns a limit which cleared in one
// second into a fifteen-second stall — and spends three more requests on a
// bucket that had already refilled.
//
// Clamped to retryWaitMax, because the hint is written by whatever answered and
// an unbounded one lets a misconfigured or hostile responder park the call for
// as long as it likes. retryWaitMax is the ceiling the caller configured for
// exactly that, and the true hint still reaches them on the RateLimitError the
// operation returns.
//
// Gated on retryOnRateLimit only because a 429 is the sole failure that carries
// a hint at all; WithoutRateLimitRetry stops the retry before this is reached.
func (r *Retrier) waitBefore(attempt int, err error) time.Duration {
	var rateLimitErr *RateLimitError
	if r.retryOnRateLimit && errors.As(err, &rateLimitErr) && rateLimitErr.RetryAfter > 0 {
		return r.capped(rateLimitErr.RetryAfter)
	}
	// A 503 carries one too, and unlike a rate limit's it is not something this
	// client could have estimated: SERVICE_DEGRADED means a dependency is away,
	// and only the service has any idea for how long. Ignoring it meant backing
	// off blind against the one failure that had told us what to do.
	//
	// Not gated on retryOnRateLimit — that option is about throttling, and
	// switching it off should not also discard an outage's wait hint.
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) && serviceErr.RetryAfter > 0 {
		return r.capped(serviceErr.RetryAfter)
	}
	return r.backoff(attempt)
}

// capped clamps a server-supplied wait to this retrier's ceiling, so a
// misconfigured or hostile hint cannot park a caller for hours.
func (r *Retrier) capped(wait time.Duration) time.Duration {
	if wait > r.retryWaitMax {
		return r.retryWaitMax
	}
	return wait
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
	//
	// WithTimeout lands here too, and deliberately. net/http renders an exceeded
	// Client.Timeout as "context deadline exceeded (Client.Timeout exceeded while
	// awaiting headers)" and it satisfies errors.Is against DeadlineExceeded, so
	// an attempt that ran out of time is final rather than repeated: the next one
	// is handed the same duration and the same slow server.
	//
	// That does not make WithTimeout a budget for the whole call, and it never
	// did. http.Client applies its Timeout per Do, so each attempt gets a fresh
	// one, and a server answering *promptly* with a retryable status never trips
	// it at all — WithTimeout(30s) under the default policy is four attempts of
	// up to 30s plus ~15s of backoff. A caller wanting one budget for the whole
	// operation passes a context with a deadline, which Do checks before every
	// wait.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// A round trip that never completed is the textbook case for trying again,
	// and used to be the case this function dropped: statuses never reached the
	// retrier, and the transport faults that did fell through to false, so
	// retryWaitMin/Max governed nothing at all.
	//
	// A fault before the response headers arrive — a refused dial, a failed
	// handshake, a reset before the status line — is reported by net/http as a
	// *url.Error, which is why this tests for the type rather than defaulting to
	// true. A response that arrived and then failed to decode is not a transport
	// fault: the body is already in hand and the next attempt parses exactly as
	// badly, so a blanket default would spend the whole backoff budget re-reading
	// a malformed 200.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}

	// A fault *after* the headers arrive does not look like one. The generated
	// client reads the body with io.ReadAll inside Parse…Response, well past the
	// *url.Error the round trip returned, so a connection dropped mid-body comes
	// back bare: io.ErrUnexpectedEOF when the peer hung up, a *net.OpError when
	// it reset. README lists that case among the faults this retries, and it is
	// the more likely of the two in practice — the request was accepted and the
	// server may well have done the work — so it has to be recognised here.
	//
	// Neither shape can be a decode failure. json.Unmarshal reports a truncated
	// document as *json.SyntaxError ("unexpected end of JSON input") and never
	// wraps io.ErrUnexpectedEOF, so a malformed 200 still falls through to false.
	var opErr *net.OpError
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &opErr)
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
// shouldRetry and waitBefore both use errors.As, so the wrapper is transparent
// to them: the signal's RateLimitError is what carries the server's retry-after
// hint into the wait between attempts.
type retrySignalError struct {
	inner error
}

func (s *retrySignalError) Error() string { return s.inner.Error() }
func (s *retrySignalError) Unwrap() error { return s.inner }

// retryHint is where a completed response leaves what it asks the retrier to do
// about the next attempt.
//
// The policy runs on a generic response type that exposes StatusCode() and
// nothing else, so neither the `Retry-After` header nor this service's own
// `retryAfter` envelope field is reachable from where the wait is decided —
// which is why that wait ignored the server's hint entirely and answered a
// one-second limit with fifteen seconds of backoff. Both sources are in hand at
// exactly one point per response, errorBodyTransport, which already holds the
// status, the headers and the body; so the hint is recorded there and travels
// back on the request context, the way httptrace's hooks do.
//
// One sink per call, created by executeWithRetry, written by the transport on
// the goroutine running the attempt and read after it returns. http.Client
// calls RoundTrip synchronously, so that ordering needs no synchronisation.
type retryHint struct {
	retryAfter time.Duration
}

// retryHintKey is the context key for a *retryHint. Unexported struct type, so
// nothing outside this package can collide with it or reach the sink.
type retryHintKey struct{}

func withRetryHint(ctx context.Context, hint *retryHint) context.Context {
	return context.WithValue(ctx, retryHintKey{}, hint)
}

// retryHintFrom returns the sink for the call in flight, or nil when the caller
// is not running under executeWithRetry — Health, which drives the retrier
// directly.
func retryHintFrom(ctx context.Context) *retryHint {
	hint, _ := ctx.Value(retryHintKey{}).(*retryHint)
	return hint
}

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
// The values are skeletal apart from retryAfter, which is the one thing the
// retrier acts on beyond the type: waitBefore prefers it over the backoff, so a
// 429 costs the wait the server asked for rather than an exponential guess over
// it. Callers still receive the full hint on the mapped RateLimitError the
// operation returns once the attempts are spent.
//
// Not every 5xx qualifies. shouldRetry's ServiceError branch tests `>= 500`
// because a caller reaching it has already decided the error is worth another
// go; deciding it here from a bare status has to be narrower, because 501 and
// 505 describe what the server will never do rather than what it could not do
// this time. Repeating those only spends the caller's timeout budget.
func retryStatusSignal(statusCode int, retryAfter time.Duration) error {
	switch statusCode {
	case http.StatusTooManyRequests:
		return &retrySignalError{inner: &RateLimitError{
			Message:    "rate limited",
			RetryAfter: retryAfter,
		}}
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
//
// The closure is handed the context to use rather than closing over the
// caller's: this one carries the retry-after sink the transport writes into.
func executeWithRetry[T statusCoder](
	ctx context.Context,
	r *Retrier,
	call func(context.Context) (T, error),
) (T, error) {
	var resp T
	attempted := false

	hint := &retryHint{}
	ctx = withRetryHint(ctx, hint)

	err := r.Do(ctx, func() error {
		hint.retryAfter = 0
		got, execErr := call(ctx)
		if execErr != nil {
			// resp is deliberately left alone. A transport fault on a later
			// attempt would otherwise overwrite the response an earlier one
			// produced, and that response is the more informative of the two.
			return execErr
		}
		resp, attempted = got, true
		return retryStatusSignal(resp.StatusCode(), hint.retryAfter)
	})

	var signal *retrySignalError
	if err != nil && !errors.As(err, &signal) {
		// A deadline that expired while the policy was still working is not the
		// most informative thing that happened: a response is in hand and
		// unmapped, and `attempted` is what says so. The deadline arrives here
		// by either of two routes — as ctx.Err() returned from Do's backoff
		// sleep, or, when it lapses while an attempt is in flight, as the
		// *url.Error net/http aborts the round trip with, which shouldRetry
		// declines and Do hands back as the last error. The error differs; the
		// situation does not. Retries are an optimisation over that response,
		// not a precondition for it, so running out of budget mid-policy costs
		// the retry rather than the answer. Otherwise the CLI, which hands the
		// same --timeout to WithTimeout and to its context, reports "context
		// deadline exceeded" for a call the service already answered "you are
		// being throttled".
		//
		// context.Canceled deliberately falls through: a caller who cancelled
		// asked for exactly that, while a caller whose deadline lapsed asked
		// for an answer within N seconds and one exists. So does a context that
		// expired before any attempt completed — attempted is false, resp is
		// the zero value, and the error is all there is.
		//
		// The ctx.Err() test is what confines this to the case above. The error
		// alone does not identify it: net/http renders an exceeded
		// Client.Timeout as a *url.Error wrapping "context deadline exceeded
		// (Client.Timeout exceeded while awaiting headers)", which satisfies
		// errors.Is against DeadlineExceeded just as the sleep's ctx.Err()
		// does. Asking the caller's context instead separates the two: a
		// WithTimeout that expires on a *later* attempt leaves this context
		// live, so the timeout is reported as itself rather than replaced by
		// whatever status an earlier attempt happened to return.
		if attempted && errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return resp, nil
		}
		return resp, err
	}
	return resp, nil
}
