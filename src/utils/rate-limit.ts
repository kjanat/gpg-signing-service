/**
 * Rate-limit response headers.
 */

import { HEADERS, TIME } from "#types";

/**
 * The headers describing the budget that just refused a request.
 *
 * A 429 used to carry none, so the one response where a caller most needs to
 * know when to come back was the only response that did not say — and, since
 * `securityHeaders` advertises exactly the rate-limit headers a response
 * carries, a browser caller had nothing exposed to read either.
 *
 * `remaining` is `0` by definition on a denial. `X-RateLimit-Reset` is derived
 * from the same `retryAfter` the body carries rather than from the raw
 * `resetAt`, so the two can never disagree: both refusal paths floor the hint at
 * one second because a sub-second `resetAt` underflows across a Durable Object
 * round trip, and a header computed independently would hand back the instant
 * already past that the floor exists to avoid.
 *
 * @param retryAfter - Whole seconds to wait, as sent in the response body
 * @returns Headers to pass as `c.json`'s third argument
 */
export function rateLimitDeniedHeaders(retryAfter: number): Record<string, string> {
	return {
		[HEADERS.RATE_LIMIT_REMAINING]: "0",
		[HEADERS.RATE_LIMIT_RESET]: String(Math.ceil(Date.now() / TIME.SECOND) + retryAfter),
	};
}
