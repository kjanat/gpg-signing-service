/**
 * The one place a rate-limit refusal is built.
 */

import type { Context } from "hono";

import type { ErrorCode } from "#schemas/errors";
import { HEADERS, HTTP, TIME } from "#types";

/**
 * A denial's `resetAt` as whole seconds to wait, floored at one.
 *
 * `resetAt` on a denial is when the bucket next holds a token, and refill is
 * proportional to capacity — 60ms on the 1000-wide row bucket, 600ms on the
 * default. Both are shorter than a Worker-to-Durable-Object round trip can be,
 * so the naive `ceil((resetAt - now) / 1000)` reaches zero or below by the time
 * the answer is read. `RateLimitErrorSchema` declares `retryAfter` positive, and
 * the Go client only honours it when it is (`retry.go:57`), so an underflowed
 * hint is both off-spec and silently discarded.
 *
 * Here rather than at each refusal for the same reason the headers are: the
 * floor was written out three times — the sign route, the admin limiter, and the
 * limiter's own `Retry-After` header — and a fourth refusal deriving its own
 * hint is a refusal that can send `retryAfter: 0`, which `rateLimitExceeded`
 * would then copy into `X-RateLimit-Reset` as *now*.
 *
 * @param resetAt - The denial's reset timestamp, in epoch milliseconds
 * @returns Whole seconds to wait, never below one
 */
export function retryAfterSeconds(resetAt: number): number {
	return Math.max(1, Math.ceil((resetAt - Date.now()) / TIME.SECOND));
}

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
 * Deliberately not exported. Every refusal goes through `rateLimitExceeded`
 * below, so no branch can author a 429 and forget these — which is how two of
 * the sign route's four refusals came to answer without them.
 *
 * @param retryAfter - Whole seconds to wait, as sent in the response body
 * @returns Headers to pass as `c.json`'s third argument
 */
function rateLimitDeniedHeaders(retryAfter: number): Record<string, string> {
	return {
		[HEADERS.RATE_LIMIT_REMAINING]: "0",
		[HEADERS.RATE_LIMIT_RESET]: String(Math.ceil(Date.now() / TIME.SECOND) + retryAfter),
	};
}

/**
 * The complete 429: body, status and the headers describing the refusing budget.
 *
 * A single constructor rather than four `c.json` calls that happened to agree.
 * The sign route has four refusal branches — per-caller and row ceiling, each on
 * the signing path and on the key-scope path — and the two on the key-scope path
 * were written separately and shipped without the headers, so what a caller
 * received depended on which branch fired. There is nothing left for a fifth
 * branch to forget.
 *
 * No `Retry-After`. The wait rides in the body and in `X-RateLimit-Reset`, and
 * `docs/errors.md` tells callers that a `Retry-After` on a 429 from this host
 * came from an intermediary rather than from the service — adding one here for
 * symmetry with the 503s would make that documented distinction untrue and take
 * away the only way a caller has to tell the two apart.
 *
 * @param c - Request context
 * @param retryAfter - Whole seconds to wait; already floored at one by caller
 * @returns The refusal, ready to return from a handler or middleware
 */
export function rateLimitExceeded(c: Context, retryAfter: number) {
	return c.json(
		{
			error: "Rate limit exceeded",
			// No `requestId`: `RateLimitErrorSchema` does not declare one, and the
			// documents point callers at the `X-Request-ID` header here instead.
			code: "RATE_LIMITED" as const satisfies ErrorCode,
			retryAfter,
		},
		HTTP.TooManyRequests,
		rateLimitDeniedHeaders(retryAfter),
	);
}
