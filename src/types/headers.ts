/**
 * Standard HTTP header names
 * Based on RFC 9110 and common practices
 */
export const HEADERS = {
	/** Custom request tracking header */
	REQUEST_ID: "X-Request-ID",
	/** Rate limit remaining requests header */
	RATE_LIMIT_REMAINING: "X-RateLimit-Remaining",
	/** Rate limit reset time header */
	RATE_LIMIT_RESET: "X-RateLimit-Reset",
	/** Rate limit maximum requests header */
	RATE_LIMIT_LIMIT: "X-RateLimit-Limit",
	/** RFC 9110 §10.2.3 wait hint, sent with a 429 or a 503 */
	RETRY_AFTER: "Retry-After",
	/**
	 * RFC 9110 §11.6.2. Named rather than spelled out at each use so the Sentry
	 * scrubber's denylist and the middlewares that read it cannot drift apart.
	 */
	AUTHORIZATION: "Authorization",
} as const;
