/**
 * Rate limiting types
 */

/** Rate limit allowed result */
interface RateLimitAllowed {
  /** Whether the request is allowed */
  allowed: true;
  /** Remaining number of requests */
  remaining: number;
  /** Reset time in milliseconds since epoch */
  resetAt: number;
}

/** Rate limit denied result */
interface RateLimitDenied {
  /** Whether the request is allowed */
  allowed: false;
  /** Remaining number of requests (always 0) */
  remaining: 0;
  /** Reset time in milliseconds since epoch */
  resetAt: number;
}

/** Rate limit result as discriminated union */
export type RateLimitResult = RateLimitAllowed | RateLimitDenied;

/** Helper to create allowed rate limit result
 * @param remaining - Remaining number of requests
 * @param resetAt - Reset time in milliseconds since epoch
 * @returns Allowed rate limit result
 * @example
 * ```typescript
 * const result = createRateLimitAllowed(10, Date.now() + 60000);
 * ```
 */
export function createRateLimitAllowed(
  remaining: number,
  resetAt: number,
): RateLimitAllowed {
  return { allowed: true, remaining, resetAt };
}

/** Helper to create denied rate limit result
 * @param resetAt - Reset time in milliseconds since epoch
 * @returns Denied rate limit result
 * @example
 * ```typescript
 * const result = createRateLimitDenied(Date.now() + 60000);
 * ```
 */
export function createRateLimitDenied(resetAt: number): RateLimitDenied {
  return { allowed: false, remaining: 0, resetAt };
}
