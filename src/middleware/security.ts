import type { MiddlewareHandler } from "hono";

import type { ErrorCode } from "#schemas/errors";
import type { Env, RateLimitResult } from "#types";
import { HEADERS, HTTP, TIME } from "#types";
import { logger } from "#utils/logger";

/**
 * Default CSP: every API route returns JSON, so nothing may be loaded at all.
 */
export const DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'";

/**
 * CSP for the Swagger UI page. It loads its stylesheet and bundle from jsDelivr,
 * boots through an inline script and fetches the spec from /doc — all blocked by
 * the default policy, which left the page blank.
 *
 * `'unsafe-inline'` for scripts is unavoidable: @hono/swagger-ui emits the
 * bootstrap as a bare inline <script> with no nonce hook. It is scoped to the
 * docs page, which renders no user input.
 */
export const DOCS_CSP = [
	"default-src 'none'",
	"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://static.cloudflareinsights.com",
	"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
	"img-src 'self' data:",
	"font-src 'self' data: https://cdn.jsdelivr.net",
	"connect-src 'self' https://cloudflareinsights.com",
	"frame-ancestors 'none'",
	// Neither of these falls back to default-src, so they must be stated to
	// stop an injected <base>/<form> from redirecting the page's requests.
	"base-uri 'none'",
	"form-action 'none'",
].join("; ");

/** Paths that render the interactive API documentation. */
const DOCS_UI_PATHS = new Set(["/ui"]);

/**
 * Security headers middleware for production hardening
 */
export const securityHeaders: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
	await next();

	// Security headers
	c.header("X-Content-Type-Options", "nosniff");
	c.header("X-Frame-Options", "DENY");
	c.header("Referrer-Policy", "strict-origin-when-cross-origin");
	c.header("Content-Security-Policy", DOCS_UI_PATHS.has(c.req.path) ? DOCS_CSP : DEFAULT_CSP);
	c.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
	// HSTS: enforce HTTPS for 1 year, include subdomains
	c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

	// Remove server identification
	c.res.headers.delete("Server");
	c.res.headers.delete("X-Powered-By");

	// Expose rate limit headers if present
	const rateLimitRemaining = c.res.headers.get(HEADERS.RATE_LIMIT_REMAINING);
	if (rateLimitRemaining !== null) {
		c.header(
			"Access-Control-Expose-Headers",
			`${HEADERS.RATE_LIMIT_LIMIT}, ${HEADERS.RATE_LIMIT_REMAINING}, ${HEADERS.RATE_LIMIT_RESET}`,
		);
	}
};

/**
 * Production CORS middleware with restricted origins
 */
export const productionCors: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
	const origin = c.req.header("Origin");
	const allowedOrigins = c.env.ALLOWED_ORIGINS?.split(",") ?? [];

	// Check if origin is allowed
	const isAllowed = allowedOrigins.length === 0 || (origin !== undefined && allowedOrigins.includes(origin));

	if (c.req.method === "OPTIONS") {
		// Preflight request
		if (isAllowed && origin !== undefined) {
			return new Response(null, {
				status: HTTP.NoContent,
				headers: {
					"Access-Control-Allow-Origin": origin,
					"Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
					"Access-Control-Allow-Headers": "Authorization, Content-Type, X-Request-ID",
					"Access-Control-Max-Age": "86400",
				},
			});
		}
		return new Response(null, { status: HTTP.NoContent });
	}

	await next();

	// Set CORS headers for allowed origins
	if (isAllowed && origin !== undefined) {
		c.header("Access-Control-Allow-Origin", origin);
		c.header("Access-Control-Allow-Credentials", "true");
	}

	return;
};

/**
 * Rate limiting middleware for admin endpoints (IP-based)
 * Stricter limits to prevent brute force attacks on admin token
 */
export const adminRateLimit: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
	// Get client IP from CF headers or fallback
	const clientIp =
		c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For")?.split(",")[0]?.trim() || "unknown";

	// Use IP-based identity for admin rate limiting
	const identity = `admin:${clientIp}`;

	try {
		const rateLimiterId = c.env.RATE_LIMITER.idFromName("admin");
		const rateLimiter = c.env.RATE_LIMITER.get(rateLimiterId);

		const rateLimitResponse = await rateLimiter.fetch(
			new Request(`http://internal/consume?identity=${encodeURIComponent(identity)}`),
		);

		// A denied consume is a *verdict*, and the Durable Object delivers it as a
		// 429 with the verdict in the body — so `!ok` alone reads the one answer
		// this middleware exists to detect as an outage, answering 503 with no
		// `retryAfter` and leaving the `allowed` branch below unreachable. Same
		// reading as the sign route's `resolveRateLimit`.
		if (!rateLimitResponse.ok && rateLimitResponse.status !== HTTP.TooManyRequests) {
			throw new Error(`Rate limiter returned ${rateLimitResponse.status}`);
		}

		const rateLimit = (await rateLimitResponse.json()) as RateLimitResult;

		if (!rateLimit.allowed) {
			return c.json(
				{
					error: "Rate limit exceeded",
					code: "RATE_LIMITED" as const satisfies ErrorCode,
					// Floored at one second. `resetAt` on a denial is when the bucket next
					// holds a token, which is sub-second at every capacity in use, so the
					// bare `ceil` underflows to zero across a Durable Object round trip —
					// off-spec against `RateLimitErrorSchema`, and ignored by the Go
					// client, which only honours a positive hint. Mirrors the sign
					// route's `retryAfterSeconds`.
					retryAfter: Math.max(1, Math.ceil((rateLimit.resetAt - Date.now()) / TIME.SECOND)),
				},
				HTTP.TooManyRequests,
			);
		}

		// Add rate limit headers
		c.header(HEADERS.RATE_LIMIT_REMAINING, String(rateLimit.remaining));
		c.header(HEADERS.RATE_LIMIT_RESET, String(Math.ceil(rateLimit.resetAt / TIME.SECOND)));

		return next();
	} catch (error) {
		logger.error("Admin rate limiter failed", {
			error: error instanceof Error ? error.message : String(error),
			clientIp,
		});
		// FAIL CLOSED - deny request when rate limiting is unavailable
		return c.json(
			{
				error: "Service temporarily unavailable",
				code: "RATE_LIMIT_ERROR" as const satisfies ErrorCode,
			},
			HTTP.ServiceUnavailable,
		);
	}
};
