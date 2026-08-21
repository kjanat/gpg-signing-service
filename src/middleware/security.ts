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

/** Rate-limit headers a cross-origin reader may see, when the response has them. */
const RATE_LIMIT_HEADERS = [HEADERS.RATE_LIMIT_LIMIT, HEADERS.RATE_LIMIT_REMAINING, HEADERS.RATE_LIMIT_RESET] as const;

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

	// Advertise only the rate-limit headers this response actually carries. The
	// list used to be hardcoded, so it named X-RateLimit-Limit — which nothing in
	// the service ever sets — on every rate-limited response.
	const exposed = RATE_LIMIT_HEADERS.filter((name) => c.res.headers.has(name));
	if (exposed.length > 0) {
		c.header("Access-Control-Expose-Headers", exposed.join(", "));
	}
};

/** Literal `ALLOWED_ORIGINS` entry opting a deployment into public browser access. */
const WILDCARD_ORIGIN = "*";

/**
 * Origins that are never granted access, whatever the allowlist says.
 *
 * `null` is the origin a sandboxed iframe, a `data:` URL and a `file://`
 * document all send, so honouring it hands one shared, unauthenticated origin to
 * every context an attacker can conjure — a weaker position than the wildcard,
 * because the attacker gets to *choose* to present it.
 */
const FORBIDDEN_ORIGINS = new Set(["null"]);

const CORS_ALLOW_METHODS = "GET, POST, DELETE, OPTIONS";
const CORS_ALLOW_HEADERS = `Authorization, Content-Type, ${HEADERS.REQUEST_ID}`;
/** 24h, the cap Chromium honours for a preflight. */
const CORS_MAX_AGE = "86400";

/**
 * Resolve the value for `Access-Control-Allow-Origin`, or `undefined` to send none.
 *
 * Fails **closed**: an unset or empty `ALLOWED_ORIGINS` grants no origin
 * anything. This used to be inverted — an empty allowlist meant "allow
 * everything", and since the binding is optional and unset in `wrangler.toml`,
 * the deployed default reflected any attacker-supplied `Origin`. The service's
 * real callers are CI runners and the Go client, neither of which is a browser
 * and neither of which needs a CORS grant to work.
 */
function resolveAllowedOrigin(allowedOrigins: string | undefined, origin: string): string | undefined {
	// Entries are trimmed the same way ALLOWED_ISSUERS is, so a padded value in a
	// comma-separated list is not silently un-matchable.
	const entries = (allowedOrigins?.split(",") ?? []).map((entry) => entry.trim()).filter((entry) => entry.length > 0);

	if (entries.length === 0) {
		return undefined;
	}
	// An explicit `*` echoes the literal wildcard rather than reflecting the
	// request origin. Safe only because no credentials are ever granted.
	if (entries.includes(WILDCARD_ORIGIN)) {
		return WILDCARD_ORIGIN;
	}
	if (FORBIDDEN_ORIGINS.has(origin)) {
		return undefined;
	}
	return entries.includes(origin) ? origin : undefined;
}

/**
 * Add `Origin` to `Vary` without duplicating a token another handler already set.
 *
 * Exported for direct testing: no handler in the service sets `Vary` today, so
 * the merge paths are unreachable through the app itself.
 */
export function varyOnOrigin(headers: Headers): void {
	const tokens = (headers.get("Vary") ?? "").split(",").map((token) => token.trim().toLowerCase());
	if (!tokens.includes("origin") && !tokens.includes("*")) {
		headers.append("Vary", "Origin");
	}
}

/**
 * Production CORS middleware with restricted origins.
 *
 * No `Access-Control-Allow-Credentials` is ever sent. The service authenticates
 * with a bearer token in `Authorization`, which a browser never attaches
 * ambiently, so the header bought nothing while making the fail-open default the
 * textbook reflect-origin-with-credentials hole. It was also only ever set on the
 * actual response and not on the preflight, so it never worked for its stated
 * purpose in the first place. A cookie- or client-certificate-based flow would
 * have to add it back to *both* branches deliberately.
 */
export const productionCors: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
	const origin = c.req.header("Origin");
	const allowOrigin = origin === undefined ? undefined : resolveAllowedOrigin(c.env.ALLOWED_ORIGINS, origin);
	// The wildcard answer is origin-independent; every other outcome — including a
	// bare denial and the no-Origin case — is what this request's Origin earned, so
	// a shared cache must key on it or it will hand one origin another's grant.
	const varies = allowOrigin !== WILDCARD_ORIGIN;

	if (c.req.method === "OPTIONS") {
		const headers = new Headers();
		if (varies) {
			varyOnOrigin(headers);
		}
		if (allowOrigin !== undefined) {
			headers.set("Access-Control-Allow-Origin", allowOrigin);
			headers.set("Access-Control-Allow-Methods", CORS_ALLOW_METHODS);
			headers.set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
			headers.set("Access-Control-Max-Age", CORS_MAX_AGE);
		}
		return new Response(null, { status: HTTP.NoContent, headers });
	}

	await next();

	if (varies) {
		varyOnOrigin(c.res.headers);
	}
	if (allowOrigin !== undefined) {
		c.header("Access-Control-Allow-Origin", allowOrigin);
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
