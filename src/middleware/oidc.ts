import type { Context, MiddlewareHandler } from "hono";
import { createLocalJWKSet, jwtVerify } from "jose";
import { getRequestId } from "#middleware/request-id";
import type { Env, LegacyJWKSResponse, OIDCClaims, RateLimitResult, Variables } from "#types";
import { createIdentity, HEADERS, HTTP, markClaimsAsValidated, TIME } from "#types";
import { logAuditEvent } from "#utils/audit";
import { CACHE_TTL } from "#utils/constants";
import { fetchRateLimiter } from "#utils/durable-objects";
import { unauthorized } from "#utils/errors";
import { scheduleBackgroundTask } from "#utils/execution";
import { fetchWithTimeout } from "#utils/fetch";
import { logger } from "#utils/logger";
import type { OIDCSubjectResolution } from "#utils/oidc-subjects";
import { resolveOIDCSubject } from "#utils/oidc-subjects";
import { validateUrl } from "#utils/url-validation";

/**
 * Rate-limiter namespace for revoked-trust reuse, kept disjoint from the
 * `<iss>:<sub>` buckets the signing path consumes.
 *
 * Not because `ALLOWED_ISSUERS` is validated — it is a bare string, split on
 * commas and checked nowhere; `SubjectCreateSchema.issuer` constrains stored
 * *rows*, and the bucket name is built from `payload.iss`. The real guarantee is
 * that a non-URL issuer cannot authenticate at all: `getJWKS` fetches
 * `${issuer}/.well-known/openid-configuration` through `validateUrl`, which
 * requires an absolute `https:` URL. So this string can never appear as an `iss`
 * that reached the point of naming a bucket.
 */
const REVOKED_REUSE_METER = "oidc-revoked-reuse";

/**
 * Write a durable record of a revoked trust being presented, if the caller is
 * within its rate-limit budget.
 *
 * Metered because it is a D1 write on a refusal path: without the check, the
 * holder of a revoked credential could flood `audit_logs`, which shares a
 * database with the authorization table every request reads. Best-effort in
 * every direction — a limiter outage or a failed write must not change the 401.
 *
 * Metered on the *revoked row's id*, not on `<iss>:<sub>` like the signing path.
 * A row is a prefix, and one prefix covers unboundedly many subjects: GitHub
 * puts the ref in `sub`, so anyone who can push a branch under the revoked scope
 * mints a fresh subject — and a per-subject bucket hands them a fresh budget
 * with it, which makes the cap no cap at all. Keying on the id bounds the whole
 * revoked trust to one bucket however many subjects it presents, the same shape
 * as the service-token path, which meters on `policy.name` rather than on
 * anything the caller picks.
 *
 * The signing path applies the same argument as a second tier: a per-caller
 * bucket for fairness, plus a per-row ceiling keyed the same way this is.
 *
 * @param c - Request context
 * @param requestId - This request's id, shared with the rest of the pipeline
 * @param payload - The verified (but unauthorized) claims
 * @param resolution - The revoked row that matched
 */
async function recordRevokedReuse(
	c: Context<{ Bindings: Env; Variables: Variables }>,
	requestId: string,
	payload: OIDCClaims,
	resolution: Extract<OIDCSubjectResolution, { status: "revoked" }>,
): Promise<void> {
	try {
		const limit = await fetchRateLimiter(c.env, createIdentity(REVOKED_REUSE_METER, resolution.id));
		if (!limit.ok) {
			return;
		}
		const { allowed } = (await limit.json()) as RateLimitResult;
		if (!allowed) {
			return;
		}
	} catch (error) {
		logger.warn("Could not meter a revoked-trust reuse, so it was not recorded", {
			requestId,
			error: error instanceof Error ? error.message : String(error),
		});
		return;
	}

	await scheduleBackgroundTask(
		c,
		requestId,
		logAuditEvent(c.env.AUDIT_DB, {
			requestId,
			action: "sign",
			issuer: payload.iss,
			subject: payload.sub,
			keyId: "*",
			success: false,
			errorCode: "AUTH_INVALID",
			metadata: JSON.stringify({
				reason: "revoked_trust_presented",
				subjectId: resolution.id,
				subjectPolicy: resolution.name,
				revokedAt: resolution.revokedAt,
			}),
		}),
	);
}

/**
 * OIDC validation middleware.
 *
 * The identity published here is `<iss>:<sub>` and becomes the sign route's
 * per-caller rate-limit bucket. GitHub puts the ref in `sub`, so that bucket
 * alone does not bound a trusted *row* — a caller who can push branches mints a
 * fresh budget per branch. `subjectPolicyId` is published alongside it for the
 * route's second-tier ceiling, which is keyed on the row and closes that gap;
 * see `SUBJECT_ROW_LIMIT` in `routes/sign.ts`.
 *
 * Every distinct `sub` still writes its own `bucket:` key in the limiter Durable
 * Object; the row ceiling bounds the signing *rate*, not that growth. The
 * limiter's reaper is what bounds it, by deleting buckets that have refilled to
 * capacity — see `alarm` in `durable-objects/rate-limiter.ts`.
 */
export const oidcAuth: MiddlewareHandler<{
	Bindings: Env;
	Variables: Variables;
}> = async (c, next) => {
	// One id for the whole request. The global request-id middleware already
	// derived it and captured that value for the `X-Request-ID` it echoes on the
	// way out, so re-deriving here mints a *different* UUID when the caller sent
	// no header — stranding every row this request writes under an id the caller
	// never sees. The fallback covers direct invocation in tests.
	const requestId = c.get("requestId") ?? getRequestId(c.req.header(HEADERS.REQUEST_ID));
	c.set("requestId", requestId);

	const authHeader = c.req.header("Authorization");

	if (!authHeader?.startsWith("Bearer ")) {
		return unauthorized(c, "Missing authorization header", "AUTH_MISSING");
	}

	const token = authHeader.split(" ")[1];
	if (!token) {
		// `code` is not decoration: the document now declares this 401 as an
		// ErrorResponse, and every client that reads the envelope branches on the
		// code rather than the prose. A bare `Bearer ` is the same fault as no
		// header at all, so it carries the same code.
		return unauthorized(c, "Missing token", "AUTH_MISSING");
	}

	// Deliberately narrow: this catch echoes the thrown message to the caller,
	// which is only safe for validateOIDCToken's curated auth strings. A database
	// read or anything downstream must not be in here — see below.
	let payload: OIDCClaims;
	try {
		payload = await validateOIDCToken(token, c.env);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Invalid token";
		return unauthorized(c, message, "AUTH_INVALID");
	}

	// Authentication is not authorization. A verified token only proves that some
	// workflow on an accepted issuer asked for our audience — and both issuers are
	// shared by every repository on GitHub Actions and every project on
	// gitlab.com. The subject must be one we trust.
	//
	// A policy we cannot read is not a bad credential. Reporting it as 401 would
	// point the operator at credentials on the day the real cause is a migration
	// that has not run yet, and would hand our schema to every caller.
	let resolution: OIDCSubjectResolution;
	try {
		resolution = await resolveOIDCSubject(c.env.AUDIT_DB, payload.iss, payload.sub);
	} catch (error) {
		logger.error("OIDC subject lookup failed", {
			issuer: payload.iss,
			error: error instanceof Error ? error.message : String(error),
		});
		return c.json({ error: "Authorization store unavailable", code: "INTERNAL_ERROR" }, HTTP.ServiceUnavailable);
	}

	if (resolution.status !== "trusted") {
		// Three different events, one response. The caller learns nothing extra —
		// telling a stranger that their subject matches a revoked row would confirm
		// the row exists — but the operator gets to tell them apart. Reuse of a
		// revoked credential is an incident; an unknown subject on a shared issuer
		// is background traffic.
		if (resolution.status === "revoked") {
			logger.warn("Revoked OIDC trust presented", {
				issuer: payload.iss,
				subject: payload.sub,
				subjectId: resolution.id,
				subjectPolicy: resolution.name,
				revokedAt: resolution.revokedAt,
			});
		} else if (resolution.status === "expired") {
			logger.warn("Expired OIDC trust presented", {
				issuer: payload.iss,
				subject: payload.sub,
				subjectId: resolution.id,
				subjectPolicy: resolution.name,
				expiresAt: resolution.expiresAt,
			});
		} else {
			logger.warn("Rejected untrusted OIDC subject", {
				issuer: payload.iss,
				subject: payload.sub,
			});
		}
		// `unknown` gets no audit_logs row: that arm is reachable by anyone holding
		// any token the issuer will mint, so a write there would be unmetered — the
		// same problem the key-scope denial had.
		//
		// `revoked` is not that. Reaching it requires the token's `sub` to match a
		// stored prefix, and GitHub binds `sub` to the caller's actual repository,
		// so the population that can trigger it is the org that used to hold the
		// trust. That is the same bounded, already-vetted caller whose scope denial
		// this service records durably — and a killed credential still in use is
		// the stronger signal of the two. It gets a row, metered the same way, so
		// it survives past the log store's retention window.
		//
		// `expired` is bounded the same way but stays log-only: a lapsed trust is
		// routine maintenance, not evidence of anything, and it is the row owner's
		// problem rather than an operator's. Recording it would mostly add volume.
		if (resolution.status === "revoked") {
			await recordRevokedReuse(c, requestId, payload, resolution);
		}

		return unauthorized(c, "Subject is not trusted for signing", "AUTH_INVALID");
	}

	const policy = resolution.policy;

	// Store validated claims in context for downstream use
	c.set("oidcClaims", markClaimsAsValidated(payload));
	c.set("identity", createIdentity(payload.iss, payload.sub));
	// Key scoping now applies to OIDC callers too, not just service tokens.
	c.set("allowedKeyIds", policy.allowedKeyIds);
	// Which trust authorized this call. Without it the audit trail records only
	// the JWT subject, so "what did the row I just revoked sign?" means re-running
	// prefix matching over the whole history. The service-token path gets this
	// for free by putting the policy name in its synthetic `sub`.
	c.set("subjectPolicyName", policy.name);
	// Metering handle for the sign route's per-row ceiling; see the note above.
	c.set("subjectPolicyId", policy.id);

	// The last-used stamp is bookkeeping; do not make every signature wait on a
	// D1 write for it.
	await scheduleBackgroundTask(c, requestId, policy.stampUsage());

	// Outside the try on purpose: an error from the sign handler is a 500, not a
	// 401 carrying an internal message.
	return next();
};

/**
 * Admin token auth for management endpoints.
 *
 * Typed with `Variables` so the 401s can read `requestId` off the context the
 * global middleware populated — the same id `X-Request-ID` echoes and
 * `audit_logs.request_id` stores.
 */
export const adminAuth: MiddlewareHandler<{
	Bindings: Env;
	Variables: Variables;
}> = async (c, next) => {
	// An unset or empty ADMIN_TOKEN is a deployment fault, not a credential
	// fault, and it is not a harmless one: timingSafeEqual("", "") compares two
	// zero-length arrays of matching length and returns true, so without this
	// guard a bare `Authorization: Bearer ` would authorize every admin route on
	// a Worker whose secret was never put. `Env` types ADMIN_TOKEN as `string`,
	// which is a compile-time promise about a value wrangler supplies at runtime
	// — nothing checks it. Answer 500, because the caller's credential is not
	// what is wrong and no amount of retrying with a better one will help.
	if (!c.env.ADMIN_TOKEN) {
		logger.error("ADMIN_TOKEN is not configured; refusing every admin request");
		return c.json(
			{ error: "Admin authentication is not configured", code: "INTERNAL_ERROR" },
			HTTP.InternalServerError,
		);
	}

	const authHeader = c.req.header("Authorization");

	if (!authHeader?.startsWith("Bearer ")) {
		return unauthorized(c, "Missing authorization header", "AUTH_MISSING");
	}

	const token = authHeader.slice(7);
	// Answered before the compare so a bare `Bearer ` gets the same code here as
	// it does on the OIDC path. The premise of declaring `code` is that clients
	// branch on it rather than on the prose, which is worth nothing if one
	// malformed header maps to two codes depending on which route received it.
	// An empty token is not a credential the service refused; it is no
	// credential at all.
	if (!token) {
		return unauthorized(c, "Missing token", "AUTH_MISSING");
	}

	// Use constant-time comparison to prevent timing attacks
	const isValid = await timingSafeEqual(token, c.env.ADMIN_TOKEN);
	if (!isValid) {
		return unauthorized(c, "Invalid admin token", "AUTH_INVALID");
	}

	return next();
};

// Constant-time string comparison to prevent timing attacks
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
	const encoder = new TextEncoder();
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);

	// Pad shorter value to match longer length for constant-time comparison
	const maxLen = Math.max(aBytes.length, bBytes.length);
	const aPadded = new Uint8Array(maxLen);
	const bPadded = new Uint8Array(maxLen);
	aPadded.set(aBytes);
	bPadded.set(bBytes);

	// Now compare same-length arrays, then check if original lengths matched
	const bytesEqual = crypto.subtle.timingSafeEqual(aPadded, bPadded);
	const lengthsEqual = aBytes.length === bBytes.length;

	return bytesEqual && lengthsEqual;
}

// Allowed JWT signing algorithms
const ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384"];

async function validateOIDCToken(token: string, env: Env): Promise<OIDCClaims> {
	// Decode JWT header and payload (without verification first)
	const parts = token.split(".");
	if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
		throw new Error("Invalid token format");
	}

	// Parse header and payload with explicit error handling
	let header: { kid: string; alg: string };
	let payload: OIDCClaims;
	try {
		header = JSON.parse(atob(parts[0])) as { kid: string; alg: string };
		payload = JSON.parse(atob(parts[1])) as OIDCClaims;
	} catch {
		throw new Error("Invalid token encoding");
	}

	// Validate algorithm against whitelist
	if (!ALLOWED_ALGORITHMS.includes(header.alg)) {
		throw new Error(`Algorithm not allowed: ${header.alg}`);
	}

	// Validate issuer. Trim to match how /admin/subjects reads the same variable:
	// if only one side trimmed, whitespace after a comma would let an issuer be
	// trusted at create time and refused here, producing exactly the silently
	// dead row that check exists to prevent.
	const allowedIssuers = env.ALLOWED_ISSUERS.split(",").map((issuer) => issuer.trim());
	if (!allowedIssuers.includes(payload.iss)) {
		throw new Error(`Issuer not allowed: ${payload.iss}`);
	}

	// Check timing claims with 60-second clock skew tolerance
	const now = Math.floor(Date.now() / 1000);
	const CLOCK_SKEW_SECONDS = 60;

	// Check not-before (nbf) with skew tolerance
	if (payload.nbf && payload.nbf > now + CLOCK_SKEW_SECONDS) {
		throw new Error("Token not yet valid");
	}

	// Check expiration with skew tolerance
	if (payload.exp < now - CLOCK_SKEW_SECONDS) {
		throw new Error("Token expired");
	}

	// Validate audience (configurable via env, defaults to service name)
	const expectedAudience = env.EXPECTED_AUDIENCE || "gpg-signing-service";
	const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (!audiences.includes(expectedAudience)) {
		throw new Error("Invalid token audience");
	}

	// Fetch JWKS and verify signature. If the cached JWKS doesn't have the
	// required key id, getJWKS will refresh from the network.
	const jwks = await getJWKS(payload.iss, env, header.kid);

	// Pre-flight: make sure a matching key exists and is intended for signatures.
	// This check prevents jose's internal JWKSNoMatchingKey error from escaping
	// as an unhandled rejection (jose's createLocalJWKSet throws synchronously
	// inside its promise chain when no matching key is found).
	const matchingKey = jwks.keys.find((key) => key.kid === header.kid);
	if (!matchingKey) {
		throw new Error("Key not found");
	}
	if (matchingKey.use && matchingKey.use !== "sig") {
		throw new Error("Key not intended for signatures");
	}

	// The `jose.jwtVerify` function handles finding the correct key from the JWKS
	// based on the `kid` in the token header, so manual key lookup is not needed.
	const JWKS = createLocalJWKSet(jwks);

	// Verify JWT signature using jose library
	// Note: jose's createLocalJWKSet can emit unhandled rejections during key lookup
	// when no matching key is found. The error is still caught here and mapped to
	// a user-friendly message, but the internal rejection may escape in test environments.
	try {
		const { payload: verifiedPayload } = await jwtVerify(token, JWKS, {
			issuer: allowedIssuers,
			algorithms: ALLOWED_ALGORITHMS,
			clockTolerance: "60s",
		});
		return verifiedPayload as OIDCClaims;
	} catch (e) {
		const err = e as Error & { code?: string };
		if (err.code === "ERR_JWKS_NO_MATCHING_KEY") {
			throw new Error("Key not found", { cause: e });
		}
		if (err.message?.includes("signature verification failed")) {
			throw new Error("Invalid token signature", { cause: e });
		}
		throw err;
	}
}

// Exported for targeted testing of error mapping logic
export function mapJoseError(err: Error & { code?: string }): never {
	// Map jose error codes/messages to user-friendly, test-specific messages.
	if (err.code === "ERR_JWKS_NO_MATCHING_KEY") {
		throw new Error("Key not found");
	}
	if (err.message?.includes("signature verification failed")) {
		throw new Error("Invalid token signature");
	}
	throw err;
}

async function getJWKS(issuer: string, env: Env, expectedKid?: string): Promise<LegacyJWKSResponse> {
	const cacheKey = `jwks:${issuer}`;

	// Check cache first
	const cached = await env.JWKS_CACHE.get(cacheKey, "json");
	if (cached) {
		const cachedJWKS = cached as LegacyJWKSResponse;
		// If an expected kid is provided and it's not in the cached JWKS, refresh
		// from the origin to pick up key rotations.
		if (expectedKid && !cachedJWKS.keys?.some((k: { kid?: string }) => k.kid === expectedKid)) {
			// fall through to network fetch below
		} else {
			return cachedJWKS;
		}
	}

	// Fetch JWKS from issuer with timeout
	const wellKnownUrl = `${issuer}/.well-known/openid-configuration`;

	// SSRF Protection: Validate wellKnown URL before fetching
	try {
		await validateUrl(wellKnownUrl);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Invalid URL";
		logger.warn("SSRF protection blocked OIDC config URL", {
			issuer,
			url: wellKnownUrl,
			error: message,
		});
		throw new Error(`SSRF protection: ${message}`, { cause: error });
	}

	const configResponse = await fetchWithTimeout(wellKnownUrl, {}, 10000);

	if (!configResponse.ok) {
		throw new Error(`Failed to fetch OIDC config from ${wellKnownUrl}`);
	}

	const config = (await configResponse.json()) as { jwks_uri: string };

	// SSRF Protection: Validate JWKS URI before fetching
	try {
		await validateUrl(config.jwks_uri);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Invalid URL";
		logger.warn("SSRF protection blocked JWKS URI", {
			issuer,
			jwks_uri: config.jwks_uri,
			error: message,
		});
		throw new Error(`SSRF protection: ${message}`, { cause: error });
	}

	const jwksResponse = await fetchWithTimeout(config.jwks_uri, {}, 10000);

	if (!jwksResponse.ok) {
		throw new Error(`Failed to fetch JWKS from ${config.jwks_uri}`);
	}

	const jwks = (await jwksResponse.json()) as LegacyJWKSResponse;

	// Cache for 5 minutes (non-critical, don't fail on cache errors)
	try {
		await env.JWKS_CACHE.put(cacheKey, JSON.stringify(jwks), {
			expirationTtl: CACHE_TTL.JWKS / TIME.SECOND,
		});
	} catch (error) {
		logger.warn("Failed to cache JWKS", {
			error: error instanceof Error ? error.message : String(error),
			issuer,
		});
		// Continue - caching is optimization, not critical path
	}

	return jwks;
}
