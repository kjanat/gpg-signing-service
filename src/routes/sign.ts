import { createRoute, z } from "@hono/zod-openapi";

import { createOpenAPIApp } from "#lib/openapi";
import {
	ErrorResponseSchema,
	PublicKeyQuerySchema,
	RateLimitErrorSchema,
	RequestHeadersSchema,
	SignRequestSchema,
	SignResponseSchema,
} from "#schemas";
import type { ErrorCode } from "#schemas/errors";
import type { AnyStoredKey } from "#schemas/keys";
import { AnyStoredKeySchema, isX509Key } from "#schemas/keys";
import type { Identity, RateLimitResult, ValidatedOIDCClaims } from "#types";
import { createIdentity, createKeyId, HEADERS, HTTP, isKeyIdShaped, TIME } from "#types";
import { logAuditEvent } from "#utils/audit";
import { fetchKeyStorage, fetchRateLimiter } from "#utils/durable-objects";
import { scheduleBackgroundTask } from "#utils/execution";
import { logger } from "#utils/logger";
import { signCommitData } from "#utils/signing";
import { signCommitDataX509 } from "#utils/x509";

const app = createOpenAPIApp();

/**
 * Rate-limiter namespace for the per-row signing ceiling. Not an issuer, so it
 * cannot collide with the `<iss>:<sub>` buckets — a non-URL issuer cannot
 * authenticate, since JWKS discovery runs the issuer through `validateUrl`.
 */
const SUBJECT_ROW_METER = "oidc-subject-row";

/**
 * Signatures per minute per trusted row, across every subject it covers.
 *
 * Ten times the per-caller budget: high enough that a busy org spread over many
 * repositories and refs never meets it, low enough that one row cannot be
 * multiplied into unbounded signing by minting subjects. Tune against real
 * traffic rather than treating this number as load-bearing.
 */
const SUBJECT_ROW_LIMIT = 1000;

/** Outcome of consulting the rate limiter, with the failure modes separated. */
type RateLimitDecision = { kind: "ok" } | { kind: "limited"; retryAfter: number } | { kind: "unavailable" };

/**
 * Resolve an in-flight rate limiter call into a decision.
 *
 * Used by the refusal paths, which only need to know whether they may perform
 * metered work — they have no signature to produce, so they never look at the
 * remaining budget. The signing path keeps its own inline handling of the same
 * response because it must distinguish an unreachable limiter (which reaches
 * the route's `catch`) from one that answered with an error status (503), a
 * split this collapses into `unavailable`.
 *
 * @param pending - An already-started `fetchRateLimiter` call
 * @param requestId - For correlating the outage in logs
 * @returns Whether the caller is within budget, or `unavailable`
 */
async function resolveRateLimit(pending: Promise<Response>, requestId: string): Promise<RateLimitDecision> {
	let response: Response;
	try {
		response = await pending;
	} catch (error) {
		logger.error("Rate limiter unreachable", {
			requestId,
			error: error instanceof Error ? error.message : String(error),
		});
		return { kind: "unavailable" };
	}

	if (!response.ok) {
		logger.error("Rate limiter failed", { status: response.status, requestId });
		return { kind: "unavailable" };
	}

	const rateLimit = (await response.json()) as RateLimitResult;
	if (!rateLimit.allowed) {
		return { kind: "limited", retryAfter: Math.ceil((rateLimit.resetAt - Date.now()) / 1000) };
	}
	return { kind: "ok" };
}

/**
 * Resolve the per-row ceiling, if this caller has one, into a retry delay.
 *
 * Both refusal paths consult it: the signing path, and the key-scope denial,
 * whose D1 write is otherwise bounded only by the per-caller bucket — and that
 * bucket is keyed on `sub`, which is the multiplication this tier exists to
 * stop. Only one of them runs per request, so the response is read once.
 *
 * An outage is deliberately not fatal here: the per-caller tier has already
 * answered, and failing closed twice would turn one outage into two.
 *
 * @param pending - An already-started row-ceiling `fetchRateLimiter` call
 * @param requestId - For correlating the refusal in logs
 * @returns Seconds to wait if the row is over its ceiling, else `undefined`
 */
async function resolveRowCeiling(
	pending: Promise<Response> | undefined,
	requestId: string,
): Promise<number | undefined> {
	if (!pending) {
		return undefined;
	}
	const decision = await resolveRateLimit(pending, requestId);
	return decision.kind === "limited" ? decision.retryAfter : undefined;
}

const signRoute = createRoute({
	method: "post",
	path: "/",
	summary: "Sign commit data",
	description: "Sign git commit data using the stored GPG key",
	security: [{ oidcAuth: [] }, { serviceTokenAuth: [] }],
	request: {
		body: {
			content: { "text/plain": { schema: SignRequestSchema } },
			required: true,
		},
		query: PublicKeyQuerySchema,
		headers: RequestHeadersSchema,
	},
	responses: {
		[HTTP.OK]: {
			content: { "text/plain": { schema: SignResponseSchema } },
			description: "PGP Signature",
		},
		[HTTP.BadRequest]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Bad Request",
		},
		[HTTP.Forbidden]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Token not allowed to use this key",
		},
		[HTTP.NotFound]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Key not found",
		},
		[HTTP.TooManyRequests]: {
			content: { "application/json": { schema: RateLimitErrorSchema } },
			description: "Rate limit exceeded",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal Server Error",
		},
		[HTTP.ServiceUnavailable]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Service Unavailable",
		},
	},
});

app.openapi(signRoute, async (c) => {
	// Set by the global request-id middleware, which validates the caller's header
	// and mints one otherwise. Reading it rather than re-deriving keeps this row
	// joinable with the one the OIDC middleware may have written for the same
	// request, and with the X-Request-ID echoed on the response.
	const requestId = c.get("requestId");
	const claims = c.get("oidcClaims") as ValidatedOIDCClaims;
	const identity = c.get("identity") as Identity;

	// Validate request body early
	const commitData = await c.req.text();

	const bodySchema = z.string().min(1);
	const bodyResult = bodySchema.safeParse(commitData);

	if (!bodyResult.success) {
		return c.json(
			{
				error: "No commit data provided",
				code: "INVALID_REQUEST" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.BadRequest,
		);
	}

	// Get key ID from query param or use default
	const { keyId: keyIdQuery } = c.req.valid("query");

	// Format-check the caller's value before any I/O. `PublicKeyQuerySchema`
	// declares keyId as a bare optional string, so `createKeyId` further down is
	// the only gate — and it *throws*, landing in the catch, which returns 500 and
	// writes an audit row having never read the limiter's verdict. That is the one
	// branch inside the metered window that escapes it, and it needs no key grant
	// to reach. A malformed query parameter is a client error: no budget, no row,
	// no 500.
	//
	// Only the caller's value is checked here. A malformed deploy-time `KEY_ID`
	// still reaches `createKeyId` and surfaces as a 500, which is the correct
	// volume for a broken deployment and is not something a caller can trigger.
	//
	// `keyIdQuery &&`, not `!== undefined`: three lines down `keyIdQuery ||
	// c.env.KEY_ID` already reads the empty string as "not supplied", and
	// `?keyId=` is what a shell template emits for an unset variable. `/public-key`
	// shares this schema and still falls back, so the two routes must agree.
	if (keyIdQuery && !isKeyIdShaped(keyIdQuery)) {
		return c.json(
			{
				error: `Invalid key ID format: ${keyIdQuery}`,
				code: "INVALID_REQUEST" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.BadRequest,
		);
	}

	const keyIdParam = keyIdQuery || c.env.KEY_ID;

	// Started here, before the key-scope check below, because that branch now
	// writes to D1: an unmetered write is a way for one trusted token to bury the
	// very event operators are told to alert on, and `audit_logs` shares a
	// database with `oidc_subjects`, which every authorization decision reads.
	// Starting rather than awaiting keeps the signing path's overlap with the key
	// fetch intact — the promise is already in flight when Promise.all takes it.
	const rateLimitPromise = fetchRateLimiter(c.env, identity);

	// Second tier. The bucket above is keyed on `<iss>:<sub>`, and GitHub puts the
	// ref in `sub`, so a caller who can push branches mints a fresh budget per
	// branch — the per-caller cap does not bound the trusted *row*. This one is
	// keyed on the row id, which is server-side and unforgeable, with a ceiling
	// well above the per-caller budget so no single workflow's behaviour changes:
	// it only stops one row from being multiplied without limit. Started here
	// rather than awaited so it overlaps the first tier and the key fetch.
	//
	// Absent on the service-token path, which is already metered per credential.
	const subjectPolicyId = c.get("subjectPolicyId");
	const rowLimitPromise = subjectPolicyId
		? fetchRateLimiter(c.env, createIdentity(SUBJECT_ROW_METER, subjectPolicyId), SUBJECT_ROW_LIMIT)
		: undefined;
	rowLimitPromise?.catch(() => {});
	// `createKeyId` below can throw before the Promise.all that normally awaits
	// this, which would leave the rejection unobserved. Attaching a handler does
	// not consume it for the real consumers.
	rateLimitPromise.catch(() => {});

	// Both auth paths may carry a key allowlist; enforce it before any signing.
	const allowedKeyIds = c.get("allowedKeyIds");
	if (allowedKeyIds && !allowedKeyIds.includes(keyIdParam)) {
		// A trusted caller reaching past its own grant is the highest-signal event
		// this service produces: either a misconfigured workflow or a credential
		// being used by something that should not hold it. Returning bare would
		// leave no way to tell which — an *untrusted* subject, a far weaker
		// signal, already gets a log line in the OIDC middleware.
		//
		// Metered like any other request, and the audit row is written only if the
		// caller is within its budget, so the denial cannot be used to flood the
		// table it is recorded in.
		const decision = await resolveRateLimit(rateLimitPromise, requestId);
		if (decision.kind === "limited") {
			return c.json(
				{
					error: "Rate limit exceeded",
					code: "RATE_LIMITED" as const satisfies ErrorCode,
					retryAfter: decision.retryAfter,
				},
				HTTP.TooManyRequests,
			);
		}

		// The row ceiling governs this branch too. Without it the per-caller bucket
		// is the only bound on the D1 write below, and that bucket is keyed on
		// `sub` — so a row that can mint subjects could still flood `audit_logs`
		// past its ceiling, which is the flooding this tier exists to stop.
		const scopeRowRetryAfter = await resolveRowCeiling(rowLimitPromise, requestId);
		if (scopeRowRetryAfter !== undefined) {
			logger.warn("Trusted row hit its signing ceiling", {
				requestId,
				subjectPolicy: c.get("subjectPolicyName"),
				subjectPolicyId,
			});
			return c.json(
				{
					error: "Rate limit exceeded",
					code: "RATE_LIMITED" as const satisfies ErrorCode,
					retryAfter: scopeRowRetryAfter,
				},
				HTTP.TooManyRequests,
			);
		}

		if (decision.kind === "ok") {
			await scheduleBackgroundTask(
				c,
				requestId,
				logAuditEvent(c.env.AUDIT_DB, {
					requestId,
					action: "sign",
					issuer: claims.iss,
					subject: claims.sub,
					keyId: keyIdParam,
					success: false,
					errorCode: "KEY_NOT_ALLOWED",
					metadata: JSON.stringify({ subjectPolicy: c.get("subjectPolicyName") }),
				}),
			);
		} else {
			// Limiter unreachable: refuse anyway, but do not write unmetered. The
			// log line keeps the denial from vanishing entirely.
			logger.warn("Key scope denied while the rate limiter was unavailable", {
				requestId,
				issuer: claims.iss,
				subject: claims.sub,
				keyId: keyIdParam,
			});
		}

		return c.json(
			{
				error: `Token is not allowed to sign with key ${keyIdParam}`,
				// Not INVALID_REQUEST: the request was well formed and the credential
				// valid. Filtering audit_logs for scope denials needs it to be
				// distinguishable from a 400.
				code: "KEY_NOT_ALLOWED" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.Forbidden,
		);
	}

	// Parallel execution: Rate limit + Key fetch (performance optimization ~15ms gain)
	// Security: Rate limit enforced BEFORE signing, parallel fetch is read-only
	let rateLimit: RateLimitResult;
	let storedKey: AnyStoredKey;

	try {
		createKeyId(keyIdParam); // Validate key ID format (inside try so errors are caught)
		const [rateLimitResponse, keyResponse] = await Promise.all([
			rateLimitPromise,
			fetchKeyStorage(c.env, `/get-key?keyId=${encodeURIComponent(keyIdParam)}`),
		]);

		// The row ceiling is advisory relative to the per-caller bucket: if it is
		// exhausted the caller is over budget regardless of which subject it
		// presented.
		const rowRetryAfter = await resolveRowCeiling(rowLimitPromise, requestId);
		if (rowRetryAfter !== undefined) {
			logger.warn("Trusted row hit its signing ceiling", {
				requestId,
				subjectPolicy: c.get("subjectPolicyName"),
				subjectPolicyId,
			});
			return c.json(
				{
					error: "Rate limit exceeded",
					code: "RATE_LIMITED" as const satisfies ErrorCode,
					retryAfter: rowRetryAfter,
				},
				HTTP.TooManyRequests,
			);
		}

		// Process rate limit
		if (!rateLimitResponse.ok) {
			logger.error("Rate limiter failed", {
				status: rateLimitResponse.status,
				requestId,
			});
			return c.json(
				{
					error: "Service temporarily unavailable",
					code: "RATE_LIMIT_ERROR" as const satisfies ErrorCode,
					requestId,
				},
				HTTP.ServiceUnavailable,
			);
		}

		rateLimit = (await rateLimitResponse.json()) as RateLimitResult;

		// Enforce rate limit BEFORE processing key
		if (!rateLimit.allowed) {
			return c.json(
				{
					error: "Rate limit exceeded",
					code: "RATE_LIMITED" as const satisfies ErrorCode,
					retryAfter: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
				},
				HTTP.TooManyRequests,
			);
		}

		// Process key response
		if (!keyResponse.ok) {
			const error = (await keyResponse.json()) as { error: string };
			throw new Error(error.error || "Key not found");
		}

		storedKey = AnyStoredKeySchema.parse(await keyResponse.json());

		// Sign the commit data (PGP armored or detached PKCS#7, per key type)
		const result = isX509Key(storedKey)
			? await signCommitDataX509(commitData, storedKey, c.env.KEY_PASSPHRASE)
			: await signCommitData(commitData, storedKey, c.env.KEY_PASSPHRASE);

		// Log successful signing (non-blocking for performance)
		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "sign",
				issuer: claims.iss,
				subject: claims.sub,
				keyId: keyIdParam,
				success: true,
				metadata: JSON.stringify({
					repository: claims.repository || claims.project_path,
					dataLength: commitData.length,
					subjectPolicy: c.get("subjectPolicyName"),
				}),
			}),
		);

		// Set rate limit headers
		c.header(HEADERS.RATE_LIMIT_REMAINING, String(rateLimit.remaining));
		c.header(HEADERS.RATE_LIMIT_RESET, String(Math.ceil(rateLimit.resetAt / TIME.SECOND)));
		c.header(HEADERS.REQUEST_ID, requestId);

		return c.text(result.signature, HTTP.OK);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Signing failed";

		// Check if this is a rate limiter error from the fetch phase
		if (message.includes("Rate limiter")) {
			logger.error("Rate limiter critical failure", {
				error: message,
				requestId,
			});
			return c.json(
				{
					error: "Service temporarily unavailable",
					code: "RATE_LIMIT_ERROR" as const satisfies ErrorCode,
					requestId,
				},
				HTTP.ServiceUnavailable,
			);
		}

		const isKeyNotFound = message === "Key not found" || message.includes("not found");

		// Log failed signing attempt (non-blocking)
		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "sign",
				issuer: claims.iss,
				subject: claims.sub,
				keyId: keyIdParam,
				success: false,
				errorCode: isKeyNotFound ? "KEY_NOT_FOUND" : "SIGN_ERROR",
				metadata: JSON.stringify({ error: message, subjectPolicy: c.get("subjectPolicyName") }),
			}),
		);

		if (isKeyNotFound) {
			return c.json(
				{
					error: message,
					code: "KEY_NOT_FOUND" as const satisfies ErrorCode,
					requestId,
				},
				HTTP.NotFound,
			);
		}

		return c.json(
			{
				error: message,
				code: "SIGN_ERROR" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.InternalServerError,
		);
	}
});

export default app;
