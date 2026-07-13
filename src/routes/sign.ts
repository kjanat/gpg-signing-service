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
import { createKeyId, HEADERS, HTTP, TIME } from "#types";
import { logAuditEvent } from "#utils/audit";
import { fetchKeyStorage, fetchRateLimiter } from "#utils/durable-objects";
import { scheduleBackgroundTask } from "#utils/execution";
import { logger } from "#utils/logger";
import { signCommitData } from "#utils/signing";
import { signCommitDataX509 } from "#utils/x509";

const app = createOpenAPIApp();

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
	const { [HEADERS.REQUEST_ID]: requestIdHeader } = c.req.valid("header");
	const requestId = requestIdHeader || crypto.randomUUID();
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
	const keyIdParam = keyIdQuery || c.env.KEY_ID;

	// Service tokens may carry a key allowlist; enforce it before any work.
	const allowedKeyIds = c.get("allowedKeyIds");
	if (allowedKeyIds && !allowedKeyIds.includes(keyIdParam)) {
		return c.json(
			{
				error: `Token is not allowed to sign with key ${keyIdParam}`,
				code: "INVALID_REQUEST" as const satisfies ErrorCode,
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
			fetchRateLimiter(c.env, identity),
			fetchKeyStorage(c.env, `/get-key?keyId=${encodeURIComponent(keyIdParam)}`),
		]);

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
				metadata: JSON.stringify({ error: message }),
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
