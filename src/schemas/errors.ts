import { z } from "@hono/zod-openapi";

/**
 * All valid error codes used in the codebase
 */
export const ErrorCodeSchema = z
	.enum([
		"AUTH_MISSING",
		/**
		 * A credential was presented and the *credential* was refused: malformed,
		 * expired, wrong audience, unlisted issuer, bad signature, wrong admin
		 * token. The fix is always to the credential or to the issuer config.
		 */
		"AUTH_INVALID",
		/**
		 * The credential verified, and the identity it proves holds no active
		 * trust. Nothing is wrong with the token — the fix is to the trust list
		 * (`POST /admin/subjects`), not to the workflow's authentication.
		 *
		 * Split out of AUTH_INVALID because those two fixes have nothing in common:
		 * one is "regenerate the token", the other is "authorize this subject", and
		 * a caller that cannot tell them apart tries the first one for both.
		 */
		"AUTH_SUBJECT_UNTRUSTED",
		"KEY_NOT_FOUND",
		/** Caller is authenticated and trusted, but its grant does not cover this key. */
		"KEY_NOT_ALLOWED",
		"KEY_PROCESSING_ERROR",
		"KEY_LIST_ERROR",
		"KEY_UPLOAD_ERROR",
		"KEY_DELETE_ERROR",
		"SIGN_ERROR",
		"RATE_LIMIT_ERROR",
		"RATE_LIMITED",
		"INVALID_REQUEST",
		"AUDIT_ERROR",
		"NOT_FOUND",
		"INTERNAL_ERROR",
	])
	.openapi("ErrorCode");

/**
 * Standard error response schema
 * Used across all endpoints for consistent error handling
 *
 * `docs`, `hint` and `subject` are declared optional because the schema also
 * describes bodies this service does not build — an intermediary's 502, a
 * deployment older than the release that added them. Every error *this* service
 * answers carries `docs`: `errorDocs` fills it in on the way out for any JSON
 * body with a `code`, so a new code cannot ship without one.
 */
export const ErrorResponseSchema = z
	.object({
		error: z.string().min(1, "Error message cannot be empty"),
		code: ErrorCodeSchema,
		requestId: z.uuid().optional(),
		/**
		 * Where to read about this exact code. Short by construction —
		 * `<service>/e/<CODE>` redirects to the reference — because the place this
		 * field is read is a wrapped, truncated, copy-pasted CI log.
		 */
		docs: z.url().optional(),
		/** What to change to make the call succeed, in prose. */
		hint: z.string().optional(),
		/**
		 * The `sub` claim the caller presented, echoed back on an authorization
		 * refusal. Leaks nothing: it comes from a signed token the caller already
		 * holds, and it is the one value needed to tell a wrong-ref from a
		 * wrong-repo from a missing trust rule.
		 */
		subject: z.string().optional(),
	})
	.openapi("ErrorResponse");

/**
 * Rate limit error response schema
 * Includes retryAfter timestamp for 429 responses
 */
export const RateLimitErrorSchema = z
	.object({
		error: z.string().min(1, "Error message cannot be empty"),
		code: ErrorCodeSchema,
		retryAfter: z.number().int().positive(),
		docs: z.url().optional(),
		hint: z.string().optional(),
	})
	.openapi("RateLimitError");

/** Type inferred from ErrorCodeSchema */
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

/** Type inferred from ErrorResponseSchema */
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;

/** Every code the enum declares, as a runtime list. */
export const ERROR_CODES = ErrorCodeSchema.options;

/** Is `value` one of the codes this service documents? */
export function isErrorCode(value: string): value is ErrorCode {
	return (ERROR_CODES as readonly string[]).includes(value);
}
