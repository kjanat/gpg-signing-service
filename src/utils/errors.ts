/**
 * Error handling utilities
 */

import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { WWW_AUTHENTICATE } from "#lib/openapi";
import type { ErrorCode } from "#schemas/errors";
import { HTTP } from "#types";
import { logger } from "#utils/logger";

interface ErrorOptions {
	code: ErrorCode;
	status?: ContentfulStatusCode;
	requestId?: string;
	context?: Record<string, unknown>;
	/** What the caller should change, in prose. Rendered on its own line by the CLI. */
	hint?: string;
}

/**
 * Standardized error response
 */
export function errorResponse(c: Context, message: string, options: ErrorOptions) {
	const { code, status = HTTP.InternalServerError, requestId, context, hint } = options;

	// Log the error
	logger.error(message, undefined, {
		code,
		status,
		...(requestId && { requestId }),
		...context,
	});

	// Return standardized response. `docs` is not set here: `errorDocs` fills it
	// in for every coded JSON error on the way out, including the ones built by
	// hand elsewhere, so writing it twice would only be a second place to forget.
	return c.json({ error: message, code, ...(requestId && { requestId }), ...(hint && { hint }) }, status);
}

/** The codes a 401 may carry. */
export type UnauthorizedCode = Extract<ErrorCode, "AUTH_MISSING" | "AUTH_INVALID" | "AUTH_SUBJECT_UNTRUSTED">;

/**
 * The service's single 401.
 *
 * Every refusal used to be a hand-written `c.json` in whichever middleware
 * caught it, and each one dropped two things the caller is owed:
 *
 * `requestId` — the key that finds this refusal in `audit_logs.request_id`.
 * A CI-only OIDC token cannot be replayed from a laptop to reproduce the
 * failure, so the id is the only route from "the pipeline said no" to the
 * record of why. It is echoed in `X-Request-ID` either way, but a caller that
 * has already parsed the envelope should not have to reach back to the headers
 * for a field the envelope declares.
 *
 * `WWW-Authenticate` — RFC 9110 §11.6.1 requires it on a 401, and the document
 * now declares it on all thirteen authenticated operations.
 *
 * Kept out of `errorResponse` above deliberately: that one logs at error level,
 * and a rejected credential is the auth layer working, not a fault worth paging
 * on. Volume here is attacker-controlled.
 *
 * @param c - Request context
 * @param message - What the caller may be told; never leaks stored state
 * @param code - AUTH_MISSING when no usable credential was presented,
 *   AUTH_INVALID when one was and the *credential* was refused,
 *   AUTH_SUBJECT_UNTRUSTED when the credential verified and the identity it
 *   proves holds no active trust
 * @param details - Extra fields for the envelope. `hint` says what to change;
 *   `subject` echoes the `sub` the caller presented, which is only ever a value
 *   it already holds in a signed token.
 */
export function unauthorized(
	c: Context,
	message: string,
	code: UnauthorizedCode,
	details: { hint?: string | undefined; subject?: string | undefined } = {},
) {
	const requestId = c.get("requestId");
	c.header("WWW-Authenticate", WWW_AUTHENTICATE);
	return c.json(
		{
			error: message,
			code,
			...(requestId && { requestId }),
			...(details.subject && { subject: details.subject }),
			...(details.hint && { hint: details.hint }),
		},
		HTTP.Unauthorized,
	);
}

/**
 * Handle unknown errors
 */
export function handleUnknownError(c: Context, error: unknown, fallbackMessage: string, code: ErrorCode): Response {
	const message = error instanceof Error ? error.message : fallbackMessage;
	const requestId = c.get("requestId");

	logger.error("Unhandled error", error, { code, requestId });

	return errorResponse(c, message, {
		code,
		requestId,
		status: HTTP.InternalServerError,
	});
}

/**
 * Create typed error class
 */
export class AppError extends Error {
	constructor(
		message: string,
		public readonly code: ErrorCode,
		public readonly status: ContentfulStatusCode = HTTP.InternalServerError,
		public readonly context?: Record<string, unknown>,
	) {
		super(message);
		this.name = "AppError";
	}
}

/**
 * Type guard for AppError
 */
export function isAppError(error: unknown): error is AppError {
	return error instanceof AppError;
}
