/**
 * Error handling utilities
 */

import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { insufficientScopeChallenge, WWW_AUTHENTICATE } from "#lib/openapi";
import type { ErrorCode } from "#schemas/errors";
import { HEADERS, HTTP } from "#types";
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
 * The service's "your credential is right, and it is too small".
 *
 * The counterpart to `unauthorized`, and deliberately not one of its codes. A
 * 401 tells the caller its credential was refused, and the only thing a caller
 * — or a scheduled job, which is the caller this exists for — does with that is
 * go and re-mint the credential. When a read-only admin bearer is refused on a
 * delete, the credential is exactly what it was provisioned to be and rotating
 * it produces this same answer forever. So: 403, a code of its own, and a
 * `WWW-Authenticate` carrying RFC 6750's `insufficient_scope` rather than the
 * bare challenge, which reads as "try again with credentials".
 *
 * Logged at warn, not error. A monitoring job that reaches a mutation route is
 * either a bug in that job or somebody probing, and both are worth a line —
 * but neither is a fault in this service, and the volume is not ours to bound.
 *
 * @param c - Request context
 * @param message - What was refused; never names stored state
 * @param details - `hint` says which credential the operation actually needs
 */
export function insufficientScope(c: Context, message: string, details: { hint?: string | undefined } = {}) {
	const requestId = c.get("requestId");

	logger.warn(message, {
		code: "AUTH_SCOPE_INSUFFICIENT",
		status: HTTP.Forbidden,
		method: c.req.method,
		path: c.req.path,
		...(requestId && { requestId }),
	});

	c.header("WWW-Authenticate", insufficientScopeChallenge(message));

	return c.json(
		{
			error: message,
			code: "AUTH_SCOPE_INSUFFICIENT" as const satisfies ErrorCode,
			...(requestId && { requestId }),
			...(details.hint && { hint: details.hint }),
		},
		HTTP.Forbidden,
	);
}

/**
 * The service's "this one is ours, and it may pass".
 *
 * A 503 that says so in the `code`, because the two neighbouring codes both
 * send the caller somewhere useless. `INTERNAL_ERROR` reads as a bug to report
 * and its reference section is about migrations; `AUTH_INVALID` reads as a
 * credential to mend. Neither is true of a JWKS fetch that timed out, and a
 * caller acting on either wastes a round of CI on a fault that had already
 * cleared.
 *
 * The `Retry-After` is the load-bearing half. The Go client retries any 5xx, so
 * this is already the one refusal it will try again — the header is what stops
 * it choosing the interval blind, and what a caller reading the response by
 * hand needs in order to know that waiting is the whole fix.
 *
 * Logged at warn, not error: a dependency being briefly unreachable is this
 * function working. Volume here follows the dependency, not the caller.
 *
 * @param c - Request context
 * @param message - What could not be reached; never names stored state
 * @param details - `hint` says what an operator would check, for the case the
 *   outage is this deployment's own configuration rather than the issuer's;
 *   `retryAfter` is whole seconds, omitted when nothing sensible can be guessed
 */
export function serviceDegraded(
	c: Context,
	message: string,
	details: { hint?: string | undefined; retryAfter?: number | undefined } = {},
) {
	const requestId = c.get("requestId");

	logger.warn(message, {
		code: "SERVICE_DEGRADED",
		status: HTTP.ServiceUnavailable,
		...(requestId && { requestId }),
	});

	// Floored at one: RFC 9110 delay-seconds is a non-negative integer, and a
	// `Retry-After: 0` reads as "immediately", which is the one thing a caller
	// should not do to a dependency that just failed.
	if (details.retryAfter !== undefined && details.retryAfter > 0) {
		c.header(HEADERS.RETRY_AFTER, String(Math.max(1, Math.ceil(details.retryAfter))));
	}

	return c.json(
		{
			error: message,
			code: "SERVICE_DEGRADED" as const satisfies ErrorCode,
			...(requestId && { requestId }),
			...(details.hint && { hint: details.hint }),
		},
		HTTP.ServiceUnavailable,
	);
}

/**
 * The service's "this one is ours, and it will not pass".
 *
 * Same "nothing on your side is wrong" as `serviceDegraded`, and the opposite
 * answer to the only question a caller asks of a 5xx: try again, or stop? This
 * one is a fault in the deployment's own configuration. It answers identically
 * until an operator edits a variable, so every retry is a slower failure.
 *
 * That distinction used to be carried by *omitting* `Retry-After`, which is not
 * a channel any client reads as "stop". The Go retrier tries any 5xx and the
 * bash example's `503)` branch retried unconditionally, so the permanent fault
 * was attempted four times and the missing header only cost it the interval.
 * A code puts the classification in a value both can branch on.
 *
 * 500, not 503, and the status is doing real work here rather than decoration.
 * RFC 9110 defines 503 as a condition "which will likely be alleviated after
 * some delay" — the exact claim this code exists to deny — and intermediaries
 * act on that reading: `retry_on: gateway-error`, `proxy_next_upstream
 * http_503`, outlier detection. A proxy in front would re-run the retry loop
 * one layer up, where the code cannot be read at all, and an ejecting one
 * would answer its own bare 502, losing the envelope that is this whole
 * feature. 500's "unexpected condition that prevented it from fulfilling the
 * request" is also the truer shape: one bad `ALLOWED_ISSUERS` entry breaks that
 * issuer's callers while everyone else keeps signing, so the *service* is not
 * unavailable.
 *
 * Between the two the status also says what it can on its own, for the reader
 * who has only a `curl -i`: `serviceDegraded`'s 503 carries a `Retry-After`,
 * this 500 carries none. Hence no parameter for one here — a caller given both
 * this code and an interval would have to guess which to believe.
 *
 * Logged at error, unlike `serviceDegraded`'s warn. A dependency being briefly
 * away is that function working; a URL this service will never fetch is a
 * deployment that cannot serve the issuer it claims to accept, and it stays
 * broken until somebody looks.
 *
 * @param c - Request context
 * @param message - What could not be reached; never names stored state
 * @param details - `hint` says which knob the operator should check
 */
export function serviceMisconfigured(c: Context, message: string, details: { hint?: string | undefined } = {}) {
	const requestId = c.get("requestId");

	logger.error(message, undefined, {
		code: "SERVICE_MISCONFIGURED",
		status: HTTP.InternalServerError,
		...(requestId && { requestId }),
	});

	return c.json(
		{
			error: message,
			code: "SERVICE_MISCONFIGURED" as const satisfies ErrorCode,
			...(requestId && { requestId }),
			...(details.hint && { hint: details.hint }),
		},
		HTTP.InternalServerError,
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
