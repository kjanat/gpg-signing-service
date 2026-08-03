import type { MiddlewareHandler } from "hono";

import { RequestIdSchema } from "#schemas";
import { HEADERS } from "#types";

/**
 * Get request ID from header or generate a new one.
 *
 * The caller's value is honoured only when it is a UUID. It lands in
 * `audit_logs.request_id`, which `AuditLogEntrySchema` declares `z.uuid()` and
 * the generated Go client decodes into a non-pointer `openapi_types.UUID` — so
 * one free-text id makes an entire `/admin/audit` page undecodable, not just its
 * own row. On the OIDC path it is also the key an operator correlates a refusal
 * against, and taking it as given lets the recorded party choose it.
 *
 * @param headerValue - Raw `X-Request-ID` header, if any
 * @returns The caller's id when it is a valid UUID, else a fresh one
 */
export function getRequestId(headerValue?: string | null): string {
	return headerValue && RequestIdSchema.safeParse(headerValue).success ? headerValue : crypto.randomUUID();
}

/**
 * Request ID middleware - ensures every request has a unique ID
 */
export const requestId: MiddlewareHandler = async (c, next) => {
	const requestId = getRequestId(c.req.header(HEADERS.REQUEST_ID));

	// Store in context
	c.set("requestId", requestId);

	// Call next middleware
	await next();

	// Add to response headers
	c.header(HEADERS.REQUEST_ID, requestId);
};

// Export with old name for backwards compatibility
export const requestIdMiddleware = requestId;
