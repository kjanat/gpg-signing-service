import type { MiddlewareHandler } from "hono";
import { HEADERS } from "~/types";

/**
 * Get request ID from header or generate a new one
 */
export function getRequestId(headerValue?: string | null): string {
  return headerValue || crypto.randomUUID();
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
