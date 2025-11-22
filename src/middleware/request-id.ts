import type { MiddlewareHandler } from "hono";
import type { Env, Variables } from "~/types";

/**
 * Request ID middleware
 * - Extracts or generates request ID
 * - Sets it in context for use in handlers
 * - Adds X-Request-ID header to response
 *
 * Eliminates duplication across route handlers
 */
export const requestIdMiddleware: MiddlewareHandler<{
  Bindings: Env;
  Variables: Variables;
}> = async (c, next) => {
  const requestId = c.req.header("X-Request-ID") || crypto.randomUUID();
  c.set("requestId", requestId);

  await next();

  // Add request ID to response headers
  c.header("X-Request-ID", requestId);
};
