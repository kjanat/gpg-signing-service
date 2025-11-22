import { z } from "@hono/zod-openapi";

/**
 * Request ID validation (UUID v4)
 */
export const RequestIdSchema = z.uuid("Request ID must be a valid UUID");

/**
 * Common request headers schema
 */
export const RequestHeadersSchema = z.object({
  "X-Request-ID": RequestIdSchema.optional(),
});
