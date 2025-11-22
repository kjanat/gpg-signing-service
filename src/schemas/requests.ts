import { z } from "@hono/zod-openapi";

/**
 * Request ID validation (UUID v4)
 */
export const RequestIdSchema = z
  .string()
  .uuid("Request ID must be a valid UUID");

/**
 * Common request headers schema
 */
export const RequestHeadersSchema = z.object({
  "X-Request-ID": RequestIdSchema.optional(),
});

/**
 * Public key query schema (optional keyId parameter)
 */
export const PublicKeyQuerySchema = z.object({
  keyId: z.string().optional().openapi({
    param: { name: "keyId", in: "query" },
    example: "A1B2C3D4E5F6G7H8",
  }),
});
