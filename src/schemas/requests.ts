import { z } from "@hono/zod-openapi";

/**
 * Request ID validation (UUID v4)
 */
export const RequestIdSchema = z.uuid("Request ID must be a valid UUID");

/**
 * Common request headers schema
 */
export const RequestHeadersSchema = z
  .object({
    "X-Request-ID": RequestIdSchema.optional(),
  })
  .openapi("RequestHeaders");

/**
 * Public key query schema (optional keyId parameter)
 */
export const PublicKeyQuerySchema = z
  .object({
    keyId: z
      .string()
      .optional()
      .openapi({
        param: { name: "keyId", in: "query" },
        example: "A1B2C3D4E5F6G7H8",
      }),
  })
  .openapi("PublicKeyQuery");

/**
 * Sign request body schema (raw commit data)
 */
export const SignRequestSchema = z.string().min(1).openapi("SignRequest", {
  example: "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147\nparent ...",
});

/**
 * Sign response schema (PGP signature)
 */
export const SignResponseSchema = z.string().openapi("SignResponse", {
  example: "-----BEGIN PGP SIGNATURE-----\n...",
});
