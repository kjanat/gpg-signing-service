import { z } from "@hono/zod-openapi";

/**
 * All valid error codes used in the codebase
 */
export const ErrorCodeSchema = z.enum([
  "AUTH_MISSING",
  "AUTH_INVALID",
  "KEY_NOT_FOUND",
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
]);

/**
 * Standard error response schema
 * Used across all endpoints for consistent error handling
 */
export const ErrorResponseSchema = z.object({
  error: z.string().min(1, "Error message cannot be empty"),
  code: ErrorCodeSchema,
  requestId: z.string().uuid().optional(),
});

/**
 * Rate limit error response schema
 * Includes retryAfter timestamp for 429 responses
 */
export const RateLimitErrorSchema = z.object({
  error: z.string().min(1, "Error message cannot be empty"),
  code: ErrorCodeSchema,
  retryAfter: z.number().int().positive(),
});

/** Type inferred from ErrorCodeSchema */
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

/** Type inferred from ErrorResponseSchema */
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
