import { z } from "@hono/zod-openapi";
import { TimestampSchema } from "./audit";

/**
 * Health status levels
 */
export const HealthStatusSchema = z.enum(["healthy", "degraded"]);

/**
 * Health check response schema
 */
export const HealthResponseSchema = z
  .object({
    status: HealthStatusSchema,
    timestamp: TimestampSchema,
    version: z.string().regex(/^\d+\.\d+\.\d+$/, "Must be semantic version"),
    checks: z.object({
      keyStorage: z.boolean(),
      database: z.boolean(),
    }),
  })
  .openapi("HealthResponse");

/** Type inferred from HealthStatusSchema */
export type HealthStatus = z.infer<typeof HealthStatusSchema>;

/** Type inferred from HealthResponseSchema */
export type HealthResponse = z.infer<typeof HealthResponseSchema>;
