import { z } from "@hono/zod-openapi";

/**
 * ISO8601 datetime validation
 */
export const TimestampSchema = z.iso.datetime({
  message: "Must be valid ISO8601 timestamp",
});

/**
 * Date range filter (used in audit queries)
 */
export const DateRangeSchema = z
  .object({
    startDate: TimestampSchema.optional(),
    endDate: TimestampSchema.optional(),
  })
  .refine(
    (data) => {
      if (!data.startDate || !data.endDate) return true;
      return new Date(data.startDate) <= new Date(data.endDate);
    },
    {
      message: "startDate must be before or equal to endDate",
    },
  );

/**
 * Audit query parameters schema
 */
export const AuditQuerySchema = z.object({
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(1000)
    .default(100)
    .openapi({ example: 100 }),
  offset: z.coerce.number().int().min(0).default(0).openapi({ example: 0 }),
  action: z.string().optional(),
  subject: z.string().optional(),
  startDate: z.iso.datetime().optional(),
  endDate: z.iso.datetime().optional(),
});
