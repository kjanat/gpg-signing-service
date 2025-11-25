import { z } from "@hono/zod-openapi";
import { LIMITS } from "~/utils/constants";
import { ErrorCodeSchema } from "./errors";

/**
 * ISO8601 datetime validation with timezone offset
 */
export const TimestampSchema = z.iso.datetime({
  offset: true,
  message: "Must be valid ISO8601 timestamp with timezone",
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
    { message: "startDate must be before or equal to endDate" },
  );

/**
 * Audit query parameters schema
 */
export const AuditQuerySchema = z
  .object({
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .max(LIMITS.MAX_AUDIT_LOGS)
      .default(100)
      .openapi({ example: 100 }),
    offset: z.coerce.number().int().min(0).default(0).openapi({ example: 0 }),
    action: z.string().optional(),
    subject: z.string().optional(),
    startDate: TimestampSchema.optional(),
    endDate: TimestampSchema.optional(),
  })
  .openapi("AuditQuery");

/**
 * Audit action types
 */
export const AuditActionSchema = z
  .enum(["sign", "key_upload", "key_rotate"])
  .openapi("AuditAction");

/**
 * Audit log entry schema
 */
export const AuditLogEntrySchema = z.object({
  id: z.string().uuid(),
  timestamp: TimestampSchema,
  requestId: z.string().uuid(),
  action: AuditActionSchema,
  issuer: z.string().min(1),
  subject: z.string().min(1),
  keyId: z.string().min(1),
  success: z.boolean(),
  errorCode: ErrorCodeSchema.optional(),
  metadata: z.string().optional(),
});

/**
 * Audit logs response schema
 */
export const AuditLogsResponseSchema = z
  .object({
    logs: z.array(AuditLogEntrySchema),
    count: z.number().int().min(0),
  })
  .openapi("AuditLogsResponse");

/** Type inferred from AuditActionSchema */
export type AuditAction = z.infer<typeof AuditActionSchema>;

/** Type inferred from AuditLogEntrySchema */
export type AuditLogEntry = z.infer<typeof AuditLogEntrySchema>;

/** Type inferred from AuditLogsResponseSchema */
export type AuditLogsResponse = z.infer<typeof AuditLogsResponseSchema>;
