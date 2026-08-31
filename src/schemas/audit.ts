import { z } from "@hono/zod-openapi";
import { ErrorCodeSchema } from "#schemas/errors";
import { LIMITS } from "#utils/constants";

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
		limit: z.coerce.number().int().min(1).max(LIMITS.MAX_AUDIT_LOGS).default(100).openapi({ example: 100 }),
		offset: z.coerce.number().int().min(0).default(0).openapi({ example: 0 }),
		action: z.string().optional(),
		subject: z.string().optional(),
		startDate: TimestampSchema.optional(),
		endDate: TimestampSchema.optional(),
	})
	.openapi("AuditQuery");

/**
 * Audit action types
 *
 * `push_sign` is the GitHub App's: one row per `push` delivery that reached the
 * point of trying to sign, successful or not. Distinct from `sign` on purpose —
 * a `sign` row is a caller asking for a signature over bytes it supplied, and a
 * `push_sign` row is this service deciding by itself to rewrite somebody's
 * branch, which is a different thing to be able to filter for.
 *
 * `check_report` is the other half of that: one row per check run this service
 * published about a commit's signature. It is separate from `push_sign` because
 * the two are different acts with different blast radii — one rewrites history
 * and one states a verdict about it — and because a delivery can do the second
 * without doing the first, which is what happens whenever the tip is already
 * signed and there is nothing left to rewrite.
 *
 * `comment_dispatch` is the third, and the one that records this service
 * spending somebody else's budget: one row per `issue_comment` delivery that got
 * far enough to decide whether a Claude workflow run should start. Its own value
 * rather than a metadata field on another, because it is the only act here whose
 * effect is outside this service entirely — an Actions run with repository
 * secrets — and "what has this service started, and at whose request" is a
 * question that deserves to be a `WHERE action = ?` rather than a JSON scan.
 * Rows are written for refusals too, which is the point: a comment refused for
 * want of write access is exactly the row an operator wants to be able to find.
 */
export const AuditActionSchema = z
	.enum([
		"sign",
		"key_upload",
		"key_rotate",
		"token_create",
		"token_revoke",
		"subject_create",
		"subject_revoke",
		"push_sign",
		"check_report",
		"comment_dispatch",
	])
	.openapi("AuditAction");

/**
 * Audit log entry schema
 */
export const AuditLogEntrySchema = z.object({
	id: z.uuid(),
	timestamp: TimestampSchema,
	requestId: z.uuid(),
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
