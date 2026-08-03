import { z } from "@hono/zod-openapi";

import { KeyIdSchema } from "#schemas/keys";

/** Trusted subject name: human-readable label for the CI identity. */
export const SubjectNameSchema = z
	.string()
	.min(1)
	.max(64)
	.regex(/^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/, "Name must be alphanumeric with ._/- separators")
	.openapi("SubjectName");

/**
 * A `sub` prefix. Matched with a delimiter boundary, so `repo:owner/name`
 * does not admit `repo:owner/name-evil`, while `repo:owner/` is owner-wide.
 */
export const SubjectPrefixSchema = z
	.string()
	.min(1)
	.max(255)
	.regex(/^\S+$/, "Subject prefix must not contain whitespace")
	.openapi("SubjectPrefix");

/** Request body for trusting an OIDC subject. */
export const SubjectCreateSchema = z
	.object({
		name: SubjectNameSchema,
		/** Issuer this subject must present, pinned so issuers cannot collide. */
		issuer: z.string().url(),
		subjectPrefix: SubjectPrefixSchema,
		/**
		 * Key ids this subject may sign with; omit for every key. Uses the same
		 * schema as key upload, which normalizes to uppercase — a lowercase id
		 * would otherwise store as written, list as allowed, and never match the
		 * case-sensitive check in the sign route.
		 */
		keyIds: z.array(KeyIdSchema).optional(),
		/** Days until expiry; omit for a non-expiring trust. */
		expiresInDays: z.number().int().min(1).max(3650).optional(),
	})
	.openapi("SubjectCreate");

/** One trusted subject in the list view. */
export const SubjectSummarySchema = z
	.object({
		id: z.string(),
		name: SubjectNameSchema,
		issuer: z.string(),
		subjectPrefix: SubjectPrefixSchema,
		keyIds: z.array(z.string()).nullable(),
		createdAt: z.string(),
		expiresAt: z.string().nullable(),
		revokedAt: z.string().nullable(),
		lastUsedAt: z.string().nullable(),
	})
	.openapi("SubjectSummary");

export const SubjectCreatedResponseSchema = SubjectSummarySchema.openapi("SubjectCreatedResponse");

export const SubjectListResponseSchema = z
	.object({ subjects: z.array(SubjectSummarySchema) })
	.openapi("SubjectListResponse");

export const SubjectRevokeResponseSchema = z
	.object({ success: z.boolean(), id: z.string() })
	.openapi("SubjectRevokeResponse");
