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
	// A prefix must identify somebody. Because a prefix ending at a delimiter is
	// deliberately owner-wide, a bare scheme segment is *host*-wide: `repo:` —
	// and `repo` too, since the boundary check then lands on the `:` — matches
	// every repository on GitHub Actions, reinstating exactly what this table
	// exists to prevent. One truncated paste of a rollout command would do it,
	// and unlike every other degenerate input here it fails open.
	//
	// Expressed as a single regex rather than a `.refine()` so it survives into
	// client/openapi.json: refinements have no JSON Schema representation, so a
	// generated client would otherwise believe `repo:` is a legal value. The
	// leading `\S*` subsumes the no-whitespace rule, and requiring a
	// non-delimiter after *some* delimiter is equivalent to requiring one after
	// the *first*, since the first precedes every other.
	.regex(
		/^\S*[:@/]\S*[^\s:@/]\S*$/,
		"Subject prefix must have no whitespace and must name an identity after its scheme, e.g. repo:owner — not repo: or repo",
	)
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
		 *
		 * An empty array is refused rather than accepted: it stores as the empty
		 * key_ids string, which means *every* key, so a caller that meant to
		 * restrict would silently widen. Omit the field to mean every key.
		 */
		keyIds: z.array(KeyIdSchema).min(1, "keyIds must list at least one key; omit it to allow every key").optional(),
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
		/**
		 * Whether this row would authorize a token right now — neither revoked nor
		 * expired. Derived server-side because the alternative is every client
		 * re-implementing the same date comparison, and an expired row looks
		 * identical to a live one until you do it.
		 */
		active: z.boolean(),
	})
	.openapi("SubjectSummary");

export const SubjectCreatedResponseSchema = SubjectSummarySchema.openapi("SubjectCreatedResponse");

export const SubjectListResponseSchema = z
	.object({ subjects: z.array(SubjectSummarySchema) })
	.openapi("SubjectListResponse");

export const SubjectRevokeResponseSchema = z
	.object({
		success: z.boolean(),
		id: z.string(),
		/** The revoked row's name — the key `sign` audit events are recorded under. */
		name: SubjectNameSchema,
	})
	.openapi("SubjectRevokeResponse");
