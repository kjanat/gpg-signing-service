import { z } from "@hono/zod-openapi";

import { KeyIdSchema } from "#schemas/keys";

/**
 * Service token name: human-readable CI identity, used as the audit subject.
 */
export const TokenNameSchema = z
	.string()
	.min(1)
	.max(64)
	.regex(/^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/, "Name must be alphanumeric with ._/- separators")
	.openapi("TokenName");

/** Request body for minting a service token. */
export const TokenCreateSchema = z
	.object({
		name: TokenNameSchema,
		/**
		 * Key ids this token may sign with; omit for every key. Normalized to
		 * uppercase. An empty array is refused: it stores as the empty key_ids
		 * string, which means every key, so it would widen rather than restrict.
		 */
		keyIds: z.array(KeyIdSchema).min(1, "keyIds must list at least one key; omit it to allow every key").optional(),
		/** Days until expiry; omit for a non-expiring token. */
		expiresInDays: z.number().int().min(1).max(3650).optional(),
	})
	.openapi("TokenCreate");

/** Mint response: the only time the plaintext token is ever returned. */
export const TokenCreatedResponseSchema = z
	.object({
		id: z.string(),
		name: TokenNameSchema,
		token: z.string().describe("Plaintext token; shown exactly once"),
		keyIds: z.array(z.string()).nullable(),
		expiresAt: z.string().nullable(),
	})
	.openapi("TokenCreatedResponse");

/** One token in the list view (no secret material). */
export const TokenSummarySchema = z
	.object({
		id: z.string(),
		name: TokenNameSchema,
		keyIds: z.array(z.string()).nullable(),
		createdAt: z.string(),
		expiresAt: z.string().nullable(),
		revokedAt: z.string().nullable(),
		lastUsedAt: z.string().nullable(),
	})
	.openapi("TokenSummary");

export const TokenListResponseSchema = z.object({ tokens: z.array(TokenSummarySchema) }).openapi("TokenListResponse");

export const TokenRevokeResponseSchema = z
	.object({ success: z.boolean(), id: z.string() })
	.openapi("TokenRevokeResponse");
