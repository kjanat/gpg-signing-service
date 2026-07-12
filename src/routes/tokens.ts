import { createRoute, z } from "@hono/zod-openapi";

import { createOpenAPIApp } from "#lib/openapi";
import {
	ErrorResponseSchema,
	TokenCreatedResponseSchema,
	TokenCreateSchema,
	TokenListResponseSchema,
	TokenRevokeResponseSchema,
} from "#schemas";
import type { ErrorCode } from "#schemas/errors";
import { HEADERS, HTTP } from "#types";
import { logAuditEvent } from "#utils/audit";
import { scheduleBackgroundTask } from "#utils/execution";
import { logger } from "#utils/logger";
import { generateToken, insertServiceToken, listServiceTokens, revokeServiceToken } from "#utils/service-tokens";

const app = createOpenAPIApp();

const createTokenRoute = createRoute({
	method: "post",
	path: "/tokens",
	summary: "Mint a service token",
	description:
		"Create a long-lived bearer token for CI systems without an OIDC issuer. " +
		"The plaintext token is returned exactly once.",
	security: [{ bearerAuth: [] }],
	request: {
		body: {
			content: { "application/json": { schema: TokenCreateSchema } },
			required: true,
		},
	},
	responses: {
		[HTTP.Created]: {
			content: { "application/json": { schema: TokenCreatedResponseSchema } },
			description: "Token minted",
		},
		[HTTP.BadRequest]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Invalid request",
		},
		[HTTP.Conflict]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Token name already exists",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(createTokenRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();
	const body = c.req.valid("json");

	const token = generateToken();
	const keyIds = body.keyIds ?? [];
	const expiresAt = body.expiresInDays ? new Date(Date.now() + body.expiresInDays * 86_400_000).toISOString() : null;

	try {
		const id = await insertServiceToken(c.env.AUDIT_DB, {
			name: body.name,
			token,
			keyIds,
			expiresAt,
		});

		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "token_create",
				issuer: "admin",
				subject: body.name,
				keyId: keyIds.join(",") || "*",
				success: true,
				metadata: JSON.stringify({ expiresAt }),
			}),
		);

		return c.json(
			{
				id,
				name: body.name,
				token,
				keyIds: keyIds.length > 0 ? keyIds : null,
				expiresAt,
			},
			HTTP.Created,
		);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Token creation failed";
		logger.error("Token creation failed", { requestId, error: message });

		if (message.includes("UNIQUE constraint failed")) {
			return c.json(
				{
					error: `Token name already exists: ${body.name}`,
					code: "INVALID_REQUEST" as const satisfies ErrorCode,
					requestId,
				},
				HTTP.Conflict,
			);
		}

		return c.json(
			{
				error: message,
				code: "INTERNAL_ERROR" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.InternalServerError,
		);
	}
});

const listTokensRoute = createRoute({
	method: "get",
	path: "/tokens",
	summary: "List service tokens",
	description: "List all service tokens; secret material never leaves the DB",
	security: [{ bearerAuth: [] }],
	responses: {
		[HTTP.OK]: {
			content: { "application/json": { schema: TokenListResponseSchema } },
			description: "Tokens",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(listTokensRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();
	try {
		const tokens = await listServiceTokens(c.env.AUDIT_DB);
		return c.json({ tokens }, HTTP.OK);
	} catch (error) {
		const message = error instanceof Error ? error.message : "List failed";
		logger.error("Token list failed", { requestId, error: message });
		return c.json(
			{
				error: message,
				code: "INTERNAL_ERROR" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.InternalServerError,
		);
	}
});

const revokeTokenRoute = createRoute({
	method: "delete",
	path: "/tokens/{id}",
	summary: "Revoke a service token",
	description: "Revoke a token by id; revocation is immediate and permanent",
	security: [{ bearerAuth: [] }],
	request: {
		params: z.object({ id: z.uuid() }),
	},
	responses: {
		[HTTP.OK]: {
			content: { "application/json": { schema: TokenRevokeResponseSchema } },
			description: "Token revoked",
		},
		[HTTP.NotFound]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Token not found or already revoked",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(revokeTokenRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();
	const { id } = c.req.valid("param");

	try {
		const revoked = await revokeServiceToken(c.env.AUDIT_DB, id);
		if (!revoked) {
			return c.json(
				{
					error: "Token not found or already revoked",
					code: "INVALID_REQUEST" as const satisfies ErrorCode,
					requestId,
				},
				HTTP.NotFound,
			);
		}

		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "token_revoke",
				issuer: "admin",
				subject: id,
				keyId: "*",
				success: true,
			}),
		);

		return c.json({ success: true, id }, HTTP.OK);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Revoke failed";
		logger.error("Token revoke failed", { requestId, error: message });
		return c.json(
			{
				error: message,
				code: "INTERNAL_ERROR" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.InternalServerError,
		);
	}
});

export default app;
