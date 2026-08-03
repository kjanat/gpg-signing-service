import { createRoute, z } from "@hono/zod-openapi";

import { createOpenAPIApp } from "#lib/openapi";
import {
	ErrorResponseSchema,
	SubjectCreatedResponseSchema,
	SubjectCreateSchema,
	SubjectListResponseSchema,
	SubjectRevokeResponseSchema,
} from "#schemas";
import type { ErrorCode } from "#schemas/errors";
import { HEADERS, HTTP } from "#types";
import { logAuditEvent } from "#utils/audit";
import { scheduleBackgroundTask } from "#utils/execution";
import { logger } from "#utils/logger";
import { insertOIDCSubject, listOIDCSubjects, revokeOIDCSubject } from "#utils/oidc-subjects";

const app = createOpenAPIApp();

const createSubjectRoute = createRoute({
	method: "post",
	path: "/subjects",
	summary: "Trust an OIDC subject",
	description:
		"Authorize a CI identity to sign. A verified OIDC token only proves that some workflow on an " +
		"accepted issuer asked for our audience, and those issuers are shared by every repository on " +
		"GitHub Actions and every project on GitLab — so a subject must be trusted explicitly.",
	security: [{ bearerAuth: [] }],
	request: {
		body: {
			content: { "application/json": { schema: SubjectCreateSchema } },
			required: true,
		},
	},
	responses: {
		[HTTP.Created]: {
			content: { "application/json": { schema: SubjectCreatedResponseSchema } },
			description: "Subject trusted",
		},
		[HTTP.BadRequest]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Invalid request",
		},
		[HTTP.Conflict]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Subject name, or issuer and prefix pair, already exists",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(createSubjectRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();
	const body = c.req.valid("json");

	// A row whose issuer is not accepted can never match a token, so it would
	// list as trusted and be silently dead. Fail at the point of the typo.
	const allowedIssuers = c.env.ALLOWED_ISSUERS.split(",").map((issuer) => issuer.trim());
	if (!allowedIssuers.includes(body.issuer)) {
		return c.json(
			{
				error: `Issuer is not in ALLOWED_ISSUERS: ${body.issuer}`,
				code: "INVALID_REQUEST" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.BadRequest,
		);
	}

	const keyIds = body.keyIds ?? [];
	const expiresAt = body.expiresInDays ? new Date(Date.now() + body.expiresInDays * 86_400_000).toISOString() : null;
	const createdAt = new Date().toISOString();

	try {
		const id = await insertOIDCSubject(c.env.AUDIT_DB, {
			name: body.name,
			issuer: body.issuer,
			subjectPrefix: body.subjectPrefix,
			keyIds,
			expiresAt,
			createdAt,
		});

		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "subject_create",
				issuer: "admin",
				subject: body.name,
				keyId: keyIds.join(",") || "*",
				success: true,
				metadata: JSON.stringify({
					issuer: body.issuer,
					subjectPrefix: body.subjectPrefix,
					expiresAt,
				}),
			}),
		);

		return c.json(
			{
				id,
				name: body.name,
				issuer: body.issuer,
				subjectPrefix: body.subjectPrefix,
				keyIds: keyIds.length > 0 ? keyIds : null,
				createdAt,
				expiresAt,
				revokedAt: null,
				lastUsedAt: null,
			},
			HTTP.Created,
		);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Subject creation failed";
		logger.error("Subject creation failed", { requestId, error: message });

		if (message.includes("UNIQUE constraint failed")) {
			// Two different collisions land here; blaming the name for a prefix
			// clash sends the operator to change the one field that was fine.
			const conflict = message.includes("subject_prefix")
				? `Issuer and subject prefix are already trusted: ${body.issuer} ${body.subjectPrefix}`
				: `Subject name already exists: ${body.name}`;
			return c.json(
				{
					error: conflict,
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

const listSubjectsRoute = createRoute({
	method: "get",
	path: "/subjects",
	summary: "List trusted OIDC subjects",
	description: "List every trusted subject, including revoked and expired ones",
	security: [{ bearerAuth: [] }],
	responses: {
		[HTTP.OK]: {
			content: { "application/json": { schema: SubjectListResponseSchema } },
			description: "Subjects",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(listSubjectsRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();
	try {
		const subjects = await listOIDCSubjects(c.env.AUDIT_DB);
		return c.json({ subjects }, HTTP.OK);
	} catch (error) {
		const message = error instanceof Error ? error.message : "List failed";
		logger.error("Subject list failed", { requestId, error: message });
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

const revokeSubjectRoute = createRoute({
	method: "delete",
	path: "/subjects/{id}",
	summary: "Revoke a trusted OIDC subject",
	description: "Revoke a subject by id; it stops being able to sign immediately",
	security: [{ bearerAuth: [] }],
	request: {
		params: z.object({ id: z.uuid() }),
	},
	responses: {
		[HTTP.OK]: {
			content: { "application/json": { schema: SubjectRevokeResponseSchema } },
			description: "Subject revoked",
		},
		[HTTP.NotFound]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Subject not found or already revoked",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(revokeSubjectRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();
	const { id } = c.req.valid("param");

	try {
		const revoked = await revokeOIDCSubject(c.env.AUDIT_DB, id);
		if (!revoked) {
			return c.json(
				{
					error: "Subject not found or already revoked",
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
				action: "subject_revoke",
				issuer: "admin",
				subject: id,
				keyId: "*",
				success: true,
			}),
		);

		return c.json({ success: true, id }, HTTP.OK);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Revoke failed";
		logger.error("Subject revoke failed", { requestId, error: message });
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
