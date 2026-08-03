import { createRoute, z } from "@hono/zod-openapi";
import { createOpenAPIApp } from "#lib/openapi";
import { getRequestId } from "#middleware/request-id";
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

/** How many surviving-trust names a single audit row will carry. */
const AUDIT_NAME_LIMIT = 20;

/**
 * Summarize surviving trusts for `audit_logs.metadata`, which has no length cap.
 *
 * @param rows - Rows still trusting the revoked subject
 * @returns Their names, truncated with a marker when there are too many
 */
function auditNames(rows: { name: string }[]): string[] {
	const names = rows.slice(0, AUDIT_NAME_LIMIT).map((row) => row.name);
	return rows.length > AUDIT_NAME_LIMIT ? [...names, `+${rows.length - AUDIT_NAME_LIMIT} more`] : names;
}

/**
 * Describe which row is holding an (issuer, prefix) slot.
 *
 * Best-effort: a failure here must not turn a 409 into a 500, so it degrades
 * to the plain message rather than propagating.
 *
 * @param db - Audit/policy database
 * @param issuer - Issuer from the rejected request
 * @param subjectPrefix - Prefix from the rejected request
 * @returns A message naming the colliding row, and how to clear it if expired
 */
async function describePrefixConflict(db: D1Database, issuer: string, subjectPrefix: string): Promise<string> {
	const base = `Issuer and subject prefix are already claimed: ${issuer} ${subjectPrefix}`;
	try {
		const row = await db
			.prepare(
				`SELECT id, expires_at FROM oidc_subjects
         WHERE issuer = ? AND subject_prefix = ? AND revoked_at IS NULL`,
			)
			.bind(issuer, subjectPrefix)
			.first<{ id: string; expires_at: string | null }>();

		if (!row) {
			return base;
		}
		if (row.expires_at && Date.parse(row.expires_at) < Date.now()) {
			return (
				`${base} — by row ${row.id}, which expired at ${row.expires_at} and so trusts nobody. ` +
				`Revoke it (DELETE /admin/subjects/${row.id}) to renew this prefix; do not widen the prefix instead.`
			);
		}
		return `${base} — by row ${row.id}. Revoke it to replace the trust.`;
	} catch {
		return base;
	}
}

/**
 * Describe which row is holding a name.
 *
 * Names are unique across *all* rows, revoked ones included, so the most
 * confusing collision is with a trust the operator revoked minutes ago —
 * "already exists" reads as "still trusted" and invites them to widen something
 * else instead of picking a new label. Best-effort, like the prefix variant.
 *
 * @param db - Audit/policy database
 * @param name - Name from the rejected request
 * @returns A message naming the blocking row and whether it is still live
 */
async function describeNameConflict(db: D1Database, name: string): Promise<string> {
	const base = `Subject name already exists: ${name}`;
	try {
		const row = await db
			.prepare("SELECT id, revoked_at FROM oidc_subjects WHERE name = ?")
			.bind(name)
			.first<{ id: string; revoked_at: string | null }>();

		if (!row) {
			return base;
		}
		if (row.revoked_at) {
			return (
				`${base} — held by row ${row.id}, which was revoked at ${row.revoked_at} and trusts nobody. ` +
				`Names are permanent labels for one generation of a trust and are never freed; choose a new name.`
			);
		}
		return `${base} — held by row ${row.id}, which is still live. Revoke it first if you meant to replace it.`;
	} catch {
		return base;
	}
}

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
	const requestId = getRequestId(c.req.header(HEADERS.REQUEST_ID));
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
				// Freshly inserted, so neither revoked nor (yet) expired.
				active: true,
			},
			HTTP.Created,
		);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Subject creation failed";
		logger.error("Subject creation failed", { requestId, error: message });

		if (message.includes("UNIQUE constraint failed")) {
			// Two different collisions land here; blaming the name for a prefix
			// clash sends the operator to change the one field that was fine.
			//
			// A prefix clash is not necessarily a live trust. Uniqueness is scoped
			// to unrevoked rows, but an *expired* row is unrevoked — it authorizes
			// nobody while still holding the slot. Saying "already trusted" there
			// is false, and the nearest thing the operator can then type is a
			// broader prefix, which is the one direction that opens access. Name
			// the offending row instead.
			const conflict = message.includes("subject_prefix")
				? await describePrefixConflict(c.env.AUDIT_DB, body.issuer, body.subjectPrefix)
				: await describeNameConflict(c.env.AUDIT_DB, body.name);
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
	const requestId = getRequestId(c.req.header(HEADERS.REQUEST_ID));
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
	description:
		"Revoke a subject by id. This does not necessarily stop the subject signing: resolution " +
		"takes the longest live prefix, so a broader row that also covers it takes over — with " +
		"that row's key grant, which may be wider. Rows nested under the revoked prefix are not " +
		"touched at all. The response lists both in `stillCoveredBy` and `stillTrustedWithin`; " +
		"only when both are empty was the revoke final.",
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
	const requestId = getRequestId(c.req.header(HEADERS.REQUEST_ID));
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
				// `sign` events are keyed by the row's name, this one by its id.
				// Carry both so the trail joins to itself without a table lookup.
				// The survivors go in too: "revoked, still signing" is the state an
				// incident review needs, and it is only knowable at this instant —
				// a row added later would make the trail read differently.
				metadata: JSON.stringify({
					subjectPolicy: revoked.name,
					// Capped: `metadata` has no length limit, and nothing stops an
					// operator scripting one row per repository under a shared parent.
					// The response carries the full lists; this is the durable summary.
					stillCoveredBy: auditNames(revoked.stillCoveredBy),
					stillTrustedWithin: auditNames(revoked.stillTrustedWithin),
				}),
			}),
		);

		if (revoked.stillCoveredBy.length > 0 || revoked.stillTrustedWithin.length > 0) {
			logger.warn("Revoked subject is still trusted through another row", {
				requestId,
				subjectId: id,
				subjectPolicy: revoked.name,
				coveredBy: revoked.stillCoveredBy.map((row) => row.name),
				trustedWithin: revoked.stillTrustedWithin.map((row) => row.name),
			});
		}

		return c.json(
			{
				success: true,
				id,
				name: revoked.name,
				stillCoveredBy: revoked.stillCoveredBy,
				stillTrustedWithin: revoked.stillTrustedWithin,
			},
			HTTP.OK,
		);
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
