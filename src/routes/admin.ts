import { createRoute, z } from "@hono/zod-openapi";

import { createOpenAPIApp } from "#lib/openapi";
import {
	AuditLogsResponseSchema,
	AuditQuerySchema,
	ErrorResponseSchema,
	KeyDeletionResponseSchema,
	KeyListResponseSchema,
	KeyResponseSchema,
	KeyUploadSchema,
	X509KeyResponseSchema,
	X509KeyUploadSchema,
} from "#schemas";
import type { ErrorCode } from "#schemas/errors";
import type { StoredKey } from "#schemas/keys";
import { AnyStoredKeySchema, isX509Key, type StoredX509Key } from "#schemas/keys";
import { createArmoredPrivateKey, createKeyId, HEADERS, HTTP, MediaType } from "#types";
import { getAuditLogs, logAuditEvent } from "#utils/audit";
import { fetchKeyStorage } from "#utils/durable-objects";
import { scheduleBackgroundTask } from "#utils/execution";
import { logger } from "#utils/logger";
import { extractPublicKey, invalidateKeyCache, parseAndValidateKey } from "#utils/signing";
import { parseAndValidateX509Key } from "#utils/x509";

const app = createOpenAPIApp();

// Routes

const uploadKeyRoute = createRoute({
	method: "post",
	path: "/keys",
	summary: "Upload a new signing key",
	description: "Upload a GPG private key for signing",
	security: [{ bearerAuth: [] }],
	request: {
		body: {
			content: { "application/json": { schema: KeyUploadSchema } },
			required: true,
		},
	},
	responses: {
		[HTTP.Created]: {
			content: { "application/json": { schema: KeyResponseSchema } },
			description: "Key uploaded successfully",
		},
		[HTTP.BadRequest]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Invalid request",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(uploadKeyRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();

	try {
		const body = c.req.valid("json");

		// Validate and parse the key
		const keyInfo = await parseAndValidateKey(body.armoredPrivateKey, c.env.KEY_PASSPHRASE);

		const storedKey: StoredKey = {
			armoredPrivateKey: createArmoredPrivateKey(body.armoredPrivateKey),
			keyId: createKeyId(body.keyId),
			fingerprint: keyInfo.fingerprint,
			createdAt: new Date().toISOString(),
			algorithm: keyInfo.algorithm,
		};

		// Store in Durable Object
		const storeResponse = await fetchKeyStorage(c.env, "/store-key", {
			method: "POST",
			body: JSON.stringify(storedKey),
			headers: { "Content-Type": MediaType.ApplicationJson },
		});

		if (!storeResponse.ok) {
			const error = (await storeResponse.json()) as { error: string };
			throw new Error(error.error || "Failed to store key");
		}

		// Invalidate any cached decrypted key (in case of key rotation/overwrite)
		invalidateKeyCache(body.keyId);

		// Log key upload (non-blocking in production, blocking in tests)
		logger.debug("Scheduling background task for upload success audit", {
			requestId,
		});
		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "key_upload",
				issuer: "admin",
				subject: "admin",
				keyId: body.keyId,
				success: true,
				metadata: JSON.stringify({
					fingerprint: keyInfo.fingerprint,
					algorithm: keyInfo.algorithm,
					userId: keyInfo.userId,
				}),
			}),
		);

		return c.json(
			{
				success: true,
				keyId: body.keyId,
				fingerprint: keyInfo.fingerprint,
				algorithm: keyInfo.algorithm,
				userId: keyInfo.userId,
			},
			HTTP.Created,
		);
	} catch (error) {
		logger.debug("Upload key route error handler", {
			error: String(error),
			requestId,
		});
		const message = error instanceof Error ? error.message : "Key upload failed";

		// Audit failed key upload attempt (non-blocking in production)
		logger.debug("Scheduling background task for upload failure audit", {
			requestId,
		});
		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "key_upload",
				issuer: "admin",
				subject: "admin",
				keyId: "unknown",
				success: false,
				errorCode: "KEY_UPLOAD_ERROR",
				metadata: JSON.stringify({ error: message }),
			}),
		);

		return c.json(
			{
				error: message,
				code: "KEY_UPLOAD_ERROR" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.InternalServerError,
		);
	}
});

const uploadX509KeyRoute = createRoute({
	method: "post",
	path: "/keys/x509",
	summary: "Upload a new X.509 signing key",
	description:
		"Upload a PKCS#8 private key and X.509 certificate for detached PKCS#7 commit signing (git gpg.format=x509)",
	security: [{ bearerAuth: [] }],
	request: {
		body: {
			content: { "application/json": { schema: X509KeyUploadSchema } },
			required: true,
		},
	},
	responses: {
		[HTTP.Created]: {
			content: { "application/json": { schema: X509KeyResponseSchema } },
			description: "Key uploaded successfully",
		},
		[HTTP.BadRequest]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Invalid request",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(uploadX509KeyRoute, async (c) => {
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();

	try {
		const body = c.req.valid("json");

		// Validate key material and key/certificate match
		const keyInfo = await parseAndValidateX509Key(body.privateKeyPem, body.certificatePem, c.env.KEY_PASSPHRASE);

		const storedKey: StoredX509Key = {
			type: "x509",
			keyId: body.keyId,
			privateKeyPem: body.privateKeyPem,
			certificatePem: body.certificatePem,
			...(body.chainPem !== undefined && { chainPem: body.chainPem }),
			fingerprint: keyInfo.fingerprint,
			createdAt: new Date().toISOString(),
			algorithm: keyInfo.algorithm,
		};

		const storeResponse = await fetchKeyStorage(c.env, "/store-key", {
			method: "POST",
			body: JSON.stringify(storedKey),
			headers: { "Content-Type": MediaType.ApplicationJson },
		});

		if (!storeResponse.ok) {
			const error = (await storeResponse.json()) as { error: string };
			throw new Error(error.error || "Failed to store key");
		}

		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "key_upload",
				issuer: "admin",
				subject: "admin",
				keyId: body.keyId,
				success: true,
				metadata: JSON.stringify({
					format: "x509",
					fingerprint: keyInfo.fingerprint,
					algorithm: keyInfo.algorithm,
					subject: keyInfo.subject,
				}),
			}),
		);

		return c.json(
			{
				success: true,
				keyId: body.keyId,
				fingerprint: keyInfo.fingerprint,
				algorithm: keyInfo.algorithm,
				subject: keyInfo.subject,
			},
			HTTP.Created,
		);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Key upload failed";

		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "key_upload",
				issuer: "admin",
				subject: "admin",
				keyId: "unknown",
				success: false,
				errorCode: "KEY_UPLOAD_ERROR",
				metadata: JSON.stringify({ format: "x509", error: message }),
			}),
		);

		return c.json(
			{
				error: message,
				code: "KEY_UPLOAD_ERROR" as const satisfies ErrorCode,
				requestId,
			},
			HTTP.InternalServerError,
		);
	}
});

const listKeysRoute = createRoute({
	method: "get",
	path: "/keys",
	summary: "List all keys",
	description: "List metadata for all stored keys",
	security: [{ bearerAuth: [] }],
	responses: {
		[HTTP.OK]: {
			content: { "application/json": { schema: KeyListResponseSchema } },
			description: "List of keys",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(listKeysRoute, async (c) => {
	try {
		const response = await fetchKeyStorage(c.env, "/list-keys");
		if (!response.ok) {
			throw new Error(`Key storage returned ${response.status}`);
		}

		const result = (await response.json()) as {
			keys: {
				keyId: string;
				fingerprint: string;
				createdAt: string;
				algorithm: string;
			}[];
		};
		return c.json(result, HTTP.OK);
	} catch (error) {
		logger.error("Failed to list keys:", error);
		return c.json(
			{
				error: "Failed to retrieve keys",
				code: "KEY_LIST_ERROR" as const satisfies ErrorCode,
			},
			HTTP.InternalServerError,
		);
	}
});

const getPublicKeyRoute = createRoute({
	method: "get",
	path: "/keys/{keyId}/public",
	summary: "Get public key",
	description: "Get the public key for a specific key ID",
	security: [{ bearerAuth: [] }],
	request: {
		params: z.object({
			keyId: z.string().openapi({
				param: { name: "keyId", in: "path" },
				example: "A1B2C3D4E5F6G7H8",
			}),
		}),
	},
	responses: {
		[HTTP.OK]: {
			content: {
				"application/pgp-keys": { schema: z.string() },
				"application/pem-certificate-chain": { schema: z.string() },
			},
			description: "Public key (PGP armored) or X.509 certificate (PEM)",
		},
		[HTTP.NotFound]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Key not found",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(getPublicKeyRoute, async (c) => {
	const { keyId } = c.req.valid("param");

	try {
		const keyResponse = await fetchKeyStorage(c.env, `/get-key?keyId=${encodeURIComponent(keyId)}`);

		if (!keyResponse.ok) {
			return c.json(
				{
					error: "Key not found",
					code: "KEY_NOT_FOUND" as const satisfies ErrorCode,
				},
				HTTP.NotFound,
			);
		}

		const storedKey = AnyStoredKeySchema.parse(await keyResponse.json());

		if (isX509Key(storedKey)) {
			return c.text(storedKey.certificatePem, HTTP.OK, {
				"Content-Type": MediaType.ApplicationPemCertificateChain,
			});
		}

		const publicKey = await extractPublicKey(storedKey.armoredPrivateKey);

		return c.text(publicKey, HTTP.OK, {
			"Content-Type": MediaType.ApplicationPgpKeys,
		});
	} catch (error) {
		logger.error("Failed to get public key:", { keyId, error });
		return c.json(
			{
				error: "Failed to process key",
				code: "KEY_PROCESSING_ERROR" as const satisfies ErrorCode,
			},
			HTTP.InternalServerError,
		);
	}
});

const deleteKeyRoute = createRoute({
	method: "delete",
	path: "/keys/{keyId}",
	summary: "Delete a key",
	description: "Delete a stored key",
	security: [{ bearerAuth: [] }],
	request: {
		params: z.object({
			keyId: z.string().openapi({
				param: { name: "keyId", in: "path" },
				example: "A1B2C3D4E5F6G7H8",
			}),
		}),
	},
	responses: {
		[HTTP.OK]: {
			content: { "application/json": { schema: KeyDeletionResponseSchema } },
			description: "Key deleted",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(deleteKeyRoute, async (c) => {
	const { keyId } = c.req.valid("param");
	const requestId = c.req.header(HEADERS.REQUEST_ID) || crypto.randomUUID();

	try {
		const response = await fetchKeyStorage(c.env, `/delete-key?keyId=${encodeURIComponent(keyId)}`, {
			method: "DELETE",
		});

		if (!response.ok) {
			throw new Error(`Key storage returned ${response.status}`);
		}

		const result = (await response.json()) as {
			success: boolean;
			deleted: boolean;
		};

		// Invalidate cached decrypted key on deletion
		if (result.deleted) {
			invalidateKeyCache(keyId);
		}

		// Log key deletion (non-blocking in production)
		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "key_rotate",
				issuer: "admin",
				subject: "admin",
				keyId,
				success: result.deleted,
			}),
		);

		return c.json(result, HTTP.OK);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Delete failed";
		logger.error("Failed to delete key:", { keyId, error });

		// Audit failed deletion attempt (non-blocking in production)
		await scheduleBackgroundTask(
			c,
			requestId,
			logAuditEvent(c.env.AUDIT_DB, {
				requestId,
				action: "key_rotate",
				issuer: "admin",
				subject: "admin",
				keyId,
				success: false,
				errorCode: "KEY_DELETE_ERROR",
				metadata: JSON.stringify({ error: message }),
			}),
		);

		return c.json(
			{
				error: "Failed to delete key",
				code: "KEY_DELETE_ERROR" as const satisfies ErrorCode,
			},
			HTTP.InternalServerError,
		);
	}
});

const getAuditLogsRoute = createRoute({
	method: "get",
	path: "/audit",
	summary: "Get audit logs",
	description: "Retrieve audit logs with filtering",
	security: [{ bearerAuth: [] }],
	request: { query: AuditQuerySchema },
	responses: {
		[HTTP.OK]: {
			content: { "application/json": { schema: AuditLogsResponseSchema } },
			description: "Audit logs",
		},
		[HTTP.BadRequest]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Invalid request",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(getAuditLogsRoute, async (c) => {
	try {
		const { limit, offset, action, subject, startDate, endDate } = c.req.valid("query");

		// Filter out undefined values for optional parameters
		const auditOptions: Parameters<typeof getAuditLogs>[1] = { limit, offset };

		if (action !== undefined) auditOptions.action = action;
		if (subject !== undefined) auditOptions.subject = subject;
		if (startDate !== undefined) auditOptions.startDate = startDate;
		if (endDate !== undefined) auditOptions.endDate = endDate;

		const logs = await getAuditLogs(c.env.AUDIT_DB, auditOptions);

		return c.json({ logs, count: logs.length }, HTTP.OK);
	} catch (error) {
		logger.error("Failed to get audit logs:", error);
		return c.json(
			{
				error: "Failed to retrieve audit logs",
				code: "AUDIT_ERROR" as const satisfies ErrorCode,
			},
			HTTP.InternalServerError,
		);
	}
});

export default app;
