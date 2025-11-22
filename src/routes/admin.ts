import { createRoute, z } from "@hono/zod-openapi";
import { createOpenAPIApp } from "~/lib/openapi";
import type { ErrorCode, KeyUploadRequest, StoredKey } from "~/types";
import { createArmoredPrivateKey, createKeyId } from "~/types";
import { getAuditLogs, logAuditEvent } from "~/utils/audit";
import { extractPublicKey, parseAndValidateKey } from "~/utils/signing";

const app = createOpenAPIApp();

// Schemas
const KeyUploadSchema = z.object({
  armoredPrivateKey: z.string().openapi({
    example: "-----BEGIN PGP PRIVATE KEY BLOCK-----\n...",
  }),
  keyId: z.string().openapi({
    example: "A1B2C3D4E5F6G7H8",
  }),
});

const KeyResponseSchema = z.object({
  success: z.boolean(),
  keyId: z.string(),
  fingerprint: z.string(),
  algorithm: z.string(),
  userId: z.string(),
});

const ErrorResponseSchema = z.object({
  error: z.string(),
  code: z.string(),
  requestId: z.string().optional(),
});

// Routes

const uploadKeyRoute = createRoute({
  method: "post",
  path: "/keys",
  summary: "Upload a new signing key",
  description: "Upload a GPG private key for signing",
  request: {
    body: {
      content: {
        "application/json": {
          schema: KeyUploadSchema,
        },
      },
      required: true,
    },
  },
  responses: {
    201: {
      content: {
        "application/json": {
          schema: KeyResponseSchema,
        },
      },
      description: "Key uploaded successfully",
    },
    400: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Invalid request",
    },
    500: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Internal server error",
    },
  },
});

app.openapi(uploadKeyRoute, async (c) => {
  const requestId = c.req.header("X-Request-ID") || crypto.randomUUID();

  try {
    const body = (await c.req.json()) as KeyUploadRequest;

    // Validate and parse the key
    const keyInfo = await parseAndValidateKey(
      body.armoredPrivateKey,
      c.env.KEY_PASSPHRASE,
    );

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(body.armoredPrivateKey),
      keyId: createKeyId(body.keyId),
      fingerprint: keyInfo.fingerprint,
      createdAt: new Date().toISOString(),
      algorithm: keyInfo.algorithm,
    };

    // Store in Durable Object
    const keyStorageId = c.env.KEY_STORAGE.idFromName("global");
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const storeResponse = await keyStorage.fetch(
      new Request("http://internal/store-key", {
        method: "POST",
        body: JSON.stringify(storedKey),
        headers: { "Content-Type": "application/json" },
      }),
    );

    if (!storeResponse.ok) {
      const error = (await storeResponse.json()) as { error: string };
      throw new Error(error.error || "Failed to store key");
    }

    // Log key upload
    await logAuditEvent(c.env.AUDIT_DB, {
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
    });

    return c.json(
      {
        success: true,
        keyId: body.keyId,
        fingerprint: keyInfo.fingerprint,
        algorithm: keyInfo.algorithm,
        userId: keyInfo.userId,
      },
      201,
    );
  } catch (error) {
    const message = error instanceof Error
      ? error.message
      : "Key upload failed";

    // Audit failed key upload attempt
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: "key_upload",
      issuer: "admin",
      subject: "admin",
      keyId: "unknown",
      success: false,
      errorCode: "KEY_UPLOAD_ERROR",
      metadata: JSON.stringify({ error: message }),
    });

    return c.json(
      {
        error: message,
        code: "KEY_UPLOAD_ERROR" satisfies ErrorCode,
        requestId,
      },
      500,
    );
  }
});

const listKeysRoute = createRoute({
  method: "get",
  path: "/keys",
  summary: "List all keys",
  description: "List metadata for all stored keys",
  responses: {
    200: {
      content: {
        "application/json": {
          schema: z.object({
            keys: z.array(
              z.object({
                keyId: z.string(),
                fingerprint: z.string(),
                createdAt: z.string(),
                algorithm: z.string(),
              }),
            ),
          }),
        },
      },
      description: "List of keys",
    },
    500: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Internal server error",
    },
  },
});

app.openapi(listKeysRoute, async (c) => {
  try {
    const keyStorageId = c.env.KEY_STORAGE.idFromName("global");
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const response = await keyStorage.fetch(
      new Request("http://internal/list-keys"),
    );
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
    return c.json(result, 200);
  } catch (error) {
    console.error("Failed to list keys:", error);
    return c.json(
      {
        error: "Failed to retrieve keys",
        code: "KEY_LIST_ERROR" satisfies ErrorCode,
      },
      500,
    );
  }
});

const getPublicKeyRoute = createRoute({
  method: "get",
  path: "/keys/{keyId}/public",
  summary: "Get public key",
  description: "Get the public key for a specific key ID",
  request: {
    params: z.object({
      keyId: z.string().openapi({
        param: {
          name: "keyId",
          in: "path",
        },
        example: "A1B2C3D4E5F6G7H8",
      }),
    }),
  },
  responses: {
    200: {
      content: {
        "application/pgp-keys": {
          schema: z.string(),
        },
      },
      description: "Public Key",
    },
    404: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Key not found",
    },
    500: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Internal server error",
    },
  },
});

app.openapi(getPublicKeyRoute, async (c) => {
  const keyId = c.req.param("keyId");

  try {
    const keyStorageId = c.env.KEY_STORAGE.idFromName("global");
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const keyResponse = await keyStorage.fetch(
      new Request(`http://internal/get-key?keyId=${encodeURIComponent(keyId)}`),
    );

    if (!keyResponse.ok) {
      return c.json(
        { error: "Key not found", code: "KEY_NOT_FOUND" satisfies ErrorCode },
        404,
      );
    }

    const storedKey = (await keyResponse.json()) as StoredKey;
    const publicKey = await extractPublicKey(storedKey.armoredPrivateKey);

    return c.text(publicKey, 200, { "Content-Type": "application/pgp-keys" });
  } catch (error) {
    console.error("Failed to get public key:", { keyId, error });
    return c.json(
      {
        error: "Failed to process key",
        code: "KEY_PROCESSING_ERROR" satisfies ErrorCode,
      },
      500,
    );
  }
});

const deleteKeyRoute = createRoute({
  method: "delete",
  path: "/keys/{keyId}",
  summary: "Delete a key",
  description: "Delete a stored key",
  request: {
    params: z.object({
      keyId: z.string().openapi({
        param: {
          name: "keyId",
          in: "path",
        },
        example: "A1B2C3D4E5F6G7H8",
      }),
    }),
  },
  responses: {
    200: {
      content: {
        "application/json": {
          schema: z.object({
            success: z.boolean(),
            deleted: z.boolean(),
          }),
        },
      },
      description: "Key deleted",
    },
    500: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Internal server error",
    },
  },
});

app.openapi(deleteKeyRoute, async (c) => {
  const keyId = c.req.param("keyId");
  const requestId = c.req.header("X-Request-ID") || crypto.randomUUID();

  try {
    const keyStorageId = c.env.KEY_STORAGE.idFromName("global");
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const response = await keyStorage.fetch(
      new Request(
        `http://internal/delete-key?keyId=${encodeURIComponent(keyId)}`,
        { method: "DELETE" },
      ),
    );

    if (!response.ok) {
      throw new Error(`Key storage returned ${response.status}`);
    }

    const result = (await response.json()) as {
      success: boolean;
      deleted: boolean;
    };

    // Log key deletion
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: "key_rotate",
      issuer: "admin",
      subject: "admin",
      keyId,
      success: result.deleted,
    });

    return c.json(result, 200);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Delete failed";
    console.error("Failed to delete key:", { keyId, error });

    // Audit failed deletion attempt
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: "key_rotate",
      issuer: "admin",
      subject: "admin",
      keyId,
      success: false,
      errorCode: "KEY_DELETE_ERROR",
      metadata: JSON.stringify({ error: message }),
    });

    return c.json(
      {
        error: "Failed to delete key",
        code: "KEY_DELETE_ERROR" satisfies ErrorCode,
      },
      500,
    );
  }
});

const getAuditLogsRoute = createRoute({
  method: "get",
  path: "/audit",
  summary: "Get audit logs",
  description: "Retrieve audit logs with filtering",
  request: {
    query: z.object({
      limit: z.string().optional().openapi({ example: "100" }),
      offset: z.string().optional().openapi({ example: "0" }),
      action: z.string().optional(),
      subject: z.string().optional(),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
    }),
  },
  responses: {
    200: {
      content: {
        "application/json": {
          schema: z.object({
            logs: z.array(
              z.object({
                id: z.string(),
                timestamp: z.string(),
                requestId: z.string(),
                action: z.string(),
                issuer: z.string(),
                subject: z.string(),
                keyId: z.string(),
                success: z.boolean(),
                errorCode: z.string().optional(),
                metadata: z.string().optional(),
              }),
            ),
            count: z.number(),
          }),
        },
      },
      description: "Audit logs",
    },
    400: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Invalid request",
    },
    500: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Internal server error",
    },
  },
});

app.openapi(getAuditLogsRoute, async (c) => {
  try {
    const limit = parseInt(c.req.query("limit") || "100", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);

    // Validate pagination parameters
    if (
      Number.isNaN(limit)
      || Number.isNaN(offset)
      || limit < 1
      || limit > 1000
      || offset < 0
    ) {
      return c.json(
        {
          error: "Invalid pagination parameters",
          code: "INVALID_REQUEST" satisfies ErrorCode,
        },
        400,
      );
    }

    const action = c.req.query("action");
    const subject = c.req.query("subject");
    const startDate = c.req.query("startDate");
    const endDate = c.req.query("endDate");

    const logs = await getAuditLogs(c.env.AUDIT_DB, {
      limit,
      offset,
      action,
      subject,
      startDate,
      endDate,
    });

    return c.json({ logs, count: logs.length }, 200);
  } catch (error) {
    console.error("Failed to get audit logs:", error);
    return c.json(
      {
        error: "Failed to retrieve audit logs",
        code: "AUDIT_ERROR" satisfies ErrorCode,
      },
      500,
    );
  }
});

export default app;
