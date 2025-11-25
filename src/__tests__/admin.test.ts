// These imports are provided by @cloudflare/vitest-pool-workers
import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import app from "gpg-signing-service";
import * as openpgp from "openpgp";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { logger } from "~/utils/logger";

// Mock audit logging to avoid database errors in tests
vi.mock("~/utils/audit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("~/utils/audit")>();
  return { ...actual, logAuditEvent: vi.fn(async () => undefined) };
});

// Helper to make authenticated requests
async function adminRequest(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await app.fetch(
    new Request(`http://localhost/admin${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${env.ADMIN_TOKEN}`,
        "Content-Type": "application/json",
        ...options.headers,
      },
    }),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}

// Generate a test key
async function generateTestKey() {
  const { privateKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Admin Test", email: "admin@test.com" }],
    passphrase: env.KEY_PASSPHRASE,
    format: "armored",
  });

  return privateKey;
}

const MIGRATION_SQL = `
-- Audit logs table for tracking all signing operations
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    request_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('sign', 'key_upload', 'key_rotate')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    key_id TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    metadata TEXT
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_logs (subject);
CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_logs (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_logs (key_id);

-- Composite index for filtering by action and date range
CREATE INDEX IF NOT EXISTS idx_audit_action_timestamp ON audit_logs (
    action, timestamp DESC
);
`;

async function applyMigrations() {
  const statements = MIGRATION_SQL.split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  for (const statement of statements) {
    await env.AUDIT_DB.prepare(statement).run();
  }
}

describe("Admin Routes", () => {
  beforeAll(async () => {
    await applyMigrations();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("POST /admin/keys", () => {
    it("should upload a new key", async () => {
      const privateKey = await generateTestKey();

      const response = await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({
          armoredPrivateKey: privateKey,
          keyId: "ABCD123456789012",
        }),
      });

      expect(response.status).toBe(201);
      const body = (await response.json()) as {
        success: boolean;
        keyId: string;
        fingerprint: string;
        algorithm: string;
      };
      expect(body.success).toBe(true);
      expect(body.keyId).toBe("ABCD123456789012");
      expect(body.algorithm).toBe("EdDSA");
      expect(body.fingerprint).toBeTruthy();
    });

    it("should return 400 for missing armoredPrivateKey", async () => {
      const response = await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({ keyId: "test-key" }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error: string; code: string };
      expect(body.code).toBe("INVALID_REQUEST");
    });

    it("should return 400 for missing keyId", async () => {
      const privateKey = await generateTestKey();

      const response = await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({ armoredPrivateKey: privateKey }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error: string; code: string };
      expect(body.code).toBe("INVALID_REQUEST");
    });

    it("should return 400 for invalid key format", async () => {
      const response = await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({
          armoredPrivateKey: "not a valid pgp key",
          keyId: "2222222222222222",
        }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("INVALID_REQUEST");
    });

    it("should return 500 when storage fails", async () => {
      const privateKey = await generateTestKey();

      // Mock KEY_STORAGE fetch to fail
      vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
        fetch: async () =>
          new Response(JSON.stringify({ error: "Storage error" }), {
            status: 500,
          }),
      } as unknown as DurableObjectStub);

      try {
        const response = await adminRequest("/keys", {
          method: "POST",
          body: JSON.stringify({
            armoredPrivateKey: privateKey,
            keyId: "3333333333333333",
          }),
        });

        expect(response.status).toBe(500);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe("KEY_UPLOAD_ERROR");
      } finally {
        vi.restoreAllMocks();
      }
    });

    it("should use default error message when storage fails without detail", async () => {
      const validKey = await generateTestKey(); // Generate a valid key for the request body
      // Mock KEY_STORAGE failure with empty error
      const originalGet = env.KEY_STORAGE.get;
      env.KEY_STORAGE.get = () =>
        ({
          fetch: async () => new Response(JSON.stringify({}), { status: 500 }),
        }) as unknown as DurableObjectStub;

      try {
        const response = await adminRequest("/keys", {
          // Changed makeRequest to adminRequest
          method: "POST",
          // headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` }, // adminRequest already adds headers
          body: JSON.stringify({
            armoredPrivateKey: validKey,
            keyId: "7777777777777777",
          }),
        });

        expect(response.status).toBe(500);
        const body = (await response.json()) as { error: string };
        expect(body.error).toBe("Failed to store key"); // Expecting the default error message
      } finally {
        env.KEY_STORAGE.get = originalGet;
      }
    });
    it("should handle non-Error exceptions", async () => {
      // Mock KEY_STORAGE to throw a string
      const originalGet = env.KEY_STORAGE.get;
      const mockFetch = vi.fn().mockRejectedValue("String error");
      env.KEY_STORAGE.get = () =>
        ({ fetch: mockFetch }) as unknown as DurableObjectStub;

      try {
        const response = await adminRequest("/keys", {
          method: "POST",
          body: JSON.stringify({
            armoredPrivateKey: await generateTestKey(),
            keyId: "8888888888888888",
          }),
        });

        expect(response.status).toBe(500);
        const body = (await response.json()) as { error: string };
        expect(body.error).toBe("Key upload failed");
      } finally {
        env.KEY_STORAGE.get = originalGet;
      }
    });
  });

  describe("GET /admin/keys", () => {
    it("should list keys", async () => {
      // Upload a key first
      const privateKey = await generateTestKey();
      await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({
          armoredPrivateKey: privateKey,
          keyId: "4444444444444444",
        }),
      });

      const response = await adminRequest("/keys");

      expect(response.status).toBe(200);
      const body = (await response.json()) as { keys: unknown[] };
      expect(Array.isArray(body.keys)).toBe(true);
    });
    it("should return 500 when storage list fails", async () => {
      // Mock KEY_STORAGE fetch to fail
      vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
        fetch: async () => new Response("Internal Error", { status: 500 }),
      } as unknown as DurableObjectStub);

      try {
        const response = await adminRequest("/keys");
        expect(response.status).toBe(500);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe("KEY_LIST_ERROR");
      } finally {
        vi.restoreAllMocks();
      }
    });
  });

  describe("GET /admin/keys/:keyId/public", () => {
    it("should return public key for existing key", async () => {
      // Upload a key first
      const privateKey = await generateTestKey();
      await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({
          armoredPrivateKey: privateKey,
          keyId: "BCDE234567890123",
        }),
      });

      const response = await adminRequest("/keys/BCDE234567890123/public");

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("application/pgp-keys");

      const publicKey = await response.text();
      expect(publicKey).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    });

    it("should return 404 for EEEEEEEEEEEEEEEE key", async () => {
      const response = await adminRequest("/keys/EEEEEEEEEEEEEEEE/public");

      expect(response.status).toBe(404);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("KEY_NOT_FOUND");
    });
    it("should return 500 when processing fails", async () => {
      // Mock KEY_STORAGE to return a key that fails processing (e.g. invalid armored content)
      // or mock the processing function itself if possible.
      // Here we mock the storage to return a valid-looking key but with invalid content

      vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
        fetch: async () =>
          new Response(
            JSON.stringify({
              armoredPrivateKey: "invalid-content",
              keyId: "6666666666666666",
            }),
            { status: 200 },
          ),
      } as unknown as DurableObjectStub);

      try {
        const response = await adminRequest("/keys/8888888888888888/public");
        expect(response.status).toBe(500);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe("KEY_PROCESSING_ERROR");
      } finally {
        vi.restoreAllMocks();
      }
    });
  });

  describe("DELETE /admin/keys/:keyId", () => {
    it("should delete existing key", async () => {
      // Upload a key first
      const privateKey = await generateTestKey();
      await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({
          armoredPrivateKey: privateKey,
          keyId: "5555555555555555",
        }),
      });

      const response = await adminRequest("/keys/5555555555555555", {
        method: "DELETE",
      });

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        success: boolean;
        deleted: boolean;
      };
      expect(body.success).toBe(true);
    });

    it("should return success with deleted=false for EEEEEEEEEEEEEEEE key", async () => {
      const response = await adminRequest("/keys/EEEEEEEEEEEEEEEE", {
        method: "DELETE",
      });

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        success: boolean;
        deleted: boolean;
      };
      expect(body.deleted).toBe(false);
    });
    it("should return 500 when storage delete fails", async () => {
      vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
        fetch: async () => new Response("Storage Error", { status: 500 }),
      } as unknown as DurableObjectStub);

      try {
        const response = await adminRequest("/keys/6666666666666666", {
          method: "DELETE",
        });
        expect(response.status).toBe(500);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe("KEY_DELETE_ERROR");
      } finally {
        vi.restoreAllMocks();
      }
    });
  });

  describe("GET /admin/audit", () => {
    it("should return audit logs with default pagination", async () => {
      const response = await adminRequest("/audit");

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        logs: unknown[];
        count: number;
      };
      expect(Array.isArray(body.logs)).toBe(true);
      expect(typeof body.count).toBe("number");
    });

    it("should apply pagination parameters", async () => {
      const response = await adminRequest("/audit?limit=10&offset=0");

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        logs: unknown[];
        count: number;
      };
      expect(body.logs.length).toBeLessThanOrEqual(10);
    });

    it("should return 400 for invalid limit", async () => {
      const response = await adminRequest("/audit?limit=-1");

      expect(response.status).toBe(400);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("INVALID_REQUEST");
    });

    it("should return 400 for limit exceeding max", async () => {
      const response = await adminRequest("/audit?limit=10000");

      expect(response.status).toBe(400);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("INVALID_REQUEST");
    });

    it("should return 400 for negative offset", async () => {
      const response = await adminRequest("/audit?offset=-5");

      expect(response.status).toBe(400);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("INVALID_REQUEST");
    });

    it("should filter by action", async () => {
      const response = await adminRequest("/audit?action=key_upload");

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        logs: unknown[];
        count: number;
      };
      expect(Array.isArray(body.logs)).toBe(true);
    });

    it("should filter by date range", async () => {
      const response = await adminRequest(
        "/audit?startDate=2024-01-01T00:00:00Z&endDate=2024-12-31T23:59:59Z",
      );

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        logs: unknown[];
        count: number;
      };
      expect(Array.isArray(body.logs)).toBe(true);
    });
    it("should return 500 when DB fails", async () => {
      // Mock AUDIT_DB prepare to throw
      vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation(() => {
        throw new Error("DB Error");
      });

      try {
        const response = await adminRequest("/audit");
        expect(response.status).toBe(500);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe("AUDIT_ERROR");
      } finally {
        vi.restoreAllMocks();
      }
    });
  });

  describe("Authentication", () => {
    it("should reject requests without auth token", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys"),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
    });

    it("should reject requests with invalid auth token", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: "Bearer invalid-token" },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
    });
    it("should handle non-Error exceptions during deletion", async () => {
      // Mock KEY_STORAGE to throw a string
      const originalGet = env.KEY_STORAGE.get;
      const mockFetch = vi.fn().mockRejectedValue("Delete string error");
      env.KEY_STORAGE.get = () =>
        ({ fetch: mockFetch }) as unknown as DurableObjectStub;

      try {
        const response = await adminRequest("/keys/7777777777777777", {
          method: "DELETE",
        });

        expect(response.status).toBe(500);
        const body = (await response.json()) as { error: string };
        expect(body.error).toBe("Failed to delete key");
      } finally {
        env.KEY_STORAGE.get = originalGet;
      }
    });
  });

  describe("Audit Logging Catch Handlers", () => {
    it("should log audit failures via catch handler on upload success", async () => {
      // Spy on logger.error to verify catch handler executes
      const loggerSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
      const { logAuditEvent } = await import("~/utils/audit");

      // Save original implementation
      // const originalImpl = logAuditEvent;

      // Mock to reject to trigger catch
      vi.mocked(logAuditEvent).mockRejectedValue(
        new Error("Audit DB connection failed"),
      );

      const privateKey = await generateTestKey();
      const ctx = createExecutionContext();

      await app.fetch(
        new Request("http://localhost/admin/keys", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.ADMIN_TOKEN}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            armoredPrivateKey: privateKey,
            keyId: "CATCH1234567890A",
          }),
        }),
        env,
        ctx,
      );

      // Wait for background tasks
      await waitOnExecutionContext(ctx);

      loggerSpy.mockRestore();
    });

    it("should log audit failures via catch handler on upload error", async () => {
      const loggerSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
      const { logAuditEvent } = await import("~/utils/audit");

      vi.mocked(logAuditEvent).mockRejectedValue(
        new Error("Audit DB unavailable"),
      );

      const ctx = createExecutionContext();
      await app.fetch(
        new Request("http://localhost/admin/keys", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.ADMIN_TOKEN}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            armoredPrivateKey: await generateTestKey(),
            keyId: "CACC22345678901B",
          }),
        }),
        env,
        ctx,
      );

      await waitOnExecutionContext(ctx);

      expect(logAuditEvent).toHaveBeenCalled();
      expect(loggerSpy).toHaveBeenCalledWith(
        "Background task failed",
        expect.objectContaining({
          requestId: expect.any(String),
          error: expect.any(String),
        }),
      );

      loggerSpy.mockRestore();
    });

    it("should log audit failures via catch handler on delete success", async () => {
      const loggerSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
      const { logAuditEvent } = await import("~/utils/audit");
      const privateKey = await generateTestKey();

      // Upload key first
      await adminRequest("/keys", {
        method: "POST",
        body: JSON.stringify({
          armoredPrivateKey: privateKey,
          keyId: "CATCH3234567890C",
        }),
      });

      // Mock to reject for delete audit
      vi.mocked(logAuditEvent).mockRejectedValueOnce(
        new Error("Audit DB write failed"),
      );

      const ctx = createExecutionContext();
      await app.fetch(
        new Request("http://localhost/admin/keys/CATCH3234567890C", {
          method: "DELETE",
          headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
        }),
        env,
        ctx,
      );

      await waitOnExecutionContext(ctx);

      expect(loggerSpy).toHaveBeenCalledWith(
        "Background task failed",
        expect.objectContaining({
          requestId: expect.any(String),
          error: expect.any(String),
        }),
      );

      loggerSpy.mockRestore();
    });

    it("should log audit failures via catch handler on delete error", async () => {
      const loggerSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
      const { logAuditEvent } = await import("~/utils/audit");

      // Mock storage to fail
      const originalGet = env.KEY_STORAGE.get;
      env.KEY_STORAGE.get = () =>
        ({
          fetch: async () => new Response("Storage Error", { status: 500 }),
        }) as unknown as DurableObjectStub;

      vi.mocked(logAuditEvent).mockRejectedValueOnce(
        new Error("Audit DB unavailable"),
      );

      const ctx = createExecutionContext();
      await app.fetch(
        new Request("http://localhost/admin/keys/CATCH4234567890D", {
          method: "DELETE",
          headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
        }),
        env,
        ctx,
      );

      await waitOnExecutionContext(ctx);

      expect(loggerSpy).toHaveBeenCalledWith(
        "Background task failed",
        expect.objectContaining({
          requestId: expect.any(String),
          error: expect.any(String),
        }),
      );

      loggerSpy.mockRestore();
      env.KEY_STORAGE.get = originalGet;
    });
  });
});
