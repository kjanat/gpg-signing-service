// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck - cloudflare:test provides types at runtime
import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import app from "gpg-signing-service";
import * as openpgp from "openpgp";
import { describe, expect, it, vi } from "vitest";
import { KeyStorage } from "~/durable-objects/key-storage";
import { RateLimiter } from "~/durable-objects/rate-limiter";
import { logAuditEvent } from "~/utils/audit";
import * as signingUtils from "~/utils/signing";

vi.mock("openpgp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("openpgp")>();
  return {
    ...actual,
    readPrivateKey: vi.fn(actual.readPrivateKey),
  };
});

vi.mock("~/utils/signing", async (importOriginal) => {
  const actual = await importOriginal<typeof import("~/utils/signing")>();
  return {
    ...actual,
    signCommitData: vi.fn(actual.signCommitData),
    // We don't mock parseAndValidateKey because we want to test its internal logic
    // relying on the mocked openpgp.readPrivateKey
  };
});

vi.mock("~/middleware/oidc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("~/middleware/oidc")>();
  return {
    ...actual,
    oidcAuth: vi.fn(async (c, next) => {
      if (c.req.header("Authorization") === "Bearer valid-token") {
        c.set("oidcClaims", {
          iss: "issuer",
          sub: "subject",
          project_path: "repo",
        });
        c.set("identity", "user");
        return next();
      }
      return actual.oidcAuth(c, next);
    }),
  };
});

// Minimal in-memory DurableObjectState mock
function createState(): DurableObjectState {
  const store = new Map<string, any>();
  return {
    storage: {
      async get(key: string) {
        return store.get(key);
      },
      async put(key: string, value: any) {
        store.set(key, value);
      },
      async delete(key: string) {
        const existed = store.has(key);
        store.delete(key);
        return existed;
      },
      async list({ prefix }: { prefix: string }) {
        const filtered = new Map<string, any>();
        for (const [k, v] of store.entries()) {
          if (k.startsWith(prefix)) filtered.set(k, v);
        }
        return filtered;
      },
    },
  } as unknown as DurableObjectState;
}

describe("Branch Coverage Helpers", () => {
  describe("KeyStorage edge cases", () => {
    it("returns 405 for store-key with wrong method", async () => {
      const storage = new KeyStorage(createState());
      const res = await storage.fetch(new Request("http://do/store-key"));
      expect(res.status).toBe(405);
    });

    it("returns 400 when deleting without keyId", async () => {
      const storage = new KeyStorage(createState());
      const res = await storage.fetch(
        new Request("http://do/delete-key", { method: "DELETE" }),
      );
      expect(res.status).toBe(400);
    });

    it("returns health status", async () => {
      const storage = new KeyStorage(createState());
      const res = await storage.fetch(new Request("http://do/health"));
      expect(res.status).toBe(200);
    });

    it("returns 404 for unknown route", async () => {
      const storage = new KeyStorage(createState());
      const res = await storage.fetch(new Request("http://do/unknown"));
      expect(res.status).toBe(404);
    });

    it("handles health check errors", async () => {
      const state = createState();
      vi.spyOn(state.storage, "list").mockRejectedValue(
        new Error("Storage fail"),
      );
      const storage = new KeyStorage(state);
      const res = await storage.fetch(new Request("http://do/health"));
      expect(res.status).toBe(500);
      expect(await res.json()).toEqual({ error: "Storage fail" });
    });
  });

  describe("RateLimiter edge cases", () => {
    it("returns 405 for reset with non-POST method", async () => {
      const limiter = new RateLimiter(createState());
      const res = await limiter.fetch(new Request("http://do/reset"));
      expect(res.status).toBe(405);
    });

    it("requires identity when resetting limits", async () => {
      const limiter = new RateLimiter(createState());
      const res = await limiter.fetch(
        new Request("http://do/reset", { method: "POST" }),
      );
      expect(res.status).toBe(400);
    });

    it("refills existing bucket on consume", async () => {
      const state = createState();
      // Seed an old bucket to force refill path
      await state.storage.put("bucket:user", {
        tokens: 10,
        lastRefill: Date.now() - 120_000,
      });
      const limiter = new RateLimiter(state);
      const res = await limiter.fetch(
        new Request("http://do/consume?identity=user"),
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.allowed).toBe(true);
      expect(body.remaining).toBeGreaterThan(0);
    });

    it("returns 404 for unknown route", async () => {
      const limiter = new RateLimiter(createState());
      const res = await limiter.fetch(new Request("http://do/unknown"));
      expect(res.status).toBe(404);
    });

    it("refills from 0 tokens when stale", async () => {
      const state = createState();
      await state.storage.put("bucket:user", {
        tokens: 0,
        lastRefill: Date.now() - 120_000,
      });
      const limiter = new RateLimiter(state);
      const res = await limiter.fetch(
        new Request("http://do/consume?identity=user"),
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.allowed).toBe(true);
    });

    it("handles storage errors", async () => {
      const state = createState();
      vi.spyOn(state.storage, "get").mockRejectedValue(
        new Error("Storage fail"),
      );
      const limiter = new RateLimiter(state);
      const res = await limiter.fetch(new Request("http://do/consume"));
      expect(res.status).toBe(500);
    });
  });

  describe("Audit logging failures", () => {
    it("logs and swallows audit DB errors", async () => {
      const db = {
        prepare: () => {
          throw new Error("DB down");
        },
      } as unknown as D1Database;

      const consoleSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});

      await logAuditEvent(db, {
        requestId: "req-1",
        action: "test" as any,
        issuer: "issuer",
        subject: "subj",
        keyId: "key",
        success: true,
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        "Failed to write audit log:",
        expect.objectContaining({ error: "DB down" }),
      );

      consoleSpy.mockRestore();
    });
  });

  describe("Middleware branches", () => {
    it("fails admin rate limit when allowance is false", async () => {
      const denyResponse = new Response(
        JSON.stringify({
          allowed: false,
          resetAt: Date.now() + 10_000,
          remaining: 0,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );

      const customEnv = {
        ...env,
        ADMIN_TOKEN: env.ADMIN_TOKEN,
        RATE_LIMITER: {
          idFromName: () => ({}) as any,
          get: () => ({ fetch: () => denyResponse }),
        },
      };

      const ctx = createExecutionContext();
      const res = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
        }),
        customEnv,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(429);
      const body = await res.json();
      expect(body.code).toBe("RATE_LIMITED");
    });

    it("allows admin request and sets headers when rate limit passes", async () => {
      const allowResponse = new Response(
        JSON.stringify({
          allowed: true,
          resetAt: Date.now() + 10_000,
          remaining: 5,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );

      const customEnv = {
        ...env,
        ADMIN_TOKEN: env.ADMIN_TOKEN,
        RATE_LIMITER: {
          idFromName: () => ({}) as any,
          get: () => ({ fetch: () => allowResponse }),
        },
      };

      const ctx = createExecutionContext();
      const res = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
        }),
        customEnv,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(200);
      expect(res.headers.get("X-RateLimit-Remaining")).toBe("5");
    });

    it("handles missing token after Bearer prefix", async () => {
      const json = vi.fn();
      const context = {
        req: { header: () => "Bearer " },
        env,
        json,
        set: vi.fn(),
      };

      await import("~/middleware/oidc").then(({ oidcAuth }) =>
        oidcAuth(context as any, () => Promise.resolve())
      );

      expect(json).toHaveBeenCalledWith({ error: "Missing token" }, 401);
    });

    it("maps jose JWKS error to friendly message", async () => {
      const { mapJoseError } = await import("~/middleware/oidc");
      const err: any = new Error("no applicable key");
      err.code = "ERR_JWKS_NO_MATCHING_KEY";
      expect(() => mapJoseError(err)).toThrow("Key not found");

      const sigErr: any = new Error("signature verification failed");
      expect(() => mapJoseError(sigErr)).toThrow("Invalid token signature");

      const generic = new Error("other");
      expect(() => mapJoseError(generic)).toThrow("other");
    });

    it("returns 401 for Basic auth", async () => {
      const json = vi.fn();
      const context = {
        req: { header: () => "Basic user:pass" },
        json,
      };
      await import("~/middleware/oidc").then(({ oidcAuth }) =>
        oidcAuth(context as any, () => Promise.resolve())
      );
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "AUTH_MISSING" }),
        401,
      );
    });

    it("fails closed when admin rate limiter fails", async () => {
      const customEnv = {
        ...env,
        RATE_LIMITER: {
          idFromName: () => ({}) as any,
          get: () => ({
            fetch: () =>
              Promise.resolve(new Response("Error", { status: 503 })),
          }),
        },
      };

      const json = vi.fn();
      const context = {
        req: {
          header: (name: string) =>
            name === "Authorization" ? "Bearer admin" : "1.2.3.4",
        },
        env: customEnv,
        json,
      };

      await import("~/middleware/security").then(({ adminRateLimit }) =>
        adminRateLimit(context as any, () => Promise.resolve())
      );

      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "RATE_LIMIT_ERROR" }),
        503,
      );
    });
  });

  describe("Route error handling", () => {
    it("triggers catch block in uploadKeyRoute with invalid key format", async () => {
      // Sending garbage key triggers openpgp error, which is caught by the route handler
      const ctx = createExecutionContext();
      const res = await app.fetch(
        new Request("http://localhost/admin/keys", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.ADMIN_TOKEN}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            armoredPrivateKey: "invalid-key-format",
            keyId: "A1B2C3D4E5F6G7H8",
          }),
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.code).toBe("KEY_UPLOAD_ERROR");
    });

    it("handles signing key not found via storage", async () => {
      const customEnv = {
        ...env,
        KEY_STORAGE: {
          idFromName: () => ({}) as any,
          get: () => ({
            fetch: () =>
              Promise.resolve(
                new Response(JSON.stringify({ error: "Key not found" }), {
                  status: 404,
                }),
              ),
          }),
        },
        AUDIT_DB: {
          prepare: () => ({ bind: () => ({ run: () => Promise.resolve() }) }),
        },
      };

      const ctx = createExecutionContext();
      const res = await app.fetch(
        new Request("http://localhost/sign?keyId=A1B2C3D4E5F6G7H8", {
          method: "POST",
          headers: {
            Authorization: "Bearer valid-token",
            "Content-Type": "text/plain",
          },
          body: "commit data",
        }),
        customEnv,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.code).toBe("KEY_NOT_FOUND");
    });

    it("handles signing errors", async () => {
      vi.mocked(signingUtils.signCommitData).mockRejectedValue(
        new Error("Signing failed"),
      );

      const customEnv = {
        ...env,
        KEY_STORAGE: {
          idFromName: () => ({}) as any,
          get: () => ({
            fetch: () =>
              Promise.resolve(
                new Response(
                  JSON.stringify({
                    armoredPrivateKey: "key",
                    keyId: "id",
                    fingerprint: "fp",
                    algorithm: "RSA",
                  }),
                  { status: 200 },
                ),
              ),
          }),
        },
        AUDIT_DB: {
          prepare: () => ({ bind: () => ({ run: () => Promise.resolve() }) }),
        },
      };

      const ctx = createExecutionContext();
      const res = await app.fetch(
        new Request("http://localhost/sign?keyId=A1B2C3D4E5F6G7H8", {
          method: "POST",
          headers: {
            Authorization: "Bearer valid-token",
            "Content-Type": "text/plain",
          },
          body: "commit data",
        }),
        customEnv,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.code).toBe("SIGN_ERROR");
    });
  });

  describe("Utility edge cases", () => {
    it("handles unknown key algorithms", async () => {
      const mockKey = {
        keyPacket: { algorithm: 99 },
        getFingerprint: () => "fp",
        getKeyID: () => ({ toHex: () => "id" }),
        getUserIDs: () => ["user"],
        isDecrypted: () => true,
      };

      vi.mocked(openpgp.readPrivateKey).mockResolvedValue(mockKey as any);

      const info = await signingUtils.parseAndValidateKey("armored-key");
      expect(info.algorithm).toBe("Unknown(99)");
    });
  });
});
