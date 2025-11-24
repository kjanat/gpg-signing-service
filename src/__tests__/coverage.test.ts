import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import app from "gpg-signing-service";
import { describe, expect, it } from "vitest";

const parseJson = async <T>(response: Response): Promise<T> =>
  (await response.json()) as T;

describe("Coverage Tests", () => {
  describe("Health Check Errors", () => {
    it("should handle key storage failure", async () => {
      // Mock KEY_STORAGE to fail
      const originalIdFromName = env.KEY_STORAGE.idFromName;
      env.KEY_STORAGE.idFromName = () => {
        throw new Error("Key storage failure");
      };

      try {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request("http://localhost/health"),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(503);
        const body = await parseJson<{ checks: { keyStorage: unknown } }>(
          response,
        );
        expect(body.checks.keyStorage).toBe(false);
      } finally {
        // Restore
        env.KEY_STORAGE.idFromName = originalIdFromName;
      }
    });

    it("should handle database failure", async () => {
      // Mock AUDIT_DB to fail
      const originalPrepare = env.AUDIT_DB.prepare;
      env.AUDIT_DB.prepare = () => {
        throw new Error("Database failure");
      };

      try {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request("http://localhost/health"),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(503);
        const body = await parseJson<{ checks: { database: unknown } }>(
          response,
        );
        expect(body.checks.database).toBe(false);
      } finally {
        // Restore
        env.AUDIT_DB.prepare = originalPrepare;
      }
    });
  });

  describe("Global Error Handler", () => {
    it("should handle unhandled errors", async () => {
      // We need to cause an error that's NOT caught by route handlers
      // The easiest way is to break something in the middleware that throws after response
      const originalDelete = env.KEY_STORAGE.get;
      env.KEY_STORAGE.get = () => {
        // Return something that will break when trying to call methods
        return null as unknown as DurableObjectStub;
      };

      try {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request("http://localhost/public-key"),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(500);
        const body = await parseJson<{ code: string; requestId: string }>(
          response,
        );
        expect(body.code).toBe("INTERNAL_ERROR");
        expect(body.requestId).toBeTruthy();
      } finally {
        // Restore
        env.KEY_STORAGE.get = originalDelete;
      }
    });
  });

  describe("Public Key Endpoint", () => {
    it("should return 404 for EEEEEEEEEEEEEEEE key", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/public-key?keyId=EEEEEEEEEEEEEEEE"),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(404);
      const body = await parseJson<{ code: string }>(response);
      expect(body.code).toBe("KEY_NOT_FOUND");
    });
  });
});
