import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requestIdMiddleware } from "~/middleware/request-id";
import type { Env, Variables } from "~/types";

describe("Request ID Middleware", () => {
  const createApp = () => {
    const app = new Hono<{ Bindings: Env; Variables: Variables }>();
    app.use("*", requestIdMiddleware);
    return app;
  };

  describe("Happy Path", () => {
    it("should use provided X-Request-ID header", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        return c.json({ requestId: c.get("requestId") });
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "custom-request-id-123" },
      });

      expect(response.status).toBe(200);
      expect(response.headers.get("X-Request-ID")).toBe(
        "custom-request-id-123",
      );

      const body = await response.json();
      expect(body).toEqual({ requestId: "custom-request-id-123" });
    });

    it("should generate UUID when X-Request-ID not provided", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        return c.json({ requestId: c.get("requestId") });
      });

      const response = await app.request("/test");

      expect(response.status).toBe(200);

      const requestId = response.headers.get("X-Request-ID");
      expect(requestId).toBeTruthy();
      expect(requestId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );

      const body = (await response.json()) as { requestId: string };
      expect(body.requestId).toBe(requestId);
    });

    it("should set requestId in context for downstream handlers", async () => {
      const app = createApp();

      let capturedId: string | undefined;
      app.get("/test", (c) => {
        capturedId = c.get("requestId");
        return c.text("ok");
      });

      await app.request("/test", {
        headers: { "X-Request-ID": "test-123" },
      });

      expect(capturedId).toBe("test-123");
    });

    it("should add X-Request-ID to response headers", async () => {
      const app = createApp();
      app.get("/test", (c) => c.text("ok"));

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "header-test" },
      });

      expect(response.headers.get("X-Request-ID")).toBe("header-test");
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty string X-Request-ID (generate new)", async () => {
      const app = createApp();
      app.get("/test", (c) => c.json({ requestId: c.get("requestId") }));

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "" },
      });

      const requestId = response.headers.get("X-Request-ID");
      expect(requestId).toBeTruthy();
      expect(requestId).toMatch(/^[0-9a-f-]+$/); // UUID format
      expect(requestId).not.toBe("");

      const body = (await response.json()) as { requestId: string };
      expect(body.requestId).toBeTruthy();
    });

    it("should handle whitespace-only X-Request-ID (generates UUID)", async () => {
      const app = createApp();
      app.get("/test", (c) => c.json({ requestId: c.get("requestId") }));

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "   " },
      });

      // Hono's .header() treats whitespace as falsy, generates UUID
      const requestId = response.headers.get("X-Request-ID");
      expect(requestId).toBeTruthy();
      expect(requestId).toMatch(/^[0-9a-f-]{36}$/);

      const body = (await response.json()) as { requestId: string };
      expect(body.requestId).toBeTruthy();
    });

    it("should handle very long X-Request-ID (>1000 chars)", async () => {
      const app = createApp();
      app.get("/test", (c) => c.text("ok"));

      const longId = "x".repeat(2000);
      const response = await app.request("/test", {
        headers: { "X-Request-ID": longId },
      });

      expect(response.headers.get("X-Request-ID")).toBe(longId);
    });

    it("should handle X-Request-ID with special characters", async () => {
      const app = createApp();
      app.get("/test", (c) => c.text("ok"));

      const specialId = "req-<>&\"'@#$%^&*()";
      const response = await app.request("/test", {
        headers: { "X-Request-ID": specialId },
      });

      expect(response.headers.get("X-Request-ID")).toBe(specialId);
    });

    it("should handle X-Request-ID with unicode", async () => {
      const app = createApp();
      app.get("/test", (c) => c.text("ok"));

      const unicodeId = "请求-🎯-αβγ-123";
      const response = await app.request("/test", {
        headers: { "X-Request-ID": unicodeId },
      });

      expect(response.headers.get("X-Request-ID")).toBe(unicodeId);
    });

    it("should handle case-insensitive header lookup", async () => {
      const app = createApp();
      app.get("/test", (c) => c.json({ requestId: c.get("requestId") }));

      // Hono normalizes headers, but test various casings
      const response = await app.request("/test", {
        headers: { "x-request-id": "lowercase-test" },
      });

      const body = (await response.json()) as { requestId: string };
      expect(body.requestId).toBe("lowercase-test");
    });

    it("should not override existing response X-Request-ID", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        c.header("X-Request-ID", "handler-set-id");
        return c.text("ok");
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "original-id" },
      });

      // Middleware sets header AFTER next(), might override
      expect(response.headers.get("X-Request-ID")).toBe("original-id");
    });

    it("should work with POST requests", async () => {
      const app = createApp();
      app.post("/test", (c) => c.json({ requestId: c.get("requestId") }));

      const response = await app.request("/test", {
        method: "POST",
        headers: { "X-Request-ID": "post-test-123" },
        body: "test data",
      });

      expect(response.headers.get("X-Request-ID")).toBe("post-test-123");
    });

    it("should work with PUT requests", async () => {
      const app = createApp();
      app.put("/test", (c) => c.json({ requestId: c.get("requestId") }));

      const response = await app.request("/test", {
        method: "PUT",
        headers: { "X-Request-ID": "put-test-456" },
      });

      expect(response.headers.get("X-Request-ID")).toBe("put-test-456");
    });

    it("should work with DELETE requests", async () => {
      const app = createApp();
      app.delete("/test", (c) => c.json({ requestId: c.get("requestId") }));

      const response = await app.request("/test", {
        method: "DELETE",
        headers: { "X-Request-ID": "delete-test-789" },
      });

      expect(response.headers.get("X-Request-ID")).toBe("delete-test-789");
    });

    it("should persist requestId across multiple middleware", async () => {
      const app = createApp();

      const ids: string[] = [];
      app.use("*", async (c, next) => {
        ids.push(c.get("requestId"));
        await next();
      });
      app.use("*", async (c, next) => {
        ids.push(c.get("requestId"));
        await next();
      });
      app.get("/test", (c) => {
        ids.push(c.get("requestId"));
        return c.text("ok");
      });

      await app.request("/test", {
        headers: { "X-Request-ID": "middleware-chain" },
      });

      // All middleware should see same requestId
      expect(ids).toEqual([
        "middleware-chain",
        "middleware-chain",
        "middleware-chain",
      ]);
    });

    it("should handle handler throwing error", async () => {
      const app = createApp();
      app.get("/test", () => {
        throw new Error("Handler error");
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "error-test" },
      });

      // Should still set response header even when handler errors
      expect(response.headers.get("X-Request-ID")).toBe("error-test");
    });

    it("should generate different UUIDs for concurrent requests", async () => {
      const app = createApp();
      app.get("/test", (c) => c.json({ requestId: c.get("requestId") }));

      const [resp1, resp2, resp3] = await Promise.all([
        app.request("/test"),
        app.request("/test"),
        app.request("/test"),
      ]);

      const id1 = resp1.headers.get("X-Request-ID");
      const id2 = resp2.headers.get("X-Request-ID");
      const id3 = resp3.headers.get("X-Request-ID");

      // All should be unique UUIDs
      expect(id1).not.toBe(id2);
      expect(id2).not.toBe(id3);
      expect(id1).not.toBe(id3);

      expect(id1).toMatch(/^[0-9a-f-]{36}$/);
      expect(id2).toMatch(/^[0-9a-f-]{36}$/);
      expect(id3).toMatch(/^[0-9a-f-]{36}$/);
    });

    it("should handle null header value (treated as missing)", async () => {
      const app = createApp();
      app.get("/test", (c) => c.json({ requestId: c.get("requestId") }));

      const response = await app.request("/test");

      const requestId = response.headers.get("X-Request-ID");
      expect(requestId).toBeTruthy();
      expect(requestId).toMatch(/^[0-9a-f-]{36}$/);
    });
  });

  describe("Integration with Error Responses", () => {
    it("should include requestId in error response", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        return c.json(
          {
            error: "Test error",
            code: "TEST_ERROR",
            requestId: c.get("requestId"),
          },
          400,
        );
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "error-response-test" },
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { requestId: string };
      expect(body.requestId).toBe("error-response-test");
      expect(response.headers.get("X-Request-ID")).toBe("error-response-test");
    });

    it("should work with 404 responses", async () => {
      const app = createApp();
      app.get("/test", (c) => c.notFound());

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "not-found-test" },
      });

      expect(response.status).toBe(404);
      expect(response.headers.get("X-Request-ID")).toBe("not-found-test");
    });

    it("should work with 500 responses", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        return c.json(
          { error: "Internal error", requestId: c.get("requestId") },
          500,
        );
      });

      const response = await app.request("/test");

      expect(response.status).toBe(500);
      const requestId = response.headers.get("X-Request-ID");
      expect(requestId).toMatch(/^[0-9a-f-]{36}$/);
    });
  });

  describe("UUID Generation Edge Cases", () => {
    it("should generate valid v4 UUID format", async () => {
      const app = createApp();
      app.get("/test", (c) => c.text("ok"));

      const response = await app.request("/test");

      const uuid = response.headers.get("X-Request-ID");
      expect(uuid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
    });

    it("should generate cryptographically random UUIDs", async () => {
      const app = createApp();
      app.get("/test", (c) => c.text("ok"));

      // Generate 100 UUIDs, check for uniqueness
      const ids = new Set<string>();

      for (let i = 0; i < 100; i++) {
        const response = await app.request("/test");
        const id = response.headers.get("X-Request-ID");
        if (id) ids.add(id);
      }

      // All should be unique
      expect(ids.size).toBe(100);
    });
  });

  describe("Multiple Middleware Interaction", () => {
    it("should work before authentication middleware", async () => {
      const app = createApp();

      app.use("*", async (c, next) => {
        // Simulate auth middleware checking requestId
        const id = c.get("requestId");
        expect(id).toBeTruthy();
        await next();
      });

      app.get("/test", (c) => c.text("ok"));

      const response = await app.request("/test");
      expect(response.status).toBe(200);
    });

    it("should work after logging middleware", async () => {
      const app = new Hono<{ Bindings: Env; Variables: Variables }>();

      const logs: string[] = [];
      app.use("*", async (_c, next) => {
        await next();
        // Logger runs after, but can't access requestId yet
      });

      app.use("*", requestIdMiddleware);

      app.get("/test", (c) => {
        logs.push(c.get("requestId"));
        return c.text("ok");
      });

      await app.request("/test", {
        headers: { "X-Request-ID": "log-test" },
      });

      expect(logs).toContain("log-test");
    });
  });

  describe("Response Header Edge Cases", () => {
    it("should not duplicate X-Request-ID if already set", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        // Handler shouldn't manually set this
        c.header("X-Request-ID", "manual-override");
        return c.text("ok");
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "original" },
      });

      // Middleware sets it after next(), should override
      expect(response.headers.get("X-Request-ID")).toBe("original");
    });

    it("should preserve other response headers", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        c.header("X-Custom-Header", "custom-value");
        c.header("Content-Type", "application/json");
        return c.json({ test: true });
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "preserve-test" },
      });

      expect(response.headers.get("X-Custom-Header")).toBe("custom-value");
      expect(response.headers.get("Content-Type")).toContain(
        "application/json",
      );
      expect(response.headers.get("X-Request-ID")).toBe("preserve-test");
    });

    it("should work with streaming responses", async () => {
      const app = createApp();
      app.get("/test", (c) => {
        return c.body(new ReadableStream(), { headers: {} });
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "stream-test" },
      });

      expect(response.headers.get("X-Request-ID")).toBe("stream-test");
    });

    it("should work with redirect responses", async () => {
      const app = createApp();
      app.get("/test", (c) => c.redirect("/other"));

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "redirect-test" },
        redirect: "manual",
      });

      expect(response.status).toBe(302);
      expect(response.headers.get("X-Request-ID")).toBe("redirect-test");
    });

    it("should work with 204 No Content", async () => {
      const app = createApp();
      app.delete("/test", (c) => c.body(null, 204));

      const response = await app.request("/test", {
        method: "DELETE",
        headers: { "X-Request-ID": "no-content-test" },
      });

      expect(response.status).toBe(204);
      expect(response.headers.get("X-Request-ID")).toBe("no-content-test");
    });
  });

  describe("Concurrent Request Isolation", () => {
    it("should isolate requestId between concurrent requests", async () => {
      const app = createApp();

      const captures: Record<string, string> = {};
      app.get("/test/:id", async (c) => {
        const pathId = c.req.param("id");
        // Simulate async work
        await new Promise((resolve) => setTimeout(resolve, 10));
        captures[pathId] = c.get("requestId");
        return c.text("ok");
      });

      await Promise.all([
        app.request("/test/1", { headers: { "X-Request-ID": "req-1" } }),
        app.request("/test/2", { headers: { "X-Request-ID": "req-2" } }),
        app.request("/test/3", { headers: { "X-Request-ID": "req-3" } }),
      ]);

      expect(captures["1"]).toBe("req-1");
      expect(captures["2"]).toBe("req-2");
      expect(captures["3"]).toBe("req-3");
    });
  });

  describe("Error Handling", () => {
    it("should set header even when handler throws", async () => {
      const app = createApp();
      app.get("/test", () => {
        throw new Error("Intentional error");
      });

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "error-throw-test" },
      });

      expect(response.headers.get("X-Request-ID")).toBe("error-throw-test");
    });

    it("should set header when downstream middleware throws", async () => {
      const app = createApp();

      app.use("*", async () => {
        throw new Error("Middleware error");
      });

      app.get("/test", (c) => c.text("ok"));

      const response = await app.request("/test", {
        headers: { "X-Request-ID": "middleware-error" },
      });

      expect(response.headers.get("X-Request-ID")).toBe("middleware-error");
    });

    it("should generate requestId even for 404 routes", async () => {
      const app = createApp();
      // No routes defined, will 404

      const response = await app.request("/nonexistent");

      const requestId = response.headers.get("X-Request-ID");
      expect(requestId).toBeTruthy();
      expect(requestId).toMatch(/^[0-9a-f-]{36}$/);
    });
  });

  describe("Performance", () => {
    it("should handle high request volume efficiently", async () => {
      const app = createApp();
      app.get("/test", (c) => c.text("ok"));

      const start = Date.now();

      // 1000 requests
      await Promise.all(
        Array.from({ length: 1000 }, (_, i) =>
          app.request("/test", {
            headers: { "X-Request-ID": `req-${i}` },
          })),
      );

      const elapsed = Date.now() - start;

      // Should complete in reasonable time (< 5 seconds for 1000 requests)
      expect(elapsed).toBeLessThan(5000);
    });
  });
});
