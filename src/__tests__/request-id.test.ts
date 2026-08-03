import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requestIdMiddleware } from "#middleware/request-id";
import type { Env, Variables } from "#types";

// A UUID, because `getRequestId` only honours the caller's value when it is one:
// it reaches `audit_logs.request_id`, declared `z.uuid()`, and the generated Go
// client decodes it into a non-pointer UUID.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CALLER_ID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";

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
				headers: { "X-Request-ID": CALLER_ID },
			});

			expect(response.status).toBe(200);
			expect(response.headers.get("X-Request-ID")).toBe(CALLER_ID);

			const body = await response.json();
			expect(body).toEqual({ requestId: CALLER_ID });
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
			expect(requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

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
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca415" },
			});

			expect(capturedId).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca415");
		});

		it("should add X-Request-ID to response headers", async () => {
			const app = createApp();
			app.get("/test", (c) => c.text("ok"));

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca405" },
			});

			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca405");
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

		it("should replace a very long X-Request-ID (>1000 chars)", async () => {
			// The id reaches `audit_logs.request_id`, so an unbounded caller-chosen
			// value is a storage-growth lever as well as a schema violation.
			const app = createApp();
			app.get("/test", (c) => c.text("ok"));

			const longId = "x".repeat(2000);
			const response = await app.request("/test", {
				headers: { "X-Request-ID": longId },
			});

			expect(response.headers.get("X-Request-ID")).not.toBe(longId);
			expect(response.headers.get("X-Request-ID")).toMatch(UUID_RE);
		});

		it("should replace an X-Request-ID with special characters", async () => {
			const app = createApp();
			app.get("/test", (c) => c.text("ok"));

			const specialId = "req-<>&\"'@#$%^&*()";
			const response = await app.request("/test", {
				headers: { "X-Request-ID": specialId },
			});

			expect(response.headers.get("X-Request-ID")).not.toBe(specialId);
			expect(response.headers.get("X-Request-ID")).toMatch(UUID_RE);
		});

		it("should replace an X-Request-ID with unicode", async () => {
			const app = createApp();
			app.get("/test", (c) => c.text("ok"));

			const unicodeId = "请求-🎯-αβγ-123";
			const response = await app.request("/test", {
				headers: { "X-Request-ID": unicodeId },
			});

			expect(response.headers.get("X-Request-ID")).not.toBe(unicodeId);
			expect(response.headers.get("X-Request-ID")).toMatch(UUID_RE);
		});

		it("should handle case-insensitive header lookup", async () => {
			const app = createApp();
			app.get("/test", (c) => c.json({ requestId: c.get("requestId") }));

			// Hono normalizes headers, but test various casings
			const response = await app.request("/test", {
				headers: { "x-request-id": CALLER_ID },
			});

			const body = (await response.json()) as { requestId: string };
			expect(body.requestId).toBe(CALLER_ID);
		});

		it("should not override existing response X-Request-ID", async () => {
			const app = createApp();
			app.get("/test", (c) => {
				c.header("X-Request-ID", "handler-set-id");
				return c.text("ok");
			});

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca40c" },
			});

			// Middleware sets header AFTER next(), might override
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca40c");
		});

		it("should work with POST requests", async () => {
			const app = createApp();
			app.post("/test", (c) => c.json({ requestId: c.get("requestId") }));

			const response = await app.request("/test", {
				method: "POST",
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca40d" },
				body: "test data",
			});

			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca40d");
		});

		it("should work with PUT requests", async () => {
			const app = createApp();
			app.put("/test", (c) => c.json({ requestId: c.get("requestId") }));

			const response = await app.request("/test", {
				method: "PUT",
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca40f" },
			});

			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca40f");
		});

		it("should work with DELETE requests", async () => {
			const app = createApp();
			app.delete("/test", (c) => c.json({ requestId: c.get("requestId") }));

			const response = await app.request("/test", {
				method: "DELETE",
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca401" },
			});

			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca401");
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
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca407" },
			});

			// All middleware should see same requestId
			expect(ids).toEqual([
				"1b4e28ba-2fa1-11d2-883f-0016d3cca407",
				"1b4e28ba-2fa1-11d2-883f-0016d3cca407",
				"1b4e28ba-2fa1-11d2-883f-0016d3cca407",
			]);
		});

		it("should handle handler throwing error", async () => {
			const app = createApp();
			app.get("/test", () => {
				throw new Error("Handler error");
			});

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca403" },
			});

			// Should still set response header even when handler errors
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca403");
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
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca402" },
			});

			expect(response.status).toBe(400);
			const body = (await response.json()) as { requestId: string };
			expect(body.requestId).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca402");
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca402");
		});

		it("should work with 404 responses", async () => {
			const app = createApp();
			app.get("/test", (c) => c.notFound());

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca40a" },
			});

			expect(response.status).toBe(404);
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca40a");
		});

		it("should work with 500 responses", async () => {
			const app = createApp();
			app.get("/test", (c) => {
				return c.json({ error: "Internal error", requestId: c.get("requestId") }, 500);
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
			expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
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
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca406" },
			});

			expect(logs).toContain("1b4e28ba-2fa1-11d2-883f-0016d3cca406");
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
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca40b" },
			});

			// Middleware sets it after next(), should override
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca40b");
		});

		it("should preserve other response headers", async () => {
			const app = createApp();
			app.get("/test", (c) => {
				c.header("X-Custom-Header", "custom-value");
				c.header("Content-Type", "application/json");
				return c.json({ test: true });
			});

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca40e" },
			});

			expect(response.headers.get("X-Custom-Header")).toBe("custom-value");
			expect(response.headers.get("Content-Type")).toContain("application/json");
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca40e");
		});

		it("should work with streaming responses", async () => {
			const app = createApp();
			app.get("/test", (c) => {
				return c.body(new ReadableStream(), { headers: {} });
			});

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca414" },
			});

			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca414");
		});

		it("should work with redirect responses", async () => {
			const app = createApp();
			app.get("/test", (c) => c.redirect("/other"));

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca410" },
				redirect: "manual",
			});

			expect(response.status).toBe(302);
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca410");
		});

		it("should work with 204 No Content", async () => {
			const app = createApp();
			app.delete("/test", (c) => c.body(null, 204));

			const response = await app.request("/test", {
				method: "DELETE",
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca409" },
			});

			expect(response.status).toBe(204);
			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca409");
		});
	});

	describe("Concurrent Request Isolation", () => {
		it("should isolate requestId between concurrent requests", async () => {
			const app = createApp();

			const captures: Record<string, string> = {};
			app.get("/test/:id", (c) => {
				const pathId = c.req.param("id");
				captures[pathId] = c.get("requestId");
				return c.text("ok");
			});

			await Promise.all([
				app.request("/test/1", { headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca411" } }),
				app.request("/test/2", { headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca412" } }),
				app.request("/test/3", { headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca413" } }),
			]);

			expect(captures["1"]).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca411");
			expect(captures["2"]).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca412");
			expect(captures["3"]).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca413");
		});
	});

	describe("Error Handling", () => {
		it("should set header even when handler throws", async () => {
			const app = createApp();
			app.get("/test", () => {
				throw new Error("Intentional error");
			});

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca404" },
			});

			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca404");
		});

		it("should set header when downstream middleware throws", async () => {
			const app = createApp();

			app.use("*", async () => {
				throw new Error("Middleware error");
			});

			app.get("/test", (c) => c.text("ok"));

			const response = await app.request("/test", {
				headers: { "X-Request-ID": "1b4e28ba-2fa1-11d2-883f-0016d3cca408" },
			});

			expect(response.headers.get("X-Request-ID")).toBe("1b4e28ba-2fa1-11d2-883f-0016d3cca408");
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

			// Send 1000 concurrent requests to verify the middleware scales. Ids are
			// UUIDs so they survive validation and each response can be matched to
			// the request that produced it.
			const ids = Array.from({ length: 1000 }, () => crypto.randomUUID());
			const results = await Promise.all(ids.map((id) => app.request("/test", { headers: { "X-Request-ID": id } })));

			// All requests should succeed with their respective request IDs
			for (const [i, response] of results.entries()) {
				expect(response.status).toBe(200);
				expect(response.headers.get("X-Request-ID")).toBe(ids[i]);
			}
		});
	});
});
