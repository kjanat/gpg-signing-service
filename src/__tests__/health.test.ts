import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";

const parseJson = async <T>(response: Response): Promise<T> => (await response.json()) as T;

describe("Health Endpoint", () => {
	it("should respond to health check", async () => {
		const request = new Request("http://localhost/health");
		const ctx = createExecutionContext();
		const response = await app.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect([200, 503]).toContain(response.status);
		const body = (await response.json()) as {
			status: string;
			timestamp: string;
			version: string;
		};
		expect(body).toHaveProperty("status");
		expect(body).toHaveProperty("timestamp");
		expect(body).toHaveProperty("version");
		expect(["healthy", "degraded"]).toContain(body.status);
	});

	it("should return correct content type", async () => {
		const request = new Request("http://localhost/health");
		const ctx = createExecutionContext();
		const response = await app.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.headers.get("content-type")).toContain("application/json");
	});
});

describe("Health Check Failures", () => {
	it("should handle key storage failure", async () => {
		// Mock KEY_STORAGE to fail
		const originalIdFromName = env.KEY_STORAGE.idFromName;
		env.KEY_STORAGE.idFromName = () => {
			throw new Error("Key storage failure");
		};

		try {
			const ctx = createExecutionContext();
			const response = await app.fetch(new Request("http://localhost/health"), env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(503);
			const body = await parseJson<{ checks: { keyStorage: unknown } }>(response);
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
			const response = await app.fetch(new Request("http://localhost/health"), env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(503);
			const body = await parseJson<{ checks: { database: unknown } }>(response);
			expect(body.checks.database).toBe(false);
		} finally {
			// Restore
			env.AUDIT_DB.prepare = originalPrepare;
		}
	});

	it("reports unhealthy when dependencies throw non-Error values", async () => {
		vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
			fetch: async () => {
				throw "key storage string failure";
			},
		} as unknown as DurableObjectStub);
		vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation(() => {
			throw "database string failure";
		});

		try {
			const ctx = createExecutionContext();
			const response = await app.fetch(new Request("http://localhost/health"), env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(503);
			const body = await parseJson<{ checks: { keyStorage: boolean; database: boolean } }>(response);
			expect(body.checks.keyStorage).toBe(false);
			expect(body.checks.database).toBe(false);
		} finally {
			vi.restoreAllMocks();
		}
	});
});

describe("404 Handler", () => {
	it("should return 404 for unknown routes", async () => {
		const request = new Request("http://localhost/unknown-route");
		const ctx = createExecutionContext();
		const response = await app.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(404);
		const body = (await response.json()) as { error: string; code: string };
		expect(body.error).toBe("Not found");
		expect(body.code).toBe("NOT_FOUND");
	});
});
