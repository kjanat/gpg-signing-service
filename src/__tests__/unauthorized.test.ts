import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import app from "#gpg-signing-service";
import { WWW_AUTHENTICATE } from "#lib/openapi";

/**
 * What every 401 owes its caller.
 *
 * The document declares one shape for all thirteen authenticated operations, so
 * the middleware has to produce that shape everywhere — not approximately, and
 * not only on the routes someone remembered to test. Each assertion here pins a
 * field a generated client reads and would otherwise silently find missing.
 */

// The service-token refusal reads this table before it can answer 401, and an
// absent table is a 500 rather than the refusal under test.
beforeAll(async () => {
	await env.AUDIT_DB.exec(
		"CREATE TABLE IF NOT EXISTS service_tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE, key_ids TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, last_used_at TEXT);",
	);
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface Envelope {
	error: string;
	code: string;
	requestId?: string;
}

async function refuse(path: string, init: RequestInit = {}, overrides: Record<string, unknown> = {}) {
	const ctx = createExecutionContext();
	const response = await app.fetch(new Request(`http://localhost${path}`, init), { ...env, ...overrides }, ctx);
	await waitOnExecutionContext(ctx);
	return { response, body: (await response.json()) as Envelope };
}

describe("the 401 envelope", () => {
	// One case per emitter, because they are eight separate `return`s in three
	// files and nothing but this table forces them to agree.
	const REFUSALS: Array<{ name: string; path: string; init: RequestInit; code: string }> = [
		{ name: "no header on /sign", path: "/sign", init: { method: "POST" }, code: "AUTH_MISSING" },
		{
			name: "bare Bearer on /sign",
			path: "/sign",
			init: { method: "POST", headers: { Authorization: "Bearer " } },
			code: "AUTH_MISSING",
		},
		{
			name: "an unverifiable OIDC token",
			path: "/sign",
			init: { method: "POST", headers: { Authorization: "Bearer not.a.jwt" } },
			code: "AUTH_INVALID",
		},
		{
			name: "an unknown service token",
			path: "/sign",
			init: { method: "POST", headers: { Authorization: "Bearer gst_nosuchtoken" } },
			code: "AUTH_INVALID",
		},
		{ name: "no header on /admin", path: "/admin/keys", init: {}, code: "AUTH_MISSING" },
		{
			name: "bare Bearer on /admin",
			path: "/admin/keys",
			init: { headers: { Authorization: "Bearer " } },
			code: "AUTH_MISSING",
		},
		{
			name: "a wrong admin token",
			path: "/admin/keys",
			init: { headers: { Authorization: "Bearer definitely-not-the-admin-token" } },
			code: "AUTH_INVALID",
		},
	];

	for (const { name, path, init, code } of REFUSALS) {
		it(`answers ${name} with a complete envelope`, async () => {
			const { response, body } = await refuse(path, init);

			expect(response.status).toBe(401);
			expect(body.code).toBe(code);
			expect(body.error).not.toBe("");

			// RFC 9110 §11.6.1. Without it the response says "no" without saying
			// what to present instead, and a credential helper has to guess.
			expect(response.headers.get("WWW-Authenticate")).toBe(WWW_AUTHENTICATE);

			// The field that turns a refusal into something an operator can look
			// up: it is the key of the `audit_logs` row this request wrote. A
			// CI-only OIDC token cannot be replayed from a laptop, so without the
			// id there is no route from "the pipeline said no" to the record of
			// why. It must also be *this* request's id, not a fresh one — the
			// header is what the caller sees, and a body disagreeing with it sends
			// the operator looking for a row that does not exist.
			expect(body.requestId).toMatch(UUID);
			expect(body.requestId).toBe(response.headers.get("X-Request-ID"));
		});
	}

	it("carries the caller's own request id when it supplied one", async () => {
		const supplied = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
		const { body } = await refuse("/admin/keys", {
			headers: { Authorization: "Bearer wrong", "X-Request-ID": supplied },
		});

		expect(body.requestId).toBe(supplied);
	});

	it("mints its own id when the caller's is not a UUID", async () => {
		// getRequestId refuses free text because the value reaches
		// `audit_logs.request_id`, declared z.uuid(). The 401 has to publish the
		// id that was actually recorded, not the one that was rejected.
		const { body } = await refuse("/admin/keys", {
			headers: { Authorization: "Bearer wrong", "X-Request-ID": "not-a-uuid" },
		});

		expect(body.requestId).toMatch(UUID);
		expect(body.requestId).not.toBe("not-a-uuid");
	});
});

describe("an unconfigured ADMIN_TOKEN", () => {
	// timingSafeEqual("", "") compares two zero-length arrays of equal length and
	// returns true. Before the guard, a Worker deployed without `wrangler secret
	// put ADMIN_TOKEN` accepted `Authorization: Bearer ` on every admin route —
	// key upload, key deletion, token minting, the audit log.
	for (const missing of ["", undefined]) {
		it(`refuses a bare Bearer when ADMIN_TOKEN is ${missing === "" ? "empty" : "unset"}`, async () => {
			const { response, body } = await refuse(
				"/admin/keys",
				{ headers: { Authorization: "Bearer " } },
				{ ADMIN_TOKEN: missing },
			);

			expect(response.status).not.toBe(200);
			expect(body.code).toBe("INTERNAL_ERROR");
		});
	}

	it("answers 500 rather than 401, because the caller's credential is not the fault", async () => {
		const { response, body } = await refuse(
			"/admin/keys",
			{ headers: { Authorization: "Bearer anything" } },
			{ ADMIN_TOKEN: "" },
		);

		// A 401 here would send an operator to rotate a token that was never the
		// problem, and would invite a client to retry with a "better" credential
		// when no credential can work.
		expect(response.status).toBe(500);
		expect(body.code).toBe("INTERNAL_ERROR");
		expect(response.headers.get("WWW-Authenticate")).toBeNull();
	});
});
