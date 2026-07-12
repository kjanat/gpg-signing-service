// These imports are provided by @cloudflare/vitest-pool-workers
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import {
	generateToken,
	hashToken,
	insertServiceToken,
	listServiceTokens,
	revokeServiceToken,
	SERVICE_TOKEN_PREFIX,
	verifyServiceToken,
} from "#utils/service-tokens";

// Mock audit logging to avoid database errors in tests
vi.mock("#utils/audit", async (importOriginal) => {
	const actual = await importOriginal<typeof import("#utils/audit")>();
	return { ...actual, logAuditEvent: vi.fn(async () => undefined) };
});

async function request(path: string, token: string, options: RequestInit = {}): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request(`http://localhost${path}`, {
			...options,
			headers: {
				Authorization: `Bearer ${token}`,
				...options.headers,
			},
		}),
		env,
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

beforeAll(async () => {
	await env.AUDIT_DB.exec(
		"CREATE TABLE IF NOT EXISTS service_tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE, key_ids TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, last_used_at TEXT);",
	);
});

beforeEach(async () => {
	await env.AUDIT_DB.exec("DELETE FROM service_tokens;");
});

describe("service token utils", () => {
	it("generates prefixed tokens with unique high entropy", () => {
		const a = generateToken();
		const b = generateToken();
		expect(a).toMatch(/^gst_[A-Za-z0-9_-]{43}$/);
		expect(a).not.toBe(b);
		expect(a.startsWith(SERVICE_TOKEN_PREFIX)).toBe(true);
	});

	it("hashes deterministically to sha-256 hex", async () => {
		const one = await hashToken("gst_example");
		const two = await hashToken("gst_example");
		expect(one).toBe(two);
		expect(one).toMatch(/^[0-9a-f]{64}$/);
		expect(await hashToken("gst_other")).not.toBe(one);
	});

	it("round-trips insert and verify", async () => {
		const token = generateToken();
		await insertServiceToken(env.AUDIT_DB, {
			name: "ci/woodpecker",
			token,
			keyIds: [],
			expiresAt: null,
		});

		const policy = await verifyServiceToken(env.AUDIT_DB, token);
		expect(policy).not.toBeNull();
		expect(policy?.name).toBe("ci/woodpecker");
		expect(policy?.allowedKeyIds).toBeNull();
	});

	it("returns the key allowlist when set", async () => {
		const token = generateToken();
		await insertServiceToken(env.AUDIT_DB, {
			name: "ci/limited",
			token,
			keyIds: ["62E75E54497815DD"],
			expiresAt: null,
		});

		const policy = await verifyServiceToken(env.AUDIT_DB, token);
		expect(policy?.allowedKeyIds).toEqual(["62E75E54497815DD"]);
	});

	it("rejects unknown, expired, and revoked tokens", async () => {
		expect(await verifyServiceToken(env.AUDIT_DB, "gst_nope")).toBeNull();

		const expired = generateToken();
		await insertServiceToken(env.AUDIT_DB, {
			name: "ci/expired",
			token: expired,
			keyIds: [],
			expiresAt: new Date(Date.now() - 1000).toISOString(),
		});
		expect(await verifyServiceToken(env.AUDIT_DB, expired)).toBeNull();

		const revoked = generateToken();
		const id = await insertServiceToken(env.AUDIT_DB, {
			name: "ci/revoked",
			token: revoked,
			keyIds: [],
			expiresAt: null,
		});
		expect(await revokeServiceToken(env.AUDIT_DB, id)).toBe(true);
		expect(await verifyServiceToken(env.AUDIT_DB, revoked)).toBeNull();
	});

	it("stamps last_used_at on verification", async () => {
		const token = generateToken();
		await insertServiceToken(env.AUDIT_DB, {
			name: "ci/stamped",
			token,
			keyIds: [],
			expiresAt: null,
		});

		await verifyServiceToken(env.AUDIT_DB, token);
		const [entry] = await listServiceTokens(env.AUDIT_DB);
		expect(entry?.lastUsedAt).not.toBeNull();
	});

	it("revoke is idempotent-safe and reports unknown ids", async () => {
		expect(await revokeServiceToken(env.AUDIT_DB, crypto.randomUUID())).toBe(false);
	});
});

describe("caller auth on /sign", () => {
	it("rejects an unknown service token", async () => {
		const response = await request("/sign", "gst_invalid", {
			method: "POST",
			body: "data",
		});
		expect(response.status).toBe(401);
		const body = (await response.json()) as { code: string };
		expect(body.code).toBe("AUTH_INVALID");
	});

	it("enforces the token key allowlist before any signing work", async () => {
		const token = generateToken();
		await insertServiceToken(env.AUDIT_DB, {
			name: "ci/limited",
			token,
			keyIds: ["AAAAAAAAAAAAAAAA"],
			expiresAt: null,
		});

		// env.KEY_ID (the default) is not in the allowlist -> 403
		const response = await request("/sign", token, {
			method: "POST",
			body: "commit data",
		});
		expect(response.status).toBe(403);
	});

	it("lets a valid token through auth (fails later on missing key)", async () => {
		const token = generateToken();
		await insertServiceToken(env.AUDIT_DB, {
			name: "ci/full",
			token,
			keyIds: [],
			expiresAt: null,
		});

		const response = await request("/sign", token, {
			method: "POST",
			body: "commit data",
		});
		// Auth passed; the test environment has no stored key, so the request
		// reaches key lookup and fails there.
		expect(response.status).toBe(404);
		const body = (await response.json()) as { code: string };
		expect(body.code).toBe("KEY_NOT_FOUND");
	});

	it("still routes non-prefixed bearers through OIDC", async () => {
		const response = await request("/sign", "not-a-service-token", {
			method: "POST",
			body: "data",
		});
		expect(response.status).toBe(401);
	});
});

describe("admin token management", () => {
	it("mints, lists, and revokes a token end to end", async () => {
		const minted = await request("/admin/tokens", env.ADMIN_TOKEN, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "ci/e2e", expiresInDays: 30 }),
		});
		expect(minted.status).toBe(201);
		const created = (await minted.json()) as {
			id: string;
			token: string;
			expiresAt: string | null;
		};
		expect(created.token).toMatch(/^gst_/);
		expect(created.expiresAt).not.toBeNull();

		const listed = await request("/admin/tokens", env.ADMIN_TOKEN);
		expect(listed.status).toBe(200);
		const { tokens } = (await listed.json()) as {
			tokens: { name: string; id: string }[];
		};
		expect(tokens.map((entry) => entry.name)).toContain("ci/e2e");
		expect(JSON.stringify(tokens)).not.toContain(created.token.slice(4));

		// The minted token authenticates until revoked
		const before = await request("/sign", created.token, {
			method: "POST",
			body: "data",
		});
		expect(before.status).toBe(404); // past auth, no key stored

		const revoked = await request(`/admin/tokens/${created.id}`, env.ADMIN_TOKEN, { method: "DELETE" });
		expect(revoked.status).toBe(200);

		const after = await request("/sign", created.token, {
			method: "POST",
			body: "data",
		});
		expect(after.status).toBe(401);
	});

	it("rejects duplicate token names", async () => {
		const mint = () =>
			request("/admin/tokens", env.ADMIN_TOKEN, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "ci/dup" }),
			});
		expect((await mint()).status).toBe(201);
		expect((await mint()).status).toBe(409);
	});

	it("rejects invalid names and key ids", async () => {
		const bad = await request("/admin/tokens", env.ADMIN_TOKEN, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "spaces are bad" }),
		});
		expect(bad.status).toBe(400);

		const badKey = await request("/admin/tokens", env.ADMIN_TOKEN, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "ci/badkey", keyIds: ["nope"] }),
		});
		expect(badKey.status).toBe(400);
	});

	it("requires admin auth", async () => {
		const response = await request("/admin/tokens", "wrong-token");
		expect(response.status).toBe(401);
	});
});
