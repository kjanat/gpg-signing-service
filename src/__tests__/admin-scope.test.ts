/**
 * The boundary between the two admin credentials.
 *
 * `ADMIN_READONLY_TOKEN` exists so a scheduled monitor can read key expiry
 * without also holding the authority to delete a signing key, mint a service
 * token or rewrite the trust list. That claim is only worth anything if it is
 * checked against the *whole* admin surface rather than the routes somebody
 * thought of, so the table below is compared with the generated OpenAPI
 * document: a new admin route fails this suite until it is classified, and a
 * route that changes state cannot be classified as a read without also being
 * proved not to mutate.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { beforeAll, describe, expect, it } from "vitest";
import app from "#gpg-signing-service";
import { openApiConfig, WWW_AUTHENTICATE_INSUFFICIENT_SCOPE } from "#lib/openapi";

const READONLY = "test-readonly-admin-token";
const FULL = "test-admin-token";

/** The key the read paths are exercised against. */
const SEEDED_KEY_ID = "5C0BE7E57000000A";
/** A second key, so the delete tests have something to destroy. */
const DOOMED_KEY_ID = "5C0BE7E57000000B";

const SEEDED_ISSUER = "https://gitlab.com";

interface Envelope {
	error: string;
	code: string;
	requestId?: string;
	hint?: string;
	docs?: string;
}

async function request(path: string, init: RequestInit = {}, overrides: Record<string, unknown> = {}) {
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request(`http://localhost${path}`, {
			...init,
			headers: { "Content-Type": "application/json", ...init.headers },
		}),
		{ ...env, ...overrides },
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

/** A request carrying one of the two admin bearers. */
function asAdmin(token: string, path: string, init: RequestInit = {}, overrides: Record<string, unknown> = {}) {
	return request(path, { ...init, headers: { Authorization: `Bearer ${token}`, ...init.headers } }, overrides);
}

async function envelope(response: Response): Promise<Envelope> {
	return (await response.json()) as Envelope;
}

const MIGRATION_SQL = [
	`CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		request_id TEXT NOT NULL,
		action TEXT NOT NULL,
		issuer TEXT NOT NULL,
		subject TEXT NOT NULL,
		key_id TEXT NOT NULL,
		success INTEGER NOT NULL DEFAULT 0,
		error_code TEXT,
		metadata TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS service_tokens (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		token_hash TEXT NOT NULL UNIQUE,
		key_ids TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		expires_at TEXT,
		revoked_at TEXT,
		last_used_at TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS oidc_subjects (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		issuer TEXT NOT NULL,
		subject_prefix TEXT NOT NULL,
		key_ids TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		expires_at TEXT,
		revoked_at TEXT,
		last_used_at TEXT
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_subjects_issuer_prefix
		ON oidc_subjects (issuer, subject_prefix) WHERE revoked_at IS NULL`,
];

async function generateKey(email: string): Promise<string> {
	const { privateKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "ed25519Legacy",
		userIDs: [{ name: "Scope Test", email }],
		passphrase: env.KEY_PASSPHRASE,
		format: "armored",
	});
	return privateKey;
}

/** Ids minted by the fixture, so the by-id routes address something real. */
const seeded = { tokenId: "", subjectId: "" };

async function uploadKey(keyId: string, email: string): Promise<void> {
	const response = await asAdmin(FULL, "/admin/keys", {
		method: "POST",
		body: JSON.stringify({ armoredPrivateKey: await generateKey(email), keyId }),
	});
	expect([keyId, response.status]).toEqual([keyId, 201]);
}

beforeAll(async () => {
	for (const statement of MIGRATION_SQL) {
		await env.AUDIT_DB.prepare(statement).run();
	}

	await uploadKey(SEEDED_KEY_ID, "seeded@scope.test");
	await uploadKey(DOOMED_KEY_ID, "doomed@scope.test");

	const token = await asAdmin(FULL, "/admin/tokens", {
		method: "POST",
		body: JSON.stringify({ name: "scope-test-token" }),
	});
	expect(token.status).toBe(201);
	seeded.tokenId = (await token.json<{ id: string }>()).id;

	const subject = await asAdmin(FULL, "/admin/subjects", {
		method: "POST",
		body: JSON.stringify({
			name: "scope-test-subject",
			issuer: SEEDED_ISSUER,
			subjectPrefix: "project_path:scope-test/monitor",
		}),
	});
	expect(subject.status).toBe(201);
	seeded.subjectId = (await subject.json<{ id: string }>()).id;
});

/**
 * One entry per admin operation the service publishes.
 *
 * `template` is the OpenAPI path, so the document can be diffed against this
 * table; `path()` is the concrete request, deferred because the by-id routes
 * address rows the fixture mints.
 */
interface AdminOperation {
	method: string;
	template: string;
	path: () => string;
	body?: () => string;
}

const READS: AdminOperation[] = [
	{ method: "GET", template: "/admin/audit", path: () => "/admin/audit" },
	{ method: "GET", template: "/admin/keys", path: () => "/admin/keys" },
	{
		method: "GET",
		template: "/admin/keys/{keyId}/public",
		path: () => `/admin/keys/${SEEDED_KEY_ID}/public`,
	},
	{ method: "GET", template: "/admin/subjects", path: () => "/admin/subjects" },
	{ method: "GET", template: "/admin/tokens", path: () => "/admin/tokens" },
];

const MUTATIONS: AdminOperation[] = [
	{
		method: "POST",
		template: "/admin/keys",
		path: () => "/admin/keys",
		body: () =>
			JSON.stringify({ armoredPrivateKey: "-----BEGIN PGP PRIVATE KEY BLOCK-----", keyId: "5C0BE7E5700F0BB1" }),
	},
	{
		method: "POST",
		template: "/admin/keys/x509",
		path: () => "/admin/keys/x509",
		body: () =>
			JSON.stringify({
				keyId: "5C0BE7E5700F0BB2",
				privateKeyPem: "-----BEGIN PRIVATE KEY-----\nnot-real\n-----END PRIVATE KEY-----",
				certificatePem: "-----BEGIN CERTIFICATE-----\nnot-real\n-----END CERTIFICATE-----",
			}),
	},
	{ method: "DELETE", template: "/admin/keys/{keyId}", path: () => `/admin/keys/${DOOMED_KEY_ID}` },
	{
		method: "POST",
		template: "/admin/tokens",
		path: () => "/admin/tokens",
		body: () => JSON.stringify({ name: "minted-by-the-monitor" }),
	},
	{ method: "DELETE", template: "/admin/tokens/{id}", path: () => `/admin/tokens/${seeded.tokenId}` },
	{
		method: "POST",
		template: "/admin/subjects",
		path: () => "/admin/subjects",
		body: () =>
			JSON.stringify({
				name: "trusted-by-the-monitor",
				issuer: SEEDED_ISSUER,
				subjectPrefix: "project_path:scope-test/escalation",
			}),
	},
	{ method: "DELETE", template: "/admin/subjects/{id}", path: () => `/admin/subjects/${seeded.subjectId}` },
];

function send(token: string, operation: AdminOperation, overrides: Record<string, unknown> = {}) {
	const init: RequestInit = { method: operation.method };
	if (operation.body) init.body = operation.body();
	return asAdmin(token, operation.path(), init, overrides);
}

const label = (operation: AdminOperation) => `${operation.method} ${operation.template}`;

describe("the admin route table this suite claims to cover", () => {
	// The claim "the read-only credential is denied on every mutation route" is
	// only as good as the list of routes. Reading that list off the document the
	// service publishes is what makes it a claim about the service rather than
	// about this file.
	const documented = (() => {
		// Round-tripped through JSON for the same reason openapi-spec.test.ts does
		// it: the generated object's declared type does not admit an index
		// signature, and the plain document is what a client actually reads.
		const document = JSON.parse(JSON.stringify(app.getOpenAPIDocument(openApiConfig))) as {
			paths: Record<string, Record<string, unknown>>;
		};
		const methods = new Set(["get", "post", "put", "patch", "delete", "head"]);
		return Object.entries(document.paths)
			.filter(([path]) => path.startsWith("/admin/"))
			.flatMap(([path, operations]) =>
				Object.keys(operations)
					.filter((method) => methods.has(method))
					.map((method) => `${method.toUpperCase()} ${path}`),
			)
			.sort();
	})();

	it("is every admin operation the service publishes, and nothing else", () => {
		expect([...READS, ...MUTATIONS].map(label).sort()).toEqual(documented);
	});

	it("pins the allowed set literally", () => {
		// Written out rather than derived, so widening what a monitoring
		// credential may read is a visible edit to this list and not a
		// side effect of adding a route.
		expect(READS.map(label)).toEqual([
			"GET /admin/audit",
			"GET /admin/keys",
			"GET /admin/keys/{keyId}/public",
			"GET /admin/subjects",
			"GET /admin/tokens",
		]);
	});

	it("pins the denied set literally", () => {
		expect(MUTATIONS.map(label).sort()).toEqual([
			"DELETE /admin/keys/{keyId}",
			"DELETE /admin/subjects/{id}",
			"DELETE /admin/tokens/{id}",
			"POST /admin/keys",
			"POST /admin/keys/x509",
			"POST /admin/subjects",
			"POST /admin/tokens",
		]);
	});

	it("covers the four routes the key-expiry monitor calls", () => {
		// Named separately from the list above because these are a requirement on
		// the service, not a description of it: dropping one from the read set
		// breaks the scheduled workflow, and nothing else in this suite says so.
		const required = ["GET /admin/keys", "GET /admin/keys/{keyId}/public", "GET /admin/subjects", "GET /admin/tokens"];
		expect(READS.map(label)).toEqual(expect.arrayContaining(required));
	});
});

describe("the read-only admin credential", () => {
	for (const operation of READS) {
		it(`is served ${label(operation)}`, async () => {
			const response = await send(READONLY, operation);

			// 2xx exactly, not "anything but a refusal": a 404 from a route that
			// silently stopped serving would otherwise read as success.
			expect([label(operation), response.status]).toEqual([label(operation), 200]);
		});
	}

	for (const operation of MUTATIONS) {
		it(`is refused ${label(operation)}`, async () => {
			const response = await send(READONLY, operation);
			const body = await envelope(response);

			expect([label(operation), response.status, body.code]).toEqual([
				label(operation),
				403,
				"AUTH_SCOPE_INSUFFICIENT",
			]);
			// 403 and not 401, said in the header as well as the code: a caller
			// whose generic handler branches on the challenge must not be told to
			// re-authenticate with a credential that is already correct.
			expect(response.headers.get("WWW-Authenticate")).toBe(WWW_AUTHENTICATE_INSUFFICIENT_SCOPE);
			// The same envelope every other refusal carries, so the refusal is
			// greppable in the audit trail and self-documenting in a CI log.
			expect(body.requestId).toBe(response.headers.get("X-Request-ID"));
			expect(body.docs).toBe("http://localhost/e/AUTH_SCOPE_INSUFFICIENT");
			expect(body.hint).toContain("ADMIN_TOKEN");
		});
	}
});

describe("what the refused calls did not change", () => {
	// The status code is the promise; this is the property. A 403 returned
	// *after* the handler had already run would satisfy every assertion above.

	it("left the key it was refused permission to delete", async () => {
		const response = await asAdmin(READONLY, "/admin/keys");
		const { keys } = await response.json<{ keys: { keyId: string }[] }>();

		expect(keys.map((key) => key.keyId)).toContain(DOOMED_KEY_ID);
	});

	it("minted no service token, and revoked none", async () => {
		const response = await asAdmin(READONLY, "/admin/tokens");
		const { tokens } = await response.json<{ tokens: { id: string; name: string; revokedAt: string | null }[] }>();

		expect(tokens.map((token) => token.name)).not.toContain("minted-by-the-monitor");
		expect(tokens.find((token) => token.id === seeded.tokenId)?.revokedAt ?? null).toBeNull();
	});

	it("trusted no subject, and revoked none", async () => {
		const response = await asAdmin(READONLY, "/admin/subjects");
		const { subjects } = await response.json<{ subjects: { id: string; name: string; revokedAt: string | null }[] }>();

		expect(subjects.map((subject) => subject.name)).not.toContain("trusted-by-the-monitor");
		expect(subjects.find((subject) => subject.id === seeded.subjectId)?.revokedAt ?? null).toBeNull();
	});
});

describe("the full admin credential", () => {
	for (const operation of MUTATIONS) {
		it(`still reaches the handler for ${label(operation)}`, async () => {
			// Asserted as "past the auth layer" rather than as success: two of these
			// carry deliberately unusable bodies, and what is under test is that the
			// 403 above was about the credential and not about the request.
			const response = await send(FULL, operation);

			expect([label(operation), response.status === 401 || response.status === 403]).toEqual([label(operation), false]);
		});
	}

	it("really can delete the key the read-only credential could not", async () => {
		// The other half of the boundary. Without this the suite would pass on a
		// service where nobody can delete anything.
		const deletion = await asAdmin(FULL, `/admin/keys/${DOOMED_KEY_ID}`, { method: "DELETE" });
		expect(deletion.status).toBe(200);

		const { keys } = await (await asAdmin(FULL, "/admin/keys")).json<{ keys: { keyId: string }[] }>();
		expect(keys.map((key) => key.keyId)).not.toContain(DOOMED_KEY_ID);
	});
});

describe("how the read-only credential is provisioned", () => {
	it("does not exist when ADMIN_READONLY_TOKEN is unset", async () => {
		// A deployment that never put the secret must not have a second working
		// bearer, and the refusal is a plain wrong-credential 401 — there is no
		// scope to be insufficient.
		const response = await asAdmin(READONLY, "/admin/keys", {}, { ADMIN_READONLY_TOKEN: undefined });

		expect(response.status).toBe(401);
		expect((await envelope(response)).code).toBe("AUTH_INVALID");
	});

	it("does not exist when ADMIN_READONLY_TOKEN is empty", async () => {
		// An unset wrangler secret and a `""` are the same thing to a caller, and
		// the empty string is what an unset variable expands to in the shell that
		// would have set it. Treating it as configured would hand the read scope
		// to `Authorization: Bearer `.
		const bare = await request("/admin/keys", { headers: { Authorization: "Bearer " } }, { ADMIN_READONLY_TOKEN: "" });

		expect(bare.status).toBe(401);
		expect((await envelope(bare)).code).toBe("AUTH_MISSING");
	});

	it("refuses the whole admin surface when the two secrets are equal", async () => {
		// The failure this configuration produces is silent and total: the
		// comparison cannot tell the two apart, so the credential labelled
		// read-only is a full administrator and every call the monitor makes
		// succeeds. Refused loudly instead, on reads as well as writes, because a
		// half-working admin API is how this goes unnoticed.
		for (const path of ["/admin/keys", "/admin/tokens"]) {
			const response = await asAdmin(FULL, path, {}, { ADMIN_READONLY_TOKEN: FULL });
			const body = await envelope(response);

			expect([path, response.status, body.code]).toEqual([path, 500, "SERVICE_MISCONFIGURED"]);
			expect(body.hint).toContain("ADMIN_READONLY_TOKEN");
		}
	});

	it("still refuses a bearer that is neither secret", async () => {
		const response = await asAdmin("not-either-of-them", "/admin/keys");

		expect(response.status).toBe(401);
		expect((await envelope(response)).code).toBe("AUTH_INVALID");
	});
});
