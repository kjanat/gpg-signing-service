import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import app from "#gpg-signing-service";

describe("Public Key Route", () => {
	it("should return public key for valid keyId", async () => {
		const ctx = createExecutionContext();
		const keyId = "FEDCBA9876543210";

		// 1. Generate a valid key
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Test", email: "test@example.com" }],
			format: "armored",
		});

		// Parse the key to get real fingerprint
		const parsedKey = await openpgp.readPrivateKey({ armoredKey: privateKey });
		const fingerprint = parsedKey.getFingerprint();

		// 2. Store the key
		const keyStorageId = env.KEY_STORAGE.idFromName("global");
		const keyStorage = env.KEY_STORAGE.get(keyStorageId);
		await keyStorage.fetch(
			new Request("http://internal/store-key", {
				method: "POST",
				body: JSON.stringify({
					armoredPrivateKey: privateKey,
					keyId,
					fingerprint,
					createdAt: new Date().toISOString(),
					algorithm: "EdDSA",
				}),
				headers: { "Content-Type": "application/json" },
			}),
		);

		// 3. Fetch public key
		const response = await app.fetch(new Request(`http://localhost/public-key?keyId=${keyId}`), env, ctx);
		await waitOnExecutionContext(ctx);

		// 4. Verify response
		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toBe("application/pgp-keys");
		const body = await response.text();
		expect(body).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
	});

	it("should return 404 for a key that was never stored", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/public-key?keyId=EEEEEEEEEEEEEEEE"), env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(404);
		const body = (await response.json()) as { code: string };
		expect(body.code).toBe("KEY_NOT_FOUND");
	});
});

describe("Global Error Handling", () => {
	it("should handle errors in publicKeyRoute", async () => {
		const ctx = createExecutionContext();

		// 1. Store a key with INVALID content to cause openpgp.readPrivateKey to throw
		const keyStorageId = env.KEY_STORAGE.idFromName("global");
		const keyStorage = env.KEY_STORAGE.get(keyStorageId);
		await keyStorage.fetch(
			new Request("http://internal/store-key", {
				method: "POST",
				body: JSON.stringify({
					armoredPrivateKey: "invalid-key-content",
					keyId: "9999999999999999",
					fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
					createdAt: new Date().toISOString(),
					algorithm: "RSA",
				}),
				headers: { "Content-Type": "application/json" },
			}),
		);

		const response = await app.fetch(new Request("http://localhost/public-key?keyId=9999999999999999"), env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(500);
		const body = (await response.json()) as { code: string };
		expect(body.code).toBe("KEY_PROCESSING_ERROR");
	});

	it("should handle unhandled errors via the global error handler", async () => {
		// Cause an error that's NOT caught by route handlers: a null DO stub
		// blows up when the route tries to call .fetch() on it.
		const originalGet = env.KEY_STORAGE.get;
		env.KEY_STORAGE.get = () => {
			return null as unknown as DurableObjectStub;
		};

		try {
			const ctx = createExecutionContext();
			const response = await app.fetch(new Request("http://localhost/public-key"), env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(500);
			const body = (await response.json()) as { code: string; requestId: string };
			expect(body.code).toBe("INTERNAL_ERROR");
			expect(body.requestId).toBeTruthy();
		} finally {
			// Restore
			env.KEY_STORAGE.get = originalGet;
		}
	});
});

describe("API Documentation Routes", () => {
	it("should serve the OpenAPI spec at /doc", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/doc"), env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		const spec = (await response.json()) as { openapi: string; paths: Record<string, unknown> };
		expect(spec.openapi).toMatch(/^3\./);
		expect(Object.keys(spec.paths).length).toBeGreaterThan(0);
	});

	it("should serve the Swagger UI at /ui with a usable CSP", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/ui"), env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		const html = await response.text();
		expect(html).toContain('id="swagger-ui"');
		expect(html).toContain("SwaggerUIBundle");

		// The page is useless unless the CSP allows the CDN assets and the
		// inline bootstrap that mounts SwaggerUIBundle.
		const csp = response.headers.get("Content-Security-Policy") ?? "";
		expect(csp).toContain("https://cdn.jsdelivr.net");
		expect(csp).toContain("'unsafe-inline'");
	});
});
