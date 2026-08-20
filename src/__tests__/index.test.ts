import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import app from "#gpg-signing-service";
import { openApiConfig } from "#lib/openapi";

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

	it("should define every security scheme the routes reference at /doc", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/doc"), env, ctx);
		await waitOnExecutionContext(ctx);

		const spec = (await response.json()) as {
			components?: { securitySchemes?: Record<string, unknown> };
			paths: Record<string, Record<string, { security?: Record<string, unknown>[] }>>;
		};

		const defined = Object.keys(spec.components?.securitySchemes ?? {});
		expect(defined).toEqual(expect.arrayContaining(["oidcAuth", "bearerAuth", "serviceTokenAuth"]));

		// A `security` requirement naming a scheme the document never defines makes
		// the spec invalid and strips the Authorize button out of the Swagger UI.
		const referenced = new Set(
			Object.values(spec.paths)
				.flatMap((methods) => Object.values(methods))
				.flatMap((operation) => operation.security ?? [])
				.flatMap((requirement) => Object.keys(requirement)),
		);
		expect(referenced.size).toBeGreaterThan(0);
		for (const name of referenced) {
			expect(defined).toContain(name);
		}
	});

	it("should declare a 401 on every operation that requires a credential", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/doc"), env, ctx);
		await waitOnExecutionContext(ctx);

		const spec = (await response.json()) as {
			paths: Record<
				string,
				Record<
					string,
					{
						security?: Record<string, unknown>[];
						responses: Record<string, { content?: Record<string, { schema?: { $ref?: string } }> }>;
					}
				>
			>;
		};

		// An undeclared status has no typed field in a generated client, so every
		// 401 the auth middleware returns arrives with its body intact and nowhere
		// to read it from — which is how `Subject is not trusted for signing`
		// reached operators as a bare "unexpected status code: 401".
		const authenticated = Object.entries(spec.paths).flatMap(([path, methods]) =>
			Object.entries(methods)
				.filter(([, operation]) => (operation.security ?? []).length > 0)
				.map(([method, operation]) => ({ id: `${method.toUpperCase()} ${path}`, operation })),
		);
		expect(authenticated.length).toBeGreaterThan(0);

		for (const { id, operation } of authenticated) {
			const unauthorized = operation.responses["401"];
			expect(unauthorized, `${id} declares no 401`).toBeDefined();
			expect(unauthorized?.content?.["application/json"]?.schema?.$ref, `${id} 401 schema`).toBe(
				"#/components/schemas/ErrorResponse",
			);
		}
	});

	it("should declare a security requirement on every route mounted behind auth", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/doc"), env, ctx);
		await waitOnExecutionContext(ctx);

		const spec = (await response.json()) as {
			paths: Record<string, Record<string, { security?: Record<string, unknown>[] }>>;
		};

		// The 401 assertion above is conditioned on `security`, which is written by
		// hand in each createRoute call — so a route that omits it declares no 401
		// either and both checks stay silent about it. Auth is not per-route: index
		// mounts /sign behind callerAuth and everything under /admin behind
		// adminAuth, which is the list the document has to agree with.
		//
		// Matched as mount points rather than as prefixes. `app.route("/sign", …)`
		// covers everything the sub-app declares, so a later `/sign/verify` is
		// behind callerAuth the moment it is added and has to be caught here —
		// while a bare `startsWith` would also claim a future top-level
		// `/administration`, which nothing mounts behind adminAuth.
		const AUTH_MOUNTS = ["/sign", "/admin"];
		const behindAuth = Object.entries(spec.paths).filter(([path]) =>
			AUTH_MOUNTS.some((mount) => path === mount || path.startsWith(`${mount}/`)),
		);
		expect(behindAuth.length).toBeGreaterThan(0);

		for (const [path, methods] of behindAuth) {
			for (const [method, operation] of Object.entries(methods)) {
				expect(
					(operation.security ?? []).length,
					`${method.toUpperCase()} ${path} is behind auth but declares no security requirement`,
				).toBeGreaterThan(0);
			}
		}
	});

	it("should include security schemes when generating a document directly", () => {
		const spec = app.getOpenAPIDocument(openApiConfig);
		expect(Object.keys(spec.components?.securitySchemes ?? {})).toEqual(
			expect.arrayContaining(["oidcAuth", "bearerAuth", "serviceTokenAuth"]),
		);
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

	it("should allow every remote asset the Swagger UI page actually references", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/ui"), env, ctx);
		await waitOnExecutionContext(ctx);

		const html = await response.text();
		const csp = response.headers.get("Content-Security-Policy") ?? "";
		const directive = (name: string): string => csp.split("; ").find((entry) => entry.startsWith(`${name} `)) ?? "";

		const originsIn = (pattern: RegExp): string[] => [
			...new Set(
				[...html.matchAll(pattern)]
					.map((match) => match[1])
					.filter((url): url is string => url !== undefined)
					.map((url) => new URL(url).origin),
			),
		];

		// The CDN host lives inside @hono/swagger-ui, not in our code. Asserting
		// against the URLs the page emits — rather than a hardcoded jsDelivr
		// string — makes a CDN change fail here instead of silently shipping a
		// blank /ui again (#25).
		const scriptOrigins = originsIn(/<script[^>]+src="(https?:\/\/[^"]+)"/g);
		const styleOrigins = originsIn(/<link[^>]+href="(https?:\/\/[^"]+)"/g);

		expect(scriptOrigins.length).toBeGreaterThan(0);
		expect(styleOrigins.length).toBeGreaterThan(0);

		for (const origin of scriptOrigins) {
			expect(directive("script-src")).toContain(origin);
		}
		for (const origin of styleOrigins) {
			expect(directive("style-src")).toContain(origin);
		}
	});

	it("should disable the third-party Swagger validator badge", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/ui"), env, ctx);
		await waitOnExecutionContext(ctx);

		// Left at its default, Swagger UI loads an <img> from validator.swagger.io,
		// which the docs CSP blocks into a broken "Error" image — and which would
		// hand the spec URL to a third party if it were allowed.
		expect(await response.text()).toContain("validatorUrl: 'none'");
	});
});
