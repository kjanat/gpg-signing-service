import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as jose from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import { varyOnOrigin } from "#middleware/security";
import { logAuditEvent } from "#utils/audit";
import { logger } from "#utils/logger";
import { insertOIDCSubject, revokeOIDCSubject } from "#utils/oidc-subjects";
import { clearTrustedSubjects, seedTrustedSubjects } from "./helpers/oidc-subjects";

const parseJson = async <T>(response: Response): Promise<T> => (await response.json()) as T;

// Mock fetch for JWKS
const { middlewareFetchMock, validateUrlMock } = vi.hoisted(() => ({
	middlewareFetchMock: vi.fn(),
	validateUrlMock: vi.fn(),
}));

vi.mock("#utils/fetch", () => ({
	fetchWithTimeout: middlewareFetchMock,
}));

vi.mock("#utils/url-validation", () => ({
	validateUrl: validateUrlMock,
}));

// Mock audit logging to avoid database errors in tests
vi.mock("#utils/audit", async (importOriginal) => {
	const actual = await importOriginal<typeof import("#utils/audit")>();
	return {
		...actual,
		logAuditEvent: vi.fn(async () => undefined),
	};
});

/** A RATE_LIMITER binding that answers every call with `body`, or `status` if given. */
function rateLimiterAnswering(body: unknown, status?: number): DurableObjectNamespace {
	return {
		idFromName: () => ({}) as DurableObjectId,
		get: () => ({
			fetch: async () => (status ? new Response("boom", { status }) : Response.json(body)),
		}),
	} as unknown as DurableObjectNamespace;
}

/** A RATE_LIMITER binding that is unreachable. */
function rateLimiterThrowing(reason: unknown = new Error("Rate limiter unavailable")): DurableObjectNamespace {
	const fail = () => {
		throw reason;
	};
	return { idFromName: fail, get: fail } as unknown as DurableObjectNamespace;
}

// Helper to make requests
async function makeRequest(path: string, options: RequestInit = {}, customEnv?: Partial<Env>): Promise<Response> {
	const ctx = createExecutionContext();
	const request = new Request(`http://localhost${path}`, options);
	const response = await app.fetch(request, customEnv ? { ...env, ...customEnv } : env, ctx);
	await waitOnExecutionContext(ctx);
	// Additional waits to ensure all microtasks, promise chains, and timers complete
	// This handles edge cases where libraries like jose might create floating promises
	await new Promise((resolve) => setImmediate(resolve));
	await new Promise((resolve) => setTimeout(resolve, 10));
	return response;
}

describe("Security Headers Middleware", () => {
	it("should set X-Content-Type-Options", async () => {
		const response = await makeRequest("/health");
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("should set X-Frame-Options", async () => {
		const response = await makeRequest("/health");
		expect(response.headers.get("X-Frame-Options")).toBe("DENY");
	});

	it("should set HSTS header", async () => {
		const response = await makeRequest("/health");
		expect(response.headers.get("Strict-Transport-Security")).toBe("max-age=31536000; includeSubDomains; preload");
	});

	it("should set Referrer-Policy", async () => {
		const response = await makeRequest("/health");
		expect(response.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
	});

	it("should set Content-Security-Policy", async () => {
		const response = await makeRequest("/health");
		expect(response.headers.get("Content-Security-Policy")).toBe("default-src 'none'; frame-ancestors 'none'");
	});

	it("should relax Content-Security-Policy for the Swagger UI page", async () => {
		const response = await makeRequest("/ui");
		const csp = response.headers.get("Content-Security-Policy") ?? "";

		expect(csp).toContain("script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net");
		expect(csp).toContain("style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net");
		expect(csp).toContain("connect-src 'self'");
		// Framing stays forbidden even on the docs page
		expect(csp).toContain("frame-ancestors 'none'");
	});

	it("should keep the strict Content-Security-Policy on /doc and API routes", async () => {
		for (const path of ["/doc", "/health", "/public-key"]) {
			const response = await makeRequest(path);
			expect(response.headers.get("Content-Security-Policy")).toBe("default-src 'none'; frame-ancestors 'none'");
		}
	});

	it("should set Permissions-Policy", async () => {
		const response = await makeRequest("/health");
		expect(response.headers.get("Permissions-Policy")).toBe("geolocation=(), microphone=(), camera=()");
	});

	describe("CORS", () => {
		/** `exactOptionalPropertyTypes` forbids assigning `undefined`, so unset by deleting. */
		function setAllowedOrigins(value: string | undefined): void {
			if (value === undefined) {
				delete env.ALLOWED_ORIGINS;
			} else {
				env.ALLOWED_ORIGINS = value;
			}
		}

		/** `env` is module-scoped and shared, so every case states its own allowlist. */
		function corsRequest(origin: string | undefined, method = "GET"): Promise<Response> {
			return makeRequest("/health", {
				method,
				headers: {
					...(origin === undefined ? {} : { Origin: origin }),
					...(method === "OPTIONS" ? { "Access-Control-Request-Method": "GET" } : {}),
				},
			});
		}

		beforeEach(() => {
			setAllowedOrigins(undefined);
		});

		afterEach(() => {
			setAllowedOrigins(undefined);
		});

		it("should handle CORS preflight for an allowed origin", async () => {
			setAllowedOrigins("https://allowed-origin.com");

			const response = await corsRequest("https://allowed-origin.com", "OPTIONS");

			expect(response.status).toBe(204);
			expect(response.headers.get("Access-Control-Allow-Origin")).toBe("https://allowed-origin.com");
			expect(response.headers.get("Access-Control-Allow-Methods")).toBe("GET, POST, DELETE, OPTIONS");
			expect(response.headers.get("Access-Control-Allow-Headers")).toBe("Authorization, Content-Type, X-Request-ID");
			expect(response.headers.get("Access-Control-Max-Age")).toBe("86400");
		});

		it("should handle CORS actual request for an allowed origin", async () => {
			setAllowedOrigins("https://allowed-origin.com");

			const response = await corsRequest("https://allowed-origin.com");

			expect(response.headers.get("Access-Control-Allow-Origin")).toBe("https://allowed-origin.com");
		});

		it("should handle CORS OPTIONS with disallowed origin", async () => {
			setAllowedOrigins("https://allowed.com");

			const response = await corsRequest("https://disallowed-origin.com", "OPTIONS");

			expect(response.status).toBe(204);
			expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
			expect(response.headers.get("Access-Control-Allow-Methods")).toBeNull();
		});

		it.each([
			["unset", undefined],
			["empty", ""],
			["only separators and whitespace", " , "],
		])("fails closed when ALLOWED_ORIGINS is %s", async (_label, allowlist) => {
			setAllowedOrigins(allowlist);

			const actual = await corsRequest("https://evil.example.com");
			const preflight = await corsRequest("https://evil.example.com", "OPTIONS");

			for (const response of [actual, preflight]) {
				expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
				expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
			}
		});

		it("never grants credentials, even to an allowed origin", async () => {
			setAllowedOrigins("https://allowed.com");

			const actual = await corsRequest("https://allowed.com");
			const preflight = await corsRequest("https://allowed.com", "OPTIONS");

			// Auth is a bearer token in `Authorization`, which no browser attaches
			// ambiently — so the header buys nothing and is never sent on either branch.
			expect(actual.headers.get("Access-Control-Allow-Credentials")).toBeNull();
			expect(preflight.headers.get("Access-Control-Allow-Credentials")).toBeNull();
		});

		it("rejects the null origin even when it is listed", async () => {
			// Sandboxed iframes, `data:` URLs and `file://` documents all send it, so
			// granting it would hand every such context the same shared origin.
			setAllowedOrigins("null,https://allowed.com");

			const actual = await corsRequest("null");
			const preflight = await corsRequest("null", "OPTIONS");

			expect(actual.headers.get("Access-Control-Allow-Origin")).toBeNull();
			expect(preflight.headers.get("Access-Control-Allow-Origin")).toBeNull();
		});

		it("still answers the null origin with the wildcard when `*` is listed", async () => {
			// The wildcard is checked before the null-origin refusal, and deliberately
			// so: `*` is an explicit opt-in to public browser access, and the CORS spec
			// already lets an opaque origin read a `*` response. The refusal above
			// covers `null` as an *allowlist entry*, which is the case that would
			// otherwise look like a targeted grant.
			setAllowedOrigins("*");

			const actual = await corsRequest("null");
			const preflight = await corsRequest("null", "OPTIONS");

			for (const response of [actual, preflight]) {
				expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
				expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
			}
		});

		it("answers a caller that sends no Origin with the wildcard too", async () => {
			// The wildcard is resolved before `Origin` is read, so a `*` deployment
			// answers every request identically and a shared cache needs one entry
			// rather than one per origin. Inert for the callers this reaches: nothing
			// consults `Access-Control-Allow-Origin` on a request it sent no `Origin`
			// on, which is every CI runner and Go client call this service serves.
			setAllowedOrigins("*");

			const actual = await corsRequest(undefined);
			const preflight = await corsRequest(undefined, "OPTIONS");

			for (const response of [actual, preflight]) {
				expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
				expect(response.headers.get("Vary")).toBeNull();
			}
		});

		it("trims whitespace around allowlist entries", async () => {
			setAllowedOrigins("https://a.example.com , https://b.example.com");

			const response = await corsRequest("https://b.example.com");

			expect(response.headers.get("Access-Control-Allow-Origin")).toBe("https://b.example.com");
		});

		it("echoes a literal wildcard rather than reflecting the origin when `*` is listed", async () => {
			setAllowedOrigins("*");

			const actual = await corsRequest("https://anyone.example.com");
			const preflight = await corsRequest("https://anyone.example.com", "OPTIONS");

			for (const response of [actual, preflight]) {
				expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
				expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
				// The answer no longer depends on the request origin, so caches need not key on it.
				expect(response.headers.get("Vary")).toBeNull();
			}
		});

		it("honours a wildcard listed beside real origins, granting every origin", async () => {
			// `entries.includes("*")` does not require the wildcard to stand alone, so
			// appending one to an allowlist that looks restrictive opens the whole
			// deployment. Pinned because the blast radius is much larger than the diff
			// that would cause it.
			setAllowedOrigins("https://allowed.com,*");

			const response = await corsRequest("https://anyone.example.com");

			expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
		});

		it.each([
			["an allowed origin", "https://allowed.com"],
			["a denied origin", "https://evil.example.com"],
			["no origin at all", undefined],
		])("sets Vary: Origin for %s", async (_label, origin) => {
			setAllowedOrigins("https://allowed.com");

			const actual = await corsRequest(origin);
			const preflight = await corsRequest(origin, "OPTIONS");

			expect(actual.headers.get("Vary")).toBe("Origin");
			expect(preflight.headers.get("Vary")).toBe("Origin");
		});

		it("exposes X-Request-ID even on a response that carries no rate-limit headers", async () => {
			// /health sets no rate-limit headers, so the conditional half of the list
			// is empty here — but X-Request-ID is on every response and is the header
			// a browser caller needs to quote when filing a bug. It is named
			// unconditionally because `requestId` is the outermost middleware and
			// stamps it *after* `securityHeaders` builds this list, so a presence test
			// would see it only on the signing route, which sets it itself. The
			// conditional half is pinned on the admin route in branch-coverage.test.ts.
			setAllowedOrigins("https://allowed.com");

			const response = await corsRequest("https://allowed.com");

			expect(response.headers.get("Access-Control-Expose-Headers")).toBe("X-Request-ID");
			expect(response.headers.get("X-Request-ID")).not.toBeNull();
		});

		it("exposes X-Request-ID on a 404, which no route handler touches", async () => {
			// The claim the unconditional listing rests on is that *every* response
			// carries the header. `app.notFound` synthesises its response outside any
			// route, so it is the path most likely to have escaped `requestId` — it
			// does not, because `notFound` runs inside the middleware chain.
			setAllowedOrigins("https://allowed.com");

			const response = await makeRequest("/no-such-route", { headers: { Origin: "https://allowed.com" } });

			expect(response.status).toBe(404);
			expect(response.headers.get("X-Request-ID")).not.toBeNull();
			expect(response.headers.get("Access-Control-Expose-Headers")).toBe("X-Request-ID");
		});

		it("names X-Request-ID in Access-Control-Allow-Headers and exposes it back", async () => {
			// Both directions, on the same deployment: a browser may *send* the header
			// (the preflight allows it) and may *read* it back (the actual response
			// exposes it). Allowing one without the other is the shape that makes a
			// caller's correlation id vanish on the way home.
			setAllowedOrigins("https://allowed.com");

			const preflight = await corsRequest("https://allowed.com", "OPTIONS");
			const actual = await corsRequest("https://allowed.com");

			expect(preflight.headers.get("Access-Control-Allow-Headers")).toContain("X-Request-ID");
			expect(actual.headers.get("Access-Control-Expose-Headers")).toContain("X-Request-ID");
		});

		// No handler in the service sets Vary, so the merge paths are only
		// reachable directly — but a future one must not have its token clobbered.
		describe("varyOnOrigin", () => {
			it.each([
				["absent", undefined, "Origin"],
				["another token", "Accept-Encoding", "Accept-Encoding, Origin"],
				["Origin already, differently cased", "origin", "origin"],
				["Origin among others", "Accept-Encoding, Origin", "Accept-Encoding, Origin"],
				["the wildcard", "*", "*"],
			])("with Vary %s", (_label, existing, expected) => {
				const headers = new Headers(existing === undefined ? {} : { Vary: existing });

				varyOnOrigin(headers);

				expect(headers.get("Vary")).toBe(expected);
			});
		});
	});

	describe("OIDC Token Validation", () => {
		beforeAll(async () => {
			// The OIDC path now requires a trusted-subject row.
			await seedTrustedSubjects(env.AUDIT_DB);

			// Clean up real KV cache to prevent test pollution from other test files (e.g. sign.test.ts)
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com/unique-test-issuer");
		});

		beforeEach(async () => {
			vi.resetAllMocks();
			middlewareFetchMock.mockReset();
			validateUrlMock.mockReset();
			// Default: validateUrl passes (no SSRF detected)
			validateUrlMock.mockResolvedValue(undefined);
			// Clean up KV cache before each test to avoid stale state
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com/unique-test-issuer");
		});

		afterEach(async () => {
			vi.resetAllMocks();
			middlewareFetchMock.mockReset();
			validateUrlMock.mockReset();
			// Clean up real KV cache to prevent test pollution
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com/unique-test-issuer");
		});

		async function setupJWKSMock(issuer: string, kid: string, publicKey: CryptoKey) {
			const jwk = await jose.exportJWK(publicKey);
			jwk.kid = kid;
			jwk.use = "sig";

			// Mock OIDC discovery
			middlewareFetchMock.mockImplementation(async (url: string) => {
				if (url === `${issuer}/.well-known/openid-configuration`) {
					return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
				}
				if (url === `${issuer}/jwks`) {
					return new Response(JSON.stringify({ keys: [jwk] }));
				}
				return new Response("Not Found", { status: 404 });
			});
		}

		it("tolerates whitespace around a comma in ALLOWED_ISSUERS", async () => {
			// /admin/subjects trims before deciding an issuer is acceptable. If this
			// side did not, a padded entry would be trustable at create time and
			// refused here — a row that lists as trusted and can never match.
			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: "https://gitlab.com",
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest(
				"/sign",
				{ method: "POST", headers: { Authorization: `Bearer ${token}` }, body: "commit data" },
				{
					ALLOWED_ISSUERS: "https://token.actions.githubusercontent.com, https://gitlab.com" as Env["ALLOWED_ISSUERS"],
				},
			);

			// Still 401 — nothing signs this token — but it must fail past the
			// issuer gate rather than at it.
			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string }>(response);
			expect(body.error).not.toContain("Issuer not allowed");
		});

		it("reports an unreadable policy store as 503 without leaking the schema", async () => {
			// Merge-day failure mode: the Worker deploys before task db:migrate
			// runs. A database we cannot read is not a bad credential, and the
			// caller must not be handed our table names to work that out.
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");

			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "store-down-key";
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, kid, publicKey);

			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const realPrepare = env.AUDIT_DB.prepare.bind(env.AUDIT_DB);
			const spy = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
				if (query.includes("FROM oidc_subjects")) {
					throw new Error("D1_ERROR: no such table: oidc_subjects: SQLITE_ERROR");
				}
				return realPrepare(query);
			});

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});
			spy.mockRestore();

			expect(response.status).toBe(503);
			const body = await parseJson<{ error: string; code: string }>(response);
			expect(body.code).toBe("INTERNAL_ERROR");
			expect(body.error).not.toContain("oidc_subjects");
			expect(body.error).not.toContain("SQLITE");
		});

		it("rejects a cryptographically valid token whose subject is not trusted", async () => {
			// The whole point of the subject allowlist: the token here is
			// perfectly valid — right issuer, right audience, good signature —
			// it is simply from a repository nobody trusted. Every repo on
			// GitHub Actions can produce exactly this.
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await clearTrustedSubjects(env.AUDIT_DB);

			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "untrusted-key";
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, kid, publicKey);

			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:attacker/evil:ref:refs/heads/main",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string; code: string }>(response);
			expect(body.error).toContain("not trusted");
			expect(body.code).toBe("AUTH_INVALID");

			// Restore the fixture for the rest of the suite.
			await seedTrustedSubjects(env.AUDIT_DB);
		});

		it("distinguishes a revoked trust still in use from an unknown subject", async () => {
			// Both are 401 to the caller — telling a stranger their subject matches
			// a revoked row would confirm the row exists. But for the operator these
			// are different events: a killed credential still being presented is an
			// incident, an unknown subject on a shared issuer is background traffic.
			// Collapsing them files the incident under the noise.
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await clearTrustedSubjects(env.AUDIT_DB);

			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "revoked-key";
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, kid, publicKey);

			const subjectId = await insertOIDCSubject(env.AUDIT_DB, {
				name: "ci/killed",
				issuer,
				subjectPrefix: "repo:victim/svc",
				keyIds: [],
				expiresAt: null,
			});
			expect(await revokeOIDCSubject(env.AUDIT_DB, subjectId)).toMatchObject({ name: "ci/killed", stillCoveredBy: [] });

			const mint = async (sub: string) =>
				new jose.SignJWT({ iss: issuer, sub, aud: "gpg-signing-service" })
					.setProtectedHeader({ alg: "ES256", kid })
					.setIssuedAt()
					.setExpirationTime("1h")
					.sign(privateKey);

			const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});

			const reused = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${await mint("repo:victim/svc:ref:refs/heads/main")}` },
				body: "commit data",
			});
			expect(reused.status).toBe(401);
			// The response must not differ from the stranger's.
			expect(await parseJson<{ error: string }>(reused)).toMatchObject({
				error: "Subject is not trusted for signing",
				code: "AUTH_INVALID",
			});
			expect(warnSpy).toHaveBeenCalledWith(
				"Revoked OIDC trust presented",
				expect.objectContaining({ subjectId, subjectPolicy: "ci/killed" }),
			);
			// A killed credential still in use outlives the log store's retention,
			// so it gets a durable row too — unlike the unknown-subject arm, which
			// anyone can trigger and which stays log-only.
			const reuseEvents = vi.mocked(logAuditEvent).mock.calls.map(([, event]) => event);
			const recorded = reuseEvents.find((event) => event.errorCode === "AUTH_INVALID");
			expect(recorded).toBeDefined();
			expect(JSON.parse(recorded?.metadata ?? "{}")).toMatchObject({
				reason: "revoked_trust_presented",
				subjectId,
				subjectPolicy: "ci/killed",
			});
			vi.mocked(logAuditEvent).mockClear();

			warnSpy.mockClear();
			const stranger = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${await mint("repo:some-rando/thing:ref:refs/heads/main")}` },
				body: "commit data",
			});
			expect(stranger.status).toBe(401);
			expect(warnSpy).toHaveBeenCalledWith("Rejected untrusted OIDC subject", expect.any(Object));
			expect(warnSpy).not.toHaveBeenCalledWith("Revoked OIDC trust presented", expect.any(Object));
			// No durable row for the unknown arm: anyone holding any token the
			// issuer will mint can reach it.
			expect(vi.mocked(logAuditEvent).mock.calls).toHaveLength(0);
			warnSpy.mockRestore();

			await seedTrustedSubjects(env.AUDIT_DB);
		});

		it("does not let the caller choose the revoked-reuse row's request id", async () => {
			// This row is written from the middleware, which answers before the
			// route's header validator runs, so X-Request-ID arrives unchecked here
			// and nowhere else on the sign path. Taking it as given would let the
			// holder of a revoked credential point its own audit rows at a real
			// signature's request id — the exact query an operator runs after the
			// AUTH_INVALID alert — and the length ceiling is the header budget, not
			// 36 characters.
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await clearTrustedSubjects(env.AUDIT_DB);

			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "forged-id-key";
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, kid, publicKey);

			const subjectId = await insertOIDCSubject(env.AUDIT_DB, {
				name: "ci/forged",
				issuer,
				subjectPrefix: "repo:forged/svc",
				keyIds: [],
				expiresAt: null,
			});
			expect(await revokeOIDCSubject(env.AUDIT_DB, subjectId)).toMatchObject({ name: "ci/forged", stillCoveredBy: [] });

			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:forged/svc:ref:refs/heads/main",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const forged = `'; DROP TABLE audit_logs; --${"A".repeat(2000)}`;
			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}`, "X-Request-ID": forged },
				body: "commit data",
			});
			expect(response.status).toBe(401);

			const events = vi.mocked(logAuditEvent).mock.calls.map(([, event]) => event);
			const recorded = events.find((event) => event.errorCode === "AUTH_INVALID");
			expect(recorded).toBeDefined();
			expect(recorded?.requestId).not.toBe(forged);
			// Replaced with a real one rather than dropped, so the row still
			// correlates with its own log lines.
			expect(recorded?.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
			vi.mocked(logAuditEvent).mockClear();

			// A caller-supplied id that *is* a UUID is still honoured, so ordinary
			// request correlation keeps working.
			const supplied = crypto.randomUUID();
			const withValidId = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}`, "X-Request-ID": supplied },
				body: "commit data",
			});
			expect(withValidId.status).toBe(401);
			const second = vi
				.mocked(logAuditEvent)
				.mock.calls.map(([, event]) => event)
				.find((event) => event.errorCode === "AUTH_INVALID");
			expect(second?.requestId).toBe(supplied);

			await seedTrustedSubjects(env.AUDIT_DB);
		});

		it("meters the revoked-reuse row per revoked row, not per subject the caller mints", async () => {
			// The budget has to bound the *row*, but a row is a prefix and one prefix
			// covers unboundedly many subjects — GitHub puts the ref in `sub`, so
			// anyone who can push a branch under the revoked scope mints a fresh
			// subject. Keyed per subject, the cap is no cap: N branches, N budgets,
			// all writing into the database the authorization table lives in.
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await clearTrustedSubjects(env.AUDIT_DB);

			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "flood-key";
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, kid, publicKey);

			const subjectId = await insertOIDCSubject(env.AUDIT_DB, {
				name: "ci/flood",
				issuer,
				subjectPrefix: "repo:flood/",
				keyIds: [],
				expiresAt: null,
			});
			expect(await revokeOIDCSubject(env.AUDIT_DB, subjectId)).toMatchObject({ name: "ci/flood" });

			// Record what the limiter is actually asked about, rather than only that
			// a write was dropped — which is why the per-subject key survived.
			const metered: string[] = [];
			const recordingLimiter = {
				idFromName: () => ({}) as DurableObjectId,
				get: () => ({
					fetch: async (request: Request) => {
						metered.push(decodeURIComponent(new URL(request.url).searchParams.get("identity") ?? ""));
						return Response.json({ allowed: true, remaining: 99, resetAt: Date.now() + 60_000 });
					},
				}),
			} as unknown as DurableObjectNamespace;

			try {
				for (const sub of ["repo:flood/one:ref:refs/heads/main", "repo:flood/two:ref:refs/heads/anything-i-like"]) {
					const token = await new jose.SignJWT({ iss: issuer, sub, aud: "gpg-signing-service" })
						.setProtectedHeader({ alg: "ES256", kid })
						.setIssuedAt()
						.setExpirationTime("1h")
						.sign(privateKey);
					const response = await makeRequest(
						"/sign",
						{ method: "POST", headers: { Authorization: `Bearer ${token}` }, body: "commit data" },
						{ RATE_LIMITER: recordingLimiter },
					);
					expect(response.status).toBe(401);
				}

				// One bucket for the row, whatever subject was presented.
				expect(metered).toEqual([`oidc-revoked-reuse:${subjectId}`, `oidc-revoked-reuse:${subjectId}`]);
				expect(metered.join(" ")).not.toContain("refs/heads");
			} finally {
				// `beforeEach` resets mocks and KV but does not reseed, so a failed
				// assertion here would leave the table cleared for the rest of the file.
				await seedTrustedSubjects(env.AUDIT_DB);
			}
		});

		it("does not write the revoked-reuse row when the caller is over budget or the limiter is down", async () => {
			// The row is metered precisely so the holder of a revoked credential
			// cannot flood the table the authorization store shares. Both failure
			// modes must drop the write and leave the 401 unchanged.
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await clearTrustedSubjects(env.AUDIT_DB);

			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "revoked-unmetered-key";
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, kid, publicKey);

			const subjectId = await insertOIDCSubject(env.AUDIT_DB, {
				name: "ci/unmetered",
				issuer,
				subjectPrefix: "repo:unmetered/svc",
				keyIds: [],
				expiresAt: null,
			});
			expect(await revokeOIDCSubject(env.AUDIT_DB, subjectId)).toMatchObject({
				name: "ci/unmetered",
				stillCoveredBy: [],
			});

			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:unmetered/svc:ref:refs/heads/main",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const request = () => ({
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			const overBudget = await makeRequest("/sign", request(), {
				RATE_LIMITER: rateLimiterAnswering({ allowed: false, remaining: 0, resetAt: Date.now() + 30_000 }),
			});
			expect(overBudget.status).toBe(401);
			expect(vi.mocked(logAuditEvent).mock.calls).toHaveLength(0);

			const limiterErrored = await makeRequest("/sign", request(), { RATE_LIMITER: rateLimiterAnswering(null, 500) });
			expect(limiterErrored.status).toBe(401);
			expect(vi.mocked(logAuditEvent).mock.calls).toHaveLength(0);

			const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
			const limiterDown = await makeRequest("/sign", request(), { RATE_LIMITER: rateLimiterThrowing() });
			expect(limiterDown.status).toBe(401);
			expect(vi.mocked(logAuditEvent).mock.calls).toHaveLength(0);
			expect(warnSpy).toHaveBeenCalledWith(
				"Could not meter a revoked-trust reuse, so it was not recorded",
				expect.objectContaining({ error: expect.any(String) }),
			);

			// Same again with a non-Error rejection, which takes the String(error) branch.
			warnSpy.mockClear();
			const nonError = await makeRequest("/sign", request(), { RATE_LIMITER: rateLimiterThrowing("down") });
			expect(nonError.status).toBe(401);
			expect(warnSpy).toHaveBeenCalledWith(
				"Could not meter a revoked-trust reuse, so it was not recorded",
				expect.objectContaining({ error: "down" }),
			);
			warnSpy.mockRestore();

			await seedTrustedSubjects(env.AUDIT_DB);
		});

		it("names an expired trust rather than reporting it as unknown", async () => {
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			await clearTrustedSubjects(env.AUDIT_DB);

			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "expired-key";
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, kid, publicKey);

			const expiresAt = new Date(Date.now() - 1000).toISOString();
			const subjectId = await insertOIDCSubject(env.AUDIT_DB, {
				name: "ci/lapsed",
				issuer,
				subjectPrefix: "repo:lapsed/svc",
				keyIds: [],
				expiresAt,
			});

			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:lapsed/svc:ref:refs/heads/main",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});
			expect(response.status).toBe(401);
			expect(warnSpy).toHaveBeenCalledWith(
				"Expired OIDC trust presented",
				expect.objectContaining({ subjectId, subjectPolicy: "ci/lapsed", expiresAt }),
			);
			warnSpy.mockRestore();

			await seedTrustedSubjects(env.AUDIT_DB);
		});

		it("should reject key not intended for signatures", async () => {
			// Clean up cache to ensure no pollution
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");

			const { publicKey } = await jose.generateKeyPair("ES256");
			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "enc-key";

			// Setup mock with use: "enc"
			const jwk = await jose.exportJWK(publicKey);
			jwk.kid = kid;
			jwk.use = "enc";

			middlewareFetchMock.mockImplementation(async (url: string) => {
				if (url === `${issuer}/.well-known/openid-configuration`) {
					return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
				}
				if (url === `${issuer}/jwks`) {
					return new Response(JSON.stringify({ keys: [jwk] }));
				}
				return new Response("Not Found", { status: 404 });
			});

			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Key not intended for signatures");
		});

		it("should handle OIDC config fetch failure", async () => {
			middlewareFetchMock.mockResolvedValue(new Response("Error", { status: 500 }));

			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: "https://token.actions.githubusercontent.com",
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Failed to fetch OIDC config");
		});

		it("should handle JWKS fetch failure", async () => {
			const issuer = "https://token.actions.githubusercontent.com";
			middlewareFetchMock.mockImplementation(async (url: string) => {
				if (url === `${issuer}/.well-known/openid-configuration`) {
					return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
				}
				return new Response("Error", { status: 500 });
			});

			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Failed to fetch JWKS");
		});

		it("should handle cache put failure", async () => {
			const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "test-key";

			await setupJWKSMock(issuer, kid, publicKey);

			// Mock cache put to fail
			const putSpy = vi.spyOn(env.JWKS_CACHE, "put").mockRejectedValue(new Error("Cache error"));

			try {
				const token = await new jose.SignJWT({
					iss: issuer,
					sub: "repo:test/svc",
					aud: "gpg-signing-service",
				})
					.setProtectedHeader({ alg: "ES256", kid })
					.setIssuedAt()
					.setExpirationTime("1h")
					.sign(privateKey);

				const response = await makeRequest("/sign", {
					method: "POST",
					headers: { Authorization: `Bearer ${token}` },
					body: "commit data",
				});

				// Should still succeed despite cache error
				expect(response.status).not.toBe(401);
			} finally {
				putSpy.mockRestore();
			}
		});

		it("should reject missing authorization header", async () => {
			const response = await makeRequest("/sign", {
				method: "POST",
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { code: string };
			expect(body.code).toBe("AUTH_MISSING");
		});

		it("should reject non-Bearer authorization", async () => {
			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: "Basic dXNlcjpwYXNz" },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { code: string };
			expect(body.code).toBe("AUTH_MISSING");
		});

		it("should reject token with wrong number of parts", async () => {
			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: "Bearer only.two" },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string; code: string };
			expect(body.code).toBe("AUTH_INVALID");
			expect(body.error).toContain("Invalid token format");
		});

		it("should reject token with invalid base64 encoding", async () => {
			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: "Bearer !!!.!!!.!!!" },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string; code: string };
			expect(body.code).toBe("AUTH_INVALID");
		});

		it("should validate a correct token", async () => {
			const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
			const issuer = "https://token.actions.githubusercontent.com/unique-test-issuer";
			const kid = "test-key";

			await setupJWKSMock(issuer, kid, publicKey);

			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:user/repo:ref:refs/heads/main",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			// We expect 400 because the token is valid but the body is empty/invalid for the endpoint
			// This proves authentication passed
			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).not.toBe(401);
		});

		it("should reject token signed by unknown key", async () => {
			// Clean cache to avoid stale JWKS from previous tests
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			// Reset mocks to ensure clean state
			vi.resetAllMocks();
			middlewareFetchMock.mockReset();
			validateUrlMock.mockReset();
			validateUrlMock.mockResolvedValue(undefined);

			const { privateKey } = await jose.generateKeyPair("ES256");
			const issuer = "https://token.actions.githubusercontent.com";

			// Setup mock with DIFFERENT key
			const { publicKey: otherKey } = await jose.generateKeyPair("ES256");
			await setupJWKSMock(issuer, "other-key", otherKey);

			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "unknown-key" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Key not found");

			// Final cleanup for this specific test
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
			vi.resetAllMocks();
		});

		it("should reject token with invalid signature", async () => {
			const { publicKey } = await jose.generateKeyPair("ES256");
			const { privateKey: otherKey } = await jose.generateKeyPair("ES256");
			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "test-key";

			await setupJWKSMock(issuer, kid, publicKey);

			// Sign with WRONG private key but claim it's the correct kid
			const token = await new jose.SignJWT({
				iss: issuer,
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(otherKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Invalid token signature");
		});

		it("should reject token with disallowed algorithm", async () => {
			// Generate RS256 key (allowed) but we'll try to use HS256 (disallowed)
			// Note: jose won't let us sign HS256 with RSA key easily, so we just mock the token structure
			// or use a separate HS256 key
			const secret = new TextEncoder().encode("secret");
			const token = await new jose.SignJWT({
				iss: "https://token.actions.githubusercontent.com",
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "HS256", kid: "test" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(secret);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Algorithm not allowed");
		});

		it("should reject token from disallowed issuer", async () => {
			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: "https://malicious-issuer.com",
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Issuer not allowed");
		});

		it("should reject expired token", async () => {
			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: "https://token.actions.githubusercontent.com",
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test" })
				.setIssuedAt()
				.setExpirationTime("-1h") // Expired
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Token expired");
		});

		it("should reject token not yet valid (nbf)", async () => {
			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: "https://token.actions.githubusercontent.com",
				sub: "repo:test/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test" })
				.setIssuedAt()
				.setNotBefore("1h") // Not valid yet
				.setExpirationTime("2h")
				.sign(privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: string };
			expect(body.error).toContain("Token not yet valid");
		});

		async function createToken(
			claims: object = {},
			keyPair?: jose.GenerateKeyPairResult,
			alg: string = "ES256",
			kid: string = "test-key",
		) {
			if (!keyPair) {
				keyPair = await jose.generateKeyPair(alg);
			}
			return new jose.SignJWT({
				iss: "https://token.actions.githubusercontent.com",
				sub: "repo:user/repo:ref:refs/heads/main",
				aud: "gpg-signing-service",
				...claims,
			})
				.setProtectedHeader({ alg, kid })
				.setIssuedAt()
				.setExpirationTime("1h")
				.sign(keyPair.privateKey);
		}

		it("should use cached JWKS", async () => {
			const keyPair = await jose.generateKeyPair("RS256");
			const token = await createToken({}, keyPair, "RS256", "test-key-RS256");
			const jwk = await jose.exportJWK(keyPair.publicKey);
			jwk.kid = "test-key-RS256";
			jwk.use = "sig";

			// Use real KV for this test
			await env.JWKS_CACHE.put("jwks:https://token.actions.githubusercontent.com", JSON.stringify({ keys: [jwk] }));

			const response = await makeRequest(
				"/sign",
				{
					method: "POST",
					headers: { Authorization: `Bearer ${token}` },
					body: "commit data",
				},
				// No custom env needed, using real (isolated) KV
			);

			// 404 means OIDC passed (using cached key) and it reached the route
			expect(response.status).toBe(404);
		});

		it("should reject token with wrong audience", async () => {
			const token = await createToken({ aud: "wrong-audience" });
			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});
			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string }>(response);
			expect(body.error).toBe("Invalid token audience");
		});

		it("should accept token with array audience containing correct audience", async () => {
			// Clean up cache to ensure no pollution
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");

			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			const issuer = "https://token.actions.githubusercontent.com";
			const kid = "test-key";

			await setupJWKSMock(issuer, kid, publicKey);

			const token = await createToken(
				{ aud: ["other-service", "gpg-signing-service"] },
				{ privateKey, publicKey },
				"ES256",
				kid,
			);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});
			// 404 means OIDC passed
			expect(response.status).toBe(404);
		});

		it("should handle non-Error exceptions during validation", async () => {
			const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
			const token = await createToken({}, { privateKey, publicKey });

			// Mock JWKS_CACHE to throw a string
			vi.spyOn(env.JWKS_CACHE, "get").mockRejectedValue("String error");

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string }>(response);
			expect(body.error).toBe("Invalid token");
		});

		describe("Algorithm Support", () => {
			const algorithms = ["RS256", "RS384", "RS512", "ES384"];

			for (const alg of algorithms) {
				it(`should support ${alg} algorithm`, async () => {
					// Clean up cache from previous iteration
					await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");

					// Generate key pair for the algorithm
					const { privateKey, publicKey } = await jose.generateKeyPair(alg);
					const jwk = await jose.exportJWK(publicKey);
					jwk.kid = `test-key-${alg}`;
					jwk.use = "sig";

					// Mock JWKS response
					// Mock JWKS response
					middlewareFetchMock.mockImplementation(async (url) => {
						if (url === "https://token.actions.githubusercontent.com/.well-known/openid-configuration") {
							return new Response(
								JSON.stringify({
									jwks_uri: "https://token.actions.githubusercontent.com/jwks",
								}),
							);
						}
						if (url === "https://token.actions.githubusercontent.com/jwks") {
							return new Response(JSON.stringify({ keys: [jwk] }));
						}
						return new Response("Not Found", { status: 404 });
					});

					// Create token
					const token = await new jose.SignJWT({
						iss: "https://token.actions.githubusercontent.com",
						sub: "repo:user/repo:ref:refs/heads/main",
						aud: "gpg-signing-service",
					})
						.setProtectedHeader({ alg, kid: jwk.kid })
						.setIssuedAt()
						.setExpirationTime("1h")
						.sign(privateKey);

					const response = await makeRequest("/sign", {
						method: "POST",
						headers: { Authorization: `Bearer ${token}` },
						body: "commit data",
					});

					// 404 means OIDC passed and it reached the route (which failed to find key)
					expect(response.status).toBe(404);
				});
			}
		});
	});

	describe("Admin Auth Middleware", () => {
		it("should reject missing authorization header", async () => {
			const response = await makeRequest("/admin/keys");

			expect(response.status).toBe(401);
			const body = (await response.json()) as { code: string };
			expect(body.code).toBe("AUTH_MISSING");
		});

		it("should reject non-Bearer authorization", async () => {
			const response = await makeRequest("/admin/keys", {
				headers: { Authorization: "Basic dXNlcjpwYXNz" },
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { code: string };
			expect(body.code).toBe("AUTH_MISSING");
		});

		it("should reject invalid admin token", async () => {
			const response = await makeRequest("/admin/keys", {
				headers: { Authorization: "Bearer wrong-token" },
			});

			expect(response.status).toBe(401);
			const body = (await response.json()) as { code: string };
			expect(body.code).toBe("AUTH_INVALID");
		});

		it("should accept valid admin token", async () => {
			const response = await makeRequest("/admin/keys", {
				headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
			});

			// Should not be 401
			expect(response.status).not.toBe(401);
		});

		it("should handle rate limiter failure", async () => {
			// Mock RATE_LIMITER failure
			const originalIdFromName = env.RATE_LIMITER.idFromName;
			env.RATE_LIMITER.idFromName = () => {
				throw new Error("Rate limiter failure");
			};

			try {
				const response = await makeRequest("/admin/keys", {
					headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
				});

				expect(response.status).toBe(503);
				const body = (await response.json()) as { code: string };
				expect(body.code).toBe("RATE_LIMIT_ERROR");
			} finally {
				env.RATE_LIMITER.idFromName = originalIdFromName;
			}
		});
	});

	describe("SSRF Protection in OIDC", () => {
		beforeEach(async () => {
			vi.resetAllMocks();
			middlewareFetchMock.mockReset();
			validateUrlMock.mockReset();
			// Default: validateUrl passes
			validateUrlMock.mockResolvedValue(undefined);
			// Clean up KV cache to avoid pollution from other tests
			await env.JWKS_CACHE.delete("jwks:https://10.0.0.1");
			await env.JWKS_CACHE.delete("jwks:https://malicious.example.com");
			await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
		});

		afterEach(async () => {
			vi.resetAllMocks();
			middlewareFetchMock.mockReset();
			validateUrlMock.mockReset();
			// Clean up all cache keys used in SSRF tests
			try {
				await env.JWKS_CACHE.delete("jwks:https://10.0.0.1");
				await env.JWKS_CACHE.delete("jwks:https://malicious.example.com");
				await env.JWKS_CACHE.delete("jwks:https://token.actions.githubusercontent.com");
				await env.JWKS_CACHE.delete("jwks:https://169.254.169.254");
				await env.JWKS_CACHE.delete("jwks:https://internal-service");
			} catch {
				// Suppress errors from cache deletes (keys might not exist)
			}
		});

		it("should block SSRF in OIDC wellKnown URL with Error object", async () => {
			// First call to validateUrl (wellKnown URL) throws Error
			validateUrlMock.mockRejectedValueOnce(new Error("Access to private IP range 10.0.0.0/8 is forbidden"));

			const { privateKey } = await jose.generateKeyPair("ES256");
			const token = await new jose.SignJWT({
				iss: "https://10.0.0.1",
				sub: "repo:test-subject/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test-key" })
				.setExpirationTime("1h")
				.sign(privateKey);

			const response = await makeRequest(
				"/sign",
				{
					method: "POST",
					headers: { Authorization: `Bearer ${token}` },
					body: "commit data",
				},
				{ ALLOWED_ISSUERS: "https://10.0.0.1" as Env["ALLOWED_ISSUERS"] },
			);

			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string }>(response);
			expect(body.error).toContain("SSRF protection");
		});

		it("should block SSRF in OIDC wellKnown URL with non-Error", async () => {
			// First call throws non-Error object
			validateUrlMock.mockRejectedValueOnce("String error");

			const token = await new jose.SignJWT({
				iss: "https://malicious.example.com",
				sub: "repo:test-subject/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test-key" })
				.setExpirationTime("1h")
				.sign((await jose.generateKeyPair("ES256")).privateKey);

			const response = await makeRequest(
				"/sign",
				{
					method: "POST",
					headers: { Authorization: `Bearer ${token}` },
					body: "commit data",
				},
				{
					ALLOWED_ISSUERS: "https://malicious.example.com" as Env["ALLOWED_ISSUERS"],
				},
			);

			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string }>(response);
			expect(body.error).toContain("SSRF protection: Invalid URL");
		});

		it("should block SSRF in JWKS URI with Error object", async () => {
			// First validateUrl call passes (wellKnown), second throws (jwks_uri)
			validateUrlMock
				.mockResolvedValueOnce(undefined) // wellKnown URL passes
				.mockRejectedValueOnce(new Error("Access to cloud metadata endpoints is forbidden")); // jwks_uri fails

			// Mock OIDC config response with malicious jwks_uri
			middlewareFetchMock.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						jwks_uri: "https://169.254.169.254/latest/meta-data/",
					}),
				),
			);

			const token = await new jose.SignJWT({
				iss: "https://token.actions.githubusercontent.com",
				sub: "repo:test-subject/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test-key" })
				.setExpirationTime("1h")
				.sign((await jose.generateKeyPair("ES256")).privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string }>(response);
			expect(body.error).toContain("SSRF protection");
		});

		it("should block SSRF in JWKS URI with non-Error", async () => {
			// First validateUrl call passes, second throws non-Error
			validateUrlMock.mockResolvedValueOnce(undefined).mockRejectedValueOnce("Non-error string");

			middlewareFetchMock.mockResolvedValueOnce(
				new Response(JSON.stringify({ jwks_uri: "https://internal-service/jwks" })),
			);

			const token = await new jose.SignJWT({
				iss: "https://token.actions.githubusercontent.com",
				sub: "repo:test-subject/svc",
				aud: "gpg-signing-service",
			})
				.setProtectedHeader({ alg: "ES256", kid: "test-key" })
				.setExpirationTime("1h")
				.sign((await jose.generateKeyPair("ES256")).privateKey);

			const response = await makeRequest("/sign", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
				body: "commit data",
			});

			expect(response.status).toBe(401);
			const body = await parseJson<{ error: string }>(response);
			expect(body.error).toContain("SSRF protection: Invalid URL");
		});
	});
});
