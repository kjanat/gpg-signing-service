/** biome-ignore-all lint/suspicious/noExplicitAny: Is a test file */
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { Hono } from "hono";
import * as openpgp from "openpgp";
import { describe, expect, it, vi } from "vitest";
import { KeyStorage } from "#durable-objects/key-storage";
import { RateLimiter } from "#durable-objects/rate-limiter";
import app from "#gpg-signing-service";
import { logAuditEvent } from "#utils/audit";
import { serviceDegraded, serviceMisconfigured } from "#utils/errors";
import * as signingUtils from "#utils/signing";

const parseJson = async <T>(response: Response): Promise<T> => (await response.json()) as T;

vi.mock("openpgp", async (importOriginal) => {
	const actual = await importOriginal<typeof import("openpgp")>();
	return {
		...actual,
		readPrivateKey: vi.fn(actual.readPrivateKey),
	};
});

vi.mock("#utils/signing", async (importOriginal) => {
	const actual = await importOriginal<typeof import("#utils/signing")>();
	return {
		...actual,
		signCommitData: vi.fn(actual.signCommitData),
		// We don't mock parseAndValidateKey because we want to test its internal logic
		// relying on the mocked openpgp.readPrivateKey
	};
});

vi.mock("#middleware/oidc", async (importOriginal) => {
	const actual = await importOriginal<typeof import("#middleware/oidc")>();
	return {
		...actual,
		oidcAuth: vi.fn(async (c, next) => {
			if (c.req.header("Authorization") === "Bearer valid-token") {
				c.set("oidcClaims", {
					iss: "issuer",
					sub: "repo:subject/svc",
					project_path: "repo",
				});
				c.set("identity", "user");
				return next();
			}
			return actual.oidcAuth(c, next);
		}),
	};
});

// Minimal in-memory DurableObjectState mock
function createState(): DurableObjectState {
	const store = new Map<string, any>();
	let alarm: number | null = null;
	return {
		storage: {
			async get(key: string) {
				return store.get(key);
			},
			async put(key: string, value: any) {
				store.set(key, value);
			},
			async delete(key: string | string[]) {
				const keys = Array.isArray(key) ? key : [key];
				let deleted = 0;
				for (const k of keys) {
					if (store.delete(k)) deleted += 1;
				}
				return Array.isArray(key) ? deleted : deleted > 0;
			},
			async list({ prefix, limit }: { prefix: string; limit?: number }) {
				const filtered = new Map<string, any>();
				for (const [k, v] of store.entries()) {
					if (limit !== undefined && filtered.size >= limit) break;
					if (k.startsWith(prefix)) filtered.set(k, v);
				}
				return filtered;
			},
			// The limiter arms an alarm to reap abandoned buckets; without these the
			// consume path throws and every case here reports as a 500.
			async getAlarm() {
				return alarm;
			},
			async setAlarm(scheduled: number) {
				alarm = scheduled;
			},
			async deleteAlarm() {
				alarm = null;
			},
		},
	} as unknown as DurableObjectState;
}

describe("Branch Coverage Helpers", () => {
	describe("KeyStorage edge cases", () => {
		it("returns 405 for store-key with wrong method", async () => {
			const storage = new KeyStorage(createState());
			const res = await storage.fetch(new Request("http://do/store-key"));
			expect(res.status).toBe(405);
		});

		it("returns 400 when deleting without keyId", async () => {
			const storage = new KeyStorage(createState());
			const res = await storage.fetch(new Request("http://do/delete-key", { method: "DELETE" }));
			expect(res.status).toBe(400);
		});

		it("returns health status", async () => {
			const storage = new KeyStorage(createState());
			const res = await storage.fetch(new Request("http://do/health"));
			expect(res.status).toBe(200);
		});

		it("returns 404 for unknown route", async () => {
			const storage = new KeyStorage(createState());
			const res = await storage.fetch(new Request("http://do/unknown"));
			expect(res.status).toBe(404);
		});

		it("handles health check errors", async () => {
			const state = createState();
			vi.spyOn(state.storage, "list").mockRejectedValue(new Error("Storage fail"));
			const storage = new KeyStorage(state);
			const res = await storage.fetch(new Request("http://do/health"));
			expect(res.status).toBe(500);
			expect(await res.json()).toEqual({ error: "Storage fail" });
		});
	});

	describe("RateLimiter edge cases", () => {
		it("returns 405 for reset with non-POST method", async () => {
			const limiter = new RateLimiter(createState());
			const res = await limiter.fetch(new Request("http://do/reset"));
			expect(res.status).toBe(405);
		});

		it("requires identity when resetting limits", async () => {
			const limiter = new RateLimiter(createState());
			const res = await limiter.fetch(new Request("http://do/reset", { method: "POST" }));
			expect(res.status).toBe(400);
		});

		it("refills existing bucket on consume", async () => {
			const state = createState();
			// Seed an old bucket to force refill path
			await state.storage.put("bucket:user", {
				tokens: 10,
				lastRefill: Date.now() - 120_000,
			});
			const limiter = new RateLimiter(state);
			const res = await limiter.fetch(new Request("http://do/consume?identity=user"));
			expect(res.status).toBe(200);
			const body = await parseJson<{ allowed: boolean; remaining: number }>(res);
			expect(body.allowed).toBe(true);
			expect(body.remaining).toBeGreaterThan(0);
		});

		it("returns 404 for unknown route", async () => {
			const limiter = new RateLimiter(createState());
			const res = await limiter.fetch(new Request("http://do/unknown"));
			expect(res.status).toBe(404);
		});

		it("refills from 0 tokens when stale", async () => {
			const state = createState();
			await state.storage.put("bucket:user", {
				tokens: 0,
				lastRefill: Date.now() - 120_000,
			});
			const limiter = new RateLimiter(state);
			const res = await limiter.fetch(new Request("http://do/consume?identity=user"));
			expect(res.status).toBe(200);
			const body = await parseJson<{ allowed: boolean }>(res);
			expect(body.allowed).toBe(true);
		});

		it("handles storage errors", async () => {
			const state = createState();
			vi.spyOn(state.storage, "get").mockRejectedValue(new Error("Storage fail"));
			const limiter = new RateLimiter(state);
			const res = await limiter.fetch(new Request("http://do/consume"));
			expect(res.status).toBe(500);
		});
	});

	describe("Audit logging failures", () => {
		it("throws on audit DB errors (fail-closed)", async () => {
			const db = {
				prepare: () => {
					throw new Error("DB down");
				},
			} as unknown as D1Database;

			await expect(
				logAuditEvent(db, {
					requestId: "req-1",
					action: "test" as any,
					issuer: "issuer",
					subject: "subj",
					keyId: "key",
					success: true,
				}),
			).rejects.toThrow("DB down");
		});
	});

	describe("Middleware branches", () => {
		it("fails admin rate limit when allowance is false", async () => {
			// 429, the way the real Durable Object answers a denial. A 200 here is the
			// shape the limiter never produces, and it is what let the middleware read
			// every 429 as an outage while this assertion still passed.
			const denyResponse = Response.json(
				{ allowed: false, resetAt: Date.now() + 10_000, remaining: 0 },
				{
					status: 429,
				},
			);

			const customEnv = {
				...env,
				ADMIN_TOKEN: env.ADMIN_TOKEN,
				RATE_LIMITER: {
					idFromName: () => ({}) as any,
					get: () => ({ fetch: () => denyResponse }),
				},
			};

			const ctx = createExecutionContext();
			const res = await app.fetch(
				new Request("http://localhost/admin/keys", {
					headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
				}),
				customEnv,
				ctx,
			);
			await waitOnExecutionContext(ctx);

			expect(res.status).toBe(429);
			// End to end, not just at the `c.json` call: the headers survive the
			// middleware chain, and `securityHeaders` advertises them to a browser.
			expect(res.headers.get("X-RateLimit-Remaining")).toBe("0");
			expect(Number(res.headers.get("X-RateLimit-Reset"))).toBeGreaterThan(Math.floor(Date.now() / 1000));
			expect(res.headers.get("Access-Control-Expose-Headers")).toBe(
				"X-Request-ID, X-RateLimit-Remaining, X-RateLimit-Reset",
			);
			const body = await parseJson<{ code: string }>(res);
			expect(body.code).toBe("RATE_LIMITED");
		});

		it("allows admin request and sets headers when rate limit passes", async () => {
			const allowResponse = new Response(
				JSON.stringify({
					allowed: true,
					resetAt: Date.now() + 10_000,
					remaining: 5,
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			);

			const customEnv = {
				...env,
				ADMIN_TOKEN: env.ADMIN_TOKEN,
				RATE_LIMITER: {
					idFromName: () => ({}) as any,
					get: () => ({ fetch: () => allowResponse }),
				},
			};

			const ctx = createExecutionContext();
			const res = await app.fetch(
				new Request("http://localhost/admin/keys", {
					headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
				}),
				customEnv,
				ctx,
			);
			await waitOnExecutionContext(ctx);

			expect(res.status).toBe(200);
			expect(res.headers.get("X-RateLimit-Remaining")).toBe("5");
			expect(res.headers.get("X-RateLimit-Reset")).not.toBeNull();
			// Only the rate-limit headers this response actually carries are named.
			// Nothing in the service sets X-RateLimit-Limit, so advertising it would
			// point a cross-origin reader at a header that is never there.
			expect(res.headers.get("X-RateLimit-Limit")).toBeNull();
			// X-Request-ID is named unconditionally: `requestId` is the outermost
			// middleware, so it stamps the header after `securityHeaders` has already
			// built this list and presence-testing it there would never see it.
			expect(res.headers.get("Access-Control-Expose-Headers")).toBe(
				"X-Request-ID, X-RateLimit-Remaining, X-RateLimit-Reset",
			);
			expect(res.headers.get("X-Request-ID")).not.toBeNull();
		});

		it("handles missing token after Bearer prefix", async () => {
			const json = vi.fn();
			const header = vi.fn();
			const context = {
				req: { header: () => "Bearer " },
				env,
				json,
				header,
				get: vi.fn(),
				set: vi.fn(),
			};

			await import("#middleware/oidc").then(({ oidcAuth }) => oidcAuth(context as any, () => Promise.resolve()));

			expect(json).toHaveBeenCalledWith(
				{
					error: "Missing token",
					code: "AUTH_MISSING",
					hint: expect.stringContaining("`Bearer ` with nothing after it"),
				},
				401,
			);
			// RFC 9110 §11.6.1: a 401 without a challenge tells the caller it was
			// refused but not what to present next.
			expect(header).toHaveBeenCalledWith("WWW-Authenticate", 'Bearer realm="gpg-signing-service"');
		});

		it("maps jose JWKS error to friendly message", async () => {
			const { mapJoseError } = await import("#middleware/oidc");
			const err: any = new Error("no applicable key");
			err.code = "ERR_JWKS_NO_MATCHING_KEY";
			expect(() => mapJoseError(err)).toThrow("Key not found");

			const sigErr: any = new Error("signature verification failed");
			expect(() => mapJoseError(sigErr)).toThrow("Invalid token signature");

			const generic = new Error("other");
			expect(() => mapJoseError(generic)).toThrow("other");
		});

		it("returns 401 for Basic auth", async () => {
			const json = vi.fn();
			const context = {
				req: { header: () => "Basic user:pass" },
				json,
				header: vi.fn(),
				// The middleware reads the published request id and republishes it
				// before looking at the Authorization header, so the stub needs both.
				get: vi.fn(),
				set: vi.fn(),
			};
			await import("#middleware/oidc").then(({ oidcAuth }) => oidcAuth(context as any, () => Promise.resolve()));
			expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: "AUTH_MISSING" }), 401);
		});

		it("returns the admin limiter's 429 as a verdict rather than an outage", async () => {
			// The real Durable Object answers a denied consume with a 429 carrying
			// the verdict. Reading that as a failure answered 503 with no
			// `retryAfter` and made the `allowed` branch unreachable.
			const customEnv = {
				...env,
				RATE_LIMITER: {
					idFromName: () => ({}) as any,
					get: () => ({
						fetch: () =>
							Promise.resolve(Response.json({ allowed: false, resetAt: Date.now() + 60_000 }, { status: 429 })),
					}),
				},
			};

			const json = vi.fn();
			const context = {
				req: {
					header: (name: string) => (name === "Authorization" ? "Bearer admin" : "1.2.3.4"),
				},
				env: customEnv,
				json,
			};

			await import("#middleware/security").then(({ adminRateLimit }) =>
				adminRateLimit(context as any, () => Promise.resolve()),
			);

			expect(json).toHaveBeenCalledWith(
				expect.objectContaining({ code: "RATE_LIMITED", retryAfter: expect.any(Number) }),
				429,
				// The refusal carries the budget that refused it. A 429 with no
				// rate-limit headers is the one response where a caller most needs to
				// know when to come back and the only one that did not say.
				{ "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": expect.any(String) },
			);
		});

		it("fails closed when admin rate limiter fails", async () => {
			const customEnv = {
				...env,
				RATE_LIMITER: {
					idFromName: () => ({}) as any,
					get: () => ({
						fetch: () => Promise.resolve(new Response("Error", { status: 503 })),
					}),
				},
			};

			const json = vi.fn();
			const context = {
				req: {
					header: (name: string) => (name === "Authorization" ? "Bearer admin" : "1.2.3.4"),
				},
				env: customEnv,
				json,
			};

			await import("#middleware/security").then(({ adminRateLimit }) =>
				adminRateLimit(context as any, () => Promise.resolve()),
			);

			expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: "RATE_LIMIT_ERROR" }), 503);
		});
	});

	describe("Route error handling", () => {
		it("triggers catch block in uploadKeyRoute with internal error", async () => {
			// Mock openpgp to throw error despite valid schema
			vi.mocked(openpgp.readPrivateKey).mockRejectedValueOnce(new Error("Internal PGP Error"));

			const validLookingKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZx3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJkEExYKAEEWIQQRTd3LSMIzSP5K+yAQMfcIqJ5LFQUCZ3PyhwIbAwUJA8JnAAUL
CQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRAQMfcIqJ5LFZoMAP9X7cPxCi2p
KIr+J8gAkl0Ny1G8TnlMq0M9xN3Vx1qb+QD/elKMaKzX3u8d9zvIykjW8K/WKWwy
7Bfg==
=oEGo
-----END PGP PRIVATE KEY BLOCK-----`;

			const ctx = createExecutionContext();
			const res = await app.fetch(
				new Request("http://localhost/admin/keys", {
					method: "POST",
					headers: {
						Authorization: `Bearer ${env.ADMIN_TOKEN}`,
						"Content-Type": "application/json",
					},
					body: JSON.stringify({
						armoredPrivateKey: validLookingKey,
						keyId: "A1B2C3D4E5F67890",
					}),
				}),
				env,
				ctx,
			);
			await waitOnExecutionContext(ctx);

			expect(res.status).toBe(500);
			const body = await parseJson<{ code: string }>(res);
			expect(body.code).toBe("KEY_UPLOAD_ERROR");
		});

		it("handles signing key not found via storage", async () => {
			const customEnv = {
				...env,
				KEY_STORAGE: {
					idFromName: () => ({}) as any,
					get: () => ({
						fetch: () =>
							Promise.resolve(
								new Response(JSON.stringify({ error: "Key not found" }), {
									status: 404,
								}),
							),
					}),
				},
				AUDIT_DB: {
					prepare: () => ({ bind: () => ({ run: () => Promise.resolve() }) }),
				},
			};

			const ctx = createExecutionContext();
			const res = await app.fetch(
				new Request("http://localhost/sign?keyId=A1B2C3D4E5F67890", {
					method: "POST",
					headers: {
						Authorization: "Bearer valid-token",
						"Content-Type": "text/plain",
					},
					body: "commit data",
				}),
				customEnv,
				ctx,
			);
			await waitOnExecutionContext(ctx);

			expect(res.status).toBe(404);
			const body = await parseJson<{ code: string }>(res);
			expect(body.code).toBe("KEY_NOT_FOUND");
		});

		it("handles signing errors", async () => {
			vi.mocked(signingUtils.signCommitData).mockRejectedValue(new Error("Signing failed"));

			const validPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEaR3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJYEExYKAD4WIQSAbTobn5V9ZzGVC8pi515USXgV3QUCaR3PygIbAwUJA8JnAAUL
CQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRBi515USXgV3UGkAQDdih4x/+9oQZ6+
0T0Etx1oIerz9Uh8CD0aRP/XzC1wPQD/Ug7bAb9n5RFDqb2Vlq2KK+uza5vDlDHq
rxgkrugpagY=
=gskf
-----END PGP PRIVATE KEY BLOCK-----`;

			const customEnv = {
				...env,
				KEY_STORAGE: {
					idFromName: () => ({}) as any,
					get: () => ({
						fetch: () =>
							Promise.resolve(
								new Response(
									JSON.stringify({
										armoredPrivateKey: validPrivateKey,
										keyId: "A1B2C3D4E5F67890",
										fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
										algorithm: "RSA",
									}),
									{ status: 200 },
								),
							),
					}),
				},
				AUDIT_DB: {
					prepare: () => ({ bind: () => ({ run: () => Promise.resolve() }) }),
				},
			};

			const ctx = createExecutionContext();
			const res = await app.fetch(
				new Request("http://localhost/sign?keyId=A1B2C3D4E5F67890", {
					method: "POST",
					headers: {
						Authorization: "Bearer valid-token",
						"Content-Type": "text/plain",
					},
					body: "commit data",
				}),
				customEnv,
				ctx,
			);
			await waitOnExecutionContext(ctx);

			expect(res.status).toBe(500);
			const body = await parseJson<{ code: string }>(res);
			expect(body.code).toBe("SIGN_ERROR");
		});
	});

	describe("Utility edge cases", () => {
		it("handles unknown key algorithms", async () => {
			const mockKey = {
				keyPacket: { algorithm: 99 },
				getFingerprint: () => "0123456789ABCDEF0123456789ABCDEF01234567",
				getKeyID: () => ({ toHex: () => "ABCD1234567890EF" }),
				getUserIDs: () => ["user"],
				isDecrypted: () => true,
			};

			vi.mocked(openpgp.readPrivateKey).mockResolvedValue(mockKey as any);

			const info = await signingUtils.parseAndValidateKey("armored-key");
			expect(info.algorithm).toBe("Unknown(99)");
		});

		// The permanent 500 driven directly, without the requestId middleware and
		// without a hint. Both are optional and neither is optional at the one
		// place that calls it today, so the route tests reach only the shape where
		// they are present — and a helper that throws on a missing requestId would
		// turn an already-broken deployment into a 500 with no code at all.
		it("builds a SERVICE_MISCONFIGURED body with nothing but a message", async () => {
			const bare = new Hono();
			bare.get("/", (c) => serviceMisconfigured(c, "SSRF protection: URL resolves to a private address"));

			const response = await bare.request("/");

			expect(response.status).toBe(500);
			// No Retry-After, ever: there is no parameter for one. A caller handed
			// both this code and an interval would have to guess which to believe.
			expect(response.headers.get("Retry-After")).toBeNull();
			expect(await parseJson<Record<string, unknown>>(response)).toEqual({
				error: "SSRF protection: URL resolves to a private address",
				code: "SERVICE_MISCONFIGURED",
			});
		});

		// The half of the split a caller who cannot read the code still gets: of
		// these two, the transient one says how long to wait and the permanent one
		// does not. While both shared 503 the header's presence varied within one
		// status, which is the ambiguity nobody should have been reading policy
		// from — and a proxy, or a `curl -i` in a CI log, had nothing to go on.
		//
		// Not a claim about every 503 this service sends: RATE_LIMIT_ERROR is one
		// too and carries no interval. It is a claim about this pair, which is
		// where somebody is being asked to tell two opposite answers apart.
		it("pairs the degraded 503 with a wait hint and the permanent 500 with none", async () => {
			const bare = new Hono();
			bare.get("/degraded", (c) => serviceDegraded(c, "Issuer unreachable", { retryAfter: 30 }));
			bare.get("/misconfigured", (c) => serviceMisconfigured(c, "SSRF protection: blocked"));

			const degraded = await bare.request("/degraded");
			const misconfigured = await bare.request("/misconfigured");

			expect(degraded.status).toBe(503);
			expect(degraded.headers.get("Retry-After")).toBe("30");
			expect(misconfigured.status).toBe(500);
			expect(misconfigured.headers.get("Retry-After")).toBeNull();
		});
	});
});
