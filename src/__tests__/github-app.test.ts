/**
 * The credential half of the GitHub App integration.
 *
 * Nothing here is reachable from a request yet — the webhook route
 * acknowledges deliveries and acts on none of them — so this suite is the only
 * thing standing behind three properties the eventual caller will rely on:
 *
 * - **The destination is pinned.** Every assertion about an outbound call reads
 *   the URL the stub was handed, and the stub itself refuses anything that is
 *   not on `api.github.com`. So a change that reintroduced a configurable host
 *   fails here rather than in production.
 * - **Secrets do not escape.** The private key, the App JWT and the
 *   installation token are fed through the failure paths on purpose, and each
 *   resulting message is checked for them. A message that quotes its input back
 *   is the ordinary way a key ends up in a log.
 * - **A cached token is always still valid.** The TTL is asserted against
 *   GitHub's stated expiry rather than against a constant, and a stored token
 *   inside the safety margin is required to be ignored.
 */

import { env } from "cloudflare:workers";
import { decodeProtectedHeader, importSPKI, jwtVerify } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env as ServiceEnv } from "#types";
import { TIME } from "#types";
import {
	GITHUB_API_ORIGIN,
	GitHubAppError,
	getInstallationToken,
	githubApiUrl,
	githubAppEnabled,
	installationTokenCacheKey,
	mintAppJwt,
	requireAppConfig,
	toPkcs8Pem,
} from "#utils/github-app";
import { verifyWebhookSignature } from "#utils/github-webhook";
import { collectEnvSecrets, scrubValue } from "#utils/sentry";

const APP_ID = "123456";

/**
 * One RSA key pair for the whole suite, in every form the code has to handle.
 *
 * Generated rather than pasted, so the fixture cannot be a real key somebody
 * copied from somewhere, and generated once because 2048-bit RSA keygen is slow
 * enough to dominate the run.
 */
let keys: {
	pkcs8Pem: string;
	pkcs8Der: Uint8Array;
	pkcs1Pem: string;
	publicSpkiPem: string;
};

/** PEM-wrap `der` at 64 columns, the way every producer of these files does. */
function toPem(label: string, der: Uint8Array): string {
	const base64 = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, "$1\n");
	return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----\n`;
}

function fromPem(pem: string): Uint8Array {
	const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
	return Uint8Array.from(atob(body), (character) => character.charCodeAt(0));
}

/**
 * The PKCS#1 `RSAPrivateKey` inside a PKCS#8 `PrivateKeyInfo`.
 *
 * WebCrypto exports only PKCS#8, and GitHub only hands out PKCS#1, so the
 * fixture has to be produced by unwrapping rather than by exporting. This walks
 * the outer SEQUENCE to the final OCTET STRING and returns its contents — the
 * exact inverse of what `toPkcs8Pem` does, which is what makes the round-trip
 * test below a real round trip rather than two copies of one mistake.
 */
function pkcs1FromPkcs8(der: Uint8Array): Uint8Array {
	// Skip the outer SEQUENCE header, then `INTEGER 0` (3 bytes) and the
	// AlgorithmIdentifier SEQUENCE, landing on the OCTET STRING.
	let offset = skipHeader(der, 0) + 3;
	offset = skipHeader(der, offset) + contentLength(der, offset);
	const contentStart = skipHeader(der, offset);

	return der.slice(contentStart, contentStart + contentLength(der, offset));
}

/** Offset of the first content byte of the TLV starting at `start`. */
function skipHeader(der: Uint8Array, start: number): number {
	const first = der[start + 1] as number;
	return first < 0x80 ? start + 2 : start + 2 + (first & 0x7f);
}

/** Content length of the TLV starting at `start`. */
function contentLength(der: Uint8Array, start: number): number {
	const first = der[start + 1] as number;
	if (first < 0x80) {
		return first;
	}

	let length = 0;
	for (let index = 0; index < (first & 0x7f); index++) {
		length = (length << 8) | (der[start + 2 + index] as number);
	}

	return length;
}

beforeEach(async () => {
	if (!keys) {
		const pair = (await crypto.subtle.generateKey(
			{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
		// `exportKey` is declared as `Promise<ArrayBuffer | JsonWebKey>` in the
		// generated runtime types, so the format literal does not narrow it.
		const pkcs8Der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
		const spkiDer = new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer);

		keys = {
			pkcs8Der,
			pkcs8Pem: toPem("PRIVATE KEY", pkcs8Der),
			pkcs1Pem: toPem("RSA PRIVATE KEY", pkcs1FromPkcs8(pkcs8Der)),
			publicSpkiPem: toPem("PUBLIC KEY", spkiDer),
		};
	}
});

afterEach(() => {
	vi.restoreAllMocks();
});

/** A deployment with the App fully configured. */
function configured(overrides: Record<string, unknown> = {}): ServiceEnv {
	return {
		...env,
		GITHUB_APP_ENABLED: "true",
		GITHUB_APP_ID: APP_ID,
		GITHUB_APP_PRIVATE_KEY: keys.pkcs8Pem,
		...overrides,
	} as unknown as ServiceEnv;
}

describe("the feature flag", () => {
	it.each([
		["true", true],
		["false", false],
		["TRUE", false],
		["True", false],
		["1", false],
		["yes", false],
		[" true", false],
		["true ", false],
		["", false],
	])("reads %o as %s", (value, expected) => {
		expect(githubAppEnabled({ GITHUB_APP_ENABLED: value })).toBe(expected);
	});

	it("reads an unset flag as off", () => {
		// Separate from the table because `exactOptionalPropertyTypes` makes
		// "absent" and "present and undefined" different things, and absent is what
		// a deployment that never heard of the feature actually has.
		expect(githubAppEnabled({})).toBe(false);
	});
});

describe("the App configuration guard", () => {
	it("accepts a complete configuration", () => {
		expect(requireAppConfig({ GITHUB_APP_ID: APP_ID, GITHUB_APP_PRIVATE_KEY: keys.pkcs8Pem })).toEqual({
			appId: APP_ID,
			privateKey: keys.pkcs8Pem.trim(),
		});
	});

	it("names both settings when both are missing", () => {
		// One deploy, not two: an operator who set neither should not have to
		// discover the second one after fixing the first.
		expect(() => requireAppConfig({})).toThrow(/GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY/);
	});

	it.each([
		["the id", { GITHUB_APP_PRIVATE_KEY: "key" }, "GITHUB_APP_ID"],
		["the key", { GITHUB_APP_ID: APP_ID }, "GITHUB_APP_PRIVATE_KEY"],
	])("names %s when only that is missing", (_name, config, expected) => {
		expect(() => requireAppConfig(config)).toThrow(expected);
	});

	it.each([
		["an empty id", { GITHUB_APP_ID: "", GITHUB_APP_PRIVATE_KEY: "key" }],
		["a whitespace id", { GITHUB_APP_ID: "   ", GITHUB_APP_PRIVATE_KEY: "key" }],
		["an empty key", { GITHUB_APP_ID: APP_ID, GITHUB_APP_PRIVATE_KEY: "" }],
		["a whitespace key", { GITHUB_APP_ID: APP_ID, GITHUB_APP_PRIVATE_KEY: "  \n  " }],
	])("treats %s as unset", (_name, config) => {
		// An unset `wrangler secret` and one put with an empty value are the same
		// thing to a Worker. Accepting the second would mean signing with a
		// zero-length key.
		expect(() => requireAppConfig(config)).toThrow(GitHubAppError);
	});

	it("reports a missing configuration as a misconfiguration, not a refusal", () => {
		// The flag the webhook path maps onto SERVICE_MISCONFIGURED. Getting it
		// wrong would answer 503 for a fault no retry can fix.
		try {
			requireAppConfig({});
			expect.unreachable("expected a throw");
		} catch (error) {
			expect(error).toBeInstanceOf(GitHubAppError);
			expect((error as GitHubAppError).misconfigured).toBe(true);
		}
	});

	it("never puts the key in the message", () => {
		try {
			requireAppConfig({ GITHUB_APP_ID: "", GITHUB_APP_PRIVATE_KEY: keys.pkcs8Pem });
			expect.unreachable("expected a throw");
		} catch (error) {
			expect((error as Error).message).not.toContain(keys.pkcs8Pem.slice(40, 90));
		}
	});
});

describe("destination pinning", () => {
	it("builds a URL on api.github.com", () => {
		expect(githubApiUrl("/app/installations/1/access_tokens").toString()).toBe(
			`${GITHUB_API_ORIGIN}/app/installations/1/access_tokens`,
		);
	});

	it.each([
		["a protocol-relative reference", "//evil.example/app"],
		["an absolute URL", "https://evil.example/app"],
		["an absolute URL on a lookalike host", "https://api.github.com.evil.example/app"],
		["a relative path", "app/installations"],
		["an empty path", ""],
		["a scheme-only value", "javascript:alert(1)"],
	])("refuses %s", (_name, path) => {
		// `validateUrl` — the SSRF guard the OIDC path uses — passes four of these
		// six, because it answers a different question: it sifts caller-controlled
		// URLs for private address space, and every one of these is a perfectly
		// respectable public host. When the hostname is a constant, the property
		// worth checking is that the constant is what came out.
		expect(() => githubApiUrl(path)).toThrow(GitHubAppError);
	});

	it("refuses a backslash the prefix check does not see", () => {
		// The case that makes the origin assertion load-bearing rather than
		// belt-and-braces. WHATWG URL parsing treats `\\` as `/` for special
		// schemes, so `/\\evil.example/x` normalises to `//evil.example/x` and
		// resolves to a different host — while starting with a single `/` and
		// sailing straight past the literal prefix check above it.
		expect(new URL(String.raw`/\evil.example/x`, GITHUB_API_ORIGIN).origin).toBe("https://evil.example");
		expect(() => githubApiUrl(String.raw`/\evil.example/x`)).toThrow(/resolved off/);
	});

	it("cannot be walked off the origin by path traversal", () => {
		// `..` normalises inside the origin rather than escaping it, so this is
		// about the path staying on the host — the installation id is separately
		// required to be a positive integer before it is ever interpolated.
		expect(githubApiUrl("/app/../../../../etc/passwd").origin).toBe(GITHUB_API_ORIGIN);
	});
});

describe("private key handling", () => {
	it("passes a PKCS#8 key through untouched", () => {
		expect(toPkcs8Pem(keys.pkcs8Pem)).toBe(keys.pkcs8Pem);
	});

	it("converts the PKCS#1 key GitHub actually hands you", () => {
		// The footgun this function exists for: GitHub's "Generate a private key"
		// button downloads `BEGIN RSA PRIVATE KEY`, and WebCrypto imports only
		// PKCS#8. Asserted against the *bytes* of the original export, so the
		// conversion is proven to reconstruct the real structure rather than
		// something that merely imports.
		const converted = toPkcs8Pem(keys.pkcs1Pem);

		expect(fromPem(converted)).toEqual(keys.pkcs8Der);
	});

	it("produces a key WebCrypto can actually import", async () => {
		await expect(
			crypto.subtle.importKey(
				"pkcs8",
				fromPem(toPkcs8Pem(keys.pkcs1Pem)).buffer as ArrayBuffer,
				{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
				false,
				["sign"],
			),
		).resolves.toBeDefined();
	});

	it.each([
		["a value with no PEM block", "not a key at all"],
		["an encrypted PKCS#8 block", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"],
		["a certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"],
	])("refuses %s as a misconfiguration", (_name, pem) => {
		try {
			toPkcs8Pem(pem);
			expect.unreachable("expected a throw");
		} catch (error) {
			expect(error).toBeInstanceOf(GitHubAppError);
			expect((error as GitHubAppError).misconfigured).toBe(true);
		}
	});

	it("encodes a short DER length as well as a long one", () => {
		// A 2048-bit key puts every length in DER's long form, so the short form —
		// contents under 128 bytes — is not reached by any real input. A length
		// encoder that only handles its expected inputs is how a later reuse
		// produces silently malformed DER, so the branch is exercised directly.
		//
		// Nothing here parses the body: `toPkcs8Pem` copies the key material
		// through untouched and only adds a header, which is exactly what makes a
		// synthetic body a valid probe of the wrapping.
		const tiny = new Uint8Array(8).fill(0x2a);
		const wrapped = fromPem(toPkcs8Pem(toPem("RSA PRIVATE KEY", tiny)));

		// SEQUENCE, then a single-byte length: 3 (version) + 15 (algorithm) + 2 + 8.
		expect(wrapped[0]).toBe(0x30);
		expect(wrapped[1]).toBe(28);
		expect(wrapped.slice(-8)).toEqual(tiny);
	});

	it("refuses a PKCS#1 header whose body is not base64", () => {
		expect(() => toPkcs8Pem("-----BEGIN RSA PRIVATE KEY-----\n!!!!\n-----END RSA PRIVATE KEY-----")).toThrow(
			/not valid base64/,
		);
	});
});

describe("the App JWT", () => {
	it("is an RS256 token GitHub could verify", async () => {
		// Verified against the real public key rather than merely decoded: a JWT
		// with the right claims and a wrong signature is what a broken key import
		// silently produces.
		const jwt = await mintAppJwt(configured());
		const { payload } = await jwtVerify(jwt, await importSPKI(keys.publicSpkiPem, "RS256"));

		expect(decodeProtectedHeader(jwt).alg).toBe("RS256");
		expect(payload.iss).toBe(APP_ID);
	});

	it("backdates iat and stays inside GitHub's ten-minute ceiling", async () => {
		// GitHub validates on their clock. A Worker a few seconds fast issues a
		// token that is "not yet valid" on arrival — which reads exactly like a bad
		// key, and is the reason the backdate exists.
		const before = Math.floor(Date.now() / TIME.SECOND);
		const jwt = await mintAppJwt(configured());
		const { payload } = await jwtVerify(jwt, await importSPKI(keys.publicSpkiPem, "RS256"));

		const iat = payload.iat as number;
		const exp = payload.exp as number;

		expect(iat).toBeLessThanOrEqual(before - 59);
		expect(exp - iat).toBeLessThanOrEqual(600);
		expect(exp).toBeGreaterThan(before);
	});

	it("mints from the PKCS#1 form as readily as the PKCS#8 one", async () => {
		const jwt = await mintAppJwt(configured({ GITHUB_APP_PRIVATE_KEY: keys.pkcs1Pem }));

		await expect(jwtVerify(jwt, await importSPKI(keys.publicSpkiPem, "RS256"))).resolves.toBeDefined();
	});

	it("reports an unimportable key without quoting it", async () => {
		// A failing key import is the single most likely place for a library to
		// quote the input it choked on straight back into a message.
		const nonsense = `-----BEGIN PRIVATE KEY-----\n${btoa("this is not a key")}\n-----END PRIVATE KEY-----`;

		try {
			await mintAppJwt(configured({ GITHUB_APP_PRIVATE_KEY: nonsense }));
			expect.unreachable("expected a throw");
		} catch (error) {
			expect(error).toBeInstanceOf(GitHubAppError);
			expect((error as GitHubAppError).misconfigured).toBe(true);
			expect((error as Error).message).not.toContain("this is not a key");
			expect((error as Error).message).not.toContain("BEGIN PRIVATE KEY");
		}
	});

	it("keeps the conversion's own diagnosis rather than replacing it", async () => {
		// `toPkcs8Pem` already says precisely what is wrong with a key that is not
		// a PEM block at all. Wrapping that in the generic "could not be imported"
		// message would throw away the only sentence that names the fix.
		await expect(mintAppJwt(configured({ GITHUB_APP_PRIVATE_KEY: "not a key at all" }))).rejects.toThrow(
			/BEGIN RSA PRIVATE KEY/,
		);
	});

	it("refuses to mint without a configuration", async () => {
		await expect(mintAppJwt({})).rejects.toThrow(GitHubAppError);
	});
});

describe("the installation-token cache key", () => {
	it("is namespaced away from the JWKS entries sharing the namespace", () => {
		const key = installationTokenCacheKey(APP_ID, 42);

		expect(key.startsWith("gh-app:")).toBe(true);
		expect(key.startsWith("jwks:")).toBe(false);
	});

	it("distinguishes installations and Apps", () => {
		// The App id is in the key because re-registering the App is how an
		// operator responds to a leaked private key, and the new App must not serve
		// tokens the old one minted.
		expect(installationTokenCacheKey(APP_ID, 1)).not.toBe(installationTokenCacheKey(APP_ID, 2));
		expect(installationTokenCacheKey("1", 1)).not.toBe(installationTokenCacheKey("2", 1));
	});
});

/** A `fetch` stub that records calls and refuses anything off api.github.com. */
function stubGitHub(handler: (request: Request) => Response | Promise<Response>) {
	const calls: Request[] = [];

	vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
		const request = new Request(input as RequestInfo, init as RequestInit);
		calls.push(request);

		// The pinning assertion, made once here rather than per test: no path
		// through this module may reach any other host, so the stub itself is what
		// fails if one ever does.
		if (new URL(request.url).origin !== GITHUB_API_ORIGIN) {
			throw new Error(`outbound request left api.github.com: ${request.url}`);
		}

		return Promise.resolve(handler(request));
	});

	return calls;
}

/** GitHub's access-token response, expiring `minutes` from now. */
function tokenResponse(token: string, minutes: number, status = 201): Response {
	return new Response(
		JSON.stringify({ token, expires_at: new Date(Date.now() + minutes * TIME.MINUTE).toISOString() }),
		{ status, headers: { "Content-Type": "application/json" } },
	);
}

describe("minting an installation token", () => {
	/** A KV double, so the cache can be inspected and made to fail. */
	function kv(store = new Map<string, { value: string; ttl?: number }>(), broken?: "get" | "put") {
		return {
			store,
			get(key: string, _type?: string) {
				if (broken === "get") {
					return Promise.reject(new Error("kv unavailable"));
				}
				const entry = store.get(key);
				return Promise.resolve(entry ? (JSON.parse(entry.value) as unknown) : null);
			},
			put(key: string, value: string, options?: { expirationTtl?: number }) {
				if (broken === "put") {
					return Promise.reject(new Error("kv unavailable"));
				}
				store.set(key, { value, ...(options?.expirationTtl !== undefined && { ttl: options.expirationTtl }) });
				return Promise.resolve();
			},
		};
	}

	it("posts to the pinned endpoint with the App JWT", async () => {
		const cache = kv();
		const calls = stubGitHub(() => tokenResponse("ghs_installationtoken", 60));

		const issued = await getInstallationToken(configured({ JWKS_CACHE: cache }), 42);

		expect(issued.token).toBe("ghs_installationtoken");
		expect(calls).toHaveLength(1);

		const request = calls[0] as Request;
		expect(request.url).toBe(`${GITHUB_API_ORIGIN}/app/installations/42/access_tokens`);
		expect(request.method).toBe("POST");
		expect(request.headers.get("Accept")).toBe("application/vnd.github+json");
		expect(request.headers.get("X-GitHub-Api-Version")).toBe("2022-11-28");

		// The bearer really is the App JWT — not, say, a token left over from
		// somewhere else — so the credential exchange is proven end to end.
		const bearer = (request.headers.get("Authorization") as string).slice("Bearer ".length);
		const { payload } = await jwtVerify(bearer, await importSPKI(keys.publicSpkiPem, "RS256"));
		expect(payload.iss).toBe(APP_ID);
	});

	it.each([
		["zero", 0],
		["a negative id", -1],
		["a fractional id", 1.5],
		["an unsafe integer", 2 ** 53],
		["NaN", Number.NaN],
	])("refuses %s without calling GitHub", async (_name, installationId) => {
		// The id arrives inside a webhook payload and is interpolated into a URL
		// path. `githubApiUrl` catches an origin change but not a value that stays
		// on the host and addresses something else.
		const calls = stubGitHub(() => tokenResponse("nope", 60));

		await expect(getInstallationToken(configured({ JWKS_CACHE: kv() }), installationId)).rejects.toThrow(
			/positive integer/,
		);
		expect(calls).toHaveLength(0);
	});

	it("serves the second call from cache", async () => {
		const cache = kv();
		const app = configured({ JWKS_CACHE: cache });
		const calls = stubGitHub(() => tokenResponse("ghs_cached", 60));

		const first = await getInstallationToken(app, 42);
		const second = await getInstallationToken(app, 42);

		expect(second).toEqual(first);
		expect(calls).toHaveLength(1);
	});

	it("gives the entry a TTL that expires before the token does", async () => {
		// The property, stated against GitHub's own `expires_at` rather than
		// against a constant: a cached token must never come back out after it has
		// stopped working, because that failure is indistinguishable from a revoked
		// App and the retry lands on the same cached value.
		const store = new Map<string, { value: string; ttl?: number }>();
		stubGitHub(() => tokenResponse("ghs_ttl", 60));

		await getInstallationToken(configured({ JWKS_CACHE: kv(store) }), 42);

		const entry = store.get(installationTokenCacheKey(APP_ID, 42));
		expect(entry).toBeDefined();

		const remaining =
			(Date.parse(JSON.parse((entry as { value: string }).value).expires_at) - Date.now()) / TIME.SECOND;
		expect(entry?.ttl).toBeLessThan(remaining);
		expect(entry?.ttl).toBeGreaterThan(0);
	});

	it("does not cache a token that is about to expire", async () => {
		// Under KV's own 60-second floor once the safety margin is taken off, so
		// there is no TTL that would be both accepted and honest.
		const store = new Map<string, { value: string; ttl?: number }>();
		stubGitHub(() => tokenResponse("ghs_brief", 5));

		const issued = await getInstallationToken(configured({ JWKS_CACHE: kv(store) }), 42);

		expect(issued.token).toBe("ghs_brief");
		expect(store.size).toBe(0);
	});

	it("ignores a stored token inside the safety margin", async () => {
		// Belt to KV expiry's braces: an entry written by an older release, or one
		// KV is still serving inside its eventual-consistency window.
		const store = new Map<string, { value: string; ttl?: number }>();
		store.set(installationTokenCacheKey(APP_ID, 42), {
			value: JSON.stringify({
				token: "ghs_stale",
				expires_at: new Date(Date.now() + TIME.MINUTE).toISOString(),
			}),
		});
		const calls = stubGitHub(() => tokenResponse("ghs_fresh", 60));

		const issued = await getInstallationToken(configured({ JWKS_CACHE: kv(store) }), 42);

		expect(issued.token).toBe("ghs_fresh");
		expect(calls).toHaveLength(1);
	});

	it("ignores a stored entry that is not an access-token response", async () => {
		const store = new Map<string, { value: string; ttl?: number }>();
		store.set(installationTokenCacheKey(APP_ID, 42), { value: JSON.stringify({ nonsense: true }) });
		stubGitHub(() => tokenResponse("ghs_fresh", 60));

		expect((await getInstallationToken(configured({ JWKS_CACHE: kv(store) }), 42)).token).toBe("ghs_fresh");
	});

	it("mints anyway when the cache cannot be read", async () => {
		stubGitHub(() => tokenResponse("ghs_despite_kv", 60));

		expect((await getInstallationToken(configured({ JWKS_CACHE: kv(undefined, "get") }), 42)).token).toBe(
			"ghs_despite_kv",
		);
	});

	it("returns the token even when it cannot be cached", async () => {
		// A degraded cache is a slow path, not a broken integration.
		stubGitHub(() => tokenResponse("ghs_uncacheable", 60));

		expect((await getInstallationToken(configured({ JWKS_CACHE: kv(undefined, "put") }), 42)).token).toBe(
			"ghs_uncacheable",
		);
	});

	it("reports a refusal by status, without the response body", async () => {
		// A 401 body from this endpoint describes the App credential that was
		// refused. Quoting it into a message is how that ends up in a log.
		stubGitHub(
			() => new Response(JSON.stringify({ message: "A JWT signed with ghs_leaky is invalid" }), { status: 401 }),
		);

		try {
			await getInstallationToken(configured({ JWKS_CACHE: kv() }), 42);
			expect.unreachable("expected a throw");
		} catch (error) {
			expect((error as Error).message).toContain("401");
			expect((error as Error).message).not.toContain("ghs_leaky");
		}
	});

	it("refuses a response it cannot read", async () => {
		stubGitHub(() => new Response(JSON.stringify({ token: "" }), { status: 201 }));

		await expect(getInstallationToken(configured({ JWKS_CACHE: kv() }), 42)).rejects.toThrow(/unreadable/);
	});

	it("refuses a response with no expiry to bound the cache with", async () => {
		stubGitHub(() => new Response(JSON.stringify({ token: "ghs_x" }), { status: 201 }));

		await expect(getInstallationToken(configured({ JWKS_CACHE: kv() }), 42)).rejects.toThrow(/unreadable/);
	});

	it("reports an unreachable GitHub without leaking the JWT", async () => {
		// The JWT was in the request that failed, and a runtime's network error can
		// carry anything from the attempt.
		vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("connection reset"));

		try {
			await getInstallationToken(configured({ JWKS_CACHE: kv() }), 42);
			expect.unreachable("expected a throw");
		} catch (error) {
			expect(error).toBeInstanceOf(GitHubAppError);
			expect((error as Error).message).toContain("Could not reach GitHub");
			expect((error as Error).message).not.toContain("eyJ");
		}
	});

	it("refuses before any network call when the App is not configured", async () => {
		const calls = stubGitHub(() => tokenResponse("nope", 60));

		await expect(getInstallationToken(configured({ GITHUB_APP_ID: "", JWKS_CACHE: kv() }), 42)).rejects.toThrow(
			GitHubAppError,
		);
		expect(calls).toHaveLength(0);
	});
});

describe("the verifier's own unset-secret guard", () => {
	it("answers false rather than throwing", async () => {
		// The middleware refuses an unset secret before the verifier is reached, so
		// this is the second of two independent guards. It matters because
		// `importKey` rejects a zero-length HMAC key with a DataError — which would
		// surface as a 500, and a 500 is what a caller retries.
		const body = new TextEncoder().encode("{}").buffer as ArrayBuffer;

		await expect(verifyWebhookSignature("", body, `sha256=${"0".repeat(64)}`)).resolves.toBe(false);
	});

	it("answers false for an absent header without touching the body", async () => {
		const body = new TextEncoder().encode("{}").buffer as ArrayBuffer;

		await expect(verifyWebhookSignature("secret", body, undefined)).resolves.toBe(false);
	});
});

describe("the new secrets in the Sentry scrubber", () => {
	it("collects both as literal values to redact", () => {
		// The scrubber's key-name denylist already catches `githubAppPrivateKey`
		// and `githubWebhookSecret` by their fragments. This is the other half: the
		// rule that catches a secret arriving under a name nobody anticipated,
		// which is the one that has to name every value the deployment holds.
		const secrets = collectEnvSecrets({
			GITHUB_APP_PRIVATE_KEY: "app-private-key-value",
			GITHUB_WEBHOOK_SECRET: "webhook-secret-value",
		});

		expect(secrets).toContain("app-private-key-value");
		expect(secrets).toContain("webhook-secret-value");
	});

	it("redacts them wherever they appear in an event", () => {
		const secrets = collectEnvSecrets({
			GITHUB_APP_PRIVATE_KEY: "app-private-key-value",
			GITHUB_WEBHOOK_SECRET: "webhook-secret-value",
		});

		const scrubbed = JSON.stringify(
			scrubValue({ note: "signed with app-private-key-value and webhook-secret-value" }, secrets),
		);

		expect(scrubbed).not.toContain("app-private-key-value");
		expect(scrubbed).not.toContain("webhook-secret-value");
	});
});
