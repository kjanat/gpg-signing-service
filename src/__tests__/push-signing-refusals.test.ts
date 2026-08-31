/**
 * The refusals the happy path never reaches, and the readers in front of them.
 *
 * Split out of `push-signing.test.ts` because these are a different kind of
 * test. That suite drives whole deliveries through the app to prove what the
 * run does; this one exercises the readers directly — the ref parser, the
 * repository scope, the response parser — and the refusals that need a broken
 * key or a broken dependency to reach.
 *
 * Every case below is one where the *permissive* reading is the tempting one:
 * a branch name that looks fine until git sees it, a repository string that
 * looks fine until it is a URL path, a key that is present and cannot sign, a
 * response body that parses as JSON and is not the document it claims.
 */

import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { Env, WebhookAuthorization } from "#types";
import { GITHUB_API_ORIGIN } from "#utils/github-app";
import { GitHubApiError, getCommit, repositoryContext } from "#utils/github-repo";
import { loadSigningKey } from "#utils/github-signing-key";
import { isBranchName, pushDiagnostics, pushSubject, signPushedCommits } from "#utils/push-signing";
import { keyIdentityEmails, verifyDetachedSignature } from "#utils/signing";

describe("branch names", () => {
	it("accepts the ones git does", () => {
		for (const name of ["master", "feat/thing", "release-1.2.3", "a".repeat(255), "user/fix.2"]) {
			expect([name, isBranchName(name)]).toEqual([name, true]);
		}
	});

	it("refuses the ones that are a traversal, a git special, or unprintable", () => {
		// Applied even though the value is percent-encoded on the way into a URL: a
		// name that encodes cleanly can still be a traversal once GitHub decodes it,
		// and this service should not be the one to find out.
		const refused = [
			"",
			"a".repeat(256),
			"..",
			"a/../b",
			"feat/../../etc",
			"/leading",
			"trailing/",
			"trailing.",
			"has space",
			"has\ttab",
			"has\nnewline",
			"caret^",
			"tilde~",
			"colon:x",
			"question?",
			"star*",
			"bracket[",
			"back\\slash",
			"at@{brace",
			"double//slash",
			".hidden",
			"feat/.hidden",
			"feat/thing.lock",
			"\u0000nul",
			"\u007fdel",
		];

		for (const name of refused) {
			expect([JSON.stringify(name), isBranchName(name)]).toEqual([JSON.stringify(name), false]);
		}
	});
});

describe("reading a push payload", () => {
	const SHA = "a".repeat(40);

	it("reads a branch, a range and a deletion", () => {
		expect(pushSubject({ ref: "refs/heads/master", before: SHA, after: SHA, deleted: true })).toEqual({
			branch: "master",
			before: SHA,
			after: SHA,
			deleted: true,
		});
	});

	it("gives back nothing at all for a payload that is not an object", () => {
		for (const payload of [null, undefined, "a string", 42, ["an", "array"]]) {
			expect(pushSubject(payload)).toEqual({ branch: null, before: null, after: null, deleted: false });
		}
	});

	it("refuses a ref that is not under refs/heads", () => {
		for (const ref of ["refs/tags/v1", "refs/pull/1/head", "master", "", 42]) {
			expect(pushSubject({ ref }).branch).toBeNull();
		}
	});

	it("refuses an object name it cannot read rather than defaulting one", () => {
		// A defaulted `before` would silently become "walk the whole history", and a
		// defaulted `after` would be a ref update to a name nobody sent.
		expect(pushSubject({ ref: "refs/heads/m", before: "short", after: SHA.toUpperCase() })).toMatchObject({
			before: null,
			after: null,
		});
	});

	it("records what the delivery said even when none of it was usable", () => {
		// The audit row's job, which is the opposite of the parser's: an
		// unrenderable ref is exactly the case an operator needs the ref for.
		expect(pushDiagnostics({ ref: "refs/tags/v1", before: 7, after: "x".repeat(200) })).toEqual({
			branch: "refs/tags/v1",
			before: null,
			after: "x".repeat(128),
		});
		expect(pushDiagnostics("not an object")).toEqual({ branch: null, before: null, after: null });
	});
});

describe("the repository a run may touch", () => {
	function authorization(overrides: Partial<WebhookAuthorization> = {}): WebhookAuthorization {
		return { scope: "repository", installationId: 42, repository: "kjanat/service", keyId: null, ...overrides };
	}

	it("splits an authorized pair into owner and repo", () => {
		expect(repositoryContext(authorization())).toEqual({
			installationId: 42,
			owner: "kjanat",
			repo: "service",
			fullName: "kjanat/service",
		});
	});

	it("grants nothing below repository scope", () => {
		expect(repositoryContext(undefined)).toBeNull();
		expect(repositoryContext(authorization({ scope: "installation", repository: null }))).toBeNull();
		expect(repositoryContext(authorization({ scope: "none", installationId: null, repository: null }))).toBeNull();
	});

	it("refuses a decision whose repository is not one, even having been authorized", () => {
		// The last check before the value becomes a URL path. `WebhookAuthorization`
		// crosses a context boundary as a plain string, so the allowlist parser's
		// diligence is not inherited here.
		expect(repositoryContext(authorization({ repository: "../../etc/passwd" }))).toBeNull();
		expect(repositoryContext(authorization({ repository: "no-slash" }))).toBeNull();
		expect(repositoryContext(authorization({ installationId: null }))).toBeNull();
		// A scope below `repository` carrying a repository anyway. `authorizeDelivery`
		// cannot produce this, which is exactly why the check is here rather than
		// inferred from the invariant: the day something else writes this type, the
		// scope is what must decide.
		expect(repositoryContext(authorization({ scope: "installation" }))).toBeNull();
		expect(repositoryContext(authorization({ scope: "none" }))).toBeNull();
	});
});

describe("reading GitHub's answers", () => {
	const context = { installationId: 1, owner: "kjanat", repo: "service", fullName: "kjanat/service" };

	/** The token response, so the failure under test is the only failure. */
	function tokenResponse(): Response {
		return new Response(
			JSON.stringify({ token: "ghs_x", expires_at: new Date(Date.now() + 3_600_000).toISOString() }),
			{
				status: 201,
				headers: { "Content-Type": "application/json" },
			},
		);
	}

	function stub(response: () => Response | Promise<Response>) {
		vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
			const request = new Request(input as RequestInfo, init as RequestInit);
			if (new URL(request.url).pathname.endsWith("/access_tokens")) {
				return Promise.resolve(tokenResponse());
			}
			return Promise.resolve(response()) as Promise<Response>;
		});
	}

	let usable: Env;

	beforeAll(async () => {
		const pair = (await crypto.subtle.generateKey(
			{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
		const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
		let binary = "";
		for (const byte of der) {
			binary += String.fromCharCode(byte);
		}
		usable = {
			...env,
			GITHUB_APP_ID: "1",
			GITHUB_APP_PRIVATE_KEY: `-----BEGIN PRIVATE KEY-----\n${btoa(binary).replace(/(.{64})/g, "$1\n")}\n-----END PRIVATE KEY-----\n`,
		} as unknown as Env;
	}, 30_000);

	it("reports a status without quoting the body", async () => {
		// A 401 from these endpoints describes the *credential* that was refused.
		stub(() => new Response(JSON.stringify({ message: "Bad credentials", token: "ghs_leaked" }), { status: 401 }));

		const error = await getCommit(usable, context, "a".repeat(40)).catch((thrown: unknown) => thrown);

		expect(error).toBeInstanceOf(GitHubApiError);
		expect((error as GitHubApiError).status).toBe(401);
		// The status is reported as a *refusal*, not read as a document. Asserting
		// the message rather than only the status: a reader that skipped the status
		// check would still fail the schema and still raise a `GitHubApiError` with
		// a 401 on it, for a completely different reason.
		expect((error as Error).message).toBe("reading a commit failed (HTTP 401)");
		expect((error as Error).message).not.toContain("ghs_leaked");
		expect((error as Error).message).not.toContain("Bad credentials");
	});

	it("refuses a 200 whose body is not JSON", async () => {
		stub(() => new Response("<html>a proxy error page</html>", { status: 200 }));

		await expect(getCommit(usable, context, "a".repeat(40))).rejects.toThrow("unreadable JSON");
	});

	it("refuses a 200 that parses and is not the document it claims", async () => {
		// The values that failed are deliberately not carried out: they come from a
		// response body this module has decided not to repeat.
		stub(() => new Response(JSON.stringify({ sha: "not-a-sha", token: "ghs_leaked" }), { status: 200 }));

		const error = await getCommit(usable, context, "a".repeat(40)).catch((thrown: unknown) => thrown);

		expect((error as Error).message).toContain("unexpected shape");
		expect((error as Error).message).not.toContain("ghs_leaked");
	});

	it("reports a request that never completed with no status at all", async () => {
		// The distinction the ref update turns into "retryable" or "unknown".
		vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
			const request = new Request(input as RequestInfo, init as RequestInit);
			if (new URL(request.url).pathname.endsWith("/access_tokens")) {
				return Promise.resolve(tokenResponse());
			}
			return Promise.reject(new Error("connection reset"));
		});

		const error = await getCommit(usable, context, "a".repeat(40)).catch((thrown: unknown) => thrown);

		expect((error as GitHubApiError).status).toBeNull();
	});

	it("never leaves api.github.com, whatever the repository is called", async () => {
		const seen: string[] = [];
		vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
			seen.push(new Request(input as RequestInfo, init as RequestInit).url);
			return Promise.resolve(tokenResponse());
		});

		// Not a repository the allowlist would admit; the point is that even if one
		// got this far, the path is assembled from encoded segments.
		await getCommit(usable, { ...context, repo: "..\\evil.example" }, "a".repeat(40)).catch(() => undefined);

		expect(seen.length).toBeGreaterThan(0);
		for (const url of seen) {
			expect(new URL(url).origin).toBe(GITHUB_API_ORIGIN);
		}
	});
});

describe("keys that cannot sign", () => {
	/** Put a key straight into storage, bypassing the admin route's validation. */
	async function store(body: unknown): Promise<void> {
		const storage = env.KEY_STORAGE.get(env.KEY_STORAGE.idFromName("global"));
		const response = await storage.fetch(
			new Request("http://internal/store-key", { method: "POST", body: JSON.stringify(body) }),
		);
		if (!response.ok) {
			throw new Error(`could not seed the key: ${response.status} ${await response.text()}`);
		}
	}

	function authorization(keyId: string): WebhookAuthorization {
		return { scope: "repository", installationId: 42, repository: "kjanat/service", keyId };
	}

	/** A `push` for a repository this deployment grants, so only the key can refuse. */
	function delivery() {
		return {
			ref: "refs/heads/master",
			before: "a".repeat(40),
			after: "b".repeat(40),
			installation: { id: 42 },
			repository: { full_name: "kjanat/service" },
		};
	}

	it("refuses an X.509 key rather than putting a PKCS#7 blob in a gpgsig header", async () => {
		// git's `gpgsig` carries OpenPGP unless the repository sets
		// `gpg.format=x509`, which is a repository-side setting this service cannot
		// see. Guessing produces a commit nothing can verify.
		const keyId = "1111111111111111";
		const filler = "A".repeat(200);
		await store({
			type: "x509",
			keyId,
			privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${filler}\n-----END PRIVATE KEY-----`,
			certificatePem: `-----BEGIN CERTIFICATE-----\n${filler}\n-----END CERTIFICATE-----`,
			fingerprint: "A".repeat(40),
			createdAt: new Date().toISOString(),
			algorithm: "RSA",
		});

		const outcome = await signPushedCommits(env as Env, authorization(keyId), delivery());

		expect(outcome).toMatchObject({ acted: false, reason: "key_type_unsupported" });
	});

	it("refuses a key that names no committer", async () => {
		// The key decides which commits it may sign, by the addresses it carries. A
		// key with none names nobody, and the fail-closed reading of an empty set is
		// "signs nothing" rather than "signs everything".
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "No Address" }],
			passphrase: env.KEY_PASSPHRASE,
			format: "armored",
		});
		const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
		const keyId = parsed.getKeyID().toHex().toUpperCase();

		await store({
			armoredPrivateKey: privateKey,
			keyId,
			fingerprint: parsed.getFingerprint(),
			algorithm: "EdDSA",
			createdAt: new Date().toISOString(),
		});

		expect(await keyIdentityEmails(privateKey)).toEqual(new Set());

		const outcome = await signPushedCommits(env as Env, authorization(keyId), delivery());
		expect(outcome).toMatchObject({ acted: false, reason: "key_without_identity" });
	});

	it("refuses rather than throwing when the App identity is not configured", async () => {
		// A deployment serving the webhook without App credentials. An escaping
		// throw would settle the delivery neither way and leave it to a lease, when
		// what happened is precisely nothing — and the operator's redelivery after
		// fixing the credentials is the whole recovery path.
		// A usable key, so the refusal under test is the only one available.
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Kaj Kowalski", email: "info@kajkowalski.nl" }],
			passphrase: env.KEY_PASSPHRASE,
			format: "armored",
		});
		const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
		const keyId = parsed.getKeyID().toHex().toUpperCase();
		await store({
			armoredPrivateKey: privateKey,
			keyId,
			fingerprint: parsed.getFingerprint(),
			algorithm: "EdDSA",
			createdAt: new Date().toISOString(),
		});

		// The two App settings deleted rather than set to undefined:
		// `exactOptionalPropertyTypes` makes those different things, and an unset
		// key is what an operator who has not run `wrangler secret put` has.
		const unconfigured = { ...(env as unknown as Env) };
		delete unconfigured.GITHUB_APP_ID;
		delete unconfigured.GITHUB_APP_PRIVATE_KEY;

		const outcome = await signPushedCommits(unconfigured, authorization(keyId), delivery());

		expect(outcome).toMatchObject({ acted: false, reason: "app_misconfigured", retryable: true });
		// And the message names the settings, never any part of their values.
		expect((outcome as { detail: string }).detail).toContain("GITHUB_APP_ID");
	});

	it("refuses a delivery that never reached repository scope", async () => {
		const outcome = await signPushedCommits(env as Env, undefined, delivery());

		expect(outcome).toMatchObject({ acted: false, reason: "not_repository_scope" });
	});

	it("tells a missing key apart from unreachable storage", async () => {
		const missing = await loadSigningKey(env as Env, authorization("EEEEEEEEEEEEEEEE"));
		expect(missing).toEqual({ allowed: false, reason: "key_missing" });

		const broken = {
			KEY_STORAGE: { idFromName: () => "id", get: () => ({ fetch: () => Promise.reject(new Error("down")) }) },
		} as unknown as Env;
		expect(await loadSigningKey(broken, authorization("EEEEEEEEEEEEEEEE"))).toEqual({
			allowed: false,
			reason: "key_storage_unavailable",
		});
	});
});

describe("verifying a signature", () => {
	it("says no rather than throwing for anything that is not a signature", async () => {
		// Called on untrusted input — a `gpgsig` header GitHub reported — so a throw
		// here would be a 500 on the webhook path for a malformed commit.
		for (const armor of ["", "not armor", "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----"]) {
			expect(await verifyDetachedSignature("payload", armor, "-----BEGIN PGP PUBLIC KEY BLOCK-----")).toBe(false);
		}
	});

	it("reads only the addressed user IDs off a key", async () => {
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Kaj Kowalski", email: "INFO@Kajkowalski.NL" }],
			format: "armored",
		});

		// Lower-cased, because a committer address is compared against this set and
		// GitHub preserves whatever case the commit was made with.
		expect(await keyIdentityEmails(privateKey)).toEqual(new Set(["info@kajkowalski.nl"]));
	});
});
