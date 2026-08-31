/**
 * The trust boundary in front of `POST /github/webhook`.
 *
 * The URL is public by construction — it is typed into a settings form and then
 * reachable by anyone who guesses it — so the HMAC is not one control among
 * several. It is the only one, and these tests are written against the ways it
 * can be lost rather than against the shape of the code that implements it.
 *
 * The three that matter, and what proves each:
 *
 * - **A verifier that re-serialises the body still passes the happy path.** So
 *   the happy path cannot be the test. `accepts a body whose re-serialisation
 *   differs` sends a document that `JSON.stringify(JSON.parse(...))` provably
 *   changes, and its sibling sends a signature over the *re-serialised* form and
 *   requires it to be refused. Between them, only a verifier working on the
 *   received octets passes both.
 * - **A disabled feature that answers differently from an unrouted path is an
 *   enumeration oracle.** The 404 is compared against a genuinely unrouted
 *   path's, byte for byte and header for header, rather than against a literal
 *   copied out of the middleware.
 * - **The order of the gates is a security property, not a style.** The limiter
 *   must be in front of the HMAC and behind the feature flag, and both halves
 *   are observable: rate-limit headers appear on a refused delivery, and do not
 *   appear on a disabled one.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import app from "#gpg-signing-service";
import { HEADERS } from "#types";
import { SIGNATURE_HEADER, SIGNATURE_PREFIX } from "#utils/github-webhook";

const SECRET = "test-webhook-secret";

/** A deployment with the integration switched on and completely configured. */
const ENABLED = { GITHUB_APP_ENABLED: "true", GITHUB_WEBHOOK_SECRET: SECRET };

interface Envelope {
	error?: string;
	code?: string;
	received?: boolean;
	event?: string;
	delivery?: string;
	installation?: boolean;
	handled?: boolean;
}

/** The `sha256=…` value GitHub would send for these exact bytes. */
async function sign(body: string, secret: string = SECRET): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));

	return SIGNATURE_PREFIX + [...mac].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function deliver(
	body: string,
	headers: Record<string, string> = {},
	overrides: Record<string, unknown> = {},
): Promise<{ response: Response; body: Envelope }> {
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request("https://sign.test/github/webhook", {
			method: "POST",
			body,
			headers: { "Content-Type": "application/json", ...headers },
		}),
		{ ...env, ...overrides },
		ctx,
	);
	await waitOnExecutionContext(ctx);

	return { response, body: (await response.json()) as Envelope };
}

/** A delivery that is correctly signed for whatever `overrides` configure. */
async function deliverSigned(
	body: string,
	headers: Record<string, string> = {},
	overrides: Record<string, unknown> = ENABLED,
): Promise<{ response: Response; body: Envelope }> {
	const secret = typeof overrides.GITHUB_WEBHOOK_SECRET === "string" ? overrides.GITHUB_WEBHOOK_SECRET : SECRET;

	return deliver(
		body,
		{
			[SIGNATURE_HEADER]: await sign(body, secret),
			"X-GitHub-Event": "ping",
			"X-GitHub-Delivery": "11111111-2222-3333-4444-555555555555",
			...headers,
		},
		overrides,
	);
}

/**
 * The same request to two paths, so the only difference between the responses
 * is which path the service was asked for.
 */
async function probe(path: string): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request(`https://sign.test${path}`, {
			method: "POST",
			body: "{}",
			headers: { "Content-Type": "application/json" },
		}),
		env,
		ctx,
	);
	await waitOnExecutionContext(ctx);

	return response;
}

/**
 * A response's headers, comparably.
 *
 * `X-Request-ID` is dropped because it is a fresh UUID per request by
 * construction, and it is the same shape on both paths. Everything else is
 * compared, including values.
 */
function headerFingerprint(response: Response): string[] {
	return [...response.headers]
		.filter(([name]) => name.toLowerCase() !== "x-request-id")
		.map(([name, value]) => `${name.toLowerCase()}: ${value}`)
		.sort();
}

describe("the webhook route when the feature is off", () => {
	// wrangler.test.toml ships GITHUB_APP_ENABLED="false", so the default env in
	// every other suite in this tree is also the disabled one. That is the point:
	// "off changes nothing" is checked by every test that never mentions it.
	it("is indistinguishable from a path the service does not route", async () => {
		const disabled = await probe("/github/webhook");
		const genuinelyUnrouted = await probe("/no-such-route");

		expect(disabled.status).toBe(genuinelyUnrouted.status);
		// Compared as bytes against the other route's actual response rather than
		// against a literal, so a change to the 404 envelope cannot make these two
		// drift apart silently — and as bytes rather than as a parsed object,
		// because a difference in key order is still one a prober can measure.
		expect(await disabled.text()).toBe(await genuinelyUnrouted.text());
		// The headers too, which is where a difference would otherwise hide: a
		// stray `WWW-Authenticate`, a rate-limit header from a gate that ran when
		// it should not have, a `Vary` only one of the two paths sets.
		expect(headerFingerprint(disabled)).toEqual(headerFingerprint(genuinelyUnrouted));
	});

	it("refuses even a delivery signed with the right secret", async () => {
		// The flag is the outermost decision. A caller holding the webhook secret
		// still gets nothing from a deployment that did not opt in — which is what
		// makes the flag a deployment control rather than a hint.
		const { response, body } = await deliverSigned("{}", {}, { GITHUB_WEBHOOK_SECRET: SECRET });

		expect(response.status).toBe(404);
		expect(body.code).toBe("NOT_FOUND");
	});

	it.each(["TRUE", "True", "1", "yes", "on", " true", "true ", ""])(
		"stays off when GITHUB_APP_ENABLED is %o",
		async (flag) => {
			// One literal spelling and no other. A flag guarding an inbound webhook
			// is the wrong place to be generous: every near-miss must read as off,
			// because the alternative is a deployment that is on by accident.
			const { response } = await deliverSigned("{}", {}, { ...ENABLED, GITHUB_APP_ENABLED: flag });

			expect(response.status).toBe(404);
		},
	);

	it("does not consult the rate limiter", async () => {
		// Proves the gate runs first. If the limiter were in front, every
		// deployment carrying this code — enabled or not — would pay a Durable
		// Object round trip for any request to this path.
		const { response } = await deliver("{}");

		expect(response.headers.get(HEADERS.RATE_LIMIT_REMAINING)).toBeNull();
	});
});

describe("the webhook route when the feature is on but not configured", () => {
	it("answers SERVICE_MISCONFIGURED rather than hiding behind the 404", async () => {
		// An operator who opted in and cannot receive deliveries must be able to
		// tell that apart from a deployment that never opted in. Answering 404 for
		// both is how a webhook integration silently receives nothing for a week.
		const { response, body } = await deliver("{}", {}, { GITHUB_APP_ENABLED: "true", GITHUB_WEBHOOK_SECRET: "" });

		expect(response.status).toBe(500);
		expect(body.code).toBe("SERVICE_MISCONFIGURED");
	});

	it("does not tell the caller which setting is missing", async () => {
		// The response goes to whoever sent the request, and "this deployment
		// enabled a webhook without a secret" is the single most useful sentence
		// an attacker could be handed. Same posture as the two `adminAuth`
		// configuration guards.
		const { body } = await deliver("{}", {}, { GITHUB_APP_ENABLED: "true", GITHUB_WEBHOOK_SECRET: "" });
		const serialized = JSON.stringify(body);

		expect(serialized).not.toContain("GITHUB_WEBHOOK_SECRET");
		expect(serialized).not.toContain("secret");
	});

	it("refuses before any signature is examined", async () => {
		// The configuration guard runs ahead of the HMAC, so a deployment with no
		// secret never reaches a comparison at all. That ordering is what keeps the
		// unset case from depending on how the comparison behaves — see
		// `github-app.test.ts` for the second, independent guard inside the
		// verifier itself.
		const { response, body } = await deliver(
			"{}",
			{ [SIGNATURE_HEADER]: `${SIGNATURE_PREFIX}${"0".repeat(64)}` },
			{ GITHUB_APP_ENABLED: "true", GITHUB_WEBHOOK_SECRET: "" },
		);

		expect(response.status).toBe(500);
		expect(body.code).toBe("SERVICE_MISCONFIGURED");
	});
});

describe("signature verification", () => {
	it("accepts a delivery GitHub signed", async () => {
		const payload = JSON.stringify({ zen: "Non-blocking is better than blocking." });
		const { response, body } = await deliverSigned(payload);

		expect(response.status).toBe(202);
		expect(body).toMatchObject({
			received: true,
			event: "ping",
			delivery: "11111111-2222-3333-4444-555555555555",
			installation: false,
			handled: false,
		});
	});

	it("refuses a delivery with no signature at all", async () => {
		const { response, body } = await deliver("{}", { "X-GitHub-Event": "ping" }, ENABLED);

		expect(response.status).toBe(401);
		// AUTH_MISSING, not AUTH_INVALID: nothing was presented. The service draws
		// that line the same way on every route, and a client branching on `code`
		// is entitled to it here too.
		expect(body.code).toBe("AUTH_MISSING");
		expect(response.headers.get("WWW-Authenticate")).toBeTruthy();
	});

	it("refuses a delivery signed with the wrong secret", async () => {
		const payload = JSON.stringify({ zen: "Anything added dilutes everything else." });
		const { response, body } = await deliver(
			payload,
			{ [SIGNATURE_HEADER]: await sign(payload, "not-the-secret"), "X-GitHub-Event": "ping" },
			ENABLED,
		);

		expect(response.status).toBe(401);
		expect(body.code).toBe("AUTH_INVALID");
	});

	it("refuses a valid signature over a different body", async () => {
		// The forwarding attack: a delivery this deployment really did receive,
		// replayed with its body swapped. The MAC covers the body, so it must not
		// survive the swap.
		const signature = await sign(JSON.stringify({ action: "opened" }));
		const { response, body } = await deliver(
			JSON.stringify({ action: "closed" }),
			{ [SIGNATURE_HEADER]: signature, "X-GitHub-Event": "issues" },
			ENABLED,
		);

		expect(response.status).toBe(401);
		expect(body.code).toBe("AUTH_INVALID");
	});

	it.each([
		["no algorithm prefix", (hex: string) => hex],
		["the sha1 prefix", (hex: string) => `sha1=${hex}`],
		["an uppercased prefix", (hex: string) => `SHA256=${hex}`],
		["a truncated digest", (hex: string) => `${SIGNATURE_PREFIX}${hex.slice(0, 62)}`],
		["an over-long digest", (hex: string) => `${SIGNATURE_PREFIX}${hex}00`],
		["a non-hex digest", (hex: string) => `${SIGNATURE_PREFIX}${"z".repeat(2)}${hex.slice(2)}`],
		["an empty digest", () => SIGNATURE_PREFIX],
		["whitespace", () => "   "],
	])("refuses a delivery presenting %s", async (_name, mangle) => {
		// Every one of these must land on the same answer as a wrong-but-well-formed
		// digest. A caller that can tell a malformed candidate from a wrong one is
		// being told where to spend its next attempt.
		const payload = JSON.stringify({ zen: "Design for failure." });
		const valid = (await sign(payload)).slice(SIGNATURE_PREFIX.length);

		const { response, body } = await deliver(
			payload,
			{ [SIGNATURE_HEADER]: mangle(valid), "X-GitHub-Event": "ping" },
			ENABLED,
		);

		expect(response.status).toBe(401);
		expect(body.code).toBe("AUTH_INVALID");
	});

	it("accepts an upper-case hex digest", async () => {
		// GitHub sends lower case, but the digest is a number written in hex and
		// case is not part of its value. Being strict here would refuse a correct
		// signature, which is the one kind of strictness that gets a check removed.
		const payload = JSON.stringify({ zen: "Practicality beats purity." });
		const signature = await sign(payload);

		const { response } = await deliver(
			payload,
			{ [SIGNATURE_HEADER]: SIGNATURE_PREFIX + signature.slice(SIGNATURE_PREFIX.length).toUpperCase() },
			ENABLED,
		);

		expect(response.status).toBe(202);
	});
});

describe("what exactly is signed", () => {
	/**
	 * A document whose re-serialisation is provably different: the keys are out
	 * of insertion order in a way `JSON.stringify` preserves, and there is
	 * insignificant whitespace `JSON.parse` discards.
	 */
	const RAW = '{\n  "zen": "Half measures are as bad as nothing at all",\n  "installation": {"id": 42},\n  "a": 1\n}';

	it("verifies the bytes that arrived, not a re-serialisation of them", async () => {
		// The load-bearing test. A verifier that parses and re-stringifies before
		// computing the MAC fails this on honest traffic, which is precisely the
		// failure that gets an HMAC check quietly weakened rather than fixed.
		expect(JSON.stringify(JSON.parse(RAW))).not.toBe(RAW);

		const { response, body } = await deliverSigned(RAW, { "X-GitHub-Event": "installation" });

		expect(response.status).toBe(202);
		expect(body.installation).toBe(true);
	});

	it("refuses a signature computed over the re-serialised form", async () => {
		// The converse. Without this, a verifier that re-serialises *both* sides
		// would still pass the test above while checking a MAC over bytes GitHub
		// never sent.
		const reserialized = JSON.stringify(JSON.parse(RAW));
		const { response, body } = await deliver(
			RAW,
			{ [SIGNATURE_HEADER]: await sign(reserialized), "X-GitHub-Event": "installation" },
			ENABLED,
		);

		expect(response.status).toBe(401);
		expect(body.code).toBe("AUTH_INVALID");
	});

	it("answers 400 for a verified delivery that is not JSON", async () => {
		// Signed, so the sender proved it holds the secret; unparseable, so there
		// is nothing to act on. That is a bad request, not a failed authentication,
		// and conflating them would send an operator to rotate a working secret.
		const { response, body } = await deliverSigned("not json at all");

		expect(response.status).toBe(400);
		expect(body.code).toBe("INVALID_REQUEST");
	});
});

describe("what the acknowledgement says", () => {
	it.each([
		["an integer id", { installation: { id: 42 } }, true],
		["no installation object", { zen: "x" }, false],
		["a null installation", { installation: null }, false],
		["a string id", { installation: { id: "42" } }, false],
		["a negative id", { installation: { id: -1 } }, false],
		["a fractional id", { installation: { id: 1.5 } }, false],
		["an id beyond the safe integer range", { installation: { id: 2 ** 53 } }, false],
		["no id at all", { installation: {} }, false],
	])("reports installation=%s for %s", async (_name, payload, expected) => {
		// The id is about to be interpolated into a GitHub API path by the code
		// this scaffold exists to prepare for, so "is there a usable one" has to be
		// answered the same way here as it is there.
		const { body } = await deliverSigned(JSON.stringify(payload), { "X-GitHub-Event": "installation" });

		expect(body.installation).toBe(expected);
	});

	it("never claims to have handled anything", async () => {
		// The scaffold acts on nothing. When that changes, this test is the thing
		// that has to be changed deliberately alongside it.
		for (const event of ["ping", "push", "issue_comment", "check_suite", "something_new"]) {
			const { body } = await deliverSigned(JSON.stringify({ installation: { id: 7 } }), { "X-GitHub-Event": event });

			expect(body).toMatchObject({ received: true, event, handled: false });
		}
	});

	it("does not echo the installation id", async () => {
		const { body } = await deliverSigned(JSON.stringify({ installation: { id: 987654 } }));

		expect(JSON.stringify(body)).not.toContain("987654");
	});

	it("falls back to a placeholder when GitHub names neither event nor delivery", async () => {
		// Both headers are GitHub's to send and this service does not control
		// them, so their absence must not be a 500.
		const payload = JSON.stringify({ zen: "x" });
		const ctx = createExecutionContext();
		const response = await app.fetch(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: payload,
				headers: { [SIGNATURE_HEADER]: await sign(payload) },
			}),
			{ ...env, ...ENABLED },
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(202);
		expect(await response.json()).toMatchObject({ event: "unknown", delivery: "unknown" });
	});
});

describe("rate limiting", () => {
	it("meters a delivery before verifying its signature", async () => {
		// Same shape as /admin: the expensive, attacker-triggerable work is the
		// verification, and a limiter behind it is a limiter that has already paid.
		// Observable because the headers are set on the way through, so they are on
		// the 401 the HMAC check produces.
		const { response } = await deliver("{}", { [SIGNATURE_HEADER]: `${SIGNATURE_PREFIX}${"0".repeat(64)}` }, ENABLED);

		expect(response.status).toBe(401);
		expect(response.headers.get(HEADERS.RATE_LIMIT_REMAINING)).not.toBeNull();
	});

	it("meters an accepted delivery", async () => {
		const { response } = await deliverSigned(JSON.stringify({ zen: "x" }));

		expect(response.status).toBe(202);
		expect(response.headers.get(HEADERS.RATE_LIMIT_REMAINING)).not.toBeNull();
	});

	it("fails closed when the limiter cannot be reached", async () => {
		// An accepted delivery with no limit in front of the HMAC is unbounded
		// verification work for an anonymous caller, so the limiter fails closed.
		// GitHub does not automatically redeliver, so this 503 costs the event —
		// deliberate while the handler acts on nothing.
		const broken = {
			...ENABLED,
			RATE_LIMITER: {
				idFromName() {
					throw new Error("durable object unavailable");
				},
			},
		};

		const { response, body } = await deliverSigned(JSON.stringify({ zen: "x" }), {}, broken);

		expect(response.status).toBe(503);
		expect(body.code).toBe("RATE_LIMIT_ERROR");
	});

	it("reports a denial as a denial rather than as an outage", async () => {
		// The Durable Object delivers a refusal as a 429 with the verdict in the
		// body. Reading `!ok` alone would turn every denial into a 503, which is
		// the bug this branch exists to not have.
		const resetAt = Date.now() + 30_000;
		const denying = {
			...ENABLED,
			RATE_LIMITER: {
				idFromName: () => "id",
				get: () => ({
					fetch: () =>
						Promise.resolve(
							new Response(JSON.stringify({ allowed: false, remaining: 0, resetAt }), {
								status: 429,
								headers: { "Content-Type": "application/json" },
							}),
						),
				}),
			},
		};

		const { response, body } = await deliverSigned(JSON.stringify({ zen: "x" }), {}, denying);

		expect(response.status).toBe(429);
		expect(body.code).toBe("RATE_LIMITED");
	});
});

describe("secret non-observability", () => {
	const PROBES: Array<{ name: string; run: () => Promise<{ response: Response; body: Envelope }> }> = [
		{ name: "a disabled deployment", run: () => deliver("{}") },
		{
			name: "a misconfigured deployment",
			run: () => deliver("{}", {}, { GITHUB_APP_ENABLED: "true", GITHUB_WEBHOOK_SECRET: "" }),
		},
		{ name: "an unsigned delivery", run: () => deliver("{}", {}, ENABLED) },
		{
			name: "a wrongly signed delivery",
			run: () => deliver("{}", { [SIGNATURE_HEADER]: `${SIGNATURE_PREFIX}${"0".repeat(64)}` }, ENABLED),
		},
		{ name: "an accepted delivery", run: () => deliverSigned(JSON.stringify({ zen: "x" })) },
		{ name: "an unparseable delivery", run: () => deliverSigned("nope") },
	];

	it.each(PROBES)("keeps the webhook secret out of the response to $name", async ({ run }) => {
		// Checked on the headers as well as the body: an error message is the
		// obvious leak, and a `WWW-Authenticate` or a `docs` link built from a
		// value is the one nobody looks for.
		const { response, body } = await run();
		const seen = JSON.stringify(body) + [...response.headers].flat().join(" ");

		expect(seen).not.toContain(SECRET);
	});
});
