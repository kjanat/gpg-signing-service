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
 * - **The body is bounded before it is buffered, and not on the sender's word.**
 *   The limiter caps request *count*, so the bytes are capped separately. A
 *   guard that only read `Content-Length` would pass every test that sends an
 *   honest one — so the tests below send a dishonest one, and a body with no
 *   declared length at all, and require the same refusal.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import app from "#gpg-signing-service";
import { HEADERS } from "#types";
import {
	declaredBodyLength,
	MAX_WEBHOOK_BODY_BYTES,
	readBodyWithin,
	SIGNATURE_HEADER,
	SIGNATURE_PREFIX,
} from "#utils/github-webhook";

const SECRET = "test-webhook-secret";

/**
 * A deployment with the integration switched on, completely configured, and
 * granting the installations the deliveries below claim.
 *
 * The allowlist is part of "configured" now: authorization is a separate gate
 * from the HMAC, so a suite about the HMAC has to get past authorization to
 * reach the answers it is asserting about. Which pairs are granted is the
 * subject of `github-authorization.test.ts`; here the list exists only so these
 * tests are exercising the boundary they mean to.
 */
const ENABLED = {
	GITHUB_APP_ENABLED: "true",
	GITHUB_WEBHOOK_SECRET: SECRET,
	GITHUB_APP_ALLOWED_REPOSITORIES: "42:kjanat/service, 7:kjanat/service, 987654:kjanat/service",
};

/**
 * A delivery id no other request in this suite uses.
 *
 * Every signed delivery needs its own, because a repeated id is now answered as
 * a duplicate — which is the correct behaviour and would otherwise make these
 * tests depend on their own execution order. `crypto.randomUUID` rather than a
 * counter so that a test which runs twice, in any file, still gets a fresh one.
 */
function freshDeliveryId(): string {
	return crypto.randomUUID();
}

interface Envelope {
	error?: string;
	code?: string;
	hint?: string;
	received?: boolean;
	event?: string;
	delivery?: string | null;
	installation?: boolean;
	scope?: string;
	duplicate?: boolean;
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
	headers: Record<string, string | null> = {},
	overrides: Record<string, unknown> = {},
): Promise<{ response: Response; body: Envelope }> {
	// A fresh delivery id unless the caller names one, and *no* id when the
	// caller passes null. The default exists because a delivery without a usable
	// id is now refused, so every test that is about something else would
	// otherwise be about that; the null escape hatch exists because "refused" is
	// itself worth asserting, and a helper that made it unreachable would hide
	// the one case it matters in.
	const withDelivery: Record<string, string | null> = { "X-GitHub-Delivery": freshDeliveryId(), ...headers };
	const sent = Object.fromEntries(
		Object.entries(withDelivery).filter((entry): entry is [string, string] => entry[1] !== null),
	);

	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request("https://sign.test/github/webhook", {
			method: "POST",
			body,
			headers: { "Content-Type": "application/json", ...sent },
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
	headers: Record<string, string | null> = {},
	overrides: Record<string, unknown> = ENABLED,
): Promise<{ response: Response; body: Envelope }> {
	const secret = typeof overrides.GITHUB_WEBHOOK_SECRET === "string" ? overrides.GITHUB_WEBHOOK_SECRET : SECRET;

	return deliver(
		body,
		{
			[SIGNATURE_HEADER]: await sign(body, secret),
			"X-GitHub-Event": "ping",
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
		const delivery = freshDeliveryId();
		const { response, body } = await deliverSigned(payload, { "X-GitHub-Delivery": delivery });

		expect(response.status).toBe(202);
		expect(body).toMatchObject({
			received: true,
			event: "ping",
			delivery,
			installation: false,
			scope: "none",
			duplicate: false,
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
	])("reports installation=%s for %s", async (_name, payload, expected) => {
		// The id is about to be interpolated into a GitHub API path by the code
		// this scaffold exists to prepare for, so "is there a usable one" has to be
		// answered the same way here as it is there.
		//
		// Only the accepted shapes are here. An `installation` object whose id
		// cannot be read is no longer answered at all — it is refused by
		// `githubWebhookAuthorize`, which is where those rows now live, because
		// "unreadable" and "absent" being the same answer is exactly the confusion
		// that refusal exists to prevent.
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

	it("falls back to a placeholder when GitHub does not name the event", async () => {
		// `X-GitHub-Event` is GitHub's to send and this service does not control
		// it, so its absence must not be a 500. Nothing branches on the event yet,
		// so there is nothing a placeholder can be wrong about.
		const { response, body } = await deliverSigned(JSON.stringify({ zen: "x" }), { "X-GitHub-Event": null });

		expect(response.status).toBe(202);
		expect(body).toMatchObject({ event: "unknown" });
	});

	it("does not fall back to a placeholder for a missing delivery id", async () => {
		// The event id is the opposite case, and the difference is the point. A
		// placeholder here would be a *shared* dedupe key: two id-less deliveries
		// would collide with each other, so the first to be claimed would silently
		// suppress every later one. Refusing is the only answer that does not
		// invent a name for something GitHub did not name.
		const { response, body } = await deliverSigned(JSON.stringify({ zen: "x" }), { "X-GitHub-Delivery": null });

		expect(response.status).toBe(400);
		expect(body.code).toBe("INVALID_REQUEST");
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

/**
 * A body that arrives as a stream, so the request carries no `Content-Length`
 * unless one is set by hand.
 *
 * The same 64 KiB buffer is enqueued `chunks` times rather than allocating the
 * whole thing: the point is the number of octets the reader is offered, and a
 * test that really materialised 25 MiB would spend its time on the allocator
 * instead of on the property.
 */
function streamed(chunks: number, chunkBytes = 64 * 1024, headers: Record<string, string> = {}): Request {
	const chunk = new Uint8Array(chunkBytes).fill(0x20);
	let sent = 0;

	return new Request("https://sign.test/github/webhook", {
		method: "POST",
		body: new ReadableStream<Uint8Array>({
			pull(controller) {
				if (sent >= chunks) {
					controller.close();
					return;
				}
				sent++;
				controller.enqueue(chunk);
			},
		}),
		headers: {
			"Content-Type": "application/json",
			"X-GitHub-Event": "push",
			// A well-formed digest that is wrong, so the request reaches the read at
			// all: a delivery presenting *no* signature is refused before the body is
			// touched, which is correct and cheaper but tests nothing about the
			// ceiling. It also sharpens what a 413 here means — the size ended the
			// request while a signature was sitting there waiting to be checked.
			[SIGNATURE_HEADER]: `${SIGNATURE_PREFIX}${"0".repeat(64)}`,
			...headers,
		},
		// Required by the Streams spec for a request with a streaming body, and
		// absent from the generated Workers types.
		duplex: "half",
	} as RequestInit);
}

/** Send a hand-built request through the app, the way `deliver` does. */
async function send(request: Request, overrides: Record<string, unknown> = ENABLED): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(request, { ...env, ...overrides }, ctx);
	await waitOnExecutionContext(ctx);

	return response;
}

describe("the payload ceiling", () => {
	/** One byte over GitHub's cap, as a `Content-Length` value. */
	const OVER = String(MAX_WEBHOOK_BODY_BYTES + 1);

	it("is GitHub's own documented cap", () => {
		// Pinned as a number rather than as an expression, so a change to the
		// constant has to be made twice — once against the arithmetic and once
		// against the figure quoted in `docs/errors.md` and `docs/github-app.md`.
		expect(MAX_WEBHOOK_BODY_BYTES).toBe(26_214_400);
	});

	it("refuses a delivery that declares a body over it", async () => {
		const response = await send(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: "{}",
				headers: { "X-GitHub-Event": "push", "Content-Length": OVER },
			}),
		);

		expect(response.status).toBe(413);
		expect(((await response.json()) as Envelope).code).toBe("PAYLOAD_TOO_LARGE");
	});

	it("refuses it before the signature is examined", async () => {
		// The decisive one for "rejected without buffering or HMAC work". The body
		// is two bytes and correctly signed, so a guard that read the octets and
		// ignored the declaration would answer 202. Answering 413 means the
		// declaration alone ended the request — which is the only way the guard can
		// be cheaper than the upload it is there to avoid.
		const response = await send(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: "{}",
				headers: {
					[SIGNATURE_HEADER]: await sign("{}"),
					"X-GitHub-Event": "push",
					"Content-Length": OVER,
				},
			}),
		);

		expect(response.status).toBe(413);
	});

	it("refuses it before the rate limiter is consulted", async () => {
		// Ordering, observed the same way the limiter's own position is: the
		// headers are set on the way through, so their absence places this gate in
		// front of a Durable Object round trip it would otherwise pay for a request
		// that had already announced it could not be honoured.
		const response = await send(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: "{}",
				headers: { "X-GitHub-Event": "push", "Content-Length": OVER },
			}),
		);

		expect(response.status).toBe(413);
		expect(response.headers.get(HEADERS.RATE_LIMIT_REMAINING)).toBeNull();
	});

	it("accepts a delivery that declares exactly the ceiling", async () => {
		// The boundary is inclusive, and asserted through the whole route rather
		// than against the constant: a `>=` in the guard would refuse a delivery
		// GitHub is willing to send, and the failure would look like GitHub having
		// stopped delivering rather than like a bug here.
		const payload = JSON.stringify({ zen: "Approachable is better than simple." });
		const response = await send(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: payload,
				headers: {
					[SIGNATURE_HEADER]: await sign(payload),
					"X-GitHub-Event": "push",
					"X-GitHub-Delivery": freshDeliveryId(),
					"Content-Length": String(MAX_WEBHOOK_BODY_BYTES),
				},
			}),
		);

		expect(response.status).toBe(202);
	});

	it.each([
		["an empty value", ""],
		["a padded value", ` ${OVER} `],
		["a negative value", `-${OVER}`],
		["a hex value", "0x1900000"],
		["a value with a unit", `${OVER} bytes`],
		["a list", `${OVER}, 2`],
	])("does not read %s as a declared length", (_name, value) => {
		// `Number("")` is 0 and `Number(" 26214401 ")` is 26214401, so a lenient
		// parse would read half of these as small bodies and the other half as
		// large ones — both wrong. They are all "not declared", which costs
		// nothing: an undeclared body is counted as it arrives.
		expect(declaredBodyLength(value)).toBeNull();
	});

	it("refuses a body over the ceiling that declared nothing at all", async () => {
		// The one that makes the protection more than header-trust. A streamed
		// request carries no `Content-Length`, so the first gate has nothing to act
		// on and the count during the read is the only thing standing between an
		// anonymous caller and unbounded buffering.
		const response = await send(streamed(MAX_WEBHOOK_BODY_BYTES / (64 * 1024) + 1));

		expect(response.status).toBe(413);
		expect(((await response.json()) as Envelope).code).toBe("PAYLOAD_TOO_LARGE");
	});

	it("refuses a body over the ceiling that declared a small one", async () => {
		// The lie that a header-only guard is built to believe: two bytes declared,
		// 25 MiB and a chunk sent. One line of client code, and it must gain the
		// sender nothing.
		const response = await send(
			streamed(MAX_WEBHOOK_BODY_BYTES / (64 * 1024) + 1, 64 * 1024, { "Content-Length": "2" }),
		);

		expect(response.status).toBe(413);
		expect(((await response.json()) as Envelope).code).toBe("PAYLOAD_TOO_LARGE");
	});

	it("counts a streamed body behind the rate limiter, not in front of it", async () => {
		// The counterpart to the declared-length ordering above, and the reason the
		// two gates are separate. Reading a body is the expensive work, so it stays
		// metered; only the free header check moved ahead of the meter.
		const response = await send(streamed(MAX_WEBHOOK_BODY_BYTES / (64 * 1024) + 1));

		expect(response.status).toBe(413);
		expect(response.headers.get(HEADERS.RATE_LIMIT_REMAINING)).not.toBeNull();
	});

	it("answers a lie and a declaration identically", async () => {
		// No oracle: a sender must not be able to tell whether the header was read.
		// Knowing that is what tells an attacker which of the two attacks is cheap
		// — declare honestly and pay for the upload, or declare nothing and let the
		// server discover it. Compared as bytes, so a difference in wording or in
		// key order counts as a difference.
		const declared = await send(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: "{}",
				headers: {
					"X-GitHub-Event": "push",
					"Content-Length": OVER,
					[SIGNATURE_HEADER]: `${SIGNATURE_PREFIX}${"0".repeat(64)}`,
				},
			}),
		);
		const counted = await send(streamed(MAX_WEBHOOK_BODY_BYTES / (64 * 1024) + 1));

		expect(counted.status).toBe(declared.status);
		expect(await counted.text()).toBe(await declared.text());
	});

	it("stays invisible on a deployment that did not opt in", async () => {
		// The ceiling must not become the enumeration oracle the 404 exists to
		// avoid. A disabled deployment answers a declared-oversize request exactly
		// as it answers everything else on this path.
		const disabled = await send(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: "{}",
				headers: { "X-GitHub-Event": "push", "Content-Length": OVER },
			}),
			{},
		);
		const unrouted = await probe("/no-such-route");

		expect(disabled.status).toBe(404);
		expect(await disabled.text()).toBe(await unrouted.text());
	});

	it("keeps the webhook secret out of the refusal", async () => {
		const response = await send(streamed(MAX_WEBHOOK_BODY_BYTES / (64 * 1024) + 1));
		const seen = (await response.text()) + [...response.headers].flat().join(" ");

		expect(seen).not.toContain(SECRET);
	});
});

describe("the bounded read itself", () => {
	/** A request whose body is exactly `bytes` octets, delivered as a stream. */
	function body(bytes: number): Request {
		return new Request("https://x.test/", {
			method: "POST",
			body: new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new Uint8Array(bytes));
					controller.close();
				},
			}),
			duplex: "half",
		} as RequestInit);
	}

	it("returns a body of exactly the limit", async () => {
		// Inclusive, tested at the octet. The route-level boundary test above can
		// only afford to assert this through a declared length; this one asserts it
		// against real bytes.
		const read = await readBodyWithin(body(1024), 1024);

		expect(read?.byteLength).toBe(1024);
	});

	it("refuses a body one octet over the limit", async () => {
		expect(await readBodyWithin(body(1025), 1024)).toBeNull();
	});

	it("preserves the exact octets", async () => {
		// The signature is computed over whatever this returns, so a reader that
		// reordered or dropped a chunk boundary would break verification on any
		// body large enough to arrive in more than one piece — the failure would
		// look like a wrong secret.
		const request = new Request("https://x.test/", {
			method: "POST",
			body: new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new TextEncoder().encode('{"a":'));
					controller.enqueue(new TextEncoder().encode("1}"));
					controller.close();
				},
			}),
			duplex: "half",
		} as RequestInit);

		const read = await readBodyWithin(request, 1024);

		expect(new TextDecoder().decode(read as ArrayBuffer)).toBe('{"a":1}');
	});

	it("ignores a Content-Length that understates the body", async () => {
		// Stated as a property of this function rather than of the route: the
		// header is written by the party whose body is in question, so the counter
		// must not consult it even to take a shortcut.
		const request = new Request("https://x.test/", {
			method: "POST",
			body: new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new Uint8Array(4096));
					controller.close();
				},
			}),
			headers: { "Content-Length": "1" },
			duplex: "half",
		} as RequestInit);

		expect(await readBodyWithin(request, 1024)).toBeNull();
	});

	it("ignores a Content-Length that overstates it", async () => {
		// The other direction, which matters just as much: refusing on the header
		// alone would drop a delivery GitHub really did send, and a dropped
		// delivery is not redelivered.
		const request = new Request("https://x.test/", {
			method: "POST",
			body: new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new Uint8Array(8));
					controller.close();
				},
			}),
			headers: { "Content-Length": "999999" },
			duplex: "half",
		} as RequestInit);

		expect((await readBodyWithin(request, 1024))?.byteLength).toBe(8);
	});

	it("handles a request with no body at all", async () => {
		// A GET reaching this code would have `request.body === null`, and the
		// branch that covers it must not throw — a fault there would be a 500 on a
		// path whose whole design is to answer 401s and 404s.
		const read = await readBodyWithin(new Request("https://x.test/"), 1024);

		expect(read?.byteLength).toBe(0);
	});

	it.each([
		["a plain integer", "2048", 2048],
		["zero", "0", 0],
		["the ceiling", String(MAX_WEBHOOK_BODY_BYTES), MAX_WEBHOOK_BODY_BYTES],
	])("reads %s as a declared length", (_name, value, expected) => {
		expect(declaredBodyLength(value)).toBe(expected);
	});

	it("reads an absent header as undeclared", () => {
		expect(declaredBodyLength(undefined)).toBeNull();
		expect(declaredBodyLength(null)).toBeNull();
	});

	it("reads a value beyond the safe integer range as undeclared", () => {
		// Digits, but not a number arithmetic can compare. Reading it as a float
		// would work by luck here — it is enormous — but the guard should refuse to
		// answer rather than answer approximately, and the read-side count catches
		// the body regardless.
		expect(declaredBodyLength("9".repeat(30))).toBeNull();
	});
});
