/**
 * Making a replayed delivery a no-op.
 *
 * A webhook signature covers the body and nothing else — no timestamp, no
 * nonce, no expiry — so a delivery that verified once verifies forever. GitHub's
 * own "Redeliver" button does exactly that on purpose, and anyone who obtains a
 * copy of a delivery can do the same. Harmless while the handler acts on
 * nothing; the moment one signs a commit, "verifies forever" means "can be made
 * to happen again, any number of times, by anyone who ever saw the bytes".
 *
 * What these tests are written against:
 *
 * - **The claim has to be atomic.** The interesting case is two copies of one
 *   delivery arriving at the same instant, which is what a double-click on
 *   "Redeliver" produces and what an attacker sends deliberately. A
 *   check-then-write across two round trips passes every sequential test in
 *   this file and fails `concurrent claims`, which fires a batch at once and
 *   requires exactly one winner.
 * - **The id must be claimed only after the delivery is trusted.** Claiming is
 *   one-way, so anything that can claim an id can suppress the real delivery
 *   carrying it. Three tests establish that an unsigned, an unauthorized and an
 *   oversize request all leave the id unclaimed — each by afterwards presenting
 *   the *same* id as a legitimate delivery and requiring it to be accepted as a
 *   first arrival.
 * - **A missing id must not become a shared one.** A placeholder would make
 *   every id-less delivery dedupe against every other, so the first to be
 *   claimed silently suppresses the rest.
 * - **Expiry has to be by the record's own clock.** The reaper runs on an
 *   alarm and can be late, so an entry past its retention must read as absent
 *   whether or not it has been swept — otherwise the protection's duration is
 *   whenever the alarm last fired.
 */

import { createExecutionContext, runInDurableObject, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { Hono } from "hono";
import { beforeAll, describe, expect, it } from "vitest";
import type { WebhookDeliveries } from "#durable-objects/webhook-deliveries";
import app from "#gpg-signing-service";
import { githubWebhookAuthorize, webhookReplayGuard } from "#middleware/github-webhook";
import type { Env, Variables } from "#types";
import { SIGNATURE_HEADER, SIGNATURE_PREFIX } from "#utils/github-webhook";
import { claimDelivery, DELIVERY_RETENTION_MS, isDeliveryId } from "#utils/webhook-replay";
import { captureLogEntries, logLine } from "./helpers/log-capture";

/** Cold-starting a Durable Object costs more than vitest's default hook budget. */
const WARMUP_TIMEOUT_MS = 30_000;

const SECRET = "test-webhook-secret";
const INSTALLATION = 24680;
const REPOSITORY = "kjanat/gpg-signing-service";

/** A deployment with the integration on and one pair granted. */
const ENABLED = {
	GITHUB_APP_ENABLED: "true",
	GITHUB_WEBHOOK_SECRET: SECRET,
	GITHUB_APP_ALLOWED_REPOSITORIES: `${INSTALLATION}:${REPOSITORY}`,
};

interface Envelope {
	code?: string;
	received?: boolean;
	duplicate?: boolean;
	delivery?: string | null;
}

async function sign(body: string, secret = SECRET): Promise<string> {
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

/** A payload naming the granted pair. */
function grantedPayload() {
	return { installation: { id: INSTALLATION }, repository: { full_name: REPOSITORY } };
}

/**
 * One delivery, with everything about it under the caller's control.
 *
 * `signature: false` sends none; `payload` can name a pair nobody granted. Both
 * exist so a test can establish that a *refused* request did not consume the
 * id it carried.
 */
async function deliver(options: {
	deliveryId?: string | null;
	payload?: unknown;
	signature?: boolean | string;
	overrides?: Record<string, unknown>;
	headers?: Record<string, string>;
}): Promise<{ response: Response; body: Envelope }> {
	const body = JSON.stringify(options.payload ?? grantedPayload());
	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		"X-GitHub-Event": "push",
		...options.headers,
	};

	if (options.signature !== false) {
		headers[SIGNATURE_HEADER] = typeof options.signature === "string" ? options.signature : await sign(body);
	}
	if (options.deliveryId !== null) {
		headers["X-GitHub-Delivery"] = options.deliveryId ?? crypto.randomUUID();
	}

	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request("https://sign.test/github/webhook", { method: "POST", body, headers }),
		{ ...env, ...ENABLED, ...options.overrides },
		ctx,
	);
	await waitOnExecutionContext(ctx);

	return { response, body: (await response.json()) as Envelope };
}

describe("what counts as a delivery id", () => {
	it("accepts the GUID GitHub sends", () => {
		expect(isDeliveryId("72d3162e-cc78-11e3-81ab-4c9367dc0958")).toBe(true);
	});

	it.each([
		["undefined", undefined],
		["null", null],
		["empty", ""],
		["a single character", "a"],
		["seven characters", "1234567"],
		["a colon, which would collide with the ledger's key prefix", "abcdefgh:ij"],
		["a slash", "abcdefgh/ij"],
		["a space", "abcdefg h"],
		["a newline", "abcdefgh\n"],
		["a leading separator", "-abcdefgh"],
		["201 characters", "a".repeat(201)],
	])("refuses %s", (_label, value) => {
		expect(isDeliveryId(value as string | null | undefined)).toBe(false);
	});

	it("accepts exactly 200 characters and refuses 201", () => {
		// The bound is asserted from both sides, because an off-by-one that only
		// refuses is invisible until a real id sits on the boundary.
		expect(isDeliveryId("a".repeat(200))).toBe(true);
		expect(isDeliveryId("a".repeat(201))).toBe(false);
	});
});

describe("the ledger", () => {
	function ledger(name: string) {
		return env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName(name));
	}

	beforeAll(async () => {
		await ledger("warmup").fetch("http://internal/claim?id=warmup-delivery-id", { method: "POST" });
	}, WARMUP_TIMEOUT_MS);

	it("claims an unseen id once and refuses it thereafter", async () => {
		const id = crypto.randomUUID();

		const first = await claimDelivery(env, id);
		const second = await claimDelivery(env, id);

		expect(first.claimed).toBe(true);
		expect(second.claimed).toBe(false);
		// The repeat reports when the *first* one happened, not now: that is what
		// makes a redelivery legible in a log without correlating two lines.
		expect(second.firstSeen).toBe(first.firstSeen);
	});

	it("keeps distinct ids distinct", async () => {
		const [a, b] = [crypto.randomUUID(), crypto.randomUUID()];

		expect((await claimDelivery(env, a)).claimed).toBe(true);
		expect((await claimDelivery(env, b)).claimed).toBe(true);
	});

	it("gives exactly one winner to concurrent claims of one id", async () => {
		// **The test the whole design exists for.** A check-then-write implemented
		// across two round trips passes every sequential test above and fails here,
		// because both copies observe "not present" before either writes.
		const id = crypto.randomUUID();

		const claims = await Promise.all(Array.from({ length: 12 }, () => claimDelivery(env, id)));

		expect(claims.filter((claim) => claim.claimed)).toHaveLength(1);
		// And every loser is told about the same first claim, rather than about
		// whichever write happened to land last.
		const firstSeen = new Set(claims.map((claim) => claim.firstSeen));
		expect(firstSeen.size).toBe(1);
	});

	it("refuses a claim with no id rather than sharing one key between them", async () => {
		// The caller validates first; this is the second of two guards. Without it
		// an empty id becomes the key `d:` — one name every id-less delivery would
		// dedupe against.
		const response = await ledger("deliveries").fetch("http://internal/claim?id=", { method: "POST" });

		expect(response.status).toBe(400);
	});

	it("refuses a GET on the claim path", async () => {
		const response = await ledger("deliveries").fetch("http://internal/claim?id=abcdefghij");

		expect(response.status).toBe(405);
	});

	it("answers 404 for a path it does not serve", async () => {
		const response = await ledger("deliveries").fetch("http://internal/nope", { method: "POST" });

		expect(response.status).toBe(404);
	});

	it("treats a record past its retention as absent, without waiting for the reaper", async () => {
		// Expiry is decided by the record's own timestamp, not by whether the alarm
		// has run. A ledger that relied on the sweep would have a protection window
		// of "whenever the alarm last fired", which is not a window anyone chose.
		const id = crypto.randomUUID();
		const stub = ledger("expiry");

		await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) => {
			await state.storage.put(`d:${id}`, { firstSeen: Date.now() - 1000, expiresAt: Date.now() - 1 });
		});

		const response = await stub.fetch(`http://internal/claim?id=${id}`, { method: "POST" });

		expect(await response.json()).toMatchObject({ claimed: true });
	});

	it("remembers an id for GitHub's redelivery window", async () => {
		// The retention is asserted against the stored expiry rather than against
		// the constant restated here, so shortening it in code fails the test that
		// says how long a replay is caught for.
		const id = crypto.randomUUID();
		const stub = ledger("retention");
		await stub.fetch(`http://internal/claim?id=${id}`, { method: "POST" });

		const record = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ expiresAt: number }>(`d:${id}`),
		);

		expect(record?.expiresAt).toBeGreaterThan(Date.now() + DELIVERY_RETENTION_MS - 60_000);
		// GitHub lists deliveries from the past 3 days, so anything at or under
		// that window fails to cover a redelivery the UI still offers.
		expect(DELIVERY_RETENTION_MS).toBeGreaterThan(3 * 24 * 60 * 60 * 1000);
	});

	it("arms a reaper when the first id is claimed", async () => {
		const stub = ledger("arming");
		await stub.fetch(`http://internal/claim?id=${crypto.randomUUID()}`, { method: "POST" });

		const alarm = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.getAlarm(),
		);

		expect(alarm).not.toBeNull();
	});

	it("reaps expired records and keeps live ones", async () => {
		const stub = ledger("sweep");
		const [dead, alive] = [crypto.randomUUID(), crypto.randomUUID()];

		await runInDurableObject(stub, async (instance: WebhookDeliveries, state) => {
			await state.storage.put(`d:${dead}`, { firstSeen: 0, expiresAt: Date.now() - 1 });
			await state.storage.put(`d:${alive}`, { firstSeen: Date.now(), expiresAt: Date.now() + 600_000 });

			await instance.alarm();

			expect(await state.storage.get(`d:${dead}`)).toBeUndefined();
			expect(await state.storage.get(`d:${alive}`)).toBeDefined();
		});
	});

	it("stops waking itself once the ledger is empty", async () => {
		// A ledger with nothing left in it must not keep an alarm alive forever.
		// Invoked directly rather than by letting a scheduled alarm fire, so what
		// is asserted is that the handler *chose* not to re-arm — the runtime
		// clears a fired alarm on its own, which would make this pass either way.
		const stub = ledger("quiescence");

		await runInDurableObject(stub, async (instance: WebhookDeliveries, state) => {
			await state.storage.put(`d:${crypto.randomUUID()}`, { firstSeen: 0, expiresAt: Date.now() - 1 });
			await state.storage.deleteAlarm();

			await instance.alarm();

			expect(await state.storage.getAlarm()).toBeNull();
		});
	});

	it("keeps waking itself while records remain", async () => {
		// The converse, and the half that actually reclaims storage: an object that
		// stopped re-arming while live records sat in it would leak them until the
		// next claim happened to arrive.
		const stub = ledger("rearming");

		await runInDurableObject(stub, async (instance: WebhookDeliveries, state) => {
			await state.storage.put(`d:${crypto.randomUUID()}`, { firstSeen: 0, expiresAt: Date.now() + 600_000 });
			await state.storage.deleteAlarm();

			await instance.alarm();

			expect(await state.storage.getAlarm()).not.toBeNull();
		});
	});

	it("carries a cursor past a full page rather than re-reading it forever", async () => {
		// `list` has no implicit cursor, so a sweep that did not persist one would
		// return the same lexicographic page every alarm — and every key behind a
		// full first page would be invisible to the reaper for good. Exercised at
		// the real batch size, because a page is only "full" relative to it.
		const stub = ledger("paging");
		const batch = 1000;

		await runInDurableObject(stub, async (instance: WebhookDeliveries, state) => {
			const page: Record<string, { firstSeen: number; expiresAt: number }> = {};
			for (let index = 0; index < batch; index++) {
				// Padded so the keys sort in the order they were written, which is what
				// makes "the cursor is the last key of the page" checkable.
				page[`d:page-${String(index).padStart(5, "0")}`] = { firstSeen: 0, expiresAt: Date.now() + 600_000 };
			}
			await state.storage.put(page);

			await instance.alarm();

			expect(await state.storage.get("sweep:cursor")).toBe(`d:page-${String(batch - 1).padStart(5, "0")}`);
			// And it comes back promptly rather than waiting a full interval, because
			// a backlog drained one interval at a time is not drained.
			const alarm = await state.storage.getAlarm();
			expect(alarm).not.toBeNull();
			expect((alarm as number) - Date.now()).toBeLessThan(60_000);
		});
	});

	it("reports a fault as a 500 rather than letting it escape", async () => {
		// Nothing above a Durable Object catches a fault from inside it, so this
		// handler is the end of the line. A throw that escaped would reach
		// `claimDelivery` as an opaque runtime error rather than a status, and the
		// delivery would be refused for a reason no log line explains.
		const stub = ledger("faulty");

		const response = await runInDurableObject(stub, async (instance: WebhookDeliveries, state) => {
			const broken = {
				blockConcurrencyWhile: state.blockConcurrencyWhile.bind(state),
				storage: {
					get: () => {
						throw new Error("storage unavailable");
					},
				},
			};
			// The field is `private` in TypeScript only, which is what makes a fault
			// this deep injectable at all — and the alternative, waiting for real
			// storage to fail, is not a test.
			(instance as unknown as { state: unknown }).state = broken;

			return instance.fetch(new Request("http://internal/claim?id=abcdefghij", { method: "POST" }));
		});

		expect(response.status).toBe(500);
	});

	it("does not reap its own cursor", async () => {
		// The cursor lives outside the `d:` prefix. One that did not would be
		// listed by the sweep it drives, and — being neither a record nor
		// unexpired — would confuse the pass that wrote it.
		const stub = ledger("cursor");

		await runInDurableObject(stub, async (instance: WebhookDeliveries, state) => {
			await state.storage.put("sweep:cursor", "d:something");
			await state.storage.put(`d:${crypto.randomUUID()}`, { firstSeen: 0, expiresAt: Date.now() + 600_000 });

			await instance.alarm();

			// The pass ended short, so the cursor is cleared rather than reaped as a
			// record — a distinction only visible because the key is still readable.
			expect(await state.storage.get("sweep:cursor")).toBeUndefined();
		});
	});
});

describe("mounted without the gates in front of it", () => {
	/**
	 * Both middlewares refuse rather than proceeding when the context does not
	 * carry a verified delivery.
	 *
	 * Unreachable through the app as it is mounted, and that is the point: this
	 * is what makes a future change to the mounting fail closed instead of
	 * authorizing an unverified payload or claiming an id for one.
	 */
	async function bare(middleware: typeof githubWebhookAuthorize): Promise<Response> {
		const bareApp = new Hono<{ Bindings: Env; Variables: Variables }>();
		bareApp.use("*", middleware);
		bareApp.post("/webhook", (c) => c.json({ reached: true }));

		const ctx = createExecutionContext();
		const response = await bareApp.fetch(
			new Request("https://sign.test/webhook", { method: "POST", body: "{}" }),
			{ ...env, ...ENABLED },
			ctx,
		);
		await waitOnExecutionContext(ctx);

		return response;
	}

	it("refuses to authorize a request no signature check ran on", async () => {
		const response = await bare(githubWebhookAuthorize);

		expect(response.status).toBe(500);
		expect(((await response.json()) as Envelope).code).toBe("SERVICE_MISCONFIGURED");
	});

	it("refuses to claim an id for a request no signature check ran on", async () => {
		const response = await bare(webhookReplayGuard);

		expect(response.status).toBe(500);
		expect(((await response.json()) as Envelope).code).toBe("SERVICE_MISCONFIGURED");
	});
});

describe("through the route", () => {
	it("accepts a delivery once and answers the repeat as a duplicate", async () => {
		const id = crypto.randomUUID();

		const first = await deliver({ deliveryId: id });
		const second = await deliver({ deliveryId: id });

		expect(first.response.status).toBe(202);
		expect(first.body).toMatchObject({ duplicate: false });

		// 200, not an error: GitHub marks any non-2xx as a failed delivery, and a
		// redelivery an operator triggered on purpose is not a failure — the event
		// was already handled, which is the outcome they wanted.
		expect(second.response.status).toBe(200);
		expect(second.body).toMatchObject({ received: true, duplicate: true, delivery: id });
	});

	it("answers a duplicate the same way however the body differs", async () => {
		// The id is the identity. A second delivery reusing an id with different
		// content is not a new event — it is either a redelivery or a forgery, and
		// neither may act.
		const id = crypto.randomUUID();
		await deliver({ deliveryId: id });

		const { response, body } = await deliver({
			deliveryId: id,
			payload: { installation: { id: INSTALLATION }, repository: { full_name: REPOSITORY }, extra: "different" },
		});

		expect(response.status).toBe(200);
		expect(body.duplicate).toBe(true);
	});

	it("refuses a delivery with no id, rather than giving them all one name", async () => {
		const { response, body } = await deliver({ deliveryId: null });

		expect(response.status).toBe(400);
		expect(body.code).toBe("INVALID_REQUEST");
	});

	it.each([
		["empty", ""],
		["too short", "abc"],
		["carrying a colon", "abcdefgh:ij"],
		["too long", "a".repeat(201)],
	])("refuses a delivery id that is %s", async (_label, id) => {
		const { response, body } = await deliver({ deliveryId: id });

		expect(response.status).toBe(400);
		expect(body.code).toBe("INVALID_REQUEST");
	});

	it("does not consume an id for a delivery with no signature", async () => {
		// **Ordering, from outside.** If the guard ran before the HMAC, anyone who
		// could reach the URL could burn the id of a delivery they cannot forge and
		// so suppress it. Proven by afterwards presenting the same id legitimately
		// and requiring a first arrival.
		const id = crypto.randomUUID();

		const forged = await deliver({ deliveryId: id, signature: false });
		expect(forged.response.status).toBe(401);

		const real = await deliver({ deliveryId: id });
		expect(real.response.status).toBe(202);
		expect(real.body.duplicate).toBe(false);
	});

	it("does not consume an id for a delivery with a wrong signature", async () => {
		const id = crypto.randomUUID();

		const forged = await deliver({ deliveryId: id, signature: `${SIGNATURE_PREFIX}${"a".repeat(64)}` });
		expect(forged.response.status).toBe(401);

		expect((await deliver({ deliveryId: id })).response.status).toBe(202);
	});

	it("does not consume an id for a delivery the allowlist refuses", async () => {
		// The subtler half, and the one an ordering that put dedupe immediately
		// after the HMAC would get wrong. An installation that holds the App's
		// webhook secret but was never granted this repository must not be able to
		// spend the ids of the installation that was.
		const id = crypto.randomUUID();

		const unauthorized = await deliver({
			deliveryId: id,
			payload: { installation: { id: 999 }, repository: { full_name: "attacker/evil" } },
		});
		expect(unauthorized.response.status).toBe(401);
		expect(unauthorized.body.code).toBe("AUTH_SUBJECT_UNTRUSTED");

		const real = await deliver({ deliveryId: id });
		expect(real.response.status).toBe(202);
		expect(real.body.duplicate).toBe(false);
	});

	it("does not consume an id for a delivery over the payload ceiling", async () => {
		const id = crypto.randomUUID();

		const oversize = await deliver({ deliveryId: id, headers: { "Content-Length": String(26 * 1024 * 1024) } });
		expect(oversize.response.status).toBe(413);

		expect((await deliver({ deliveryId: id })).response.status).toBe(202);
	});

	it("does not consume an id on a deployment that has the feature off", async () => {
		const id = crypto.randomUUID();

		const off = await deliver({ deliveryId: id, overrides: { GITHUB_APP_ENABLED: "false" } });
		expect(off.response.status).toBe(404);

		expect((await deliver({ deliveryId: id })).response.status).toBe(202);
	});

	it("refuses the delivery when the ledger cannot be reached", async () => {
		// Fails closed, like every other dependency on this path: a claim that did
		// not happen is not a claim, and reading an unreachable ledger as "not seen
		// before" removes the protection exactly when nothing can check it.
		const { response, body } = await deliver({
			overrides: {
				WEBHOOK_DELIVERIES: {
					idFromName: () => ({}),
					get: () => ({
						fetch: () => {
							throw new Error("durable object unavailable");
						},
					}),
				},
			},
		});

		expect(response.status).toBe(503);
		expect(body.code).toBe("SERVICE_DEGRADED");
		expect(response.headers.get("Retry-After")).not.toBeNull();
	});

	it("refuses the delivery when the ledger answers with an error status", async () => {
		// A non-2xx from the ledger is not a verdict. Reading one as "not claimed"
		// would turn every ledger fault into an invitation to act twice.
		const { response, body } = await deliver({
			overrides: {
				WEBHOOK_DELIVERIES: {
					idFromName: () => ({}),
					get: () => ({ fetch: async () => new Response("nope", { status: 500 }) }),
				},
			},
		});

		expect(response.status).toBe(503);
		expect(body.code).toBe("SERVICE_DEGRADED");
	});

	it("refuses the delivery when the ledger answers something unreadable", async () => {
		// A malformed body read as `claimed: undefined` would be falsy, which
		// happens to fail closed. That is an accident of coercion, not a property,
		// so the parse is explicit and this is what says so.
		const { response, body } = await deliver({
			overrides: {
				WEBHOOK_DELIVERIES: {
					idFromName: () => ({}),
					get: () => ({ fetch: async () => Response.json({ claimed: "yes" }) }),
				},
			},
		});

		expect(response.status).toBe(503);
		expect(body.code).toBe("SERVICE_DEGRADED");
	});

	it("does not leak a delivery id into a refusal for a different one", async () => {
		// The response echoes the id it was sent and nothing else. An answer that
		// mentioned a *stored* id would make the ledger enumerable by anyone
		// holding the webhook secret, which is one compromised App away from a map
		// of every event this deployment has handled.
		const seen = crypto.randomUUID();
		await deliver({ deliveryId: seen });

		const other = crypto.randomUUID();
		const { body } = await deliver({ deliveryId: other });

		expect(JSON.stringify(body)).not.toContain(seen);
	});
});

describe("what a ledger failure reports to the operator", () => {
	// A 503 carries no detail on purpose, so the log line is the only account of
	// why a delivery was dropped — and a dropped delivery is one GitHub will not
	// resend. These require it to arrive with the request id where every other
	// line in the service puts it, and the thrown value where `captureError`
	// looks for an exception.
	const LEDGER_FAILURE = "Delivery ledger failed";

	/** A ledger that is reliably unreachable. */
	const UNREACHABLE = {
		WEBHOOK_DELIVERIES: {
			idFromName: () => ({}),
			get: () => ({
				fetch: () => {
					throw new Error("durable object unavailable");
				},
			}),
		},
	};

	it("logs the failure with the request id in context and the throw as the error", async () => {
		const requestId = crypto.randomUUID();
		let response: Response | undefined;

		const entries = await captureLogEntries(async () => {
			({ response } = await deliver({ overrides: UNREACHABLE, headers: { "X-Request-ID": requestId } }));
		});
		const line = logLine(entries, LEDGER_FAILURE);

		expect(response?.status).toBe(503);
		expect(line.level).toBe("error");
		// The same id the caller sent and the response echoes, so the 503 a person
		// is holding and the line an operator is reading are the same request.
		expect(line.requestId).toBe(requestId);
		expect(response?.headers.get("X-Request-ID")).toBe(requestId);
		expect(line.event).toBe("push");
		expect(line.error).toMatchObject({ message: "durable object unavailable", name: "Error" });
	});

	it("does not nest the request id inside the error payload", async () => {
		// `logger.error(msg, { requestId, error })` — the two-argument mistake —
		// produces a line with no top-level request id and a `context` of
		// `undefined` on the Sentry report. This is what says so.
		const requestId = crypto.randomUUID();

		const entries = await captureLogEntries(() =>
			deliver({ overrides: UNREACHABLE, headers: { "X-Request-ID": requestId } }),
		);
		const line = logLine(entries, LEDGER_FAILURE);

		expect((line.error as Record<string, unknown>).requestId).toBeUndefined();
		expect((line.error as Record<string, unknown>).error).toBeUndefined();
	});

	it("reports a ledger that answered rather than threw the same way", async () => {
		// A non-2xx and an unreadable body are turned into errors by
		// `claimDelivery` rather than by the middleware, so this checks the
		// synthesised error survives the same path.
		const requestId = crypto.randomUUID();

		const entries = await captureLogEntries(() =>
			deliver({
				overrides: {
					WEBHOOK_DELIVERIES: {
						idFromName: () => ({}),
						get: () => ({ fetch: async () => new Response("nope", { status: 500 }) }),
					},
				},
				headers: { "X-Request-ID": requestId },
			}),
		);
		const line = logLine(entries, LEDGER_FAILURE);

		expect(line.requestId).toBe(requestId);
		expect(String((line.error as { message?: string }).message)).toContain("500");
	});
});

describe("a claimed id is not released when the handler fails", () => {
	// The semantics `docs/github-app.md` names "at-most-once", asserted rather
	// than only described. The guard claims the id and then calls `next()`, and
	// nothing gives the claim back — so a handler that fails after the claim
	// leaves the delivery consumed, and the redelivery an operator sends after
	// seeing the red row is answered as a duplicate without acting.
	//
	// Harmless while the handler acts on nothing. A hard prerequisite for the
	// first one that does, which is why this is a test and not a paragraph: a
	// future two-phase ledger has to fail here deliberately rather than pass by
	// accident.
	it("consumes the id for a handler that throws, so the redelivery is a duplicate", async () => {
		const id = crypto.randomUUID();

		/** The pipeline as mounted, with a handler that fails after the claim. */
		async function through(handler: () => unknown): Promise<Response> {
			const failing = new Hono<{ Bindings: Env; Variables: Variables }>();
			failing.use("*", async (c, next) => {
				// Stands in for `githubWebhookAuth`, which has already run by the time
				// the guard sees a request through the real route.
				c.set("webhookDelivery", { event: "push", id, installationId: INSTALLATION });
				c.set("webhookPayload", grantedPayload());
				await next();
			});
			failing.use("*", webhookReplayGuard);
			failing.post("/webhook", () => handler() as never);
			failing.onError((_error, c) => c.json({ code: "INTERNAL_ERROR" }, 500));

			const ctx = createExecutionContext();
			const response = await failing.fetch(
				new Request("https://sign.test/webhook", { method: "POST", body: "{}" }),
				{ ...env, ...ENABLED },
				ctx,
			);
			await waitOnExecutionContext(ctx);

			return response;
		}

		const failed = await through(() => {
			throw new Error("handler failed after the id was claimed");
		});
		expect(failed.status).toBe(500);

		// The redelivery. It never reaches the handler: the guard short-circuits it
		// as a repeat, which is the cost this documents.
		const redelivered = await through(() => {
			throw new Error("the handler was reached, which this test says it is not");
		});
		expect(redelivered.status).toBe(200);
		expect(((await redelivered.json()) as Envelope).duplicate).toBe(true);
	});
});
