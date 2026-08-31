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
import type { Context } from "hono";
import { Hono } from "hono";
import { beforeAll, describe, expect, it } from "vitest";
import type { WebhookDeliveries } from "#durable-objects/webhook-deliveries";
import app from "#gpg-signing-service";
import { githubWebhookAuthorize, webhookReplayGuard } from "#middleware/github-webhook";
import type { Env, Variables } from "#types";
import { SIGNATURE_HEADER, SIGNATURE_PREFIX } from "#utils/github-webhook";
import {
	commitDelivery,
	DELIVERY_RESERVATION_MS,
	DELIVERY_RETENTION_MS,
	isDeliveryId,
	releaseDelivery,
	reserveDelivery,
} from "#utils/webhook-replay";
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
		await ledger("warmup").fetch("http://internal/reserve?id=warmup-delivery-id", { method: "POST" });
	}, WARMUP_TIMEOUT_MS);

	it("reserves an unseen id once and refuses it thereafter", async () => {
		const id = crypto.randomUUID();

		const first = await reserveDelivery(env, id);
		const second = await reserveDelivery(env, id);

		expect(first.reserved).toBe(true);
		expect(second.reserved).toBe(false);
		// The repeat reports when the *first* one happened, not now: that is what
		// makes a redelivery legible in a log without correlating two lines.
		expect(second.firstSeen).toBe(first.firstSeen);
	});

	it("keeps distinct ids distinct", async () => {
		const [a, b] = [crypto.randomUUID(), crypto.randomUUID()];

		expect((await reserveDelivery(env, a)).reserved).toBe(true);
		expect((await reserveDelivery(env, b)).reserved).toBe(true);
	});

	it("gives exactly one winner to concurrent reservations of one id", async () => {
		// **The test the whole design exists for.** A check-then-write implemented
		// across two round trips passes every sequential test above and fails here,
		// because both copies observe "not present" before either writes.
		const id = crypto.randomUUID();

		const attempts = await Promise.all(Array.from({ length: 12 }, () => reserveDelivery(env, id)));

		expect(attempts.filter((attempt) => attempt.reserved)).toHaveLength(1);
		// And every loser is told about the same first reservation, rather than
		// about whichever write happened to land last.
		const firstSeen = new Set(attempts.map((attempt) => attempt.firstSeen));
		expect(firstSeen.size).toBe(1);
	});

	it("refuses a reservation with no id rather than sharing one key between them", async () => {
		// The caller validates first; this is the second of two guards. Without it
		// an empty id becomes the key `d:` — one name every id-less delivery would
		// dedupe against.
		const response = await ledger("deliveries").fetch("http://internal/reserve?id=", { method: "POST" });

		expect(response.status).toBe(400);
	});

	it("refuses a GET on the reserve path", async () => {
		const response = await ledger("deliveries").fetch("http://internal/reserve?id=abcdefghij");

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
			await state.storage.put(`d:${id}`, { firstSeen: Date.now() - 1000, expiresAt: Date.now() - 1, committed: true });
		});

		const response = await stub.fetch(`http://internal/reserve?id=${id}`, { method: "POST" });

		expect(await response.json()).toMatchObject({ reserved: true });
	});

	it("remembers an id for GitHub's redelivery window", async () => {
		// The retention is asserted against the stored expiry rather than against
		// the constant restated here, so shortening it in code fails the test that
		// says how long a replay is caught for.
		const id = crypto.randomUUID();
		const stub = ledger("retention");
		// Reserved *and committed*: the retention window belongs to the second
		// phase. A reservation on its own is held for minutes, which is the
		// property `holds a reservation for minutes` asserts further down.
		await stub.fetch(`http://internal/reserve?id=${id}`, { method: "POST" });
		await stub.fetch(`http://internal/commit?id=${id}`, { method: "POST" });

		const record = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ expiresAt: number }>(`d:${id}`),
		);

		expect(record?.expiresAt).toBeGreaterThan(Date.now() + DELIVERY_RETENTION_MS - 60_000);
		// GitHub lists deliveries from the past 3 days, so anything at or under
		// that window fails to cover a redelivery the UI still offers.
		expect(DELIVERY_RETENTION_MS).toBeGreaterThan(3 * 24 * 60 * 60 * 1000);
	});

	it("holds an id for the retention window without committing it", async () => {
		// The phase the dispatch path takes *before* its request leaves. Durable and
		// retention-length, so an isolate that never runs again still leaves the id
		// spent — which is the whole difference from a reservation, and the reason
		// the expiry is asserted against the constant rather than against "longer
		// than a moment".
		const id = crypto.randomUUID();
		const stub = ledger("holding");

		await stub.fetch(`http://internal/reserve?id=${id}`, { method: "POST" });
		const held = await stub.fetch(`http://internal/hold?id=${id}`, { method: "POST" });

		expect(await held.json()).toMatchObject({ settled: true, reason: "held" });

		const record = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ expiresAt: number; committed: boolean; held: boolean }>(`d:${id}`),
		);

		expect(record?.committed).toBe(false);
		expect(record?.held).toBe(true);
		expect(record?.expiresAt).toBeGreaterThan(Date.now() + DELIVERY_RETENTION_MS - 60_000);
	});

	it("refuses a redelivery of a held id, and says which kind of repeat it is", async () => {
		// What a process that died after its dispatch left behind. The second
		// arrival is a duplicate — at-most-once holds without the first handler ever
		// having come back — and it reports `held` rather than `committed`, because
		// "sent something and vanished" and "finished" are different lines in a log.
		const id = crypto.randomUUID();
		const stub = ledger("deliveries");

		await reserveDelivery(env, id);
		await stub.fetch(`http://internal/hold?id=${id}`, { method: "POST" });

		const again = await reserveDelivery(env, id);

		expect(again.reserved).toBe(false);
		expect(again.held).toBe(true);
		expect(again.committed).toBe(false);
	});

	it("hands a held id back when it is released", async () => {
		// The 4xx path. A hold is releasable and a commit is not, which is the only
		// reason it is a separate phase: GitHub stating it created nothing is an
		// answer worth acting on, and an operator's fix plus a redelivery has to be
		// a real retry.
		const id = crypto.randomUUID();
		const stub = ledger("release-held");

		await stub.fetch(`http://internal/reserve?id=${id}`, { method: "POST" });
		await stub.fetch(`http://internal/hold?id=${id}`, { method: "POST" });
		const released = await stub.fetch(`http://internal/release?id=${id}`, { method: "POST" });

		expect(await released.json()).toMatchObject({ settled: true, reason: "released" });
		const record = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get(`d:${id}`),
		);
		expect(record).toBeUndefined();
	});

	it("will not release a committed id, however it got there", async () => {
		// The asymmetry that makes the hold safe to add. There is still no path from
		// committed back to absent except the retention window elapsing — a
		// committed record is a statement that something happened in a repository,
		// and a later arrival able to erase it could make a replay act again.
		const id = crypto.randomUUID();
		const stub = ledger("no-uncommit");

		await stub.fetch(`http://internal/reserve?id=${id}`, { method: "POST" });
		await stub.fetch(`http://internal/hold?id=${id}`, { method: "POST" });
		await stub.fetch(`http://internal/commit?id=${id}`, { method: "POST" });
		const released = await stub.fetch(`http://internal/release?id=${id}`, { method: "POST" });

		expect(await released.json()).toMatchObject({ settled: false, reason: "already_committed" });
		const record = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ committed: boolean }>(`d:${id}`),
		);
		expect(record?.committed).toBe(true);
	});

	it("holds an id whose reservation had already lapsed", async () => {
		// The state that used to leave an irreversible delivery recorded nowhere,
		// now reachable one step earlier: a handler slow enough to outrun its own
		// reservation still has to be able to record that its request is leaving.
		const id = crypto.randomUUID();
		const stub = ledger("hold-lapsed");

		const response = await stub.fetch(`http://internal/hold?id=${id}`, { method: "POST" });

		expect(await response.json()).toMatchObject({ settled: true, reason: "held_without_reservation" });
		const record = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ expiresAt: number; held: boolean }>(`d:${id}`),
		);
		expect(record?.held).toBe(true);
		expect(record?.expiresAt).toBeGreaterThan(Date.now() + DELIVERY_RETENTION_MS - 60_000);
	});

	it("does not let a late hold downgrade a committed record", async () => {
		const id = crypto.randomUUID();
		const stub = ledger("no-downgrade");

		await stub.fetch(`http://internal/reserve?id=${id}`, { method: "POST" });
		await stub.fetch(`http://internal/commit?id=${id}`, { method: "POST" });
		await stub.fetch(`http://internal/hold?id=${id}`, { method: "POST" });

		const record = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ committed: boolean }>(`d:${id}`),
		);
		expect(record?.committed).toBe(true);
	});

	it("arms a reaper when the first id is reserved", async () => {
		const stub = ledger("arming");
		await stub.fetch(`http://internal/reserve?id=${crypto.randomUUID()}`, { method: "POST" });

		const alarm = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.getAlarm(),
		);

		expect(alarm).not.toBeNull();
	});

	it("reaps expired records and keeps live ones", async () => {
		const stub = ledger("sweep");
		const [dead, alive] = [crypto.randomUUID(), crypto.randomUUID()];

		await runInDurableObject(stub, async (instance: WebhookDeliveries, state) => {
			await state.storage.put(`d:${dead}`, { firstSeen: 0, expiresAt: Date.now() - 1, committed: true });
			await state.storage.put(`d:${alive}`, {
				firstSeen: Date.now(),
				expiresAt: Date.now() + 600_000,
				committed: true,
			});

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
			await state.storage.put(`d:${crypto.randomUUID()}`, { firstSeen: 0, expiresAt: Date.now() - 1, committed: true });
			await state.storage.deleteAlarm();

			await instance.alarm();

			expect(await state.storage.getAlarm()).toBeNull();
		});
	});

	it("keeps waking itself while records remain", async () => {
		// The converse, and the half that actually reclaims storage: an object that
		// stopped re-arming while live records sat in it would leak them until the
		// next reservation happened to arrive.
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
		// `reserveDelivery` as an opaque runtime error rather than a status, and the
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

			return instance.fetch(new Request("http://internal/reserve?id=abcdefghij", { method: "POST" }));
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

	it("refuses to reserve an id for a request no signature check ran on", async () => {
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
		// Fails closed, like every other dependency on this path: a reservation that
		// did not happen is not a reservation, and reading an unreachable ledger as "not seen
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
		// A non-2xx from the ledger is not a verdict. Reading one as "not reserved"
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
		// A malformed body read as `reserved: undefined` would be falsy, which
		// happens to fail closed. That is an accident of coercion, not a property,
		// so the parse is explicit and this is what says so.
		const { response, body } = await deliver({
			overrides: {
				WEBHOOK_DELIVERIES: {
					idFromName: () => ({}),
					get: () => ({ fetch: async () => Response.json({ reserved: "yes" }) }),
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
		// `reserveDelivery` rather than by the middleware, so this checks the
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

describe("two phases: a delivery that caused nothing stays redeliverable", () => {
	// The prerequisite `docs/github-app.md` named before the first acting handler
	// could land, now resolved and asserted rather than described.
	//
	// A one-way claim taken before the handler is *at-most-once*: an event is
	// acted on no more than once and possibly not at all. That was right for a
	// scaffold and wrong for a handler that signs, because it makes every failure
	// permanent — a delivery the rate limiter refused, or one that arrived while
	// key storage was down, caused nothing at all, and the operator's redelivery
	// would come back `duplicate: true` without acting.
	//
	// So the id is reserved before the handler and settled after it: released when
	// the handler says it published nothing, committed otherwise. The three tests
	// below are the three outcomes, and the direction of each is a security
	// property rather than an ergonomic one.

	/** The guard as mounted, with a handler under test behind it. */
	async function through(id: string, handler: (c: Context<{ Bindings: Env; Variables: Variables }>) => unknown) {
		const pipeline = new Hono<{ Bindings: Env; Variables: Variables }>();
		pipeline.use("*", async (c, next) => {
			// Stands in for `githubWebhookAuth`, which has already run by the time
			// the guard sees a request through the real route.
			c.set("webhookDelivery", { event: "push", id, installationId: INSTALLATION });
			c.set("webhookPayload", grantedPayload());
			await next();
		});
		pipeline.use("*", webhookReplayGuard);
		pipeline.post("/webhook", (c) => handler(c) as never);
		pipeline.onError((_error, c) => c.json({ code: "INTERNAL_ERROR" }, 500));

		const ctx = createExecutionContext();
		const response = await pipeline.fetch(
			new Request("https://sign.test/webhook", { method: "POST", body: "{}" }),
			{ ...env, ...ENABLED },
			ctx,
		);
		await waitOnExecutionContext(ctx);

		return response;
	}

	it("releases the id when the handler published nothing, so a redelivery retries", async () => {
		// The case the whole two-phase change exists for. A handler that refused
		// before doing anything sets `webhookRetryable`, and the redelivery must
		// reach it — not be answered as a duplicate.
		const id = crypto.randomUUID();
		let reached = 0;

		const first = await through(id, (c) => {
			reached += 1;
			c.set("webhookRetryable", true);
			return c.json({ refused: true }, 503);
		});
		expect(first.status).toBe(503);

		const second = await through(id, (c) => {
			reached += 1;
			c.set("webhookRetryable", true);
			return c.json({ refused: true }, 503);
		});

		expect(reached).toBe(2);
		expect(((await second.json()) as Envelope).duplicate).toBeUndefined();
	});

	it("commits the id when the handler says nothing, so a redelivery is a duplicate", async () => {
		// The default direction, and deliberately the safe one rather than the
		// convenient one: a handler that acted and forgot to say so must not be
		// repeatable. Absent means committed.
		const id = crypto.randomUUID();
		let reached = 0;

		await through(id, (c) => {
			reached += 1;
			return c.json({ ok: true }, 200);
		});

		const redelivered = await through(id, (c) => {
			reached += 1;
			return c.json({ ok: true }, 200);
		});

		expect(reached).toBe(1);
		expect(redelivered.status).toBe(200);
		expect(((await redelivered.json()) as Envelope).duplicate).toBe(true);
	});

	it("commits the id when the handler throws, because nothing is known about what it did", async () => {
		// An uncaught throw says nothing about whether the handler published. The
		// unknown state is treated as "may have acted", because acting twice is
		// worse than not acting — and the acting handler catches its own failures
		// and marks them explicitly rather than relying on this.
		const id = crypto.randomUUID();

		const failed = await through(id, () => {
			throw new Error("handler failed");
		});
		expect(failed.status).toBe(500);

		// Committed, not merely still reserved. The distinction is the whole test:
		// a settle that was skipped altogether would leave a reservation, which
		// also answers the redelivery below as a duplicate — and then lapses five
		// minutes later and becomes retryable, which is the wrong direction for an
		// outcome nobody can describe. The stored record is what tells them apart.
		const stored = await runInDurableObject(
			env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName("deliveries")),
			async (_instance: WebhookDeliveries, state) => state.storage.get<{ committed: boolean }>(`d:${id}`),
		);
		expect(stored?.committed).toBe(true);

		const redelivered = await through(id, () => {
			throw new Error("the handler was reached, which this test says it is not");
		});
		expect(redelivered.status).toBe(200);
		expect(((await redelivered.json()) as Envelope).duplicate).toBe(true);
	});

	it("will not release a committed record, so a second arrival cannot un-say the first", async () => {
		// The asymmetry that makes the phases safe. If release could undo a commit,
		// anything able to call it could reopen an action that already happened.
		const id = crypto.randomUUID();

		await reserveDelivery(env, id);
		await commitDelivery(env, id);
		await releaseDelivery(env, id);

		expect((await reserveDelivery(env, id)).reserved).toBe(false);
	});

	it("holds a reservation for minutes, not for the retention window", async () => {
		// An uncommitted reservation must lapse on its own: a handler whose isolate
		// died would otherwise hold the id for four days, and every redelivery in
		// the meantime would be answered as a duplicate without acting — at exactly
		// the moment an operator is trying to recover.
		const id = crypto.randomUUID();
		const stub = env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName("deliveries"));

		await reserveDelivery(env, id);
		const reserved = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ expiresAt: number; committed: boolean }>(`d:${id}`),
		);

		expect(reserved?.committed).toBe(false);
		expect((reserved as { expiresAt: number }).expiresAt).toBeLessThanOrEqual(Date.now() + DELIVERY_RESERVATION_MS);
		// Asserted as a relation rather than against a repeated literal, so
		// widening the reservation towards the retention window fails here.
		expect(DELIVERY_RESERVATION_MS).toBeLessThan(DELIVERY_RETENTION_MS);

		await commitDelivery(env, id);
		const committed = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ expiresAt: number; committed: boolean }>(`d:${id}`),
		);

		expect(committed?.committed).toBe(true);
		expect((committed as { expiresAt: number }).expiresAt).toBeGreaterThan(Date.now() + DELIVERY_RESERVATION_MS);
	});

	it("reports a repeat of a committed id differently from one still being handled", async () => {
		// Same answer to the sender either way. Different thing to find in a log:
		// one says the event was handled, the other says two copies arrived at once.
		const id = crypto.randomUUID();

		await reserveDelivery(env, id);
		expect((await reserveDelivery(env, id)).committed).toBe(false);

		await commitDelivery(env, id);
		expect((await reserveDelivery(env, id)).committed).toBe(true);
	});

	it("does not fail a response because the ledger could not be settled", async () => {
		// The response is already decided by the time the settle runs. Raising here
		// would turn a bookkeeping failure into a 500 for a delivery that may have
		// been handled perfectly — and a reservation that was not settled lapses on
		// its own, after which a redelivery meets the handler's own idempotence.
		const id = crypto.randomUUID();
		let reserved = false;

		const flaky = {
			WEBHOOK_DELIVERIES: {
				idFromName: () => ({}),
				get: () => ({
					fetch: (request: Request) => {
						if (new URL(request.url).pathname === "/reserve") {
							reserved = true;
							return Promise.resolve(Response.json({ reserved: true, firstSeen: Date.now(), committed: false }));
						}
						return Promise.resolve(new Response("ledger is down", { status: 500 }));
					},
				}),
			},
		};

		const pipeline = new Hono<{ Bindings: Env; Variables: Variables }>();
		pipeline.use("*", async (c, next) => {
			c.set("webhookDelivery", { event: "push", id, installationId: INSTALLATION });
			c.set("webhookPayload", grantedPayload());
			await next();
		});
		pipeline.use("*", webhookReplayGuard);
		pipeline.post("/webhook", (c) => c.json({ ok: true }, 200));

		const ctx = createExecutionContext();
		const response = await pipeline.fetch(
			new Request("https://sign.test/webhook", { method: "POST", body: "{}" }),
			{ ...env, ...ENABLED, ...flaky },
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(reserved).toBe(true);
		expect(response.status).toBe(200);
	});

	it("reads a ledger that answers without a reason as no reason, not as a crash", async () => {
		// The answer is a diagnosis, not a decision — nothing branches on it except
		// a log line — so a ledger that stopped sending one must not take the
		// commit path down with it.
		const silent = {
			WEBHOOK_DELIVERIES: {
				idFromName: () => ({}),
				get: () => ({ fetch: () => Promise.resolve(Response.json({ settled: true })) }),
			},
		} as unknown as Env;

		await expect(commitDelivery({ ...env, ...silent } as unknown as Env, crypto.randomUUID())).resolves.toBeNull();
	});

	it("releases an id it never held without raising", async () => {
		// A reservation that lapsed mid-handler is gone by the time its handler
		// settles. On the *release* path that is nothing at all: the delivery
		// caused nothing, and gone is where release was taking the record anyway.
		await expect(releaseDelivery(env, crypto.randomUUID())).resolves.toBeUndefined();
	});

	it("commits an id it never held by creating the record, not by shrugging", async () => {
		// The other direction, and it is not symmetric. A commit is only ever
		// called once something irreversible has happened — a branch has moved —
		// so answering "absent, nothing written" would leave that fact recorded
		// nowhere at all, and the operator's redelivery would be handled as a
		// first arrival and force-update the branch a second time.
		//
		// Reachable without any exotic failure: the reservation lapses after five
		// minutes, and a handler that outlives its own reservation arrives here
		// with nothing to update.
		const id = crypto.randomUUID();
		const stub = env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName("deliveries"));

		await expect(commitDelivery(env, id)).resolves.toBe("committed_without_reservation");

		const stored = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ committed: boolean; expiresAt: number }>(`d:${id}`),
		);

		// Committed, and for the full retention window rather than a reservation's
		// five minutes — a record that lapsed back into "never seen" after five
		// minutes would be no protection at all against the redelivery it exists
		// to refuse.
		expect(stored?.committed).toBe(true);
		expect((stored as { expiresAt: number }).expiresAt).toBeGreaterThan(Date.now() + DELIVERY_RESERVATION_MS);
		expect((stored as { expiresAt: number }).expiresAt).toBeLessThanOrEqual(Date.now() + DELIVERY_RETENTION_MS);

		// And it is a real refusal, not just a row: the next arrival of this id is
		// a duplicate.
		expect((await reserveDelivery(env, id)).reserved).toBe(false);
		expect((await reserveDelivery(env, id)).committed).toBe(true);
	});

	it("still deduplicates a redelivery after the reservation vanished mid-handler", async () => {
		// The same property from outside, end to end, because the one above could
		// pass on a ledger that wrote a record nobody consults. A handler that
		// publishes and *then* finds its reservation gone must still leave a
		// delivery that a redelivery cannot get past.
		//
		// The reservation is deleted from underneath the running handler, which is
		// what a lapse looks like from the handler's point of view — the record is
		// simply not there when the `finally` gets to it.
		const id = crypto.randomUUID();
		const stub = env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName("deliveries"));
		let reached = 0;

		const published = await through(id, async (c) => {
			reached += 1;
			await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) => state.storage.delete(`d:${id}`));
			return c.json({ ok: true }, 200);
		});
		expect(published.status).toBe(200);

		const redelivered = await through(id, (c) => {
			reached += 1;
			return c.json({ ok: true }, 200);
		});

		// One trip through the handler, not two. Without the commit path creating
		// the record it did not find, the ledger would hold nothing here and this
		// would be a second force update.
		expect(reached).toBe(1);
		expect(redelivered.status).toBe(200);
		expect(((await redelivered.json()) as Envelope).duplicate).toBe(true);
	});

	it("says so in the log when a delivery outran its own reservation", async () => {
		// The ledger fails closed silently otherwise, and a ledger that quietly
		// starts doing the unusual thing is one you find out about when something
		// else also breaks. The line names the reservation window because that is
		// the number an operator would be reaching for.
		const id = crypto.randomUUID();
		const stub = env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName("deliveries"));

		const entries = await captureLogEntries(async () => {
			await through(id, async (c) => {
				await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) => state.storage.delete(`d:${id}`));
				return c.json({ ok: true }, 200);
			});
		});

		const line = logLine(entries, "Delivery committed after its reservation had lapsed");
		expect(line.level).toBe("warn");
		expect(line.delivery).toBe(id);
		expect(line.reservationMs).toBe(DELIVERY_RESERVATION_MS);
	});

	it("does not create a record when a delivery that caused nothing loses its reservation", async () => {
		// The mirror image, so "commit writes what it does not find" cannot quietly
		// become "settle writes what it does not find". A handler that published
		// nothing and lost its reservation must leave the id retryable — that is
		// the whole reason the phases exist.
		const id = crypto.randomUUID();
		const stub = env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName("deliveries"));
		let reached = 0;

		const refused = await through(id, async (c) => {
			reached += 1;
			c.set("webhookRetryable", true);
			await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) => state.storage.delete(`d:${id}`));
			return c.json({ refused: true }, 503);
		});
		expect(refused.status).toBe(503);

		const stored = await runInDurableObject(stub, async (_instance: WebhookDeliveries, state) =>
			state.storage.get<{ committed: boolean }>(`d:${id}`),
		);
		expect(stored).toBeUndefined();

		const redelivered = await through(id, (c) => {
			reached += 1;
			return c.json({ ok: true }, 200);
		});

		expect(reached).toBe(2);
		expect(((await redelivered.json()) as Envelope).duplicate).toBeUndefined();
	});
});
