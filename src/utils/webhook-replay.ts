/**
 * Replay protection for webhook deliveries, and what it can and cannot promise.
 *
 * A webhook signature covers the body and nothing else — no timestamp, no
 * nonce, no expiry. So a delivery that verified once verifies forever, and
 * anyone who obtains a copy of one can present it again unchanged. GitHub's own
 * "Redeliver" button does exactly that on purpose. That is harmless while the
 * handler acts on nothing; the moment one signs a commit, opens a check run or
 * dispatches a workflow, "verifies forever" means "can be made to happen again,
 * any number of times, by anyone who ever saw the bytes".
 *
 * The only thing distinguishing a repeat from a fresh event is
 * `X-GitHub-Delivery`, [a GUID identifying the
 * event](https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers)
 * that a redelivery reuses. So: remember the ones already acted upon, and
 * refuse the second arrival.
 *
 * Three things this has to get right, each of which has an appealing wrong
 * answer:
 *
 * **The reservation must be atomic.** Two copies of one delivery arriving at the same
 * instant is the case that matters — it is what a double-click on "Redeliver"
 * produces, and what an attacker sends deliberately — and a check-then-write
 * across two round trips lets both see "not seen" and both proceed. KV cannot
 * do this at all: it is eventually consistent and has no compare-and-set. D1
 * could, via a unique constraint. This uses a Durable Object, which serialises
 * by construction, and takes the read-modify-write inside
 * `blockConcurrencyWhile` so the guarantee is stated in the code rather than
 * argued from the runtime's input-gate semantics.
 *
 * **The retention must be bounded, and bounded by something real.** GitHub
 * [lists deliveries from the past 3
 * days](https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/viewing-webhook-deliveries)
 * and that listing is the redelivery affordance — a delivery that has aged out
 * of it cannot be redelivered from the UI or through
 * `POST /app/hook/deliveries/{id}/attempts`. So the window in which a *legitimate*
 * repeat can occur is three days, and {@link DELIVERY_RETENTION_MS} is that
 * plus a day of margin for clock skew and for the boundary itself. Keeping ids
 * forever would be the "safer" choice and is not available: unbounded storage
 * growth is its own outage.
 *
 * What that costs, stated plainly rather than buried: **an attacker who
 * captured a delivery can replay it successfully once the retention expires.**
 * No TTL-based dedupe can prevent that, because the signature carries no
 * timestamp to age against and this service cannot distinguish a four-day-old
 * capture from a fresh delivery. Bounding it to GitHub's own window is the
 * honest trade — it covers every repeat GitHub itself can cause — and a handler
 * whose action is destructive rather than idempotent needs a second control
 * (the event's own state, checked against GitHub) and not a longer TTL.
 *
 * **The id must be taken only after the delivery is trusted.** See
 * `webhookReplayGuard`: an unauthenticated or unauthorized request that could
 * consume an id would be able to suppress the real delivery carrying it, which
 * turns replay protection into a denial-of-service primitive pointed at exactly
 * the events it was built to protect.
 *
 * ### Two phases, because the handler now acts
 *
 * A one-way claim taken before the handler runs is *at-most-once*: an event is
 * acted on no more than once and possibly not at all. That was the right
 * default while the handler acted on nothing, and it is the wrong one now,
 * because it makes every failure permanent. A delivery refused by the rate
 * limiter, or arriving while key storage is down, or naming a key nobody bound,
 * has caused nothing at all — and under a one-way claim the operator's
 * redelivery comes back `200 {"duplicate": true}` and the event is lost.
 *
 * So the id is **reserved** before the handler and **committed** only once the
 * delivery has caused something irreversible; a delivery that caused nothing
 * **releases** it. The reservation is what keeps simultaneous copies to one
 * winner, so nothing about the concurrency guarantee changes: at every instant
 * exactly one request holds a given id.
 *
 * The line the phases turn on is not "did the handler succeed" but **"has
 * anything left this service that cannot be taken back"**. For push signing
 * that line is the ref update: signing a commit produces bytes nobody can see,
 * creating a commit object leaves something unreachable that GitHub collects,
 * and *moving the branch* is the first step a person could observe. See
 * `#routes/github-webhook` for where the commit is taken and why it is taken
 * before the ref update rather than after it.
 */

import type { Env } from "#types";
import { TIME } from "#types";

/**
 * How long a committed delivery id is remembered.
 *
 * GitHub's 3-day redelivery window plus a day. See the module comment for why
 * this number and not a larger one.
 */
export const DELIVERY_RETENTION_MS = 4 * TIME.DAY;

/**
 * How long a reservation is held before it lapses on its own.
 *
 * This is the window in which a handler must finish. Two failure modes bound it
 * from opposite sides, and the number has to sit between them:
 *
 * - **Too short** and a redelivery can overtake a handler that is still
 *   working, which is the double-action the reservation exists to prevent. A
 *   Worker's own limits put a much lower ceiling on how long a handler can run
 *   than this does, so overtaking a live handler is not reachable in practice.
 * - **Too long** and a handler whose isolate died — evicted, crashed, killed
 *   mid-request — holds the id until it lapses, and every redelivery in the
 *   meantime is answered as a duplicate without acting. That is the state an
 *   operator hits at exactly the moment they are trying to recover.
 *
 * Five minutes is comfortably longer than any request this service can make and
 * short enough that an abandoned reservation is a pause rather than an outage.
 */
export const DELIVERY_RESERVATION_MS = 5 * TIME.MINUTE;

/**
 * The single Durable Object every delivery id goes through.
 *
 * One object, not a shard set: dedupe is only correct when the same id always
 * reaches the same object, and one object makes that true without a hash
 * function to get wrong. It also serialises all webhook dedupe through a single
 * actor, which at the volume a private App delivers is not a cost worth a
 * design to avoid. If it ever is, the change is a deterministic id → shard
 * function here and nothing else.
 */
const DELIVERY_LEDGER = "deliveries";

/**
 * What a delivery id may look like.
 *
 * GitHub sends a UUID. This accepts more than that on purpose — pinning the
 * exact GUID format would make a change in GitHub's id scheme an outage — but
 * far less than "any string", because this value becomes a storage key. Bounded
 * length so a record cannot be made enormous, and a charset with no `:` in it so
 * an id can never be confused with the `d:` prefix the ledger keys are built
 * from.
 *
 * The lower bound matters as much as the upper: an empty or one-character id is
 * exactly what a request forging a *collision* would use, and it is not
 * something GitHub sends.
 */
const DELIVERY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{7,199}$/;

/** Is `value` an id this service is willing to dedupe on? */
export function isDeliveryId(value: string | null | undefined): value is string {
	return typeof value === "string" && DELIVERY_ID_PATTERN.test(value);
}

/** The outcome of trying to reserve a delivery id. */
export interface DeliveryReservation {
	/** True the first time an id is presented, false while anything else holds it. */
	reserved: boolean;
	/** When the id was first taken, in epoch milliseconds. */
	firstSeen: number;
	/**
	 * Whether the holder had already committed.
	 *
	 * Only meaningful when `reserved` is false. It separates "this delivery was
	 * acted upon" from "another copy of it is being handled right now", which are
	 * the same answer to the caller and different lines in a log.
	 */
	committed: boolean;
}

/** One ledger call, parsed rather than cast. */
async function ledgerCall(env: Env, operation: string, deliveryId: string): Promise<Record<string, unknown>> {
	const ledger = env.WEBHOOK_DELIVERIES.get(env.WEBHOOK_DELIVERIES.idFromName(DELIVERY_LEDGER));

	const response = await ledger.fetch(
		new Request(`http://internal/${operation}?id=${encodeURIComponent(deliveryId)}`, { method: "POST" }),
	);

	if (!response.ok) {
		throw new Error(`Delivery ledger returned ${response.status}`);
	}

	return (await response.json()) as Record<string, unknown>;
}

/**
 * Take `deliveryId`, or discover that something already holds it.
 *
 * @param env - Deployment bindings
 * @param deliveryId - A value that has passed {@link isDeliveryId}
 * @throws When the ledger cannot be reached. Callers must fail closed: a
 *   reservation that did not happen is not a reservation, and treating an
 *   unreachable ledger as "not seen before" removes the protection at exactly
 *   the moment it is least able to be checked.
 */
export async function reserveDelivery(env: Env, deliveryId: string): Promise<DeliveryReservation> {
	const body = await ledgerCall(env, "reserve", deliveryId);

	// Parsed rather than cast through: this decides whether an event is acted on
	// twice, and a malformed body silently read as `reserved: undefined` would be
	// falsy — which happens to fail closed, and is not a property worth resting
	// on an accident of coercion.
	if (typeof body.reserved !== "boolean" || typeof body.firstSeen !== "number" || typeof body.committed !== "boolean") {
		throw new Error("Delivery ledger returned an unreadable reservation");
	}

	return { reserved: body.reserved, firstSeen: body.firstSeen, committed: body.committed };
}

/**
 * Keep `deliveryId` for the full retention window.
 *
 * Called once a delivery has caused something that cannot be undone. After
 * this, every later arrival of the id is a no-op — including a redelivery an
 * operator triggers because the response looked like a failure.
 *
 * @throws When the ledger cannot be reached. The caller decides what that means
 *   for the response; it does not mean the action can be undone.
 */
export async function commitDelivery(env: Env, deliveryId: string): Promise<void> {
	await ledgerCall(env, "commit", deliveryId);
}

/**
 * Give `deliveryId` back, so a redelivery is a genuine retry.
 *
 * Called when a delivery caused nothing: a refusal, a configuration error, an
 * outage in a dependency, a failure while assembling work that was never
 * published. The ledger refuses to release a record that has been committed, so
 * a mistaken call here cannot reopen an action that already happened.
 */
export async function releaseDelivery(env: Env, deliveryId: string): Promise<void> {
	await ledgerCall(env, "release", deliveryId);
}
