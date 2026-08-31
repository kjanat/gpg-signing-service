/**
 * The ledger of webhook delivery ids, in three phases.
 *
 * Why a Durable Object and not KV or D1 is argued in `#utils/webhook-replay`;
 * the short version is that the only interesting case is two copies of one
 * delivery arriving at the same instant, and this is the storage in this
 * service that can decide that case rather than race it.
 *
 * The object holds one key per known id, `d:<deliveryId>`, and an alarm that
 * reaps the expired ones. Entries are not read after they expire even if the
 * reaper has not reached them — the expiry stored in the value is what decides,
 * so a lagging sweep can waste storage but can never waste a refusal.
 *
 * ### Why more than one phase
 *
 * A single-phase claim is consumed the instant a delivery is accepted and is
 * never given back, which makes every failure permanent: a handler that fails
 * before doing anything at all still burns the id, and the operator's
 * redelivery — the one recovery affordance GitHub offers — comes back
 * `duplicate: true` without acting. That is fine for a scaffold that acts on
 * nothing and wrong for a handler that signs commits.
 *
 * So an id moves through two states:
 *
 * - **Reserved** by {@link WebhookDeliveries.reserve} before the handler runs,
 *   under `blockConcurrencyWhile`, which is what keeps simultaneous copies to
 *   one winner. A reservation is short-lived: it expires on its own, so a
 *   handler whose isolate died does not hold an id hostage.
 * - **Held** by {@link WebhookDeliveries.settle} immediately *before* an
 *   irreversible request leaves. This is the phase that makes at-most-once
 *   independent of the handler surviving: the retention window starts when the
 *   request is sent rather than when the answer comes back, so a process that
 *   dies mid-flight still leaves the id spent.
 * - **Committed** by {@link WebhookDeliveries.settle} once the delivery has
 *   caused something irreversible. A committed record lasts the full retention
 *   window and is what makes a replay a no-op. It is written whether or not the
 *   reservation survived: a commit that finds nothing to update creates the
 *   record instead, because the alternative is an irreversible action nothing
 *   remembers.
 *
 * And one way back: release drops a record that caused nothing — a reservation,
 * or a hold whose request came back as a definite refusal — so a redelivery is
 * a genuine retry. Release refuses to touch a *committed* record, and that
 * direction stays one-way on purpose, because it is the direction that would
 * let a second arrival un-say the first one's action.
 */

import { HTTP, MediaType } from "#types";
import { logger } from "#utils/logger";
import { DELIVERY_RESERVATION_MS, DELIVERY_RETENTION_MS } from "#utils/webhook-replay";

/** What is remembered about a delivery id. */
interface DeliveryRecord {
	/** First reserved at, epoch milliseconds. */
	firstSeen: number;
	/** Stops counting as taken at, epoch milliseconds. */
	expiresAt: number;
	/**
	 * Whether the delivery got far enough to do something irreversible.
	 *
	 * False while a handler is still running. A record that is false and expired
	 * is an abandoned reservation and means nothing; a record that is true is a
	 * fact about the world and is never removed before its retention elapses.
	 */
	committed: boolean;
	/**
	 * Whether an irreversible request is *in flight* for this delivery.
	 *
	 * Set by {@link WebhookDeliveries.settle}'s hold phase, before the request
	 * leaves, and it is what makes the retention window start at that moment
	 * rather than when the handler comes back. Absent on records written before
	 * the phase existed, so it is read as `=== true` rather than trusted.
	 */
	held?: boolean;
}

export class WebhookDeliveries implements DurableObject {
	private state: DurableObjectState;

	/** Prefix for delivery-id records. Nothing else in this object uses it. */
	private readonly keyPrefix = "d:";

	// Reaping, shaped exactly like `RateLimiter`'s: a cursor so a pass covers the
	// whole prefix rather than re-reading its first page forever, a batch so one
	// alarm is bounded, and a delete chunk because `storage.delete()` takes at
	// most 128 keys.
	private readonly sweepIntervalMs = 60 * 60 * 1000; // 1 hour
	private readonly sweepBatch = 1000;
	private readonly deleteChunk = 128;
	/** Where the last sweep stopped. Outside `keyPrefix`, so the sweep cannot reap its own cursor. */
	private readonly sweepCursorKey = "sweep:cursor";

	constructor(state: DurableObjectState) {
		this.state = state;
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		try {
			const operation = url.pathname;

			if (operation !== "/reserve" && operation !== "/commit" && operation !== "/hold" && operation !== "/release") {
				return new Response("Not found", { status: HTTP.NotFound });
			}

			if (request.method !== "POST") {
				return new Response("Method not allowed", { status: HTTP.MethodNotAllowed });
			}

			const id = url.searchParams.get("id");
			if (!id) {
				// The caller validates the id shape before it gets here; this is the
				// second of two guards, so a future caller cannot inherit the first
				// one's diligence by forgetting it. An empty id would otherwise
				// become the key `d:` — one shared name that every id-less delivery
				// would dedupe against.
				return new Response(JSON.stringify({ error: "Delivery id required" }), {
					status: HTTP.BadRequest,
					headers: { "Content-Type": MediaType.ApplicationJson },
				});
			}

			if (operation === "/reserve") {
				return await this.reserve(id);
			}

			return await this.settle(id, operation === "/commit" ? "commit" : operation === "/hold" ? "hold" : "release");
		} catch (error) {
			// The end of the line, as in `RateLimiter.fetch`: nothing above this
			// catches a fault from inside a Durable Object, so it is reported here or
			// not at all. The delivery id is deliberately absent from the log — the
			// path is what says which operation failed, and the id is the caller's
			// value.
			logger.error("Delivery ledger request failed", error, { action: "webhook-replay", path: url.pathname });
			const message = error instanceof Error ? error.message : "Unknown error";
			return new Response(JSON.stringify({ error: message }), {
				status: HTTP.InternalServerError,
				headers: { "Content-Type": MediaType.ApplicationJson },
			});
		}
	}

	/**
	 * Run `work` with the object closed to every other request.
	 *
	 * The `try` is inside the critical section and the `throw` is outside it, on
	 * purpose. **An exception raised inside `blockConcurrencyWhile` resets the
	 * Durable Object** — the runtime discards its in-memory state and aborts every
	 * in-flight request to it — which is a drastic response to a transient storage
	 * read, and it would take the exception out of reach of the handler that turns
	 * faults into a 500. Catching there and rethrowing a step later keeps the
	 * atomicity and keeps the fault reportable.
	 */
	private async exclusively<T>(work: () => Promise<T>): Promise<T> {
		const outcome = await this.state.blockConcurrencyWhile<{ value: T } | { failure: unknown }>(async () => {
			try {
				return { value: await work() };
			} catch (failure) {
				return { failure };
			}
		});

		if ("failure" in outcome) {
			throw outcome.failure;
		}

		return outcome.value;
	}

	/**
	 * Take `id`, unless something already holds it.
	 *
	 * The read and the write are inside one critical section, which is the whole
	 * point of this class. Without it, two concurrent reservations for the same id
	 * could both observe "not present" before either writes, and both would be told
	 * they had it — the exact double-action this exists to prevent, arriving in the
	 * one case an attacker can arrange on purpose.
	 *
	 * A reservation is held for {@link DELIVERY_RESERVATION_MS} and no longer. Long
	 * enough that a running handler is never overtaken by a redelivery; short
	 * enough that a handler which died without either committing or releasing gives
	 * the id back on its own, rather than turning one crashed request into an event
	 * that can never be redelivered.
	 *
	 * Returns 200 either way. "Already taken" is an answer, not a failure, and a
	 * non-2xx here would be indistinguishable to the caller from the ledger being
	 * broken — which it must fail closed on, and this must not.
	 */
	private async reserve(id: string): Promise<Response> {
		const key = `${this.keyPrefix}${id}`;

		const result = await this.exclusively(async () => {
			const now = Date.now();
			const existing = await this.state.storage.get<DeliveryRecord>(key);

			// An expired record is not a hold — neither an expired reservation, whose
			// handler is gone, nor a committed record whose retention has elapsed.
			// Overwritten rather than deleted and re-created, so an id that returns
			// after its window starts a fresh one, which is the same thing that would
			// have happened had the reaper got to it first. The two must not differ.
			if (existing && existing.expiresAt > now) {
				return {
					reserved: false,
					firstSeen: existing.firstSeen,
					committed: existing.committed,
					held: existing.held === true,
				};
			}

			await this.state.storage.put<DeliveryRecord>(key, {
				firstSeen: now,
				expiresAt: now + DELIVERY_RESERVATION_MS,
				committed: false,
				held: false,
			});

			return { reserved: true, firstSeen: now, committed: false, held: false };
		});

		// Outside the critical section: arming the reaper is not part of the
		// decision, and holding the object closed for it would serialise every
		// reservation behind an alarm write that only ever matters once.
		await this.scheduleSweep();

		return new Response(JSON.stringify(result), {
			status: HTTP.OK,
			headers: { "Content-Type": MediaType.ApplicationJson },
		});
	}

	/**
	 * Move `id` on: hold it, commit it, or give it back.
	 *
	 * `hold` and `commit` both extend the record to the full retention window;
	 * `release` deletes it, so a redelivery is a real retry.
	 *
	 * ### Why there are three phases and not two
	 *
	 * A reservation lasts {@link DELIVERY_RESERVATION_MS} and a handler that dies
	 * mid-request gives it back by lapsing. That is the right default — a crashed
	 * request usually caused nothing — and it is wrong for the instant a handler
	 * is *about to* do something irreversible that has no idempotency key, which
	 * is what dispatching a workflow is. Between "reserved, and a crash means
	 * nothing happened" and "committed, and nothing may ever reopen it" there is
	 * a real third state: **an irreversible request is in flight, and if this
	 * process disappears the delivery must stay spent.**
	 *
	 * `hold` is that state. It is durable before the request leaves, so the
	 * at-most-once guarantee does not depend on the handler surviving long enough
	 * to settle; and it is still `committed: false`, so the one party that can
	 * ever learn the request definitely did nothing — the handler that made it,
	 * which is also the only request holding the reservation — may release it.
	 *
	 * That asymmetry is deliberate and it is narrower than reopening a committed
	 * record would be. There is still **no path from committed back to absent**
	 * except the retention window elapsing: a committed record is a statement
	 * that something happened in a repository, and a later request able to erase
	 * it could make a replay act a second time. A held record says only that
	 * something was *attempted*.
	 *
	 * ### An absent record means opposite things on the phases
	 *
	 * A reservation lapses on its own, so a handler can outlive its own
	 * reservation and arrive here with nothing to settle. What that means depends
	 * entirely on which way it was going.
	 *
	 * On **release** it means nothing: the delivery caused nothing, the record is
	 * already gone, and gone is where release was taking it. Reported and dropped.
	 *
	 * On **commit** and on **hold** it is the one state this ledger exists to
	 * prevent. The caller only reaches either once something irreversible has
	 * happened or is about to — a branch has moved, a dispatch is leaving — and
	 * answering "absent, nothing written" would leave that fact recorded nowhere,
	 * so the operator's redelivery would be handled as a first arrival and do it
	 * again. So both **write the record they did not find**, for the full
	 * retention window, and report that they had to. `firstSeen` is the write
	 * itself: the original reservation's timestamp went with the record that
	 * lapsed, and inventing an earlier one would misdate the only evidence of
	 * what happened.
	 *
	 * A `hold` never downgrades a committed record, and a `commit` never clears a
	 * hold. The two flags accumulate, because each is a fact about what the
	 * delivery did and neither un-says the other.
	 */
	private async settle(id: string, phase: "commit" | "hold" | "release"): Promise<Response> {
		const key = `${this.keyPrefix}${id}`;

		const result = await this.exclusively(async () => {
			const existing = await this.state.storage.get<DeliveryRecord>(key);
			const now = Date.now();

			if (!existing) {
				if (phase === "release") {
					return { settled: false, reason: "absent" as const };
				}

				await this.state.storage.put<DeliveryRecord>(key, {
					firstSeen: now,
					expiresAt: now + DELIVERY_RETENTION_MS,
					committed: phase === "commit",
					held: phase === "hold",
				});
				return {
					settled: true,
					reason:
						phase === "commit" ? ("committed_without_reservation" as const) : ("held_without_reservation" as const),
				};
			}

			if (phase !== "release") {
				await this.state.storage.put<DeliveryRecord>(key, {
					firstSeen: existing.firstSeen,
					expiresAt: now + DELIVERY_RETENTION_MS,
					committed: phase === "commit" || existing.committed,
					held: phase === "hold" || existing.held === true,
				});
				return { settled: true, reason: phase === "commit" ? ("committed" as const) : ("held" as const) };
			}

			if (existing.committed) {
				return { settled: false, reason: "already_committed" as const };
			}

			// Reached by a held record as well as a reserved one, and that is the
			// 4xx path: GitHub answered that it created nothing, so the delivery
			// that was held a moment ago goes back and an operator's fix plus a
			// redelivery is a real retry.
			await this.state.storage.delete(key);
			return { settled: true, reason: "released" as const };
		});

		// A commit or a hold can now create a record where `reserve` created none,
		// and the reaper is only ever armed by `reserve`. Without this, a record
		// written after the sweep emptied the ledger — which stops re-arming itself
		// when it finds nothing — would sit there until the next unrelated
		// reservation.
		if (phase !== "release") {
			await this.scheduleSweep();
		}

		return new Response(JSON.stringify(result), {
			status: HTTP.OK,
			headers: { "Content-Type": MediaType.ApplicationJson },
		});
	}

	/**
	 * Arm the reaper if it is not already armed.
	 *
	 * An existing alarm is left alone. Re-arming on every reservation would push the
	 * sweep out indefinitely under sustained delivery — exactly when there is
	 * most to reap.
	 */
	private async scheduleSweep(): Promise<void> {
		if ((await this.state.storage.getAlarm()) === null) {
			await this.state.storage.setAlarm(Date.now() + this.sweepIntervalMs);
		}
	}

	/**
	 * Delete records whose retention has elapsed.
	 *
	 * Reaping changes no verdict: `reserve` already treats an expired record as
	 * absent, so this only reclaims the storage. That is what makes it safe to
	 * run late, in pages, and behind a cursor.
	 *
	 * One page per alarm, resumed from a persisted cursor — `list` has no
	 * implicit one, so without it a first page of live records would hide every
	 * key behind it from the sweep forever.
	 */
	async alarm(): Promise<void> {
		const now = Date.now();
		const cursor = await this.state.storage.get<string>(this.sweepCursorKey);
		const records = await this.state.storage.list<DeliveryRecord>({
			prefix: this.keyPrefix,
			...(cursor === undefined ? {} : { startAfter: cursor }),
			limit: this.sweepBatch,
		});

		const expired: string[] = [];
		let lastKey: string | undefined;
		for (const [key, record] of records) {
			lastKey = key;
			if (record.expiresAt <= now) {
				expired.push(key);
			}
		}

		for (let index = 0; index < expired.length; index += this.deleteChunk) {
			await this.state.storage.delete(expired.slice(index, index + this.deleteChunk));
		}

		// A full page means keys remain behind it: carry the cursor past it and
		// come back promptly rather than draining a backlog one interval at a time.
		if (records.size === this.sweepBatch && lastKey !== undefined) {
			await this.state.storage.put(this.sweepCursorKey, lastKey);
			await this.state.storage.setAlarm(now + 1_000);
			return;
		}

		// A short page ends the pass; the next one starts from the beginning.
		await this.state.storage.delete(this.sweepCursorKey);

		// Re-arm only while records remain, asked of the whole object rather than
		// of this page — a pass can end on a page that was entirely expired while
		// live records sit in the pages before it. An empty ledger stops waking
		// itself, and the next reservation re-arms it.
		const remaining = await this.state.storage.list<DeliveryRecord>({ prefix: this.keyPrefix, limit: 1 });
		if (remaining.size > 0) {
			await this.state.storage.setAlarm(now + this.sweepIntervalMs);
		}
	}
}
