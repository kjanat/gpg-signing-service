/**
 * The ledger of webhook delivery ids that have already been acted upon.
 *
 * Why a Durable Object and not KV or D1 is argued in `#utils/webhook-replay`;
 * the short version is that the only interesting case is two copies of one
 * delivery arriving at the same instant, and this is the storage in this
 * service that can decide that case rather than race it.
 *
 * The object holds one key per claimed id, `d:<deliveryId>`, and an alarm that
 * reaps the expired ones. Entries are not read after they expire even if the
 * reaper has not reached them — the expiry stored in the value is what decides,
 * so a lagging sweep can waste storage but can never waste a refusal.
 */

import { HTTP, MediaType } from "#types";
import { logger } from "#utils/logger";
import { DELIVERY_RETENTION_MS } from "#utils/webhook-replay";

/** What is remembered about a claimed delivery id. */
interface DeliveryRecord {
	/** First claimed at, epoch milliseconds. */
	firstSeen: number;
	/** Stops counting as claimed at, epoch milliseconds. */
	expiresAt: number;
}

export class WebhookDeliveries implements DurableObject {
	private state: DurableObjectState;

	/** Prefix for claimed-id keys. Nothing else in this object uses it. */
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
			if (url.pathname === "/claim") {
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

				return await this.claim(id);
			}

			return new Response("Not found", { status: HTTP.NotFound });
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
	 * Record `id` as spent, unless it already is.
	 *
	 * The read and the write are inside one `blockConcurrencyWhile`, which is the
	 * whole point of this class. Without it, two concurrent claims for the same
	 * id could both observe "not present" before either writes, and both would be
	 * told they had claimed it — the exact double-action this exists to prevent,
	 * arriving in the one case an attacker can arrange on purpose.
	 *
	 * Returns 200 either way. "Already claimed" is an answer, not a failure, and
	 * a non-2xx here would be indistinguishable to the caller from the ledger
	 * being broken — which it must fail closed on, and this must not.
	 */
	private async claim(id: string): Promise<Response> {
		const key = `${this.keyPrefix}${id}`;

		// The `try` is inside the critical section and the `throw` is outside it, on
		// purpose. **An exception raised inside `blockConcurrencyWhile` resets the
		// Durable Object** — the runtime discards its in-memory state and aborts
		// every in-flight request to it — which is a drastic response to a
		// transient storage read, and it would take the exception out of reach of
		// the handler that turns faults into a 500. Catching here and rethrowing a
		// step later keeps the atomicity and keeps the fault reportable.
		const outcome = await this.state.blockConcurrencyWhile(
			async (): Promise<{ claimed: boolean; firstSeen: number } | { failure: unknown }> => {
				try {
					const now = Date.now();
					const existing = await this.state.storage.get<DeliveryRecord>(key);

					// An expired record is not a claim. Overwritten rather than deleted
					// and re-created, so an id that returns after its retention window
					// starts a fresh one — which is the same thing that would have
					// happened had the reaper got to it first, and the two must not
					// differ.
					if (existing && existing.expiresAt > now) {
						return { claimed: false, firstSeen: existing.firstSeen };
					}

					await this.state.storage.put<DeliveryRecord>(key, {
						firstSeen: now,
						expiresAt: now + DELIVERY_RETENTION_MS,
					});

					return { claimed: true, firstSeen: now };
				} catch (failure) {
					return { failure };
				}
			},
		);

		if ("failure" in outcome) {
			throw outcome.failure;
		}

		const result = outcome;

		// Outside the critical section: arming the reaper is not part of the
		// decision, and holding the object closed for it would serialise every
		// claim behind an alarm write that only ever matters once.
		await this.scheduleSweep();

		return new Response(JSON.stringify(result), {
			status: HTTP.OK,
			headers: { "Content-Type": MediaType.ApplicationJson },
		});
	}

	/**
	 * Arm the reaper if it is not already armed.
	 *
	 * An existing alarm is left alone. Re-arming on every claim would push the
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
	 * Reaping changes no verdict: `claim` already treats an expired record as
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
		// itself, and the next claim re-arms it.
		const remaining = await this.state.storage.list<DeliveryRecord>({ prefix: this.keyPrefix, limit: 1 });
		if (remaining.size > 0) {
			await this.state.storage.setAlarm(now + this.sweepIntervalMs);
		}
	}
}
