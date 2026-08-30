import type { RateLimitResult } from "#types";
import { createRateLimitAllowed, createRateLimitDenied, HTTP, MediaType } from "#types";
import { retryAfterSeconds } from "#utils/rate-limit";

interface TokenBucket {
	tokens: number;
	lastRefill: number;
	/**
	 * This bucket's capacity, stored rather than assumed: buckets with different
	 * ceilings share one Durable Object, and a bucket refilled against the wrong
	 * capacity would silently grant the wrong budget.
	 */
	capacity?: number;
}

export class RateLimiter implements DurableObject {
	private state: DurableObjectState;

	// Rate limit configuration. A bucket refills at its own capacity per window,
	// so a wider bucket refills proportionally faster rather than taking longer to
	// recover than a narrow one.
	private readonly maxTokens = 100; // Default capacity, and requests per window
	private readonly windowMs = 60_000; // 1 minute window

	// Reaping. Identities are caller-varied — `<iss>:<sub>` carries the git ref —
	// so the set of bucket keys grows without bound while nothing removes them.
	// A bucket idle for a full window has refilled to capacity, which is exactly
	// what a *missing* bucket is created as, so deleting it changes no verdict.
	private readonly idleTtlMs = 60_000;
	private readonly sweepIntervalMs = 300_000; // 5 minutes
	private readonly sweepBatch = 1000; // Keys examined per alarm
	private readonly deleteChunk = 128; // Storage delete() takes at most 128 keys
	// Where the last sweep stopped. Outside the `bucket:` prefix so it is neither
	// listed nor reaped by the sweep it drives.
	private readonly sweepCursorKey = "sweep:cursor";

	constructor(state: DurableObjectState) {
		this.state = state;
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname;

		try {
			switch (path) {
				case "/check":
					return await this.checkLimit(
						url.searchParams.get("identity") || "default",
						this.parseLimit(url.searchParams.get("limit")),
					);

				case "/consume":
					return await this.consumeToken(
						url.searchParams.get("identity") || "default",
						this.parseLimit(url.searchParams.get("limit")),
					);

				case "/reset":
					if (request.method !== "POST") {
						return new Response("Method not allowed", {
							status: HTTP.MethodNotAllowed,
						});
					}
					return await this.resetLimit(url.searchParams.get("identity") || "");

				default:
					return new Response("Not found", { status: HTTP.NotFound });
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unknown error";
			return new Response(JSON.stringify({ error: message }), {
				status: HTTP.InternalServerError,
				headers: { "Content-Type": MediaType.ApplicationJson },
			});
		}
	}

	/**
	 * Read a caller-supplied bucket capacity.
	 *
	 * Bounded and integral: the value reaches here from application code, not
	 * from a request, but a NaN would poison the stored bucket permanently.
	 *
	 * Returns `undefined` rather than the default when nothing usable was
	 * supplied, so `getBucket` can tell "no opinion" — which must not overwrite a
	 * wide bucket's stored ceiling — from an explicit capacity, which must.
	 *
	 * @param raw - The `limit` query parameter, if present
	 * @returns A usable capacity, or `undefined` if none was supplied
	 */
	private parseLimit(raw: string | null): number | undefined {
		const parsed = Number(raw);
		if (!raw || !Number.isFinite(parsed) || parsed < 1) {
			return undefined;
		}
		return Math.min(Math.floor(parsed), 1_000_000);
	}

	/**
	 * When a denied bucket next holds a whole token.
	 *
	 * Refill is proportional to capacity, so a wide bucket repays its debt fast:
	 * one token against a ceiling of 1000 is back in 60ms, not 60s. Reporting the
	 * window instead told every refused caller to wait a full minute — a 1000x
	 * overstatement on the row bucket, which is the one whose `Retry-After` idles
	 * every sibling under a trusted row rather than just the caller that spent it.
	 */
	private retryAt(bucket: TokenBucket, now: number): number {
		const capacity = bucket.capacity ?? this.maxTokens;
		return now + Math.ceil(((1 - bucket.tokens) / capacity) * this.windowMs);
	}

	private async checkLimit(identity: string, capacity?: number): Promise<Response> {
		const bucket = await this.getBucket(identity, capacity);
		const resetAt = bucket.lastRefill + this.windowMs;

		const result: RateLimitResult =
			bucket.tokens >= 1
				? createRateLimitAllowed(Math.floor(bucket.tokens), resetAt)
				: createRateLimitDenied(this.retryAt(bucket, Date.now()));

		return new Response(JSON.stringify(result), {
			status: HTTP.OK,
			headers: { "Content-Type": MediaType.ApplicationJson },
		});
	}

	private async consumeToken(identity: string, capacity?: number): Promise<Response> {
		const bucket = await this.getBucket(identity, capacity);
		const resetAt = bucket.lastRefill + this.windowMs;

		if (bucket.tokens < 1) {
			const retryAt = this.retryAt(bucket, Date.now());
			const result: RateLimitResult = createRateLimitDenied(retryAt);

			return new Response(JSON.stringify(result), {
				status: HTTP.TooManyRequests,
				headers: {
					"Content-Type": MediaType.ApplicationJson,
					// The same floor the body's `retryAfter` gets, from the same
					// function: this header and that field describe one wait, and two
					// spellings of one expression are two things that can drift.
					"Retry-After": String(retryAfterSeconds(retryAt)),
				},
			});
		}

		// Consume one token. This is the only path that persists a bucket: a bucket
		// nobody has drawn down is fully described by its absence, so `/check` and
		// the refill above stay read-only rather than minting a key per identity.
		bucket.tokens -= 1;
		await this.state.storage.put(`bucket:${identity}`, bucket);
		await this.scheduleSweep();

		const result: RateLimitResult = createRateLimitAllowed(Math.floor(bucket.tokens), resetAt);

		return new Response(JSON.stringify(result), {
			status: HTTP.OK,
			headers: { "Content-Type": MediaType.ApplicationJson },
		});
	}

	private async resetLimit(identity: string): Promise<Response> {
		if (!identity) {
			return new Response(JSON.stringify({ error: "Identity required" }), {
				status: HTTP.BadRequest,
				headers: { "Content-Type": MediaType.ApplicationJson },
			});
		}

		await this.state.storage.delete(`bucket:${identity}`);

		return new Response(JSON.stringify({ success: true }), {
			status: HTTP.OK,
			headers: { "Content-Type": MediaType.ApplicationJson },
		});
	}

	private async getBucket(identity: string, capacity?: number): Promise<TokenBucket> {
		const now = Date.now();
		let bucket = await this.state.storage.get<TokenBucket>(`bucket:${identity}`);

		if (!bucket) {
			const newCapacity = capacity ?? this.maxTokens;
			bucket = { tokens: newCapacity, lastRefill: now, capacity: newCapacity };
		} else {
			// An explicitly supplied capacity wins over the stored one, so the
			// ceilings in the routes stay tunable: nothing reaps `bucket:` keys, so a
			// capacity pinned at creation would outlive every later change to it.
			// Falls back to the stored value when the caller has no opinion — the
			// `/check` path names no limit — and to the default for buckets written
			// before capacities were per-bucket.
			const bucketCapacity = capacity ?? bucket.capacity ?? this.maxTokens;
			const elapsed = now - bucket.lastRefill;
			const tokensToAdd = (elapsed / this.windowMs) * bucketCapacity;

			// Clamped to the current capacity, so a lowered ceiling takes effect on
			// the next request rather than after the bucket happens to drain.
			bucket.tokens = Math.min(bucketCapacity, bucket.tokens + tokensToAdd);
			bucket.lastRefill = now;
			bucket.capacity = bucketCapacity;
		}

		return bucket;
	}

	/**
	 * Arm the reaper if it is not already armed.
	 *
	 * Re-arming on every write would push the sweep out indefinitely under
	 * sustained traffic — precisely when there is most to reap — so an existing
	 * alarm is left alone.
	 */
	private async scheduleSweep(): Promise<void> {
		if ((await this.state.storage.getAlarm()) === null) {
			await this.state.storage.setAlarm(Date.now() + this.sweepIntervalMs);
		}
	}

	/**
	 * Delete buckets that have refilled to capacity.
	 *
	 * Deleting one is not a reset: `getBucket` creates a missing bucket full, so a
	 * reaped bucket and an idle one answer identically. What it drops is the key.
	 *
	 * That equivalence holds unconditionally only for buckets at the default
	 * ceiling. A reaped wide bucket loses its stored capacity, and a caller that
	 * names no limit would then be answered against the default rather than the
	 * ceiling the bucket was created with. Wide buckets are therefore left alone:
	 * there is one per trusted row, so they are not the growth this exists to
	 * bound.
	 *
	 * To be clear about what that buys and costs. `/check` is the only endpoint
	 * that names no limit, and nothing in `src/` calls it — so the divergence is
	 * unobservable today, and the skip is defending the invariant rather than a
	 * live consumer. The price is paid unconditionally: an immortal bucket class
	 * means the re-arm below always finds something, so a limiter that has served
	 * one trusted row wakes every `sweepIntervalMs` forever. That is one `list` of
	 * a single key per five minutes, and it is the deliberate trade — an argument
	 * that stops holding the moment somebody adds a `/check` caller is not one
	 * worth resting a limiter's correctness on.
	 *
	 * One page per alarm, resumed from a persisted cursor, so a pass covers the
	 * whole prefix rather than the first `sweepBatch` keys of it.
	 */
	async alarm(): Promise<void> {
		const now = Date.now();
		// Resume where the last alarm stopped. `list` has no implicit cursor, so
		// without one it returns the same lexicographic page every time: a first
		// page of live buckets both hides every key behind it from the sweep and
		// re-arms it at a second, forever.
		const cursor = await this.state.storage.get<string>(this.sweepCursorKey);
		const buckets = await this.state.storage.list<TokenBucket>({
			prefix: "bucket:",
			...(cursor === undefined ? {} : { startAfter: cursor }),
			limit: this.sweepBatch,
		});

		const stale: string[] = [];
		let lastKey: string | undefined;
		for (const [key, bucket] of buckets) {
			lastKey = key;
			const isDefaultCeiling = (bucket.capacity ?? this.maxTokens) === this.maxTokens;
			if (isDefaultCeiling && now - bucket.lastRefill >= this.idleTtlMs) {
				stale.push(key);
			}
		}

		for (let index = 0; index < stale.length; index += this.deleteChunk) {
			await this.state.storage.delete(stale.slice(index, index + this.deleteChunk));
		}

		// A full page means keys remain behind it: carry the cursor past it and
		// come back promptly, rather than draining a large backlog one five-minute
		// window at a time — or, without the cursor, never draining it at all.
		if (buckets.size === this.sweepBatch && lastKey !== undefined) {
			await this.state.storage.put(this.sweepCursorKey, lastKey);
			await this.state.storage.setAlarm(now + 1_000);
			return;
		}

		// A short page ends the pass; the next one starts from the beginning.
		await this.state.storage.delete(this.sweepCursorKey);

		// Re-arm only while buckets remain — asked of the whole object rather than
		// of this page, since a pass can end on a page that was entirely stale
		// while live buckets sit in the pages before it. An object with nothing
		// left stops waking itself, and `scheduleSweep` re-arms it on the next
		// consume. Note that a wide bucket is never reaped, so in practice only the
		// admin limiter and an unused signing limiter ever reach that quiescence.
		const remaining = await this.state.storage.list<TokenBucket>({ prefix: "bucket:", limit: 1 });
		if (remaining.size > 0) {
			await this.state.storage.setAlarm(now + this.sweepIntervalMs);
		}
	}
}
