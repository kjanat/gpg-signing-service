import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import type { RateLimiter } from "#durable-objects/rate-limiter";
import type { RateLimitResult } from "#types";

/**
 * Cold-starting a Durable Object costs more than vitest's 10s default hook
 * budget when the rest of the suite is competing for the same worker, which
 * showed up as this whole file erroring with zero failed tests.
 */
const WARMUP_TIMEOUT_MS = 30_000;

describe("RateLimiter Durable Object", () => {
	// Get a fresh DO stub for each test
	function getRateLimiter(name = "test") {
		const id = env.RATE_LIMITER.idFromName(name);
		return env.RATE_LIMITER.get(id);
	}

	beforeAll(async () => {
		await getRateLimiter("warmup").fetch("http://localhost/check?identity=warmup");
	}, WARMUP_TIMEOUT_MS);

	describe("per-bucket capacity", () => {
		it("applies a lowered ceiling without waiting for the bucket to drain", async () => {
			// Nothing reaps `bucket:` keys, so a capacity pinned at creation would
			// outlive every later change to the route's ceiling — the tunable would
			// silently stop tuning for exactly the rows already in use.
			const stub = getRateLimiter("capacity-lowered");
			await stub.fetch("http://localhost/consume?identity=lowered&limit=1000");

			const lowered = (await (
				await stub.fetch("http://localhost/consume?identity=lowered&limit=10")
			).json()) as RateLimitResult;

			expect(lowered.allowed).toBe(true);
			if (lowered.allowed) {
				expect(lowered.remaining).toBeLessThanOrEqual(10);
			}
		});

		it("refills a widened bucket past its former ceiling", async () => {
			// Widening grants no tokens outright; what it changes is the ceiling and
			// the refill rate. A bucket held at 10 can never pass 10 however long it
			// waits, so crossing it is the proof the new capacity took.
			const stub = getRateLimiter("capacity-widened");
			await stub.fetch("http://localhost/consume?identity=widened&limit=10");
			await stub.fetch("http://localhost/consume?identity=widened&limit=1000");

			// At 1000/min this is ~6 tokens; at the former ceiling, ~0.07. Waiting
			// longer under load only widens the gap, so the margin is one-sided.
			await new Promise((resolve) => setTimeout(resolve, 400));

			const widened = (await (
				await stub.fetch("http://localhost/consume?identity=widened&limit=1000")
			).json()) as RateLimitResult;

			expect(widened.allowed).toBe(true);
			if (widened.allowed) {
				expect(widened.remaining).toBeGreaterThan(10);
			}
		});

		it("keeps a wide bucket's ceiling when the caller names no limit", async () => {
			// `/check` names no limit; it must not narrow a bucket it only reads.
			const stub = getRateLimiter("capacity-unnamed");
			await stub.fetch("http://localhost/consume?identity=unnamed&limit=1000");

			const checked = (await (await stub.fetch("http://localhost/check?identity=unnamed")).json()) as RateLimitResult;

			expect(checked.allowed).toBe(true);
			if (checked.allowed) {
				expect(checked.remaining).toBeGreaterThan(900);
			}
		});

		it("scales the retry hint to the bucket's capacity, not the window", async () => {
			// Refill is proportional to capacity, so a wide bucket repays one token in
			// a fraction of a window. Reporting the window told a refused caller to
			// wait 60s over 60ms of debt — and on the row bucket that hint idles every
			// sibling under the trusted row, not just the caller that spent it.
			const stub = getRateLimiter("retry-hint");
			// Seeded and spent inside one entry into the object, against the instance
			// rather than through the stub. A bucket seeded empty at `now` refills one
			// token per `windowMs / capacity` — 60ms at a ceiling of 1000 — so a
			// stub round trip that loses a scheduling slice between the `put` and the
			// `consume` hands the caller a token and answers 200. Calling the instance
			// closes that window to the microseconds it takes to await a `put`, which
			// is the difference between a test of the hint and a race against the
			// refill. The denial path performs no write, so the seeded state is what
			// the request sees either way.
			//
			// Bodies are read inside the callback too: a Response created in one
			// Durable Object's context cannot be consumed outside it.
			const consume = async (instance: RateLimiter, query: string) => {
				const response = await instance.fetch(new Request(`http://localhost/consume?${query}`));
				return { status: response.status, result: (await response.json()) as RateLimitResult };
			};

			const [wide, narrow] = await runInDurableObject(stub, async (instance, state) => {
				await state.storage.put("bucket:wide", { tokens: 0, lastRefill: Date.now(), capacity: 1000 });
				await state.storage.put("bucket:narrow", { tokens: 0, lastRefill: Date.now(), capacity: 100 });

				return Promise.all([consume(instance, "identity=wide&limit=1000"), consume(instance, "identity=narrow")]);
			});

			expect(wide.status).toBe(429);
			expect(narrow.status).toBe(429);

			// One token against a ceiling of 1000 is ~60ms; against 100, ~600ms.
			// Either way, not the 60s the window would have reported.
			expect(wide.result.resetAt - Date.now()).toBeLessThan(500);
			expect(narrow.result.resetAt - Date.now()).toBeGreaterThan(wide.result.resetAt - Date.now());
			expect(narrow.result.resetAt - Date.now()).toBeLessThan(5_000);
		});

		it("falls back to the default for a malformed limit", async () => {
			const stub = getRateLimiter("capacity-malformed");
			const response = await stub.fetch("http://localhost/consume?identity=malformed&limit=not-a-number");

			const result = (await response.json()) as RateLimitResult;
			expect(result.allowed).toBe(true);
			if (result.allowed) {
				expect(result.remaining).toBe(99);
			}
		});
	});

	describe("/check endpoint", () => {
		it("should return allowed for new identity", async () => {
			const stub = getRateLimiter("check-new");
			const response = await stub.fetch("http://localhost/check?identity=new-user");

			expect(response.status).toBe(200);

			const result = (await response.json()) as RateLimitResult;
			expect(result.allowed).toBe(true);
			if (result.allowed) {
				expect(result.remaining).toBe(100); // maxTokens
				expect(result.resetAt).toBeGreaterThan(Date.now());
			}
		});

		it("should use default identity when not provided", async () => {
			const stub = getRateLimiter("check-default");
			const response = await stub.fetch("http://localhost/check");

			expect(response.status).toBe(200);
			const result = (await response.json()) as RateLimitResult;
			expect(result.allowed).toBe(true);
		});

		it("should return denied when tokens are exhausted", async () => {
			const stub = getRateLimiter("check-exhausted");

			// A capacity of one drains in a single call, so neither the drain nor the
			// `/check` below is racing the refill. Draining down from 100 needed a
			// loop bounded at 500 sequential round-trips, and a run slow enough to
			// need them was a run slow enough to blow the 5s test timeout.
			await stub.fetch("http://localhost/consume?identity=exhausted-user&limit=1");
			const denied = await stub.fetch("http://localhost/consume?identity=exhausted-user&limit=1");

			const result = (await denied.json()) as RateLimitResult;
			expect(denied.status).toBe(429);
			expect(result.allowed).toBe(false);
			expect(result.remaining).toBe(0);

			// `/check` has its own denied branch, and at a capacity of one the bucket
			// needs a full window to hand a token back.
			const response = await stub.fetch("http://localhost/check?identity=exhausted-user");
			expect(response.status).toBe(200);
			const checked = (await response.json()) as RateLimitResult;
			expect(checked.allowed).toBe(false);
			expect(checked.remaining).toBe(0);
		});
	});

	describe("/consume endpoint", () => {
		it("should consume token and return remaining", async () => {
			const stub = getRateLimiter("consume-basic");
			const response = await stub.fetch("http://localhost/consume?identity=user1");

			expect(response.status).toBe(200);

			const result = (await response.json()) as RateLimitResult;
			expect(result.allowed).toBe(true);
			if (result.allowed) {
				expect(result.remaining).toBe(99); // 100 - 1
			}
		});

		it("should decrement tokens with multiple consumes", async () => {
			const stub = getRateLimiter("consume-multiple");

			// First consume
			let response = await stub.fetch("http://localhost/consume?identity=user2");
			let result = (await response.json()) as RateLimitResult;
			expect(result.allowed && result.remaining).toBe(99);

			// Second consume
			response = await stub.fetch("http://localhost/consume?identity=user2");
			result = (await response.json()) as RateLimitResult;
			expect(result.allowed && result.remaining).toBe(98);

			// Third consume
			response = await stub.fetch("http://localhost/consume?identity=user2");
			result = (await response.json()) as RateLimitResult;
			expect(result.allowed && result.remaining).toBe(97);
		});

		it("should return 429 when tokens exhausted", async () => {
			const stub = getRateLimiter("consume-exhausted");

			// Drained by giving the bucket a capacity of one rather than by racing
			// the refill down from 100. The loop this replaces cost up to 500
			// sequential round-trips into a single-threaded Durable Object, which
			// overran vitest's 5s default under CI load — a timeout that reported as
			// the whole file erroring rather than as this assertion.
			await stub.fetch("http://localhost/consume?identity=test-user&limit=1");
			const denied = await stub.fetch("http://localhost/consume?identity=test-user&limit=1");

			expect(denied.status).toBe(429);
		});

		it("answers its own 429 with a whole positive Retry-After", async () => {
			// The one header this object writes for itself. Nothing outside the
			// Durable Object reads it — both middlewares rebuild the refusal from the
			// body — so it was the one refusal artefact with no test at all: zeroing
			// it, deleting it, or emitting the raw millisecond debt all passed the
			// suite. It shares `retryAfterSeconds` with the body's `retryAfter` as of
			// this change, and a shared owner is only as safe as the sites that
			// notice when it stops being shared.
			const stub = getRateLimiter("retry-after-header");

			// Drained the same way the test above is: a ceiling of one, so the debt
			// is the whole window rather than a race against the refill.
			await stub.fetch("http://localhost/consume?identity=header&limit=1");
			const denied = await stub.fetch("http://localhost/consume?identity=header&limit=1");

			expect(denied.status).toBe(429);

			const retryAfter = Number(denied.headers.get("Retry-After"));
			// Whole seconds, per RFC 9110 — and never a `0`, which reads to a client
			// as "immediately", the one answer a refusal must not give.
			expect(Number.isInteger(retryAfter)).toBe(true);
			expect(retryAfter).toBeGreaterThan(0);
			// Bounded by the window: milliseconds here would be 60000, which a client
			// would honour as sixteen hours.
			expect(retryAfter).toBeLessThanOrEqual(60);
		});

		it("should use default identity when not provided", async () => {
			const stub = getRateLimiter("consume-default");
			const response = await stub.fetch("http://localhost/consume");

			expect(response.status).toBe(200);
			const result = (await response.json()) as RateLimitResult;
			expect(result.allowed).toBe(true);
		});
	});

	describe("bucket reaping", () => {
		/** Move a bucket's clock back past a full window without waiting one out. */
		async function backdate(state: DurableObjectState, key: string) {
			const bucket = await state.storage.get<{ tokens: number; lastRefill: number }>(key);
			expect(bucket).toBeDefined();
			await state.storage.put(key, { ...bucket, lastRefill: Date.now() - 120_000 });
		}

		it("persists no key for a bucket nobody has drawn down", async () => {
			// `/check` used to mint a row per identity it was asked about, which on
			// the admin limiter is one row per source IP, before any credential.
			const stub = getRateLimiter("reap-read-only");
			await stub.fetch("http://localhost/check?identity=untouched");

			await runInDurableObject(stub, async (_instance, state) => {
				expect(await state.storage.get("bucket:untouched")).toBeUndefined();
			});
		});

		it("reaps a bucket that has refilled to capacity and keeps a live one", async () => {
			const stub = getRateLimiter("reap-sweep");
			await stub.fetch("http://localhost/consume?identity=idle");
			await stub.fetch("http://localhost/consume?identity=busy");

			await runInDurableObject(stub, async (instance, state) => {
				await backdate(state, "bucket:idle");
				await (instance as RateLimiter).alarm();

				// Not a reset: a missing bucket is created full, which is what an idle
				// one has refilled to, so the two answer identically.
				expect(await state.storage.get("bucket:idle")).toBeUndefined();
				expect(await state.storage.get("bucket:busy")).toBeDefined();
				// A live bucket remains, so the reaper stays armed for it.
				expect(await state.storage.getAlarm()).not.toBeNull();
			});
		});

		it("stops re-arming once nothing is left to reap", async () => {
			// Otherwise an object that has gone quiet wakes itself forever.
			const stub = getRateLimiter("reap-quiesce");
			await stub.fetch("http://localhost/consume?identity=lonely");

			await runInDurableObject(stub, async (instance, state) => {
				await backdate(state, "bucket:lonely");
				await state.storage.deleteAlarm();
				await (instance as RateLimiter).alarm();

				expect(await state.storage.get("bucket:lonely")).toBeUndefined();
				expect(await state.storage.getAlarm()).toBeNull();
			});
		});

		it("sweeps past a full page instead of re-reading it", async () => {
			// `list` has no implicit cursor. A first page of live buckets used to
			// hide every key behind it from the sweep *and* re-arm the alarm at one
			// second, so the object woke every second forever and reaped nothing —
			// on the one Durable Object that gates every signature.
			const stub = getRateLimiter("reap-paging");
			await stub.fetch("http://localhost/consume?identity=seed");

			await runInDurableObject(stub, async (instance, state) => {
				const now = Date.now();
				// A full page (`sweepBatch`) of live buckets, all sorting before the
				// one stale bucket behind them.
				const live = Array.from({ length: 1000 }, (_, index) => [
					`bucket:a${String(index).padStart(5, "0")}`,
					{ tokens: 5, lastRefill: now, capacity: 100 },
				]);
				for (let index = 0; index < live.length; index += 128) {
					await state.storage.put(Object.fromEntries(live.slice(index, index + 128)));
				}
				await state.storage.put("bucket:zzz-idle", { tokens: 100, lastRefill: now - 120_000, capacity: 100 });
				await state.storage.delete("bucket:seed");

				// First alarm consumes the full page and carries a cursor past it.
				await (instance as RateLimiter).alarm();
				expect(await state.storage.get("sweep:cursor")).toBeDefined();

				// Second alarm resumes behind the cursor and reaps what the first
				// could not see, then ends the pass.
				await (instance as RateLimiter).alarm();
				expect(await state.storage.get("bucket:zzz-idle")).toBeUndefined();
				expect(await state.storage.get("sweep:cursor")).toBeUndefined();
				// The live page is untouched, and still holds the reaper armed.
				expect(await state.storage.get("bucket:a00000")).toBeDefined();
				expect(await state.storage.getAlarm()).not.toBeNull();
			});
		}, 60_000);

		it("leaves a wide bucket alone, since reaping it would lose its ceiling", async () => {
			// The safety argument is that a reaped bucket and an idle one answer
			// identically. That holds only at the default ceiling: reaping a wide
			// bucket drops its stored capacity, and `/check` names no limit, so it
			// would then be answered against 100 rather than the 1000 it was created
			// with. There is one wide bucket per trusted row, so they are not the
			// growth being bounded and skipping them costs nothing.
			const stub = getRateLimiter("reap-wide");
			await stub.fetch("http://localhost/consume?identity=wide-row&limit=1000");

			await runInDurableObject(stub, async (instance, state) => {
				await backdate(state, "bucket:wide-row");
				await (instance as RateLimiter).alarm();
				expect(await state.storage.get("bucket:wide-row")).toBeDefined();
			});

			const checked = (await (await stub.fetch("http://localhost/check?identity=wide-row")).json()) as RateLimitResult;
			expect(checked.allowed && checked.remaining).toBeGreaterThan(900);
		});

		it("answers a reaped identity exactly as it answers a fresh one", async () => {
			const stub = getRateLimiter("reap-equivalence");
			await stub.fetch("http://localhost/consume?identity=recycled");

			await runInDurableObject(stub, async (instance, state) => {
				await backdate(state, "bucket:recycled");
				await (instance as RateLimiter).alarm();
			});

			const recycled = (await (
				await stub.fetch("http://localhost/consume?identity=recycled")
			).json()) as RateLimitResult;
			const fresh = (await (
				await stub.fetch("http://localhost/consume?identity=never-seen")
			).json()) as RateLimitResult;

			expect(recycled).toStrictEqual(expect.objectContaining({ allowed: true }));
			expect(recycled.allowed && recycled.remaining).toBe(fresh.allowed && fresh.remaining);
		});
	});

	describe("/reset endpoint", () => {
		it("should reset limit for identity", async () => {
			const stub = getRateLimiter("reset-test");

			// Consume some tokens
			await stub.fetch("http://localhost/consume?identity=reset-user");
			await stub.fetch("http://localhost/consume?identity=reset-user");
			await stub.fetch("http://localhost/consume?identity=reset-user");

			// Verify tokens consumed
			let response = await stub.fetch("http://localhost/check?identity=reset-user");
			let result = (await response.json()) as RateLimitResult;
			expect(result.allowed && result.remaining).toBeLessThan(100);

			// Reset
			response = await stub.fetch("http://localhost/reset?identity=reset-user", { method: "POST" });
			expect(response.status).toBe(200);

			const resetResult = (await response.json()) as { success: boolean };
			expect(resetResult.success).toBe(true);

			// Check tokens are back to max
			response = await stub.fetch("http://localhost/check?identity=reset-user");
			result = (await response.json()) as RateLimitResult;
			expect(result.allowed && result.remaining).toBe(100);
		});

		it("should return 400 when identity not provided", async () => {
			const stub = getRateLimiter("reset-no-id");
			const response = await stub.fetch("http://localhost/reset", {
				method: "POST",
			});

			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: string };
			expect(body.error).toBe("Identity required");
		});

		it("should return 405 for non-POST requests", async () => {
			const stub = getRateLimiter("reset-method");
			const response = await stub.fetch("http://localhost/reset?identity=test", { method: "GET" });

			expect(response.status).toBe(405);
		});
	});

	describe("error handling", () => {
		it("should return 404 for unknown paths", async () => {
			const stub = getRateLimiter("unknown-path");
			const response = await stub.fetch("http://localhost/unknown");

			expect(response.status).toBe(404);
		});
	});
});
