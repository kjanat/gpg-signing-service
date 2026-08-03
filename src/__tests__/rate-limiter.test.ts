import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
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

			// Consume until the bucket actually reports empty rather than a fixed
			// count: the bucket refills at one token per 600ms, so a fixed loop that
			// runs slowly under load hands tokens back faster than it takes them and
			// the check below finds the bucket non-empty.
			let denied: Response | undefined;
			for (let i = 0; i < 500 && !denied; i++) {
				const consumed = await stub.fetch("http://localhost/consume?identity=exhausted-user");
				if (consumed.status === 429) {
					denied = consumed;
				}
			}
			expect(denied).toBeDefined();

			// Assert on the denial itself rather than a second round-trip: the loop
			// exits with a fraction of a token left, and the bucket refills at one
			// per 600ms, so a separate /check can be answered *after* enough time
			// has passed to hand that fraction back.
			const result = (await denied?.json()) as RateLimitResult;
			expect(result.allowed).toBe(false);
			expect(result.remaining).toBe(0);

			// /check has its own denied branch. The bucket sits just under one token
			// and refills at one per 600ms, so a stalled scheduler can hand it back
			// between calls — drain again rather than assuming a single round-trip
			// wins the race.
			let checked: RateLimitResult | undefined;
			for (let i = 0; i < 10; i++) {
				const response = await stub.fetch("http://localhost/check?identity=exhausted-user");
				expect(response.status).toBe(200);
				checked = (await response.json()) as RateLimitResult;
				if (!checked.allowed) {
					break;
				}
				await stub.fetch("http://localhost/consume?identity=exhausted-user");
			}
			expect(checked?.allowed).toBe(false);
			expect(checked?.remaining).toBe(0);
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

			let hitLimit = false;
			// Bounded well above the bucket size: refill runs at one token per 600ms,
			// so a loop that iterates slowly under load needs more turns than the
			// 100-token capacity to get ahead of it.
			for (let i = 0; i < 500; i++) {
				const res = await stub.fetch("http://localhost/consume?identity=test-user");
				if (res.status === 429) {
					hitLimit = true;
					break;
				}
			}

			expect(hitLimit).toBe(true);
		});

		it("should use default identity when not provided", async () => {
			const stub = getRateLimiter("consume-default");
			const response = await stub.fetch("http://localhost/consume");

			expect(response.status).toBe(200);
			const result = (await response.json()) as RateLimitResult;
			expect(result.allowed).toBe(true);
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
