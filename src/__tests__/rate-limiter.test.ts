// These imports are provided by @cloudflare/vitest-pool-workers
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck - cloudflare:test types are provided at runtime by vitest-pool-workers
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { RateLimitResult } from "~/types";

describe("RateLimiter Durable Object", () => {
  // Get a fresh DO stub for each test
  function getRateLimiter(name = "test") {
    const id = env.RATE_LIMITER.idFromName(name);
    return env.RATE_LIMITER.get(id);
  }

  describe("/check endpoint", () => {
    it("should return allowed for new identity", async () => {
      const stub = getRateLimiter("check-new");
      const response = await stub.fetch(
        "http://localhost/check?identity=new-user",
      );

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
  });

  describe("/consume endpoint", () => {
    it("should consume token and return remaining", async () => {
      const stub = getRateLimiter("consume-basic");
      const response = await stub.fetch(
        "http://localhost/consume?identity=user1",
      );

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
      let response = await stub.fetch(
        "http://localhost/consume?identity=user2",
      );
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

      // Exhaust all tokens
      for (let i = 0; i < 100; i++) {
        await stub.fetch("http://localhost/consume?identity=exhausted");
      }

      // Next request should be denied
      const response = await stub.fetch(
        "http://localhost/consume?identity=exhausted",
      );

      expect(response.status).toBe(429);
      expect(response.headers.get("Retry-After")).toBeTruthy();

      const result = (await response.json()) as RateLimitResult;
      expect(result.allowed).toBe(false);
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
      let response = await stub.fetch(
        "http://localhost/check?identity=reset-user",
      );
      let result = (await response.json()) as RateLimitResult;
      expect(result.allowed && result.remaining).toBeLessThan(100);

      // Reset
      response = await stub.fetch(
        "http://localhost/reset?identity=reset-user",
        { method: "POST" },
      );
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
      const response = await stub.fetch(
        "http://localhost/reset?identity=test",
        { method: "GET" },
      );

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
