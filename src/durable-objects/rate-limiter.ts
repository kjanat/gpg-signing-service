import type { RateLimitResult } from "~/types";
import { createRateLimitAllowed, createRateLimitDenied } from "~/types";

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

export class RateLimiter implements DurableObject {
  private state: DurableObjectState;

  // Rate limit configuration
  private readonly maxTokens = 100; // Max requests per window
  private readonly refillRate = 100; // Tokens per minute
  private readonly windowMs = 60_000; // 1 minute window

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case "/check":
          return this.checkLimit(url.searchParams.get("identity") || "default");

        case "/consume":
          return this.consumeToken(
            url.searchParams.get("identity") || "default",
          );

        case "/reset":
          if (request.method !== "POST") {
            return new Response("Method not allowed", { status: 405 });
          }
          return this.resetLimit(url.searchParams.get("identity") || "");

        default:
          return new Response("Not found", { status: 404 });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return new Response(JSON.stringify({ error: message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  private async checkLimit(identity: string): Promise<Response> {
    const bucket = await this.getBucket(identity);
    const resetAt = bucket.lastRefill + this.windowMs;

    const result: RateLimitResult =
      bucket.tokens > 0 ?
        createRateLimitAllowed(Math.floor(bucket.tokens), resetAt)
      : createRateLimitDenied(resetAt);

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  private async consumeToken(identity: string): Promise<Response> {
    const bucket = await this.getBucket(identity);
    const resetAt = bucket.lastRefill + this.windowMs;

    if (bucket.tokens < 1) {
      const result: RateLimitResult = createRateLimitDenied(resetAt);

      return new Response(JSON.stringify(result), {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": String(Math.ceil((resetAt - Date.now()) / 1000)),
        },
      });
    }

    // Consume one token
    bucket.tokens -= 1;
    await this.state.storage.put(`bucket:${identity}`, bucket);

    const result: RateLimitResult = createRateLimitAllowed(
      Math.floor(bucket.tokens),
      resetAt,
    );

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  private async resetLimit(identity: string): Promise<Response> {
    if (!identity) {
      return new Response(JSON.stringify({ error: "Identity required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    await this.state.storage.delete(`bucket:${identity}`);

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  private async getBucket(identity: string): Promise<TokenBucket> {
    const now = Date.now();
    let bucket = await this.state.storage.get<TokenBucket>(
      `bucket:${identity}`,
    );

    if (!bucket) {
      bucket = { tokens: this.maxTokens, lastRefill: now };
    } else {
      // Refill tokens based on time elapsed
      const elapsed = now - bucket.lastRefill;
      const tokensToAdd = (elapsed / this.windowMs) * this.refillRate;

      bucket.tokens = Math.min(this.maxTokens, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
    }

    await this.state.storage.put(`bucket:${identity}`, bucket);
    return bucket;
  }
}
