/**
 * @fileoverview Token bucket rate limiter implemented as a Durable Object.
 *
 * This module implements a token bucket algorithm for rate limiting API requests.
 * Each OIDC identity gets its own rate limit bucket with configurable capacity
 * and refill rate.
 *
 * Algorithm overview:
 * - Each identity starts with a full bucket of tokens (default: 100)
 * - Each request consumes one token from the bucket
 * - Tokens are refilled over time at a constant rate (default: 100/minute)
 * - When bucket is empty, requests are rejected with HTTP 429
 *
 * Storage characteristics:
 * - Strong consistency ensures accurate rate limiting across edge
 * - Per-identity isolation prevents cross-contamination
 *
 * @see {@link https://en.wikipedia.org/wiki/Token_bucket} - Token bucket algorithm
 *
 * @module durable-objects/rate-limiter
 */

import type { RateLimitResult } from "~/types";
import {
  createRateLimitAllowed,
  createRateLimitDenied,
  HTTP,
  MediaType,
} from "~/types";

/**
 * Token bucket state stored in Durable Object.
 */
interface TokenBucket {
  /** Current number of tokens in the bucket (can be fractional) */
  tokens: number;
  /** Timestamp of last refill operation (ms since epoch) */
  lastRefill: number;
}

/**
 * Durable Object class implementing token bucket rate limiting.
 *
 * Provides HTTP endpoints for rate limit operations:
 * - `GET /check?identity=X` - Check rate limit without consuming
 * - `GET /consume?identity=X` - Check and consume a token
 * - `POST /reset?identity=X` - Reset rate limit for identity
 *
 * @example
 * ```typescript
 * // Consume a token for rate limiting
 * const response = await env.RATE_LIMITER.get(id).fetch('/consume?identity=user123');
 * const result = await response.json();
 * if (!result.allowed) {
 *   // Rate limited - wait until result.resetAt
 * }
 * ```
 */
export class RateLimiter implements DurableObject {
  private state: DurableObjectState;

  /** Maximum tokens per bucket (requests per window) */
  private readonly maxTokens = 100;
  /** Token refill rate (tokens added per minute) */
  private readonly refillRate = 100;
  /** Rate limit window duration in milliseconds */
  private readonly windowMs = 60_000;

  /**
   * Creates a new RateLimiter Durable Object instance.
   *
   * @param state - Durable Object state provided by Cloudflare runtime
   */
  constructor(state: DurableObjectState) {
    this.state = state;
  }

  /**
   * Handles incoming HTTP requests to the Durable Object.
   *
   * @param request - Incoming HTTP request
   * @returns Response with rate limit result or error
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case "/check":
          return await this.checkLimit(
            url.searchParams.get("identity") || "default",
          );

        case "/consume":
          return await this.consumeToken(
            url.searchParams.get("identity") || "default",
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
   * Checks rate limit status without consuming a token.
   *
   * @param identity - Unique identifier for the rate limit bucket
   * @returns Response with rate limit status
   */
  private async checkLimit(identity: string): Promise<Response> {
    const bucket = await this.getBucket(identity);
    const resetAt = bucket.lastRefill + this.windowMs;

    const result: RateLimitResult = bucket.tokens >= 1
      ? createRateLimitAllowed(Math.floor(bucket.tokens), resetAt)
      : createRateLimitDenied(resetAt);

    return new Response(JSON.stringify(result), {
      status: HTTP.OK,
      headers: { "Content-Type": MediaType.ApplicationJson },
    });
  }

  /**
   * Consumes a token from the rate limit bucket.
   *
   * If tokens are available, decrements the count and returns allowed status.
   * If bucket is empty, returns denied status with retry time.
   *
   * @param identity - Unique identifier for the rate limit bucket
   * @returns Response with rate limit result (HTTP 200 if allowed, 429 if denied)
   */
  private async consumeToken(identity: string): Promise<Response> {
    const bucket = await this.getBucket(identity);
    const resetAt = bucket.lastRefill + this.windowMs;

    if (bucket.tokens < 1) {
      const result: RateLimitResult = createRateLimitDenied(resetAt);

      return new Response(JSON.stringify(result), {
        status: HTTP.TooManyRequests,
        headers: {
          "Content-Type": MediaType.ApplicationJson,
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
      status: HTTP.OK,
      headers: { "Content-Type": MediaType.ApplicationJson },
    });
  }

  /**
   * Resets rate limit for a specific identity (admin operation).
   *
   * @param identity - Unique identifier for the rate limit bucket to reset
   * @returns Response with success status
   */
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

  /**
   * Gets or creates a token bucket for an identity.
   *
   * If bucket doesn't exist, creates one with full tokens.
   * If bucket exists, refills tokens based on elapsed time.
   *
   * Refill formula: `tokens += (elapsed / windowMs) * refillRate`
   * Tokens are capped at maxTokens to prevent unbounded accumulation.
   *
   * @param identity - Unique identifier for the rate limit bucket
   * @returns Token bucket with current state
   */
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
