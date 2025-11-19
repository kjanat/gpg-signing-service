import { Hono } from "hono";
import type {
  Env,
  Variables,
  StoredKey,
  ValidatedOIDCClaims,
  RateLimitResult,
  Identity,
  ErrorCode,
} from "../types";
import { createKeyId } from "../types";
import { signCommitData } from "../utils/signing";
import { logAuditEvent } from "../utils/audit";

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.post("/", async (c) => {
  const requestId = c.req.header("X-Request-ID") || crypto.randomUUID();
  const claims = c.get("oidcClaims") as ValidatedOIDCClaims;
  const identity = c.get("identity") as Identity;

  // Check rate limit - FAIL CLOSED if rate limiter unavailable
  let rateLimit: RateLimitResult;
  try {
    const rateLimiterId = c.env.RATE_LIMITER.idFromName("global");
    const rateLimiter = c.env.RATE_LIMITER.get(rateLimiterId);

    const rateLimitResponse = await rateLimiter.fetch(
      new Request(
        `http://internal/consume?identity=${encodeURIComponent(identity)}`,
      ),
    );

    if (!rateLimitResponse.ok) {
      throw new Error(`Rate limiter returned ${rateLimitResponse.status}`);
    }

    rateLimit = (await rateLimitResponse.json()) as RateLimitResult;
  } catch (error) {
    console.error("Rate limiter failed:", error);
    // FAIL CLOSED - deny request when rate limiting is unavailable
    return c.json(
      {
        error: "Service temporarily unavailable",
        code: "RATE_LIMIT_ERROR" satisfies ErrorCode,
        requestId,
      },
      503,
    );
  }

  if (!rateLimit.allowed) {
    return c.json(
      {
        error: "Rate limit exceeded",
        code: "RATE_LIMITED" satisfies ErrorCode,
        retryAfter: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
      },
      429,
    );
  }

  // Get commit data from request body
  const commitData = await c.req.text();

  if (!commitData) {
    return c.json(
      {
        error: "No commit data provided",
        code: "INVALID_REQUEST" satisfies ErrorCode,
        requestId,
      },
      400,
    );
  }

  // Get key ID from query param or use default
  const keyIdParam = c.req.query("keyId") || c.env.KEY_ID;
  createKeyId(keyIdParam); // Validate key ID format

  try {
    // Fetch private key from Durable Object
    const keyStorageId = c.env.KEY_STORAGE.idFromName("global");
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

    const keyResponse = await keyStorage.fetch(
      new Request(
        `http://internal/get-key?keyId=${encodeURIComponent(keyIdParam)}`,
      ),
    );

    if (!keyResponse.ok) {
      const error = (await keyResponse.json()) as { error: string };
      throw new Error(error.error || "Key not found");
    }

    const storedKey = (await keyResponse.json()) as StoredKey;

    // Sign the commit data
    const result = await signCommitData(
      commitData,
      storedKey,
      c.env.KEY_PASSPHRASE,
    );

    // Log successful signing
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: "sign",
      issuer: claims.iss,
      subject: claims.sub,
      keyId: keyIdParam,
      success: true,
      metadata: JSON.stringify({
        repository: claims.repository || claims.project_path,
        dataLength: commitData.length,
      }),
    });

    // Set rate limit headers
    c.header("X-RateLimit-Remaining", String(rateLimit.remaining));
    c.header("X-RateLimit-Reset", String(Math.ceil(rateLimit.resetAt / 1000)));
    c.header("X-Request-ID", requestId);

    return c.text(result.signature, 200);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Signing failed";

    // Log failed signing attempt
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: "sign",
      issuer: claims.iss,
      subject: claims.sub,
      keyId: keyIdParam,
      success: false,
      errorCode: "SIGN_ERROR",
      metadata: JSON.stringify({ error: message }),
    });

    return c.json(
      { error: message, code: "SIGN_ERROR" satisfies ErrorCode, requestId },
      500,
    );
  }
});

export default app;
