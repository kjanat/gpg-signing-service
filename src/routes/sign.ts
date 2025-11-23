import { createRoute, z } from "@hono/zod-openapi";
import { createOpenAPIApp } from "~/lib/openapi";
import {
  ErrorResponseSchema,
  PublicKeyQuerySchema,
  RateLimitErrorSchema,
  RequestHeadersSchema,
} from "~/schemas";
import type {
  ErrorCode,
  Identity,
  RateLimitResult,
  StoredKey,
  ValidatedOIDCClaims,
} from "~/types";
import { createKeyId } from "~/types";
import { logAuditEvent } from "~/utils/audit";
import { fetchKeyStorage, fetchRateLimiter } from "~/utils/durable-objects";
import { scheduleBackgroundTask } from "~/utils/execution";
import { signCommitData } from "~/utils/signing";

const app = createOpenAPIApp();

const signRoute = createRoute({
  method: "post",
  path: "/",
  summary: "Sign commit data",
  description: "Sign git commit data using the stored GPG key",
  request: {
    body: {
      content: {
        "text/plain": {
          schema: z.string().min(1).openapi({
            example:
              "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147\nparent ...",
          }),
        },
      },
      required: true,
    },
    query: PublicKeyQuerySchema,
    headers: RequestHeadersSchema,
  },
  responses: {
    200: {
      content: {
        "text/plain": {
          schema: z.string().openapi({
            example: "-----BEGIN PGP SIGNATURE-----\n...",
          }),
        },
      },
      description: "PGP Signature",
    },
    400: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Bad Request",
    },
    404: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Key not found",
    },
    429: {
      content: {
        "application/json": {
          schema: RateLimitErrorSchema,
        },
      },
      description: "Rate limit exceeded",
    },
    500: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Internal Server Error",
    },
    503: {
      content: {
        "application/json": {
          schema: ErrorResponseSchema,
        },
      },
      description: "Service Unavailable",
    },
  },
});

app.openapi(signRoute, async (c) => {
  const { "X-Request-ID": requestIdHeader } = c.req.valid("header");
  const requestId = requestIdHeader || crypto.randomUUID();
  const claims = c.get("oidcClaims") as ValidatedOIDCClaims;
  const identity = c.get("identity") as Identity;

  // Validate request body early
  const commitData = await c.req.text();

  const bodySchema = z.string().min(1);
  const bodyResult = bodySchema.safeParse(commitData);

  if (!bodyResult.success) {
    return c.json(
      {
        error: "No commit data provided",
        code: "INVALID_REQUEST" as const satisfies ErrorCode,
        requestId,
      },
      400,
    );
  }

  // Get key ID from query param or use default
  const { keyId: keyIdQuery } = c.req.valid("query");
  const keyIdParam = keyIdQuery || c.env.KEY_ID;

  // Parallel execution: Rate limit + Key fetch (performance optimization ~15ms gain)
  // Security: Rate limit enforced BEFORE signing, parallel fetch is read-only
  let rateLimit: RateLimitResult;
  let storedKey: StoredKey;

  try {
    createKeyId(keyIdParam); // Validate key ID format (inside try so errors are caught)
    const [rateLimitResponse, keyResponse] = await Promise.all([
      fetchRateLimiter(c.env, identity),
      fetchKeyStorage(
        c.env,
        `/get-key?keyId=${encodeURIComponent(keyIdParam)}`,
      ),
    ]);

    // Process rate limit
    if (!rateLimitResponse.ok) {
      console.error("Rate limiter failed:", rateLimitResponse.status);
      return c.json(
        {
          error: "Service temporarily unavailable",
          code: "RATE_LIMIT_ERROR" as const satisfies ErrorCode,
          requestId,
        },
        503,
      );
    }

    rateLimit = (await rateLimitResponse.json()) as RateLimitResult;

    // Enforce rate limit BEFORE processing key
    if (!rateLimit.allowed) {
      return c.json(
        {
          error: "Rate limit exceeded",
          code: "RATE_LIMITED" as const satisfies ErrorCode,
          retryAfter: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
        },
        429,
      );
    }

    // Process key response
    if (!keyResponse.ok) {
      const error = (await keyResponse.json()) as { error: string };
      throw new Error(error.error || "Key not found");
    }

    storedKey = (await keyResponse.json()) as StoredKey;

    // Sign the commit data
    const result = await signCommitData(
      commitData,
      storedKey,
      c.env.KEY_PASSPHRASE,
    );

    // Log successful signing (non-blocking for performance)
    await scheduleBackgroundTask(
      c,
      requestId,
      logAuditEvent(c.env.AUDIT_DB, {
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
      }),
    );

    // Set rate limit headers
    c.header("X-RateLimit-Remaining", String(rateLimit.remaining));
    c.header("X-RateLimit-Reset", String(Math.ceil(rateLimit.resetAt / 1000)));
    c.header("X-Request-ID", requestId);

    return c.text(result.signature, 200);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Signing failed";

    // Check if this is a rate limiter error from the fetch phase
    if (message.includes("Rate limiter")) {
      console.error("Rate limiter critical failure:", error);
      return c.json(
        {
          error: "Service temporarily unavailable",
          code: "RATE_LIMIT_ERROR" as const satisfies ErrorCode,
          requestId,
        },
        503,
      );
    }

    const isKeyNotFound = message === "Key not found"
      || message.includes("not found");

    // Log failed signing attempt (non-blocking)
    await scheduleBackgroundTask(
      c,
      requestId,
      logAuditEvent(c.env.AUDIT_DB, {
        requestId,
        action: "sign",
        issuer: claims.iss,
        subject: claims.sub,
        keyId: keyIdParam,
        success: false,
        errorCode: isKeyNotFound ? "KEY_NOT_FOUND" : "SIGN_ERROR",
        metadata: JSON.stringify({ error: message }),
      }),
    );

    if (isKeyNotFound) {
      return c.json(
        {
          error: message,
          code: "KEY_NOT_FOUND" as const satisfies ErrorCode,
          requestId,
        },
        404,
      );
    }

    return c.json(
      {
        error: message,
        code: "SIGN_ERROR" as const satisfies ErrorCode,
        requestId,
      },
      500,
    );
  }
});

export default app;
