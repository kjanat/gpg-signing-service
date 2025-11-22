import { createRoute, z } from "@hono/zod-openapi";
import { createOpenAPIApp } from "~/lib/openapi";
import type {
  ErrorCode,
  Identity,
  RateLimitResult,
  StoredKey,
  ValidatedOIDCClaims,
} from "~/types";
import { createKeyId } from "~/types";
import { logAuditEvent } from "~/utils/audit";
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
          schema: z.string().openapi({
            example:
              "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147\nparent ...",
          }),
        },
      },
      required: true,
    },
    query: z.object({
      keyId: z.string().optional().openapi({
        param: {
          name: "keyId",
          in: "query",
        },
        example: "A1B2C3D4E5F6G7H8",
      }),
    }),
    headers: z.object({
      "X-Request-ID": z.string().optional().openapi({
        param: {
          name: "X-Request-ID",
          in: "header",
        },
        example: "123e4567-e89b-12d3-a456-426614174000",
      }),
    }),
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
          schema: z.object({
            error: z.string(),
            code: z.string(),
            requestId: z.string().optional(),
          }),
        },
      },
      description: "Bad Request",
    },
    404: {
      content: {
        "application/json": {
          schema: z.object({
            error: z.string(),
            code: z.string(),
          }),
        },
      },
      description: "Key not found",
    },
    429: {
      content: {
        "application/json": {
          schema: z.object({
            error: z.string(),
            code: z.string(),
            retryAfter: z.number(),
          }),
        },
      },
      description: "Rate limit exceeded",
    },
    500: {
      content: {
        "application/json": {
          schema: z.object({
            error: z.string(),
            code: z.string(),
            requestId: z.string().optional(),
          }),
        },
      },
      description: "Internal Server Error",
    },
    503: {
      content: {
        "application/json": {
          schema: z.object({
            error: z.string(),
            code: z.string(),
            requestId: z.string().optional(),
          }),
        },
      },
      description: "Service Unavailable",
    },
  },
});

app.openapi(signRoute, async (c) => {
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
    const isKeyNotFound = message === "Key not found"
      || message.includes("not found");

    // Log failed signing attempt
    await logAuditEvent(c.env.AUDIT_DB, {
      requestId,
      action: "sign",
      issuer: claims.iss,
      subject: claims.sub,
      keyId: keyIdParam,
      success: false,
      errorCode: isKeyNotFound ? "KEY_NOT_FOUND" : "SIGN_ERROR",
      metadata: JSON.stringify({ error: message }),
    });

    if (isKeyNotFound) {
      return c.json(
        {
          error: message,
          code: "KEY_NOT_FOUND" satisfies ErrorCode,
          requestId,
        },
        404,
      );
    }

    return c.json(
      { error: message, code: "SIGN_ERROR" satisfies ErrorCode, requestId },
      500,
    );
  }
});

export default app;
