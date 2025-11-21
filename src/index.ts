import { swaggerUI } from "@hono/swagger-ui";
import { createRoute, z } from "@hono/zod-openapi";
import { logger } from "hono/logger";
import * as openpgp from "openpgp";
import { createOpenAPIApp, openApiConfig } from "~/lib/openapi";
import { adminAuth, oidcAuth } from "~/middleware/oidc";
import {
  adminRateLimit,
  productionCors,
  securityHeaders,
} from "~/middleware/security";
import adminRoutes from "~/routes/admin";
import signRoutes from "~/routes/sign";
import type { HealthResponse } from "~/types";

// Export Durable Objects
export { KeyStorage } from "~/durable-objects/key-storage";
export { RateLimiter } from "~/durable-objects/rate-limiter";

const app = createOpenAPIApp();

// Global middleware
app.use("*", logger());
app.use("*", securityHeaders);
app.use("*", productionCors);

// Health check endpoint (no auth)
const healthRoute = createRoute({
  method: "get",
  path: "/health",
  summary: "Health check",
  description: "Check the health of the service",
  responses: {
    200: {
      content: {
        "application/json": {
          schema: z.object({
            status: z.string(),
            timestamp: z.string(),
            version: z.string(),
            checks: z.object({
              keyStorage: z.boolean(),
              database: z.boolean(),
            }),
          }),
        },
      },
      description: "Service is healthy",
    },
    503: {
      content: {
        "application/json": {
          schema: z.object({
            status: z.string(),
            timestamp: z.string(),
            version: z.string(),
            checks: z.object({
              keyStorage: z.boolean(),
              database: z.boolean(),
            }),
          }),
        },
      },
      description: "Service is degraded",
    },
  },
});

app.openapi(healthRoute, async (c) => {
  const checks = { keyStorage: false, database: false };

  try {
    // Check key storage
    const keyStorageId = c.env.KEY_STORAGE.idFromName("global");
    const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);
    const keyHealthResponse = await keyStorage.fetch(
      new Request("http://internal/health"),
    );
    checks.keyStorage = keyHealthResponse.ok;
  } catch (error) {
    console.error("Key storage health check failed:", error);
    checks.keyStorage = false;
  }

  try {
    // Check database
    const result = await c.env.AUDIT_DB.prepare("SELECT 1").first();
    checks.database = result !== null;
  } catch (error) {
    console.error("Database health check failed:", error);
    checks.database = false;
  }

  const allHealthy = checks.keyStorage && checks.database;

  const response: HealthResponse = {
    status: allHealthy ? "healthy" : "degraded",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
    checks,
  };

  return c.json(response, allHealthy ? 200 : 503);
});

// Public key endpoint (no auth) - for git to verify signatures
const publicKeyRoute = createRoute({
  method: "get",
  path: "/public-key",
  summary: "Get public key",
  description: "Get the public key for signature verification",
  request: {
    query: z.object({
      keyId: z
        .string()
        .optional()
        .openapi({
          param: {
            name: "keyId",
            in: "query",
          },
          example: "A1B2C3D4E5F6G7H8",
        }),
    }),
  },
  responses: {
    200: {
      content: {
        "application/pgp-keys": {
          schema: z.string(),
        },
      },
      description: "Public Key",
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
    500: {
      content: {
        "application/json": {
          schema: z.object({
            error: z.string(),
            code: z.string(),
          }),
        },
      },
      description: "Internal server error",
    },
  },
});

app.openapi(publicKeyRoute, async (c) => {
  const keyId = c.req.query("keyId") || c.env.KEY_ID;

  const keyStorageId = c.env.KEY_STORAGE.idFromName("global");
  const keyStorage = c.env.KEY_STORAGE.get(keyStorageId);

  const keyResponse = await keyStorage.fetch(
    new Request(`http://internal/get-key?keyId=${encodeURIComponent(keyId)}`),
  );

  if (!keyResponse.ok) {
    return c.json({ error: "Key not found", code: "KEY_NOT_FOUND" }, 404);
  }

  try {
    const storedKey = (await keyResponse.json()) as {
      armoredPrivateKey: string;
    };
    const privateKey = await openpgp.readPrivateKey({
      armoredKey: storedKey.armoredPrivateKey,
    });
    const publicKey = privateKey.toPublic().armor();

    return c.text(publicKey, 200, { "Content-Type": "application/pgp-keys" });
  } catch (error) {
    console.error("Key processing error:", error);
    return c.json({
      error: "Key processing error",
      code: "KEY_PROCESSING_ERROR",
    }, 500);
  }
});

// Sign endpoint with OIDC auth
app.route(
  "/sign",
  createOpenAPIApp().use("*", oidcAuth).route("/", signRoutes),
);

// Admin endpoints with rate limiting and admin auth
app.route(
  "/admin",
  createOpenAPIApp()
    .use("*", adminRateLimit) // Rate limit before auth to prevent brute force
    .use("*", adminAuth)
    .route("/", adminRoutes),
);

// OpenAPI Docs
app.doc("/doc", openApiConfig);

// Swagger UI
app.get("/ui", swaggerUI({ url: "/doc" }));

// 404 handler
app.notFound((c) => {
  return c.json({ error: "Not found", code: "NOT_FOUND" }, 404);
});

// Error handler
app.onError((err, c) => {
  const requestId = crypto.randomUUID();
  console.error("Unhandled error:", { requestId, error: err });
  return c.json(
    { error: "Internal server error", code: "INTERNAL_ERROR", requestId },
    500,
  );
});

export default app;
