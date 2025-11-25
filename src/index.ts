import { swaggerUI } from "@hono/swagger-ui";
import { createRoute } from "@hono/zod-openapi";
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
import {
  ErrorResponseSchema,
  HealthResponseSchema,
  PublicKeyQuerySchema,
  PublicKeyResponseSchema,
} from "~/schemas";
import type { HealthResponse } from "~/schemas/health";
import { HTTP, MediaType } from "~/types";
import { fetchKeyStorage } from "~/utils/durable-objects";
import { logger as customLogger } from "~/utils/logger";

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
      content: { "application/json": { schema: HealthResponseSchema } },
      description: "Service is healthy",
    },
    503: {
      content: { "application/json": { schema: HealthResponseSchema } },
      description: "Service is degraded",
    },
  },
});

app.openapi(healthRoute, async (c) => {
  const checks = { keyStorage: false, database: false };

  try {
    // Check key storage
    const keyHealthResponse = await fetchKeyStorage(c.env, "/health");
    checks.keyStorage = keyHealthResponse.ok;
  } catch (error) {
    customLogger.error("Key storage health check failed", {
      error: error instanceof Error ? error.message : String(error),
    });
    checks.keyStorage = false;
  }

  try {
    // Check database
    const result = await c.env.AUDIT_DB.prepare("SELECT 1").first();
    checks.database = result !== null;
  } catch (error) {
    customLogger.error("Database health check failed", {
      error: error instanceof Error ? error.message : String(error),
    });
    checks.database = false;
  }

  const allHealthy = checks.keyStorage && checks.database;

  const response: HealthResponse = {
    status: allHealthy ? "healthy" : "degraded",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
    checks,
  };

  return c.json(response, allHealthy ? HTTP.OK : HTTP.ServiceUnavailable);
});

// Public key endpoint (no auth) - for git to verify signatures
const publicKeyRoute = createRoute({
  method: "get",
  path: "/public-key",
  summary: "Get public key",
  description: "Get the public key for signature verification",
  request: { query: PublicKeyQuerySchema },
  responses: {
    200: {
      content: { "application/pgp-keys": { schema: PublicKeyResponseSchema } },
      description: "Public Key",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Key not found",
    },
    500: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Internal server error",
    },
  },
});

app.openapi(publicKeyRoute, async (c) => {
  const { keyId: keyIdQuery } = c.req.valid("query");
  const keyId = keyIdQuery || c.env.KEY_ID;

  const keyResponse = await fetchKeyStorage(
    c.env,
    `/get-key?keyId=${encodeURIComponent(keyId)}`,
  );

  if (!keyResponse.ok) {
    return c.json(
      { error: "Key not found", code: "KEY_NOT_FOUND" },
      HTTP.NotFound,
    );
  }

  try {
    const storedKey = (await keyResponse.json()) as {
      armoredPrivateKey: string;
    };
    const privateKey = await openpgp.readPrivateKey({
      armoredKey: storedKey.armoredPrivateKey,
    });
    const publicKey = privateKey.toPublic().armor();

    return c.text(publicKey, HTTP.OK, {
      "Content-Type": MediaType.ApplicationPgpKeys,
    });
  } catch (error) {
    customLogger.error("Key processing error", {
      error: error instanceof Error ? error.message : String(error),
      keyId: c.req.query("keyId"),
    });
    return c.json(
      { error: "Key processing error", code: "KEY_PROCESSING_ERROR" },
      HTTP.InternalServerError,
    );
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
  return c.json({ error: "Not found", code: "NOT_FOUND" }, HTTP.NotFound);
});

// Error handler
app.onError((err, c) => {
  const requestId = crypto.randomUUID();
  customLogger.error("Unhandled error", {
    requestId,
    error: err instanceof Error ? err.message : String(err),
    stack: err instanceof Error ? err.stack : undefined,
  });
  return c.json(
    { error: "Internal server error", code: "INTERNAL_ERROR", requestId },
    HTTP.InternalServerError,
  );
});

export default app;
