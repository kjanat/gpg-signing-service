import { Hono } from "hono";
import { logger } from "hono/logger";
import * as openpgp from "openpgp";
import type { Env, Variables, HealthResponse } from "~/types";
import { oidcAuth, adminAuth } from "~/middleware/oidc";
import {
  securityHeaders,
  productionCors,
  adminRateLimit,
} from "~/middleware/security";
import signRoutes from "~/routes/sign";
import adminRoutes from "~/routes/admin";

// Export Durable Objects
export { KeyStorage } from "~/durable-objects/key-storage";
export { RateLimiter } from "~/durable-objects/rate-limiter";

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Global middleware
app.use("*", logger());
app.use("*", securityHeaders);
app.use("*", productionCors);

// Health check endpoint (no auth)
app.get("/health", async (c) => {
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
app.get("/public-key", async (c) => {
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
    console.error("Failed to extract public key:", { keyId, error });
    return c.json(
      { error: "Failed to process key", code: "KEY_PROCESSING_ERROR" },
      500,
    );
  }
});

// Sign endpoint with OIDC auth
app.route(
  "/sign",
  new Hono<{ Bindings: Env; Variables: Variables }>()
    .use("*", oidcAuth)
    .route("/", signRoutes),
);

// Admin endpoints with rate limiting and admin auth
app.route(
  "/admin",
  new Hono<{ Bindings: Env; Variables: Variables }>()
    .use("*", adminRateLimit) // Rate limit before auth to prevent brute force
    .use("*", adminAuth)
    .route("/", adminRoutes),
);

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
