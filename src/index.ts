import { swaggerUI } from "@hono/swagger-ui";
import { createRoute } from "@hono/zod-openapi";
import * as Sentry from "@sentry/cloudflare";
import { logger } from "hono/logger";
import * as openpgp from "openpgp";
import { KeyStorage as KeyStorageClass } from "#durable-objects/key-storage";
import { RateLimiter as RateLimiterClass } from "#durable-objects/rate-limiter";
import { createOpenAPIApp, openApiConfig, registerSecuritySchemes } from "#lib/openapi";
import { callerAuth } from "#middleware/caller-auth";
import { errorDocs } from "#middleware/error-docs";
import { adminAuth } from "#middleware/oidc";
import { requestIdMiddleware } from "#middleware/request-id";
import { adminRateLimit, productionCors, securityHeaders } from "#middleware/security";
import adminRoutes from "#routes/admin";
import subjectRoutes from "#routes/oidc-subjects";
import signRoutes from "#routes/sign";
import tokenRoutes from "#routes/tokens";
import { ErrorResponseSchema, HealthResponseSchema, PublicKeyQuerySchema, PublicKeyResponseSchema } from "#schemas";
import { isErrorCode } from "#schemas/errors";
import type { HealthResponse } from "#schemas/health";
import type { Env } from "#types";
import { HTTP, MediaType } from "#types";
import { fetchKeyStorage } from "#utils/durable-objects";
import { errorDocsTarget } from "#utils/error-docs";
import { runKeyExpiryMonitor } from "#utils/key-expiry-monitor";
import { logger as customLogger } from "#utils/logger";
import { sentryOptions } from "#utils/sentry";

// Export Durable Objects
//
// Wrapped rather than re-exported so a fault inside either object is reported
// with the same options — and through the same scrubber — as one in the request
// path. Both are otherwise invisible: nothing in `fetchKeyStorage` or the
// limiter's caller logs the far side of the stub, and `RateLimiter.alarm()`
// runs with no request to attach to at all.
//
// The wrapper is a Proxy whose `construct` trap returns the real instance, so
// the class name Cloudflare matches against `[[migrations]]`, the constructor
// signature, and every method's behaviour are unchanged. The base classes stay
// importable from their own modules, which is what the Durable Object suites
// use.
export const KeyStorage = instrumentDurableObject(KeyStorageClass);
export const RateLimiter = instrumentDurableObject(RateLimiterClass);

// The instance types, re-exported alongside the wrapped constructors.
// `wrangler types` writes `DurableObjectNamespace<import("./src/index").KeyStorage>`
// into worker-configuration.d.ts, and the previous `export { KeyStorage } from
// ...` carried the class's type as well as its value. A `const` carries only
// the value, so without these two lines every stub in the generated env — and
// the `runInDurableObject` calls typed off it — degrades to the bare
// `DurableObject` interface.
export type KeyStorage = KeyStorageClass;
export type RateLimiter = RateLimiterClass;

const app = createOpenAPIApp();

// Global middleware
// Ahead of everything else so `c.get("requestId")` is populated for the whole
// pipeline and every response echoes X-Request-ID. The value is the caller's
// only when it is a UUID — it reaches audit_logs.request_id, declared z.uuid().
app.use("*", requestIdMiddleware);
// Directly after the request id, and before everything that can refuse: it runs
// on the way *out*, so the outermost registration is the one that sees every
// error body — including the 401s the auth middlewares answer without ever
// reaching a route, and whatever `onError` produces.
app.use("*", errorDocs);
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
		[HTTP.OK]: {
			content: { "application/json": { schema: HealthResponseSchema } },
			description: "Service is healthy",
		},
		[HTTP.ServiceUnavailable]: {
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
		[HTTP.OK]: {
			content: { "application/pgp-keys": { schema: PublicKeyResponseSchema } },
			description: "Public Key",
		},
		[HTTP.NotFound]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Key not found",
		},
		[HTTP.InternalServerError]: {
			content: { "application/json": { schema: ErrorResponseSchema } },
			description: "Internal server error",
		},
	},
});

app.openapi(publicKeyRoute, async (c) => {
	const { keyId: keyIdQuery } = c.req.valid("query");
	const keyId = keyIdQuery || c.env.KEY_ID;

	const keyResponse = await fetchKeyStorage(c.env, `/get-key?keyId=${encodeURIComponent(keyId)}`);

	if (!keyResponse.ok) {
		return c.json({ error: "Key not found", code: "KEY_NOT_FOUND" }, HTTP.NotFound);
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
		return c.json({ error: "Key processing error", code: "KEY_PROCESSING_ERROR" }, HTTP.InternalServerError);
	}
});

/**
 * The short link every error response carries.
 *
 * `GET /e/AUTH_SUBJECT_UNTRUSTED` -> the reference section for that code.
 *
 * It exists so the `docs` field can be short. A link is read off a wrapped,
 * truncated CI log and retyped by hand often enough that length is a
 * correctness property, and this form puts the only thing that has to be right
 * — the code, which the response already got right — at the end of a
 * six-character path. Because it is a redirect, the documentation can move
 * without invalidating links printed into logs that are already archived.
 *
 * Unauthenticated on purpose: a caller holding a refusal has, by construction,
 * no credential that works, and the target is public documentation.
 *
 * Registered with `app.get` rather than through the OpenAPI router because it
 * is for humans following a link, not for the generated clients — declaring it
 * would put a redirect-following method on every one of them for no caller.
 */
app.get("/e/:code", (c) => {
	// Uppercased so the lowercase form from a URL bar works. Codes are uppercase
	// by convention and the anchor is derived by lowercasing again, so this only
	// ever widens what is accepted.
	const code = c.req.param("code").toUpperCase();

	if (!isErrorCode(code)) {
		// Deliberately not a redirect to the reference's top: silently landing
		// somewhere plausible is how a typo'd code turns into "the docs don't
		// mention my error". Say the code is unknown, and hand over the index.
		return c.json(
			{
				error: `Unknown error code: ${code}`,
				code: "NOT_FOUND" as const,
				hint: `No error in this service carries that code. The full list is at ${errorDocsTarget(c.env)}.`,
			},
			HTTP.NotFound,
		);
	}

	return c.redirect(errorDocsTarget(c.env, code), HTTP.Found);
});

// Sign endpoint: OIDC or service-token auth
app.route("/sign", createOpenAPIApp().use("*", callerAuth).route("/", signRoutes));

// Admin endpoints with rate limiting and admin auth
app.route(
	"/admin",
	createOpenAPIApp()
		.use("*", adminRateLimit) // Rate limit before auth to prevent brute force
		.use("*", adminAuth)
		.route("/", adminRoutes)
		.route("/", tokenRoutes)
		.route("/", subjectRoutes),
);

// OpenAPI Docs
registerSecuritySchemes(app);
app.doc("/doc", openApiConfig);

// Swagger UI
// `validatorUrl: "none"` disables Swagger UI's online validator badge, which
// otherwise loads an <img> from validator.swagger.io — blocked by the docs CSP
// (rendering a broken "Error" image) and leaking the spec URL to a third party.
app.get("/ui", swaggerUI({ url: "/doc", validatorUrl: "none" }));

// 404 handler
app.notFound((c) => {
	return c.json({ error: "Not found", code: "NOT_FOUND" }, HTTP.NotFound);
});

// Error handler
app.onError((err, c) => {
	// The id the caller was handed, so the one in a 500 body is greppable against
	// the logs. The fallback covers a throw from before the middleware ran.
	const requestId = c.get("requestId") ?? crypto.randomUUID();
	customLogger.error("Unhandled error", {
		requestId,
		error: err instanceof Error ? err.message : String(err),
		stack: err instanceof Error ? err.stack : undefined,
	});
	return c.json({ error: "Internal server error", code: "INTERNAL_ERROR", requestId }, HTTP.InternalServerError);
});

/**
 * The Worker's handlers.
 *
 * `scheduled` is attached to the Hono app rather than to a fresh object literal
 * because the app *is* the default export elsewhere: `scripts/generate-openapi.ts`
 * and two suites read `getOpenAPIDocument` off it, and a `{ fetch, scheduled }`
 * literal would drop that surface for the sake of a shape the runtime does not
 * require. The runtime asks only that `fetch` and `scheduled` be callable
 * properties of the default export, and both are.
 */
const handler = Object.assign(app, {
	/**
	 * The Cron Trigger. Warns before an active signing key lapses.
	 *
	 * Deliberately not wrapped in a catch-and-continue: a run that could not read
	 * its own state, or could not send the mail it had to send, has not monitored
	 * anything, and reporting that as a success is how a monitor becomes
	 * decoration. Logged for the tail, then rethrown so the invocation is recorded
	 * as failed.
	 */
	async scheduled(controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
		try {
			await runKeyExpiryMonitor(env);
		} catch (error) {
			customLogger.error("Scheduled key expiry monitor failed", error, {
				action: "key-expiry-check",
				cron: controller.cron,
			});
			throw error;
		}
	},
});

/**
 * Instrument a Durable Object class without changing what it is.
 *
 * The SDK types this against the `DurableObject` base class exported from
 * `cloudflare:workers`. Neither of this Worker's objects extends it — they
 * implement the ambient `DurableObject` interface and take only `state` — so
 * the constraint cannot be satisfied structurally even though the runtime
 * contract (constructed with `(state, env)`, dispatched through `fetch` and
 * `alarm`) is exactly what the instrumentation expects. The casts are confined
 * to this helper, and its signature returns the class it was handed, so no
 * caller loses a type.
 */
function instrumentDurableObject<C extends new (state: DurableObjectState, env: Env) => object>(target: C): C {
	return Sentry.instrumentDurableObjectWithSentry(sentryOptions as never, target as never) as unknown as C;
}

/**
 * The exported handler, wrapped.
 *
 * `withSentry` mutates and returns the same object, so `getOpenAPIDocument` and
 * everything else `scripts/generate-openapi.ts` and two suites read off the
 * default export survive the wrapping. With no `SENTRY_DSN` configured the
 * options carry `enabled: false` and no integrations at all, which is what
 * makes the wrap a real no-op rather than a quiet one.
 */
export default Sentry.withSentry(sentryOptions, handler);
