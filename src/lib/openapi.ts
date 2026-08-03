import { OpenAPIHono } from "@hono/zod-openapi";

import type { Env, Variables } from "#types";
import { HTTP } from "#types";

/**
 * OpenAPI configuration
 */
export const openApiConfig = {
	// OpenAPI 3.1.x is not yet supported by `oapi-codegen`
	// See https://github.com/oapi-codegen/oapi-codegen/issues/373
	openapi: "3.0.0",
	info: { version: "1.0.0", title: "GPG Signing Service API" },
};

/**
 * Security schemes referenced by the `security` block of every authenticated
 * route.
 *
 * These must go through the registry rather than `openApiConfig.components`:
 * `getOpenAPIDocument()` rebuilds `components` from the route registry and
 * discards whatever the config object put there, so config-supplied schemes
 * never reached the served document and left all 13 `security` references
 * dangling — no Authorize button in Swagger UI, and no auth in generated
 * clients.
 */
export const securitySchemes = {
	oidcAuth: {
		type: "http" as const,
		scheme: "bearer",
		bearerFormat: "JWT",
		description: "OIDC token from GitHub Actions or GitLab CI",
	},
	bearerAuth: {
		type: "http" as const,
		scheme: "bearer",
		bearerFormat: "JWT",
		description: "Admin token for /admin/* endpoints",
	},
	serviceTokenAuth: {
		type: "http" as const,
		scheme: "bearer",
		bearerFormat: "gst_...",
		description: "Service token minted via POST /admin/tokens",
	},
};

/**
 * Register {@link securitySchemes} on an app's OpenAPI registry so they are
 * emitted into `components.securitySchemes`. Call once, on the root app.
 */
export function registerSecuritySchemes(app: OpenAPIHono<{ Bindings: Env; Variables: Variables }>): void {
	for (const [name, scheme] of Object.entries(securitySchemes)) {
		app.openAPIRegistry.registerComponent("securitySchemes", name, scheme);
	}
}

export function createOpenAPIApp() {
	return new OpenAPIHono<{ Bindings: Env; Variables: Variables }>({
		defaultHook: (result, c) => {
			if (!result.success) {
				return c.json(
					{
						error: "Validation failed",
						code: "INVALID_REQUEST",
						issues: result.error.issues,
					},
					HTTP.BadRequest,
				);
			}
			return;
		},
	});
}
