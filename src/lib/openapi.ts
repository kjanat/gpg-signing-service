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
 * Register the security schemes in an app's OpenAPI registry so every document
 * generated from that app includes them in `components.securitySchemes`.
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
