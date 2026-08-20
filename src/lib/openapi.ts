import { OpenAPIHono } from "@hono/zod-openapi";

import { ErrorResponseSchema } from "#schemas/errors";
import type { Env, Variables } from "#types";
import { HTTP } from "#types";

/**
 * The challenge every 401 carries, and the value the document advertises.
 *
 * RFC 9110 §11.6.1 makes `WWW-Authenticate` mandatory on a 401 — it is how a
 * caller learns *which* scheme to present rather than guessing from prose. The
 * realm names the service so a caller talking to several bearer-guarded hosts
 * through one credential helper can tell whose challenge it is.
 */
export const WWW_AUTHENTICATE = 'Bearer realm="gpg-signing-service"';

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

/**
 * The 401 declaration shared by every operation that requires a credential.
 *
 * Written once because the three things it promises — the ErrorResponse
 * envelope, the `code` clients branch on, and the `WWW-Authenticate` challenge
 * — are properties of the auth middleware, not of any one route. Thirteen
 * hand-copied blocks drift; one helper cannot. `description` stays per-route:
 * what a missing admin token means is not what an untrusted OIDC subject means.
 *
 * @param description - What this operation's 401 means to its caller
 */
export function unauthorizedResponse(description: string) {
	return {
		content: { "application/json": { schema: ErrorResponseSchema } },
		description,
		headers: {
			"WWW-Authenticate": {
				description: "Authentication scheme the caller must present.",
				schema: { type: "string" as const, example: WWW_AUTHENTICATE },
			},
		},
	};
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
