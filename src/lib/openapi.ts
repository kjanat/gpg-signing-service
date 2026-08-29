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
 * The challenge a 403 carries when the credential was good and too small.
 *
 * RFC 6750 §3.1 defines `insufficient_scope` for exactly this — a bearer that
 * authenticated and is not authorized for the operation — and §3 puts the
 * parameters on the same `WWW-Authenticate` a 401 uses. Sending it here rather
 * than reusing the bare challenge is what stops a client's generic 401/403
 * handler treating this as "re-authenticate": the error parameter says the
 * credential is fine, and re-presenting it will produce this same answer.
 */
export const WWW_AUTHENTICATE_INSUFFICIENT_SCOPE =
	'Bearer realm="gpg-signing-service", error="insufficient_scope", error_description="This admin credential may only read"';

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

/**
 * The 403 declaration shared by every admin operation that changes state.
 *
 * Separate from `unauthorizedResponse` because the two say opposite things
 * about the credential — one refuses it, this one accepts it and refuses the
 * *operation* — and a generated client that cannot see the difference in the
 * document will not branch on it in code either. Declared on the mutation
 * routes only: that set *is* the boundary, so the document states it.
 *
 * @param description - Which authority this operation needs, in the caller's terms
 */
export function forbiddenResponse(description: string) {
	return {
		content: { "application/json": { schema: ErrorResponseSchema } },
		description,
		headers: {
			"WWW-Authenticate": {
				description: 'Bearer challenge carrying RFC 6750 `error="insufficient_scope"`.',
				schema: { type: "string" as const, example: WWW_AUTHENTICATE_INSUFFICIENT_SCOPE },
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
