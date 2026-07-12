import type { MiddlewareHandler } from "hono";

import { oidcAuth } from "#middleware/oidc";
import type { Env, OIDCClaims, Variables } from "#types";
import { createIdentity, HTTP, markClaimsAsValidated } from "#types";
import { SERVICE_TOKEN_PREFIX, verifyServiceToken } from "#utils/service-tokens";

/** Synthetic issuer for service-token callers in audit trails. */
export const SERVICE_TOKEN_ISSUER = "urn:gpg-signing-service:token";

/**
 * Caller authentication for the signing endpoint. A bearer starting with
 * `gst_` is a service token (the one-secret path for arbitrary CI); anything
 * else goes through OIDC validation (GitHub Actions / GitLab CI).
 */
export const callerAuth: MiddlewareHandler<{
	Bindings: Env;
	Variables: Variables;
}> = async (c, next) => {
	const authHeader = c.req.header("Authorization");

	if (!authHeader?.startsWith("Bearer ")) {
		return c.json({ error: "Missing authorization header", code: "AUTH_MISSING" }, HTTP.Unauthorized);
	}

	const token = authHeader.slice(7);
	if (!token.startsWith(SERVICE_TOKEN_PREFIX)) {
		return oidcAuth(c, next);
	}

	const policy = await verifyServiceToken(c.env.AUDIT_DB, token);
	if (!policy) {
		return c.json({ error: "Invalid service token", code: "AUTH_INVALID" }, HTTP.Unauthorized);
	}

	// Synthetic claims keep the sign route and audit trail uniform across
	// both auth paths.
	const claims: OIDCClaims = {
		iss: SERVICE_TOKEN_ISSUER,
		sub: policy.name,
		aud: "gpg-signing-service",
		exp: Math.floor(Date.now() / 1000) + 60,
		iat: Math.floor(Date.now() / 1000),
	};
	c.set("oidcClaims", markClaimsAsValidated(claims));
	c.set("identity", createIdentity(SERVICE_TOKEN_ISSUER, policy.name));
	c.set("allowedKeyIds", policy.allowedKeyIds);

	return next();
};
