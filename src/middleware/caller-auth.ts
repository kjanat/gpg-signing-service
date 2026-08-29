import type { MiddlewareHandler } from "hono";

import { oidcAuth } from "#middleware/oidc";
import type { Env, OIDCClaims, Variables } from "#types";
import { createIdentity, markClaimsAsValidated } from "#types";
import { serviceDegraded, unauthorized } from "#utils/errors";
import { logger } from "#utils/logger";
import { SERVICE_TOKEN_PREFIX, verifyServiceToken } from "#utils/service-tokens";

/** Synthetic issuer for service-token callers in audit trails. */
export const SERVICE_TOKEN_ISSUER = "urn:gpg-signing-service:token";

/**
 * What a caller is asked to wait when the token store could not be read.
 *
 * The same interval the OIDC path uses for the same database, deliberately: one
 * D1 outage should not hand two callers two different answers about how long it
 * lasts. See `ISSUER_RETRY_AFTER_SECONDS` in `middleware/oidc.ts`.
 */
const STORE_RETRY_AFTER_SECONDS = 30;

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
		return unauthorized(c, "Missing authorization header", "AUTH_MISSING", {
			hint: "Send `Authorization: Bearer <token>` with either an OIDC token minted for this service's audience or a service token starting with `gst_`.",
		});
	}

	const token = authHeader.slice(7);
	if (!token.startsWith(SERVICE_TOKEN_PREFIX)) {
		return oidcAuth(c, next);
	}

	// The same argument the OIDC path makes one file over: a store this
	// deployment cannot read is not a credential fault. `verifyServiceToken` does
	// its D1 read unguarded, so a brief D1 outage threw straight past this
	// middleware into `onError` and came back `500 INTERNAL_ERROR` — a code whose
	// reference says "an unhandled fault, worth reporting with the requestId" for
	// what is the *same* outage the OIDC branch answers `503 SERVICE_DEGRADED`
	// with a `Retry-After`. Two callers of one database, told two different
	// things about one failure, and only one of them told to wait.
	let policy: Awaited<ReturnType<typeof verifyServiceToken>>;
	try {
		policy = await verifyServiceToken(c.env.AUDIT_DB, token);
	} catch (error) {
		// The caught value goes in `logger.error`'s error slot, not folded into
		// context: that is the argument whose stack and name the logger unpacks,
		// and the third argument is where `requestId` has to land for this entry
		// to join up with the id the caller was handed back.
		logger.error("Service token lookup failed", error, {
			requestId: c.get("requestId"),
		});
		return serviceDegraded(c, "Authorization store unavailable", {
			hint: "The service-token lookup failed, so this request could not be authorized either way. Nothing about the token is wrong. Retry after the interval in Retry-After; if it persists, the operator should check D1 and that `task db:migrate` has been applied.",
			retryAfter: STORE_RETRY_AFTER_SECONDS,
		});
	}

	if (!policy) {
		return unauthorized(c, "Invalid service token", "AUTH_INVALID", {
			hint: "The token is unknown, revoked or expired. List the live ones with GET /admin/tokens, and mint a replacement with POST /admin/tokens.",
		});
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
