/**
 * Environment bindings and context types
 */

import type { Context } from "hono";
import type { Identity } from "#types/branded";
import type { ValidatedOIDCClaims } from "#types/oidc";

/** Context variables (for c.set/c.get) */
export interface Variables {
	/** Validated OIDC claims */
	oidcClaims: ValidatedOIDCClaims;
	/** Validated identity */
	identity: Identity;
	/** Request ID */
	requestId: string;
	/** Service-token key allowlist; null/absent means every key */
	allowedKeyIds?: string[] | null;
	/**
	 * Name of the trusted-subject row that authorized an OIDC caller, so the
	 * audit trail records *which trust* signed rather than only the JWT subject.
	 * Absent on the service-token path, where the row's name is already the
	 * synthetic `sub`.
	 */
	subjectPolicyName?: string;
	/**
	 * Id of the trusted-subject row that authorized an OIDC caller. Server-side
	 * and stable, unlike `sub`, which the caller varies per ref — so this is what
	 * the per-row signing ceiling is metered on. Absent on the service-token path,
	 * which is already metered per credential.
	 */
	subjectPolicyId?: string;
}

/** Cloudflare Workers environment bindings */
export interface Env {
	/** Durable Object namespace for key storage */
	KEY_STORAGE: DurableObjectNamespace;
	/** Durable Object namespace for rate limiting */
	RATE_LIMITER: DurableObjectNamespace;

	/** D1 Database */
	AUDIT_DB: D1Database;

	/** KV Namespace */
	JWKS_CACHE: KVNamespace;

	/** Environment variables */
	/** Comma-separated list of allowed issuers */
	ALLOWED_ISSUERS: string;
	/** GPG Key identifier */
	KEY_ID: string;
	/** Optional: comma-separated list of allowed CORS origins */
	ALLOWED_ORIGINS?: string;
	/** Optional: expected JWT audience (defaults to "gpg-signing-service") */
	EXPECTED_AUDIENCE?: string;
	/**
	 * Optional: public origin to build the `docs` links on error responses from.
	 * Defaults to the origin the request arrived on, which is right everywhere
	 * except behind a proxy that rewrites the host.
	 */
	SERVICE_BASE_URL?: string;
	/**
	 * Optional: document that `GET /e/:code` redirects into. Defaults to the
	 * error reference in this repository.
	 */
	ERROR_DOCS_URL?: string;
	/**
	 * Optional: set to "true" to name the trusted subject prefixes in an
	 * untrusted-subject 401. Off by default — the issuers this service accepts
	 * are shared with every repository on their platform, so that list would be
	 * readable by anyone who can run a workflow. See `RefusalContext`.
	 */
	DISCLOSE_TRUST_PATTERNS?: string;

	/** Secrets */
	/** Passphrase for private key */
	KEY_PASSPHRASE: string;
	/** Admin token for authentication */
	ADMIN_TOKEN: string;
}

/** Hono context with env bindings and variables */
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;
