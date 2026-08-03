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
	/**
	 * Comma-separated list of allowed OIDC subject prefixes.
	 *
	 * Required. The issuers above are shared by every repository on GitHub
	 * Actions and every project on gitlab.com, so without this any of them
	 * could mint a token for our audience and sign. Entries are matched as
	 * delimiter-terminated prefixes of `sub`, e.g.
	 * `repo:kjanat/gpg-signing-service`.
	 */
	ALLOWED_SUBJECTS: string;
	/** GPG Key identifier */
	KEY_ID: string;
	/** Optional: comma-separated list of allowed CORS origins */
	ALLOWED_ORIGINS?: string;
	/** Optional: expected JWT audience (defaults to "gpg-signing-service") */
	EXPECTED_AUDIENCE?: string;

	/** Secrets */
	/** Passphrase for private key */
	KEY_PASSPHRASE: string;
	/** Admin token for authentication */
	ADMIN_TOKEN: string;
}

/** Hono context with env bindings and variables */
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;
