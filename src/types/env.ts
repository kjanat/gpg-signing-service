/**
 * Environment bindings and context types
 */

import type { Context } from "hono";
import type { Identity } from "./branded";
import type { ValidatedOIDCClaims } from "./oidc";

/** Context variables (for c.set/c.get) */
export interface Variables {
  /** Validated OIDC claims */
  oidcClaims: ValidatedOIDCClaims;
  /** Validated identity */
  identity: Identity;
  /** Request ID */
  requestId: string;
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

  /** Secrets */
  /** Passphrase for private key */
  KEY_PASSPHRASE: string;
  /** Admin token for authentication */
  ADMIN_TOKEN: string;
}

/** Hono context with env bindings and variables */
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;
