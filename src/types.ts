import type { Context } from "hono";

// =============================================================================
// Branded Types for Security-Critical Strings
// =============================================================================

/**
 * Brand type for nominal typing - creates distinct types from string
 */
declare const __brand: unique symbol;
type Brand<T, B> = T & { readonly [__brand]: B };

/** GPG Key identifier
 * @example "A1B2C3D4E5F6G7H8"
 */
export type KeyId = Brand<string, "KeyId">;

/** GPG Key fingerprint (40-char hex string) */
export type KeyFingerprint = Brand<string, "KeyFingerprint">;

/** PGP armored private key string */
export type ArmoredPrivateKey = Brand<string, "ArmoredPrivateKey">;

/** OIDC identity string in format `<iss>:<sub>` */
export type Identity = Brand<string, "Identity">;

/** Helper function to create validated key ID */
export function createKeyId(value: string): KeyId {
  // Basic validation - full validation via KeyIdSchema
  if (!/^[A-F0-9]{16}$/i.test(value)) {
    throw new Error(`Invalid KeyId format: ${value}`);
  }
  return value.toUpperCase() as KeyId;
}

/** Helper function to create validated key fingerprint */
export function createKeyFingerprint(value: string): KeyFingerprint {
  // Basic validation - full validation via FingerprintSchema
  if (!/^[A-F0-9]{40}$/i.test(value)) {
    throw new Error(`Invalid KeyFingerprint format: ${value}`);
  }
  return value.toUpperCase() as KeyFingerprint;
}

/** Helper function to create validated armored private key */
export function createArmoredPrivateKey(value: string): ArmoredPrivateKey {
  // Basic validation - full validation via ArmoredPrivateKeySchema
  if (!value.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
    throw new Error("Invalid ArmoredPrivateKey: missing PGP header");
  }
  if (!value.includes("END PGP PRIVATE KEY BLOCK")) {
    throw new Error("Invalid ArmoredPrivateKey: missing PGP footer");
  }
  if (value.length < 350 || value.length > 10_000) {
    throw new Error(`Invalid ArmoredPrivateKey length: ${value.length}`);
  }
  return value as ArmoredPrivateKey;
}

/** Helper function to create validated identity */
export function createIdentity(issuer: string, subject: string): Identity {
  return `${issuer}:${subject}` as Identity;
}

// =============================================================================
// Error Types (re-exported from schemas)
// =============================================================================

export type { ErrorCode, ErrorResponse } from "~/schemas/errors";

// =============================================================================
// Context Variables
// =============================================================================

/** Marker interface for OIDC claims that have passed validation */
export interface ValidatedOIDCClaims extends OIDCClaims {
  readonly __validated: true;
}

/** Context variables (for c.set/c.get) */
export interface Variables {
  /** Validated OIDC claims */
  oidcClaims: ValidatedOIDCClaims;
  /** Validated identity */
  identity: Identity;
  /** Request ID */
  requestId: string;
}

// =============================================================================
// Environment Bindings
// =============================================================================

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

// Hono context with env bindings and variables
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;

// =============================================================================
// OIDC Types
// =============================================================================

/** OIDC token claims (unvalidated)
 * @param iss - Issuer URL
 * @param sub - Subject (repository or project)
 * @param aud - Audience
 * @param exp - Expiration
 * @param iat - Issued at
 * @param nbf - Not before
 * @param repository - GitHub-specific repository
 * @param repository_owner - GitHub-specific repository owner
 * @param workflow - GitHub-specific workflow
 * @param ref - GitHub-specific ref
 * @param project_path - GitLab-specific project path
 * @param namespace_path - GitLab-specific namespace path
 * @param pipeline_source - GitLab-specific pipeline source
 */
export interface OIDCClaims {
  /** Issuer URL */
  iss: string;
  /** Subject (repository or project) */
  sub: string;
  /** Audience */
  aud: string | string[];
  /** Expiration */
  exp: number;
  /** Issued at */
  iat: number;
  /** Not before */
  nbf?: number;

  /** GitHub-specific repository */
  repository?: string;
  /** GitHub-specific repository owner */
  repository_owner?: string;
  /** GitHub-specific workflow */
  workflow?: string;
  /** GitHub-specific ref */
  ref?: string;

  /** GitLab-specific project path */
  project_path?: string;
  /** GitLab-specific namespace path */
  namespace_path?: string;
  /** GitLab-specific pipeline source */
  pipeline_source?: string;
}

/** Helper to mark claims as validated after verification
 * @param claims - OIDC claims to mark as validated
 * @returns Validated OIDC claims
 * @example
 * ```typescript
 * const validatedClaims = markClaimsAsValidated(claims);
 * ```
 */
export function markClaimsAsValidated(claims: OIDCClaims): ValidatedOIDCClaims {
  return { ...claims, __validated: true as const };
}

// =============================================================================
// Audit Types (re-exported from schemas)
// =============================================================================

export type { AuditAction, AuditLogEntry } from "~/schemas/audit";

// =============================================================================
// Key Storage Types (re-exported from schemas)
// =============================================================================

export type { StoredKey } from "~/schemas/keys";

/** Unvalidated key upload request (from API)
 * @param armoredPrivateKey - Armored private key
 * @param keyId - Key ID
 */
export interface KeyUploadRequest {
  armoredPrivateKey: string;
  keyId: string;
}

// =============================================================================
// Rate Limiting Types - Discriminated Union
// =============================================================================

/** Rate limit allowed result
 * @param allowed - Whether the request is allowed
 * @param remaining - Remaining number of requests
 * @param resetAt - Reset time in seconds since epoch
 */
interface RateLimitAllowed {
  /** Whether the request is allowed */
  allowed: true;
  /** Remaining number of requests */
  remaining: number;
  /** Reset time in seconds since epoch */
  resetAt: number;
}

/** Rate limit denied result
 * @param allowed - Whether the request is allowed
 * @param remaining - Remaining number of requests (always `0`)
 * @param resetAt - Reset time in seconds since epoch
 */
interface RateLimitDenied {
  /** Whether the request is allowed */
  allowed: false;
  /** Remaining number of requests */
  remaining: 0;
  /** Reset time in seconds since epoch */
  resetAt: number;
}

/** Rate limit result as discriminated union
 * @param allowed - Whether the request is allowed
 * @param remaining - Remaining number of requests
 * @param resetAt - Reset time in seconds since epoch
 */
export type RateLimitResult = RateLimitAllowed | RateLimitDenied;

/** Helper to create allowed rate limit result
 * @param remaining - Remaining number of requests
 * @param resetAt - Reset time in seconds since epoch
 * @returns Allowed rate limit result
 * @example
 * ```typescript
 * const result = createRateLimitAllowed(10, Date.now() / 1000 + 60);
 * ```
 */
export function createRateLimitAllowed(
  remaining: number,
  resetAt: number,
): RateLimitAllowed {
  return { allowed: true, remaining, resetAt };
}

/** Helper to create denied rate limit result
 * @param resetAt - Reset time in seconds since epoch
 * @returns Denied rate limit result
 * @example
 * ```typescript
 * const result = createRateLimitDenied(Date.now() / 1000 + 60);
 * ```
 */
export function createRateLimitDenied(resetAt: number): RateLimitDenied {
  return { allowed: false, remaining: 0, resetAt };
}

// =============================================================================
// Health Check Types (re-exported from schemas)
// =============================================================================

export type { HealthResponse, HealthStatus } from "~/schemas/health";

// =============================================================================
// JWKS Types - Discriminated Union for RSA/EC Keys
// =============================================================================

/** Base JWK fields common to all key types */
interface JWKBase {
  /** Use */
  use: "sig";
  /** Key ID */
  kid: string;
}

/** RSA public key in JWK format */
export interface RSAPublicKeyJWK extends JWKBase {
  /** Key type */
  kty: "RSA";
  /** Algorithm */
  alg: "RS256" | "RS384" | "RS512";
  /** Modulus */
  n: string;
  /** Exponent */
  e: string;
}

/** EC public key in JWK format */
export interface ECPublicKeyJWK extends JWKBase {
  /** Key type */
  kty: "EC";
  /** Algorithm */
  alg: "ES256" | "ES384" | "ES512";
  /** Curve */
  crv: "P-256" | "P-384" | "P-521";
  /** X coordinate */
  x: string;
  /** Y coordinate */
  y: string;
}

/** JWK type as discriminated union */
export type JWK = RSAPublicKeyJWK | ECPublicKeyJWK;

/** JWKS response with properly typed keys */
export interface JWKSResponse {
  /** JWKS keys */
  keys: JWK[];
}

/** Legacy JWK type for backward compatibility with existing code */
export interface LegacyJWK {
  /** Key type */
  kty: string;
  /** Algorithm */
  alg: string;
  /** Use */
  use: string;
  /** Key ID */
  kid: string;
  /** Modulus */
  n?: string;
  /** Exponent */
  e?: string;
  /** X coordinate */
  x?: string;
  /** Y coordinate */
  y?: string;
  /** Curve */
  crv?: string;
}

/** Legacy JWKS response for backward compatibility */
export interface LegacyJWKSResponse {
  /** JWKS keys */
  keys: LegacyJWK[];
}

// =============================================================================
// Signing Types
// =============================================================================

/** Result from signing operation */
export interface SigningResult {
  /** Detached signature */
  signature: string;
  /** Key ID */
  keyId: KeyId;
  /** Algorithm */
  algorithm: string;
  /** Fingerprint */
  fingerprint: KeyFingerprint;
}

/** Parsed key information */
export interface ParsedKeyInfo {
  /** Key ID */
  keyId: KeyId;
  /** Fingerprint */
  fingerprint: KeyFingerprint;
  /** Algorithm */
  algorithm: string;
  /** User ID */
  userId: string;
}
