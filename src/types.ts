import type { Context } from "hono";

// =============================================================================
// Branded Types for Security-Critical Strings
// =============================================================================

/**
 * Brand type for nominal typing - creates distinct types from string
 */
declare const __brand: unique symbol;
type Brand<T, B> = T & { readonly [__brand]: B };

/** GPG Key identifier (e.g., "A1B2C3D4E5F6G7H8") */
export type KeyId = Brand<string, "KeyId">;

/** GPG Key fingerprint (40-char hex string) */
export type KeyFingerprint = Brand<string, "KeyFingerprint">;

/** PGP armored private key string */
export type ArmoredPrivateKey = Brand<string, "ArmoredPrivateKey">;

/** OIDC identity string in format "{iss}:{sub}" */
export type Identity = Brand<string, "Identity">;

// Helper functions for creating branded types
// NOTE: These are internal constructors used by validated schemas
// For external usage, import and use the Zod schemas from ~/schemas/keys
export function createKeyId(value: string): KeyId {
  // Basic validation - full validation via KeyIdSchema
  if (!/^[A-F0-9]{16}$/i.test(value)) {
    throw new Error(`Invalid KeyId format: ${value}`);
  }
  return value.toUpperCase() as KeyId;
}

export function createKeyFingerprint(value: string): KeyFingerprint {
  // Basic validation - full validation via FingerprintSchema
  if (!/^[A-F0-9]{40}$/i.test(value)) {
    throw new Error(`Invalid KeyFingerprint format: ${value}`);
  }
  return value.toUpperCase() as KeyFingerprint;
}

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
  oidcClaims: ValidatedOIDCClaims;
  identity: Identity;
  requestId: string;
}

// =============================================================================
// Environment Bindings
// =============================================================================

export interface Env {
  // Durable Objects
  KEY_STORAGE: DurableObjectNamespace;
  RATE_LIMITER: DurableObjectNamespace;

  // D1 Database
  AUDIT_DB: D1Database;

  // KV Namespace
  JWKS_CACHE: KVNamespace;

  // Environment variables
  ALLOWED_ISSUERS: string;
  KEY_ID: string;
  /** Optional: comma-separated list of allowed CORS origins */
  ALLOWED_ORIGINS?: string;
  /** Optional: expected JWT audience (defaults to "gpg-signing-service") */
  EXPECTED_AUDIENCE?: string;

  // Secrets
  KEY_PASSPHRASE: string;
  ADMIN_TOKEN: string;
}

// Hono context with env bindings and variables
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;

// =============================================================================
// OIDC Types
// =============================================================================

/** OIDC token claims (unvalidated) */
export interface OIDCClaims {
  iss: string; // Issuer URL
  sub: string; // Subject (repository or project)
  aud: string | string[]; // Audience
  exp: number; // Expiration
  iat: number; // Issued at
  nbf?: number; // Not before

  // GitHub-specific
  repository?: string;
  repository_owner?: string;
  workflow?: string;
  ref?: string;

  // GitLab-specific
  project_path?: string;
  namespace_path?: string;
  pipeline_source?: string;
}

/** Helper to mark claims as validated after verification */
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

/** Unvalidated key upload request (from API) */
export interface KeyUploadRequest {
  armoredPrivateKey: string;
  keyId: string;
}

// =============================================================================
// Rate Limiting Types - Discriminated Union
// =============================================================================

/** Rate limit allowed result */
interface RateLimitAllowed {
  allowed: true;
  remaining: number;
  resetAt: number;
}

/** Rate limit denied result - remaining is always 0 */
interface RateLimitDenied {
  allowed: false;
  remaining: 0;
  resetAt: number;
}

/** Rate limit result as discriminated union */
export type RateLimitResult = RateLimitAllowed | RateLimitDenied;

/** Helper to create allowed rate limit result */
export function createRateLimitAllowed(
  remaining: number,
  resetAt: number,
): RateLimitAllowed {
  return { allowed: true, remaining, resetAt };
}

/** Helper to create denied rate limit result */
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
  use: "sig";
  kid: string;
}

/** RSA public key in JWK format */
export interface RSAPublicKeyJWK extends JWKBase {
  kty: "RSA";
  alg: "RS256" | "RS384" | "RS512";
  /** Modulus */
  n: string;
  /** Exponent */
  e: string;
}

/** EC public key in JWK format */
export interface ECPublicKeyJWK extends JWKBase {
  kty: "EC";
  alg: "ES256" | "ES384" | "ES512";
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
  keys: JWK[];
}

/** Legacy JWK type for backward compatibility with existing code */
export interface LegacyJWK {
  kty: string;
  alg: string;
  use: string;
  kid: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  crv?: string;
}

/** Legacy JWKS response for backward compatibility */
export interface LegacyJWKSResponse {
  keys: LegacyJWK[];
}

// =============================================================================
// Signing Types
// =============================================================================

/** Result from signing operation */
export interface SigningResult {
  signature: string;
  keyId: KeyId;
  algorithm: string;
  fingerprint: KeyFingerprint;
}

/** Parsed key information */
export interface ParsedKeyInfo {
  keyId: KeyId;
  fingerprint: KeyFingerprint;
  algorithm: string;
  userId: string;
}
