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
export function createKeyId(value: string): KeyId {
  return value as KeyId;
}

export function createKeyFingerprint(value: string): KeyFingerprint {
  return value.toUpperCase() as KeyFingerprint;
}

export function createArmoredPrivateKey(value: string): ArmoredPrivateKey {
  return value as ArmoredPrivateKey;
}

export function createIdentity(issuer: string, subject: string): Identity {
  return `${issuer}:${subject}` as Identity;
}

// =============================================================================
// Error Codes
// =============================================================================

/** All valid error codes used in the codebase */
export type ErrorCode =
  // Authentication errors
  | "AUTH_MISSING"
  | "AUTH_INVALID"
  // Key management errors
  | "KEY_NOT_FOUND"
  | "KEY_PROCESSING_ERROR"
  | "KEY_LIST_ERROR"
  | "KEY_UPLOAD_ERROR"
  | "KEY_DELETE_ERROR"
  // Signing errors
  | "SIGN_ERROR"
  // Rate limiting
  | "RATE_LIMIT_ERROR"
  | "RATE_LIMITED"
  // General errors
  | "INVALID_REQUEST"
  | "AUDIT_ERROR"
  | "NOT_FOUND"
  | "INTERNAL_ERROR";

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
// Request/Response Types
// =============================================================================

/** Error response with typed error code */
export interface ErrorResponse {
  error: string;
  code: ErrorCode;
  requestId?: string;
}

// =============================================================================
// Audit Types
// =============================================================================

/** Audit action types */
export type AuditAction = "sign" | "key_upload" | "key_rotate";

/** Audit log entry */
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  requestId: string;
  action: AuditAction;
  issuer: string;
  subject: string;
  keyId: string;
  success: boolean;
  errorCode?: ErrorCode;
  metadata?: string;
}

// =============================================================================
// Key Storage Types
// =============================================================================

/** Key storage data with branded types */
export interface StoredKey {
  armoredPrivateKey: ArmoredPrivateKey;
  keyId: KeyId;
  fingerprint: KeyFingerprint;
  createdAt: string;
  algorithm: string;
}

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
// Health Check Types
// =============================================================================

/** Health status levels */
export type HealthStatus = "healthy" | "degraded";

/** Health check response */
export interface HealthResponse {
  status: HealthStatus;
  timestamp: string;
  version: string;
  checks: { keyStorage: boolean; database: boolean };
}

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
