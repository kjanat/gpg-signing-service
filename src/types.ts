import type { Context } from 'hono';

// Context variables (for c.set/c.get)
export interface Variables {
  oidcClaims: OIDCClaims;
  identity: string;
}

// Environment bindings
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

  // Secrets
  KEY_PASSPHRASE: string;
  ADMIN_TOKEN: string;
}

// Hono context with env bindings and variables
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;

// OIDC token claims
export interface OIDCClaims {
  iss: string;           // Issuer URL
  sub: string;           // Subject (repository or project)
  aud: string | string[]; // Audience
  exp: number;           // Expiration
  iat: number;           // Issued at

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

// Sign request
export interface SignRequest {
  commitData: string;
  keyId?: string;
}

// Sign response
export interface SignResponse {
  signature: string;
  keyId: string;
  algorithm: string;
}

// Error response
export interface ErrorResponse {
  error: string;
  code: string;
  requestId?: string;
}

// Audit log entry
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  requestId: string;
  action: 'sign' | 'key_upload' | 'key_rotate';
  issuer: string;
  subject: string;
  keyId: string;
  success: boolean;
  errorCode?: string;
  metadata?: string;
}

// Key storage data
export interface StoredKey {
  armoredPrivateKey: string;
  keyId: string;
  fingerprint: string;
  createdAt: string;
  algorithm: string;
}

// Rate limit result
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

// Health check response
export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  checks: {
    keyStorage: boolean;
    database: boolean;
  };
}

// Admin key upload request
export interface KeyUploadRequest {
  armoredPrivateKey: string;
  keyId: string;
}

// JWKS response
export interface JWKSResponse {
  keys: Array<{
    kty: string;
    alg: string;
    use: string;
    kid: string;
    n?: string;
    e?: string;
    x?: string;
    y?: string;
    crv?: string;
  }>;
}
