/**
 * Application configuration constants
 * These may be adjusted based on performance tuning and business requirements
 *
 * For immutable protocol-level constants, see:
 * - ~/types/time (TIME)
 * - ~/types/headers (HEADERS)
 * - ~/types/media-types (MediaType)
 */

import { TIME } from "~/types/time";

// =============================================================================
// Cache TTL (Configurable for performance tuning)
// =============================================================================

/**
 * Cache time-to-live settings
 * These can be adjusted based on OIDC provider reliability and performance needs
 */
export const CACHE_TTL = {
  /** JWKS cache duration - balance between freshness and performance */
  JWKS: 5 * TIME.MINUTE, // Could be increased if OIDC provider is highly reliable
} as const;

// =============================================================================
// Validation Limits (Configurable business constraints)
// =============================================================================

/**
 * Size and count limits for validation
 * These can be adjusted based on deployment scale and requirements
 */
export const LIMITS = {
  /** Maximum GPG key size in characters */
  MAX_KEY_SIZE: 10_000, // Could be increased for larger key types (e.g., RSA 8192)

  /** Minimum GPG key size in characters */
  MIN_KEY_SIZE: 350, // Based on Ed25519 minimum size

  /** Maximum number of audit logs to return in a single query */
  MAX_AUDIT_LOGS: 1000, // Could be increased for larger deployments with pagination
} as const;
