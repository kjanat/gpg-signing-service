/**
 * OIDC (OpenID Connect) authentication types
 */

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

/** Marker interface for OIDC claims that have passed validation */
export interface ValidatedOIDCClaims extends OIDCClaims {
  readonly __validated: true;
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
