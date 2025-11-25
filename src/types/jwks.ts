/**
 * JWKS (JSON Web Key Set) types for JWT verification
 */

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
