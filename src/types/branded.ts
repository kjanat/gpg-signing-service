/**
 * Branded types for security-critical strings
 */

import { LIMITS } from "~/utils/constants";

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
  if (
    value.length < LIMITS.MIN_KEY_SIZE ||
    value.length > LIMITS.MAX_KEY_SIZE
  ) {
    throw new Error(`Invalid ArmoredPrivateKey length: ${value.length}`);
  }
  return value as ArmoredPrivateKey;
}

/** Helper function to create validated identity */
export function createIdentity(issuer: string, subject: string): Identity {
  return `${issuer}:${subject}` as Identity;
}
