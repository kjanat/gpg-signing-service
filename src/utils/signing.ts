/**
 * @fileoverview OpenPGP signing utilities for Git commit data.
 *
 * This module provides functions for signing Git commit data using OpenPGP
 * private keys. It uses openpgp.js v6 for cryptographic operations and
 * implements caching for decrypted keys to optimize performance.
 *
 * @see {@link https://openpgpjs.org/} - OpenPGP.js documentation
 * @see {@link https://datatracker.ietf.org/doc/html/rfc4880} - RFC 4880 (OpenPGP)
 *
 * @module utils/signing
 */

import * as openpgp from "openpgp";
import type { StoredKey } from "~/schemas/keys";
import type { ArmoredPrivateKey, ParsedKeyInfo, SigningResult } from "~/types";
import {
  createArmoredPrivateKey,
  createKeyFingerprint,
  createKeyId,
} from "~/types";
import { DecryptedKeyCache } from "./key-cache";

// Re-export types for convenience
export type { ParsedKeyInfo, SigningResult };

/**
 * Module-level cache instance for decrypted keys.
 * Safe in Workers: each V8 isolate has its own instance.
 * Keys are cached for the lifetime of the isolate (~50ms after request).
 */
const decryptedKeyCache = new DecryptedKeyCache();

/**
 * Signs Git commit data using an OpenPGP private key.
 *
 * This function creates a detached ASCII-armored GPG signature compatible with
 * `git verify-commit`. The signature is generated using the stored private key,
 * which is decrypted with the provided passphrase.
 *
 * Performance optimizations:
 * - Decrypted keys are cached in memory to avoid repeated decryption
 * - Cache is per-isolate and cleared when the Worker terminates
 *
 * @param commitData - Raw Git commit data (output of `git cat-file commit <ref>`)
 * @param storedKey - Stored key object containing the armored private key
 * @param passphrase - Passphrase to decrypt the private key
 * @returns Promise resolving to signing result with signature and key metadata
 *
 * @throws {Error} If key decryption fails (wrong passphrase)
 * @throws {Error} If signing operation fails
 *
 * @example
 * ```typescript
 * const result = await signCommitData(
 *   'tree abc123\nparent def456\nauthor ...',
 *   storedKey,
 *   'my-passphrase'
 * );
 * console.log(result.signature); // -----BEGIN PGP SIGNATURE-----...
 * ```
 */
export async function signCommitData(
  commitData: string,
  storedKey: StoredKey,
  passphrase: string,
): Promise<SigningResult> {
  // Try to get cached decrypted key first
  let decryptedKey = decryptedKeyCache.get(storedKey.keyId);

  if (!decryptedKey) {
    // Cache miss: parse and decrypt the key
    const privateKey = await openpgp.readPrivateKey({
      armoredKey: storedKey.armoredPrivateKey,
    });

    // Decrypt if passphrase protected
    decryptedKey = privateKey;
    if (!privateKey.isDecrypted()) {
      decryptedKey = await openpgp.decryptKey({ privateKey, passphrase });
    }

    // Cache the decrypted key for future requests
    decryptedKeyCache.set(storedKey.keyId, decryptedKey);
  }

  // Create message from commit data
  const message = await openpgp.createMessage({ text: commitData });

  // Create detached signature
  const signature = await openpgp.sign({
    message,
    signingKeys: decryptedKey,
    detached: true,
    format: "armored",
  });

  return {
    signature: signature as string,
    keyId: storedKey.keyId,
    algorithm: storedKey.algorithm,
    fingerprint: storedKey.fingerprint,
  };
}

/**
 * Parses and validates an ASCII-armored OpenPGP private key.
 *
 * This function extracts metadata from a private key and optionally validates
 * that the provided passphrase can decrypt it. Used during key upload to
 * verify key integrity and extract information for storage.
 *
 * @param armoredKey - ASCII-armored private key string
 * @param passphrase - Optional passphrase to verify decryption capability
 * @returns Promise resolving to parsed key information
 *
 * @throws {Error} If key format is invalid or cannot be parsed
 * @throws {Error} If passphrase is provided but incorrect
 *
 * @example
 * ```typescript
 * const keyInfo = await parseAndValidateKey(armoredKey, 'passphrase');
 * console.log(keyInfo.fingerprint); // 1234567890ABCDEF...
 * console.log(keyInfo.algorithm);   // EdDSA
 * ```
 */
export async function parseAndValidateKey(
  armoredKey: string,
  passphrase?: string,
): Promise<ParsedKeyInfo> {
  const privateKey = await openpgp.readPrivateKey({ armoredKey });

  // Verify we can decrypt if passphrase provided
  if (passphrase && !privateKey.isDecrypted()) {
    await openpgp.decryptKey({ privateKey, passphrase });
  }

  const keyPacket = privateKey.keyPacket;
  const fingerprint = createKeyFingerprint(privateKey.getFingerprint());
  const keyId = createKeyId(privateKey.getKeyID().toHex().toUpperCase());

  /**
   * Get algorithm name
   *
   * @link https://datatracker.ietf.org/doc/html/rfc4880#section-9.1
   */
  const algorithmMap: Record<number, string> = {
    1: "RSA", // RSA Encrypt or Sign
    2: "RSA-E", // RSA Encrypt-Only
    3: "RSA-S", // RSA Sign-Only
    16: "Elgamal", // Encrypt-Only
    17: "DSA", // Digital Signature Algorithm
    18: "ECDH", // Reserved for Elliptic Curve
    19: "ECDSA", // Reserved for ECDSA
    22: "EdDSA",
  };

  const algorithm = algorithmMap[keyPacket.algorithm]
    || `Unknown(${keyPacket.algorithm})`;

  // Get user ID
  const userIds = privateKey.getUserIDs();
  const userId = userIds[0] || "Unknown";

  return { keyId, fingerprint, algorithm, userId };
}

/**
 * Extracts the public key component from an ASCII-armored private key.
 *
 * This function derives the public key from a private key without requiring
 * decryption (passphrase not needed). The resulting public key can be
 * distributed for signature verification.
 *
 * @param armoredPrivateKey - ASCII-armored private key string
 * @returns Promise resolving to ASCII-armored public key string
 *
 * @throws {Error} If private key format is invalid
 *
 * @example
 * ```typescript
 * const publicKey = await extractPublicKey(armoredPrivateKey);
 * console.log(publicKey); // -----BEGIN PGP PUBLIC KEY BLOCK-----...
 * ```
 */
export async function extractPublicKey(
  armoredPrivateKey: ArmoredPrivateKey | string,
): Promise<string> {
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: armoredPrivateKey,
  });
  return privateKey.toPublic().armor();
}

/**
 * Create a StoredKey from raw input data
 */
export function createStoredKey(
  armoredPrivateKey: string,
  keyId: string,
  fingerprint: string,
  algorithm: string,
): StoredKey {
  return {
    armoredPrivateKey: createArmoredPrivateKey(armoredPrivateKey),
    keyId: createKeyId(keyId),
    fingerprint: createKeyFingerprint(fingerprint),
    createdAt: new Date().toISOString(),
    algorithm,
  };
}

/**
 * Invalidate a specific key from the decrypted key cache
 * Call this when a key is rotated or deleted
 */
export function invalidateKeyCache(keyId: string): void {
  decryptedKeyCache.invalidate(keyId);
}

/**
 * Clear the entire decrypted key cache
 * Call this on service restart or security events
 */
export function clearKeyCache(): void {
  decryptedKeyCache.clear();
}

/**
 * Get cache statistics for monitoring
 */
export function getKeyCacheStats(): { size: number; ttl: number } {
  return decryptedKeyCache.stats();
}
