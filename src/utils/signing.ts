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

// Module-level cache instance for decrypted keys
// Safe in Workers: each isolate has its own instance
const decryptedKeyCache = new DecryptedKeyCache();

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
