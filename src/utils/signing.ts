import * as openpgp from "openpgp";
import type { StoredKey } from "~/schemas/keys";
import type { ArmoredPrivateKey, ParsedKeyInfo, SigningResult } from "~/types";
import {
  createArmoredPrivateKey,
  createKeyFingerprint,
  createKeyId,
} from "~/types";

// Re-export types for convenience
export type { ParsedKeyInfo, SigningResult };

export async function signCommitData(
  commitData: string,
  storedKey: StoredKey,
  passphrase: string,
): Promise<SigningResult> {
  // Read the encrypted private key
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: storedKey.armoredPrivateKey,
  });

  // Decrypt if passphrase protected
  let decryptedKey = privateKey;
  if (!privateKey.isDecrypted()) {
    decryptedKey = await openpgp.decryptKey({ privateKey, passphrase });
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

  const algorithm =
    algorithmMap[keyPacket.algorithm] || `Unknown(${keyPacket.algorithm})`;

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
