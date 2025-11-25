/**
 * GPG signing operation types
 */

import type { KeyFingerprint, KeyId } from "./branded";

/** Result from signing operation */
export interface SigningResult {
  /** Detached signature */
  signature: string;
  /** Key ID */
  keyId: KeyId;
  /** Algorithm */
  algorithm: string;
  /** Fingerprint */
  fingerprint: KeyFingerprint;
}

/** Parsed key information */
export interface ParsedKeyInfo {
  /** Key ID */
  keyId: KeyId;
  /** Fingerprint */
  fingerprint: KeyFingerprint;
  /** Algorithm */
  algorithm: string;
  /** User ID */
  userId: string;
}

/** Unvalidated key upload request (from API) */
export interface KeyUploadRequest {
  armoredPrivateKey: string;
  keyId: string;
}
