import { z } from "@hono/zod-openapi";
import {
  createArmoredPrivateKey,
  createKeyFingerprint,
  createKeyId,
} from "~/types";
import { LIMITS } from "~/utils/constants";

/**
 * GPG Key ID validation
 * - Must be exactly 16 hexadecimal characters
 * - Case-insensitive input, normalized to uppercase
 * - Returns branded KeyId type
 */
export const KeyIdSchema = z
  .string()
  .length(16, "Key ID must be exactly 16 characters")
  .regex(/^[A-Fa-f0-9]{16}$/, "Key ID must be 16 hexadecimal characters")
  .transform((s) => createKeyId(s.toUpperCase()));

/**
 * GPG Key fingerprint validation
 * - Must be exactly 40 hexadecimal characters
 * - Case-insensitive input, normalized to uppercase
 * - Returns branded KeyFingerprint type
 */
export const FingerprintSchema = z
  .string()
  .length(40, "Fingerprint must be exactly 40 characters")
  .regex(/^[A-Fa-f0-9]{40}$/, "Fingerprint must be 40 hexadecimal characters")
  .transform((s) => createKeyFingerprint(s.toUpperCase()));

/**
 * Validates PGP armored private key block
 * - Supports standard PGP header/footer variations
 * - Enforces realistic size limits (350-10,000 chars based on Ed25519 to RSA 4096)
 * - Validates structure (header, base64 body, checksum, footer)
 * - Returns branded Armore dPrivateKey type
 */
export const ArmoredPrivateKeySchema = z
  .string()
  .min(100, "Private key too short - minimum 100 characters")
  .max(
    LIMITS.MAX_KEY_SIZE,
    `Private key too large - maximum ${LIMITS.MAX_KEY_SIZE} characters`,
  )
  .refine(
    (val) => {
      // Match standard PGP private key block headers
      const headerPattern = /^-----BEGIN PGP PRIVATE KEY BLOCK-----/m;
      const footerPattern = /-----END PGP PRIVATE KEY BLOCK-----$/m;

      return headerPattern.test(val) && footerPattern.test(val);
    },
    {
      message: "Must be a valid PGP armored private key with BEGIN/END markers",
    },
  )
  .refine(
    (val) => {
      // Validate structure: header -> optional armor headers -> blank line -> base64 -> checksum -> footer
      const lines = val.split("\n");

      // Must have at least: header, blank, data, checksum, footer (5 lines minimum)
      if (lines.length < 5) return false;

      // First line must be header
      if (!lines[0]?.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
        return false;
      }

      // Last line must be footer (trim to handle trailing newline)
      const lastLine = lines[lines.length - 1]?.trim()
        || lines[lines.length - 2]?.trim();
      if (!lastLine?.startsWith("-----END PGP PRIVATE KEY BLOCK-----")) {
        return false;
      }

      // Must contain at least one base64 line (alphanumeric + / + = chars)
      const hasBase64 = lines.some((line) =>
        /^[A-Za-z0-9+/=]{1,76}$/.test(line.trim())
      );
      if (!hasBase64) return false;

      // Should contain checksum line (starts with '=')
      const hasChecksum = lines.some((line) =>
        /^=[A-Za-z0-9+/=]{4}$/.test(line.trim())
      );

      return hasChecksum;
    },
    {
      message:
        "Invalid PGP armored format - must include base64 data and checksum",
    },
  )
  .transform(createArmoredPrivateKey);

/**
 * Key upload request schema
 */
export const KeyUploadSchema = z
  .object({ armoredPrivateKey: ArmoredPrivateKeySchema, keyId: KeyIdSchema })
  .openapi("KeyUpload");

/**
 * Key response schema
 */
export const KeyResponseSchema = z
  .object({
    success: z.boolean().optional(),
    keyId: KeyIdSchema,
    fingerprint: FingerprintSchema,
    algorithm: z.string(),
    userId: z.string(),
  })
  .openapi("KeyResponse");

/**
 * Stored key schema
 * Represents a key stored in Durable Object storage
 */
export const StoredKeySchema = z.object({
  armoredPrivateKey: ArmoredPrivateKeySchema,
  keyId: KeyIdSchema,
  fingerprint: FingerprintSchema,
  createdAt: z.iso.datetime({ offset: true }),
  algorithm: z.string().min(1),
});

/** Type inferred from StoredKeySchema */
export type StoredKey = z.infer<typeof StoredKeySchema>;

/**
 * Public key response schema (PGP armored public key)
 */
export const PublicKeyResponseSchema = z.string().openapi("PublicKeyResponse", {
  example: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
});

/**
 * Key list item schema
 */
export const KeyListItemSchema = z
  .object({
    keyId: z.string(),
    fingerprint: z.string(),
    createdAt: z.string(),
    algorithm: z.string(),
  })
  .openapi("KeyListItem");

/**
 * Key list response schema
 */
export const KeyListResponseSchema = z
  .object({ keys: z.array(KeyListItemSchema) })
  .openapi("KeyListResponse");

/**
 * Key deletion response schema
 */
export const KeyDeletionResponseSchema = z
  .object({ success: z.boolean(), deleted: z.boolean() })
  .openapi("KeyDeletionResponse");
