import { z } from "@hono/zod-openapi";
import {
  createArmoredPrivateKey,
  createKeyFingerprint,
  createKeyId,
} from "~/types";

/**
 * GPG Key ID validation
 * - Must be exactly 16 hexadecimal characters
 * - Case-insensitive input, normalized to uppercase
 * - Returns branded KeyId type
 */
export const KeyIdSchema = z
  .string()
  .length(16, "Key ID must be exactly 16 characters")
  .regex(/^[A-F0-9]{16}$/i, "Key ID must be 16 hexadecimal characters")
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
  .regex(/^[A-F0-9]{40}$/i, "Fingerprint must be 40 hexadecimal characters")
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
  .min(350, "Private key too short - minimum 350 characters")
  .max(10_000, "Private key too large - maximum 10,000 characters")
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
export const KeyUploadSchema = z.object({
  armoredPrivateKey: z.string().openapi({
    example: "-----BEGIN PGP PRIVATE KEY BLOCK-----\\n...",
  }),
  keyId: z.string().openapi({
    example: "A1B2C3D4E5F6G7H8",
  }),
});

/**
 * Key response schema
 */
export const KeyResponseSchema = z.object({
  success: z.boolean(),
  keyId: z.string(),
  fingerprint: z.string(),
  algorithm: z.string(),
  userId: z.string(),
});

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
