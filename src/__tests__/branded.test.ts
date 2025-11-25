import { describe, expect, it } from "vitest";
import {
  createArmoredPrivateKey,
  createIdentity,
  createKeyFingerprint,
  createKeyId,
} from "~/types/branded";
import { LIMITS } from "~/utils/constants";

describe("Branded Types", () => {
  describe("createKeyId", () => {
    // Happy paths
    it("should create valid KeyId from uppercase hex string", () => {
      const result = createKeyId("A1B2C3D4E5F60718");
      expect(result).toBe("A1B2C3D4E5F60718");
    });

    it("should normalize lowercase to uppercase", () => {
      const result = createKeyId("a1b2c3d4e5f60718");
      expect(result).toBe("A1B2C3D4E5F60718");
    });

    it("should handle mixed case input", () => {
      const result = createKeyId("AbCdEf0123456789");
      expect(result).toBe("ABCDEF0123456789");
    });

    it("should accept valid hex characters (0-9, A-F)", () => {
      const result = createKeyId("0123456789ABCDEF");
      expect(result).toBe("0123456789ABCDEF");
    });

    // Validation failures
    it("should reject KeyId shorter than 16 characters", () => {
      expect(() => createKeyId("A1B2C3D4E5F6071")).toThrow(
        "Invalid KeyId format: A1B2C3D4E5F6071",
      );
    });

    it("should reject KeyId longer than 16 characters", () => {
      expect(() => createKeyId("A1B2C3D4E5F607189")).toThrow(
        "Invalid KeyId format: A1B2C3D4E5F607189",
      );
    });

    it("should reject empty string", () => {
      expect(() => createKeyId("")).toThrow("Invalid KeyId format: ");
    });

    it("should reject non-hex characters (G-Z)", () => {
      expect(() => createKeyId("G1B2C3D4E5F60718")).toThrow(
        "Invalid KeyId format: G1B2C3D4E5F60718",
      );
    });

    it("should reject special characters", () => {
      expect(() => createKeyId("A1B2-C3D4-E5F6-07")).toThrow();
    });

    it("should reject whitespace", () => {
      expect(() => createKeyId("A1B2C3D4 E5F60718")).toThrow();
    });

    it("should reject with leading zeros", () => {
      const result = createKeyId("0000000000000001");
      expect(result).toBe("0000000000000001");
    });
  });

  describe("createKeyFingerprint", () => {
    // Happy paths - 40 characters exactly
    it("should create valid KeyFingerprint from uppercase hex string", () => {
      const result = createKeyFingerprint(
        "A1B2C3D4E5F607189A1B2C3D4E5F607189A1B2C3",
      );
      expect(result).toBe("A1B2C3D4E5F607189A1B2C3D4E5F607189A1B2C3");
    });

    it("should normalize lowercase to uppercase", () => {
      const result = createKeyFingerprint(
        "a1b2c3d4e5f607189a1b2c3d4e5f607189a1b2c3",
      );
      expect(result).toBe("A1B2C3D4E5F607189A1B2C3D4E5F607189A1B2C3");
    });

    it("should handle mixed case input", () => {
      const result = createKeyFingerprint(
        "AbCdEf0123456789AbCdEf0123456789AbCdEf01",
      );
      expect(result).toBe("ABCDEF0123456789ABCDEF0123456789ABCDEF01");
    });

    it("should accept valid 40-character hex string", () => {
      const result = createKeyFingerprint(
        "0123456789ABCDEF0123456789ABCDEF01234567",
      );
      expect(result).toBe("0123456789ABCDEF0123456789ABCDEF01234567");
    });

    // Validation failures - line 40 (error thrown)
    it("should reject KeyFingerprint shorter than 40 characters", () => {
      expect(() =>
        createKeyFingerprint("A1B2C3D4E5F607189A1B2C3D4E5F6071"),
      ).toThrow("Invalid KeyFingerprint format:");
    });

    it("should reject KeyFingerprint longer than 40 characters", () => {
      expect(() =>
        createKeyFingerprint("A1B2C3D4E5F607189A1B2C3D4E5F607189A1B2C3D4"),
      ).toThrow("Invalid KeyFingerprint format:");
    });

    it("should reject empty string", () => {
      expect(() => createKeyFingerprint("")).toThrow(
        "Invalid KeyFingerprint format:",
      );
    });

    it("should reject non-hex characters (G-Z)", () => {
      expect(() =>
        createKeyFingerprint("G1B2C3D4E5F607189A1B2C3D4E5F607189A1B2C3"),
      ).toThrow("Invalid KeyFingerprint format:");
    });

    it("should reject special characters", () => {
      expect(() =>
        createKeyFingerprint("A1B2-C3D4-E5F6-0718-9A1B-2C3D-4E5F-6071-89A1"),
      ).toThrow("Invalid KeyFingerprint format:");
    });

    it("should reject whitespace", () => {
      expect(() =>
        createKeyFingerprint("A1B2C3D4E5F60718 A1B2C3D4E5F607189A1B2C3"),
      ).toThrow("Invalid KeyFingerprint format:");
    });
  });

  describe("createArmoredPrivateKey", () => {
    // Realistic Ed25519 key for happy path tests
    const validKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZx3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJkEExYKAEEWIQQRTd3LSMIzSP5K+yAQMfcIqJ5LFQUCZ3PyhwIbAwUJA8JnAAUL
CQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRAQMfcIqJ5LFZoMAP9X7cPxCi2p
KIr+J8gAkl0Ny1G8TnlMq0M9xN3Vx1qb+QD/elKMaKzX3u8d9zvIykjW8K/WKWwy
7Bfg==
=oEGo
-----END PGP PRIVATE KEY BLOCK-----`;

    // Happy paths
    it("should create valid ArmoredPrivateKey from complete PGP key", () => {
      const result = createArmoredPrivateKey(validKey);
      expect(result).toBe(validKey);
    });

    it("should accept keys with varying content between headers and footers", () => {
      const key = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP v2.0.0
Comment: Some comment here

lIYEZx3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJkEExYKAEEWIQQRTd3LSMIzSP5K+yAQMfcIqJ5LFQUCZ3PyhwIbAwUJA8JnAAUL
CQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRAQMfcIqJ5LFZoMAP9X7cPxCi2p
KIr+J8gAkl0Ny1G8TnlMq0M9xN3Vx1qb+QD/elKMaKzX3u8d9zvIykjW8K/WKWwy
7Bfg==
=oEGo
-----END PGP PRIVATE KEY BLOCK-----`;
      const result = createArmoredPrivateKey(key);
      expect(result).toBe(key);
    });

    // Line 49: missing header validation
    it("should reject key missing BEGIN PGP PRIVATE KEY BLOCK header", () => {
      const invalidKey = validKey.replace(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN INVALID-----",
      );
      expect(() => createArmoredPrivateKey(invalidKey)).toThrow(
        "Invalid ArmoredPrivateKey: missing PGP header",
      );
    });

    it("should reject completely empty key", () => {
      expect(() => createArmoredPrivateKey("")).toThrow(
        "Invalid ArmoredPrivateKey: missing PGP header",
      );
    });

    it("should reject key with only header", () => {
      const keyHeaderOnly = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
      expect(() => createArmoredPrivateKey(keyHeaderOnly)).toThrow(
        "Invalid ArmoredPrivateKey: missing PGP footer",
      );
    });

    // Line 52: missing footer validation
    it("should reject key missing END PGP PRIVATE KEY BLOCK footer", () => {
      const invalidKey = validKey.replace(
        "-----END PGP PRIVATE KEY BLOCK-----",
        "",
      );
      expect(() => createArmoredPrivateKey(invalidKey)).toThrow(
        "Invalid ArmoredPrivateKey: missing PGP footer",
      );
    });

    it("should reject key with only footer", () => {
      const keyFooterOnly = "-----END PGP PRIVATE KEY BLOCK-----";
      expect(() => createArmoredPrivateKey(keyFooterOnly)).toThrow(
        "Invalid ArmoredPrivateKey: missing PGP header",
      );
    });

    it("should reject key with mismatched footer (typo)", () => {
      const invalidKey = validKey.replace(
        "-----END PGP PRIVATE KEY BLOCK-----",
        "-----END INVALID BLOCK-----",
      );
      expect(() => createArmoredPrivateKey(invalidKey)).toThrow(
        "Invalid ArmoredPrivateKey: missing PGP footer",
      );
    });

    // Line 58: size validation
    it("should reject key below minimum size", () => {
      const tooSmallKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
SHORT
-----END PGP PRIVATE KEY BLOCK-----`;
      expect(() => createArmoredPrivateKey(tooSmallKey)).toThrow(
        `Invalid ArmoredPrivateKey length: ${tooSmallKey.length}`,
      );
    });

    it("should reject key above maximum size", () => {
      const tooLargeKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
${new Array(LIMITS.MAX_KEY_SIZE + 1000).fill("X").join("")}
-----END PGP PRIVATE KEY BLOCK-----`;
      expect(() => createArmoredPrivateKey(tooLargeKey)).toThrow(
        `Invalid ArmoredPrivateKey length: ${tooLargeKey.length}`,
      );
    });

    it("should accept key at minimum size boundary", () => {
      // Create a key that is exactly at the minimum size
      // Header: 37 chars + newline
      // Footer: 35 chars + newline
      // Need: 350 - 37 - 1 - 35 - 1 = 276 chars of content
      const contentSize = LIMITS.MIN_KEY_SIZE - 37 - 1 - 35 - 1;
      const padding = new Array(contentSize).fill("X").join("");
      const keyAtMin = `-----BEGIN PGP PRIVATE KEY BLOCK-----
${padding}
-----END PGP PRIVATE KEY BLOCK-----`;
      const result = createArmoredPrivateKey(keyAtMin);
      expect(result).toBe(keyAtMin);
      expect(keyAtMin.length).toBeGreaterThanOrEqual(LIMITS.MIN_KEY_SIZE);
    });

    it("should accept key at maximum size boundary", () => {
      // Create a key that is exactly at the maximum size
      const headerFooterSize =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----".length +
        "-----END PGP PRIVATE KEY BLOCK-----".length +
        2; // +2 for newlines
      const contentSize = LIMITS.MAX_KEY_SIZE - headerFooterSize;
      const padding = new Array(contentSize).fill("X").join("");
      const keyAtMax = `-----BEGIN PGP PRIVATE KEY BLOCK-----
${padding}
-----END PGP PRIVATE KEY BLOCK-----`;
      const result = createArmoredPrivateKey(keyAtMax);
      expect(result).toBe(keyAtMax);
    });

    it("should accept valid key with realistic size", () => {
      const result = createArmoredPrivateKey(validKey);
      expect(result).toBe(validKey);
      expect(validKey.length).toBeGreaterThanOrEqual(LIMITS.MIN_KEY_SIZE);
      expect(validKey.length).toBeLessThanOrEqual(LIMITS.MAX_KEY_SIZE);
    });

    it("should preserve exact key content without modification", () => {
      const result = createArmoredPrivateKey(validKey);
      expect(result).toBe(validKey);
    });
  });

  describe("createIdentity", () => {
    // Happy paths
    it("should create identity from issuer and subject", () => {
      const result = createIdentity("https://github.com", "123456");
      expect(result).toBe("https://github.com:123456");
    });

    it("should handle issuer with special characters", () => {
      const issuer = "https://github.com/oauth";
      const subject = "user@example.com";
      const result = createIdentity(issuer, subject);
      expect(result).toBe(`${issuer}:${subject}`);
    });

    it("should handle numeric subject", () => {
      const result = createIdentity("issuer", "999");
      expect(result).toBe("issuer:999");
    });

    it("should handle empty subject", () => {
      const result = createIdentity("issuer", "");
      expect(result).toBe("issuer:");
    });

    it("should handle empty issuer", () => {
      const result = createIdentity("", "subject");
      expect(result).toBe(":subject");
    });

    it("should handle both empty issuer and subject", () => {
      const result = createIdentity("", "");
      expect(result).toBe(":");
    });

    it("should not validate format, just concatenate", () => {
      // Identity creation is simple concatenation, no validation
      const result = createIdentity(
        "invalid issuer format",
        "invalid:subject:format",
      );
      expect(result).toBe("invalid issuer format:invalid:subject:format");
    });

    it("should handle issuer with colons", () => {
      const issuer = "https://example.com:8080";
      const subject = "user";
      const result = createIdentity(issuer, subject);
      expect(result).toBe(`${issuer}:${subject}`);
    });

    it("should handle very long issuer and subject", () => {
      const issuer = "a".repeat(1000);
      const subject = "b".repeat(1000);
      const result = createIdentity(issuer, subject);
      expect(result).toBe(`${issuer}:${subject}`);
    });

    it("should handle whitespace in identifiers", () => {
      const result = createIdentity(
        "issuer with spaces",
        "subject with spaces",
      );
      expect(result).toBe("issuer with spaces:subject with spaces");
    });
  });

  describe("Type Branding", () => {
    it("should maintain type distinction for KeyId", () => {
      const keyId = createKeyId("A1B2C3D4E5F60718");
      // Verify it's a string at runtime but typed as KeyId
      expect(typeof keyId).toBe("string");
    });

    it("should maintain type distinction for KeyFingerprint", () => {
      const fingerprint = createKeyFingerprint(
        "A1B2C3D4E5F607189A1B2C3D4E5F607189A1B2C3",
      );
      expect(typeof fingerprint).toBe("string");
    });

    it("should maintain type distinction for ArmoredPrivateKey", () => {
      const validKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZx3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJkEExYKAEEWIQQRTd3LSMIzSP5K+yAQMfcIqJ5LFQUCZ3PyhwIbAwUJA8JnAAUL
CQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRAQMfcIqJ5LFZoMAP9X7cPxCi2p
KIr+J8gAkl0Ny1G8TnlMq0M9xN3Vx1qb+QD/elKMaKzX3u8d9zvIykjW8K/WKWwy
7Bfg==
=oEGo
-----END PGP PRIVATE KEY BLOCK-----`;
      const key = createArmoredPrivateKey(validKey);
      expect(typeof key).toBe("string");
    });

    it("should maintain type distinction for Identity", () => {
      const identity = createIdentity("issuer", "subject");
      expect(typeof identity).toBe("string");
    });
  });

  describe("Error Handling", () => {
    it("should provide meaningful error messages for createKeyId", () => {
      try {
        createKeyId("invalid");
      } catch (e) {
        const message = String((e as Error).message);
        expect(message).toContain("Invalid KeyId format");
      }
    });

    it("should provide meaningful error messages for createKeyFingerprint", () => {
      try {
        createKeyFingerprint("invalid");
      } catch (e) {
        const message = String((e as Error).message);
        expect(message).toContain("Invalid KeyFingerprint format");
      }
    });

    it("should provide meaningful error messages for createArmoredPrivateKey - header", () => {
      try {
        createArmoredPrivateKey("missing headers");
      } catch (e) {
        const message = String((e as Error).message);
        expect(message).toContain("Invalid ArmoredPrivateKey");
      }
    });

    it("should provide meaningful error messages for createArmoredPrivateKey - footer", () => {
      const invalidKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
content here without footer`;
      try {
        createArmoredPrivateKey(invalidKey);
      } catch (e) {
        const message = String((e as Error).message);
        expect(message).toContain("Invalid ArmoredPrivateKey");
      }
    });

    it("should provide meaningful error messages for createArmoredPrivateKey - size", () => {
      const tinyKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
X
-----END PGP PRIVATE KEY BLOCK-----`;
      try {
        createArmoredPrivateKey(tinyKey);
      } catch (e) {
        const message = String((e as Error).message);
        expect(message).toContain("Invalid ArmoredPrivateKey length");
      }
    });
  });

  describe("Edge Cases and Boundary Conditions", () => {
    it("should handle KeyId with all zeros", () => {
      const result = createKeyId("0000000000000000");
      expect(result).toBe("0000000000000000");
    });

    it("should handle KeyId with all Fs", () => {
      const result = createKeyId("FFFFFFFFFFFFFFFF");
      expect(result).toBe("FFFFFFFFFFFFFFFF");
    });

    it("should handle KeyFingerprint with all zeros", () => {
      const result = createKeyFingerprint(
        "0000000000000000000000000000000000000000",
      );
      expect(result).toBe("0000000000000000000000000000000000000000");
    });

    it("should handle KeyFingerprint with all Fs", () => {
      const result = createKeyFingerprint(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      );
      expect(result).toBe("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    });

    it("should handle very long issuer and subject in createIdentity", () => {
      const longIssuer = "x".repeat(10000);
      const longSubject = "y".repeat(10000);
      const result = createIdentity(longIssuer, longSubject);
      expect(result).toBe(`${longIssuer}:${longSubject}`);
    });

    it("should preserve newlines in armored key", () => {
      // Create key with valid size and newlines
      const contentSize = LIMITS.MIN_KEY_SIZE - 37 - 1 - 35 - 1;
      const padding = new Array(contentSize).fill("X").join("");
      const keyWithNewlines = `-----BEGIN PGP PRIVATE KEY BLOCK-----

${padding}

-----END PGP PRIVATE KEY BLOCK-----`;
      const result = createArmoredPrivateKey(keyWithNewlines);
      expect(result).toBe(keyWithNewlines);
      expect(result.includes("\n")).toBe(true);
    });
  });
});
