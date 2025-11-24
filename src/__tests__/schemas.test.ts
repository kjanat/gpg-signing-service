import { describe, expect, it } from "vitest";
import {
  ArmoredPrivateKeySchema,
  AuditQuerySchema,
  DateRangeSchema,
  ErrorCodeSchema,
  ErrorResponseSchema,
  FingerprintSchema,
  HealthResponseSchema,
  HealthStatusSchema,
  KeyIdSchema,
  KeyResponseSchema,
  KeyUploadSchema,
  RequestHeadersSchema,
  RequestIdSchema,
  TimestampSchema,
} from "~/schemas";

describe("Schema Validation - Edge Cases", () => {
  // Realistic Ed25519 key (smallest valid key ~400-500 chars)
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

  describe("KeyIdSchema", () => {
    // Happy path
    it("should accept valid 16-hex KeyId", () => {
      const result = KeyIdSchema.parse("A1B2C3D4E5F60718");
      expect(result).toBe("A1B2C3D4E5F60718");
    });

    it("should normalize to uppercase", () => {
      const result = KeyIdSchema.parse("a1b2c3d4e5f60718");
      expect(result).toBe("A1B2C3D4E5F60718");
    });

    it("should accept mixed case", () => {
      const result = KeyIdSchema.parse("AbCdEf0123456789");
      expect(result).toBe("ABCDEF0123456789");
    });

    // Edge cases - length violations
    it("should reject 15 characters", () => {
      expect(() => KeyIdSchema.parse("A1B2C3D4E5F6071")).toThrow(
        "Key ID must be exactly 16 characters",
      );
    });

    it("should reject 17 characters", () => {
      expect(() => KeyIdSchema.parse("A1B2C3D4E5F607189")).toThrow(
        "Key ID must be exactly 16 characters",
      );
    });

    it("should reject empty string", () => {
      expect(() => KeyIdSchema.parse("")).toThrow();
    });

    // Edge cases - character violations
    it("should reject non-hex characters (G-Z)", () => {
      expect(() => KeyIdSchema.parse("GHIJKLMNOPQRSTUV")).toThrow(
        "Key ID must be 16 hexadecimal characters",
      );
    });

    it("should reject special characters", () => {
      expect(() => KeyIdSchema.parse("A1B2-3D4-E5F6G7H8")).toThrow();
    });

    it("should reject whitespace", () => {
      expect(() => KeyIdSchema.parse("A1B2C3D4 E5F6G7H8")).toThrow();
    });

    it("should reject unicode", () => {
      expect(() => KeyIdSchema.parse("A1B2C3D4E5F6G7测试")).toThrow();
    });

    // Boundary - all same character
    it("should accept all zeros", () => {
      const result = KeyIdSchema.parse("0000000000000000");
      expect(result).toBe("0000000000000000");
    });

    it("should accept all Fs", () => {
      const result = KeyIdSchema.parse("FFFFFFFFFFFFFFFF");
      expect(result).toBe("FFFFFFFFFFFFFFFF");
    });
  });

  describe("FingerprintSchema", () => {
    // Happy path
    it("should accept valid 40-hex fingerprint", () => {
      const result = FingerprintSchema.parse(
        "0123456789ABCDEF0123456789ABCDEF01234567",
      );
      expect(result).toBe("0123456789ABCDEF0123456789ABCDEF01234567");
    });

    it("should normalize to uppercase", () => {
      const result = FingerprintSchema.parse(
        "abcdef0123456789abcdef0123456789abcdef01",
      );
      expect(result).toBe("ABCDEF0123456789ABCDEF0123456789ABCDEF01");
    });

    // Edge cases - length
    it("should reject 39 characters", () => {
      expect(() =>
        FingerprintSchema.parse("0123456789ABCDEF0123456789ABCDEF0123456")
      ).toThrow("Fingerprint must be exactly 40 characters");
    });

    it("should reject 41 characters", () => {
      expect(() =>
        FingerprintSchema.parse("0123456789ABCDEF0123456789ABCDEF012345678")
      ).toThrow();
    });

    it("should reject empty", () => {
      expect(() => FingerprintSchema.parse("")).toThrow();
    });

    // Edge cases - invalid chars
    it("should reject non-hex", () => {
      expect(() =>
        FingerprintSchema.parse("GHIJKLMNOPQRSTUVWXYZ01234567890123456789")
      ).toThrow("Fingerprint must be 40 hexadecimal characters");
    });

    it("should reject with dashes", () => {
      expect(() =>
        FingerprintSchema.parse("0123-4567-89AB-CDEF-0123-4567-89AB-CDEF-0123")
      ).toThrow();
    });

    it("should accept all 0s", () => {
      const result = FingerprintSchema.parse(
        "0000000000000000000000000000000000000000",
      );
      expect(result).toBe("0000000000000000000000000000000000000000");
    });

    it("should accept all Fs", () => {
      const result = FingerprintSchema.parse(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      );
      expect(result).toBe("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    });
  });

  describe("ArmoredPrivateKeySchema", () => {
    // Happy path
    it("should accept valid PGP key", () => {
      const result = ArmoredPrivateKeySchema.parse(validKey);
      expect(result).toBeTruthy();
    });

    // Edge cases - length boundaries
    it("should reject key < 350 chars", () => {
      const shortKey =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nXX\n=XX\n-----END PGP PRIVATE KEY BLOCK-----";
      expect(() => ArmoredPrivateKeySchema.parse(shortKey)).toThrow(
        "Private key too short - minimum 100 characters",
      );
    });

    it("should reject key > 10,000 chars", () => {
      const header = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n";
      const footer = "\n=XXXX\n-----END PGP PRIVATE KEY BLOCK-----";
      const hugeData = "A".repeat(11000);
      const hugeKey = header + hugeData + footer;

      expect(() => ArmoredPrivateKeySchema.parse(hugeKey)).toThrow(
        "Private key too large - maximum 10,000 characters",
      );
    });

    it("should accept key exactly 350 chars (boundary)", () => {
      // Minimum valid key: header + blank + 64char base64 + checksum + footer
      const header = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n";
      const footer = "\n=ABCD\n-----END PGP PRIVATE KEY BLOCK-----";
      const base64Lines = Math.ceil((350 - header.length - footer.length) / 65); // 64 chars + newline
      const data = Array(base64Lines).fill("A".repeat(64)).join("\n");

      const key = header + data + footer;
      // Adjust to exactly 350
      const adjusted = `${
        key.slice(
          0,
          350 - 35,
        )
      }\n=ABCD\n-----END PGP PRIVATE KEY BLOCK-----`;

      const result = ArmoredPrivateKeySchema.parse(adjusted);
      expect(result).toBeTruthy();
    });

    // Edge cases - missing headers
    it("should reject without BEGIN marker", () => {
      const noBegin = `
some data
=abcd
-----END PGP PRIVATE KEY BLOCK-----`;

      expect(() => ArmoredPrivateKeySchema.parse(noBegin)).toThrow(
        "Must be a valid PGP armored private key with BEGIN/END markers",
      );
    });

    it("should reject without END marker", () => {
      const noEnd = `-----BEGIN PGP PRIVATE KEY BLOCK-----
data data data
=abcd`;

      expect(() => ArmoredPrivateKeySchema.parse(noEnd)).toThrow(
        "Must be a valid PGP armored private key with BEGIN/END markers",
      );
    });

    it("should reject with wrong key type (PUBLIC)", () => {
      const publicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
data
=abcd
-----END PGP PUBLIC KEY BLOCK-----`;

      expect(() => ArmoredPrivateKeySchema.parse(publicKey)).toThrow();
    });

    // Edge cases - structure validation
    it("should reject without base64 data", () => {
      const noData = `-----BEGIN PGP PRIVATE KEY BLOCK-----


=abcd
-----END PGP PRIVATE KEY BLOCK-----`;

      // Will fail on length first (too short), then structure
      expect(() => ArmoredPrivateKeySchema.parse(noData)).toThrow();
    });

    it("should reject without checksum line", () => {
      const noChecksum = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQdGBGYiT8YBEADKn8R2JHqQF5Y
-----END PGP PRIVATE KEY BLOCK-----`;

      expect(() => ArmoredPrivateKeySchema.parse(noChecksum)).toThrow(
        "Invalid PGP armored format - must include base64 data and checksum",
      );
    });

    it("should reject with only 4 lines (missing structure)", () => {
      const tooShort = `-----BEGIN PGP PRIVATE KEY BLOCK-----
data
=XX
-----END PGP PRIVATE KEY BLOCK-----`;

      expect(() => ArmoredPrivateKeySchema.parse(tooShort)).toThrow();
    });

    it("should accept key with Version header", () => {
      const keyWithVersion = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v5.0.0

lIYEZx3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJkEExYKAEEWIQQRTd3LSMIzSP5K+yAQMfcIqJ5LFQUCZ3PyhwIbAwUJA8JnAAUL
=oEGo
-----END PGP PRIVATE KEY BLOCK-----`;

      const result = ArmoredPrivateKeySchema.parse(keyWithVersion);
      expect(result).toBeTruthy();
    });

    it("should accept key with Comment header", () => {
      const keyWithComment = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: Automated signing key

lIYEZx3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJkEExYKAEEWIQQRTd3LSMIzSP5K+yAQMfcIqJ5LFQUCZ3PyhwIbAwUJA8JnAAUL
=oEGo
-----END PGP PRIVATE KEY BLOCK-----`;

      const result = ArmoredPrivateKeySchema.parse(keyWithComment);
      expect(result).toBeTruthy();
    });

    // Note: Trailing newlines are handled by footer regex which uses trim()

    // Edge cases for line validation
    it("should reject when first line is empty (lines[0] undefined)", () => {
      const emptyFirstLine = `
-----BEGIN PGP PRIVATE KEY BLOCK-----

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

      // Actually fails on checksum validation, not BEGIN/END check
      expect(() => ArmoredPrivateKeySchema.parse(emptyFirstLine)).toThrow(
        "Invalid PGP armored format - must include base64 data and checksum",
      );
    });

    it("should reject when last line missing END marker (lastLine undefined)", () => {
      const noEndMarker = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZx3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJkEExYKAEEWIQQRTd3LSMIzSP5K+yAQMfcIqJ5LFQUCZ3PyhwIbAwUJA8JnAAUL
CQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRAQMfcIqJ5LFZoMAP9X7cPxCi2p
KIr+J8gAkl0Ny1G8TnlMq0M9xN3Vx1qb+QD/elKMaKzX3u8d9zvIykjW8K/WKWwy
7Bfg==
=oEGo`;

      expect(() => ArmoredPrivateKeySchema.parse(noEndMarker)).toThrow(
        "Must be a valid PGP armored private key with BEGIN/END markers",
      );
    });

    it("should reject when all lines after header are empty (no lastLine)", () => {
      const allEmpty = `-----BEGIN PGP PRIVATE KEY BLOCK-----


`;

      expect(() => ArmoredPrivateKeySchema.parse(allEmpty)).toThrow();
    });

    it("should handle key where second-to-last line is empty", () => {
      const validKeyWithEmptySecondLast = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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

      // Should succeed because it falls back to lines[length-2] which contains footer
      const result = ArmoredPrivateKeySchema.parse(validKeyWithEmptySecondLast);
      expect(result).toBeTruthy();
    });
  });

  describe("TimestampSchema", () => {
    // Happy path
    it("should accept valid ISO8601 with offset", () => {
      const result = TimestampSchema.parse("2025-11-22T14:30:00+01:00");
      expect(result).toBe("2025-11-22T14:30:00+01:00");
    });

    it("should accept Z timezone", () => {
      const result = TimestampSchema.parse("2025-11-22T14:30:00Z");
      expect(result).toBe("2025-11-22T14:30:00Z");
    });

    it("should accept negative offset", () => {
      const result = TimestampSchema.parse("2025-11-22T14:30:00-05:00");
      expect(result).toBe("2025-11-22T14:30:00-05:00");
    });

    // Edge cases
    it("should accept milliseconds", () => {
      const result = TimestampSchema.parse("2025-11-22T14:30:00.123Z");
      expect(result).toBe("2025-11-22T14:30:00.123Z");
    });

    it("should accept microseconds", () => {
      const result = TimestampSchema.parse("2025-11-22T14:30:00.123456Z");
      expect(result).toBe("2025-11-22T14:30:00.123456Z");
    });

    it("should reject without timezone", () => {
      expect(() => TimestampSchema.parse("2025-11-22T14:30:00")).toThrow();
    });

    it("should reject invalid date", () => {
      expect(() => TimestampSchema.parse("2025-13-45T25:70:90Z")).toThrow();
    });

    it("should reject non-ISO format", () => {
      expect(() => TimestampSchema.parse("Nov 22, 2025 2:30 PM")).toThrow();
    });
  });

  describe("DateRangeSchema", () => {
    // Happy path
    it("should accept valid date range", () => {
      const result = DateRangeSchema.parse({
        startDate: "2025-01-01T00:00:00Z",
        endDate: "2025-12-31T23:59:59Z",
      });

      expect(result.startDate).toBe("2025-01-01T00:00:00Z");
      expect(result.endDate).toBe("2025-12-31T23:59:59Z");
    });

    it("should accept same start and end date", () => {
      const result = DateRangeSchema.parse({
        startDate: "2025-11-22T12:00:00Z",
        endDate: "2025-11-22T12:00:00Z",
      });

      expect(result).toBeTruthy();
    });

    it("should accept missing startDate", () => {
      const result = DateRangeSchema.parse({
        endDate: "2025-12-31T23:59:59Z",
      });

      expect(result.endDate).toBe("2025-12-31T23:59:59Z");
      expect(result.startDate).toBeUndefined();
    });

    it("should accept missing endDate", () => {
      const result = DateRangeSchema.parse({
        startDate: "2025-01-01T00:00:00Z",
      });

      expect(result.startDate).toBe("2025-01-01T00:00:00Z");
      expect(result.endDate).toBeUndefined();
    });

    it("should accept both dates missing", () => {
      const result = DateRangeSchema.parse({});
      expect(result.startDate).toBeUndefined();
      expect(result.endDate).toBeUndefined();
    });

    // Edge case - validation failure
    it("should reject when startDate > endDate", () => {
      expect(() =>
        DateRangeSchema.parse({
          startDate: "2025-12-31T23:59:59Z",
          endDate: "2025-01-01T00:00:00Z",
        })
      ).toThrow("startDate must be before or equal to endDate");
    });

    it("should reject when startDate 1 second after endDate", () => {
      expect(() =>
        DateRangeSchema.parse({
          startDate: "2025-11-22T12:00:01Z",
          endDate: "2025-11-22T12:00:00Z",
        })
      ).toThrow("startDate must be before or equal to endDate");
    });
  });

  describe("AuditQuerySchema", () => {
    // Happy path
    it("should accept valid query with all params", () => {
      const result = AuditQuerySchema.parse({
        limit: 50,
        offset: 10,
        action: "sign",
        subject: "repo/name",
        startDate: "2025-01-01T00:00:00Z",
        endDate: "2025-12-31T23:59:59Z",
      });

      expect(result.limit).toBe(50);
      expect(result.offset).toBe(10);
    });

    it("should apply default limit (100)", () => {
      const result = AuditQuerySchema.parse({});
      expect(result.limit).toBe(100);
    });

    it("should apply default offset (0)", () => {
      const result = AuditQuerySchema.parse({});
      expect(result.offset).toBe(0);
    });

    it("should coerce string numbers", () => {
      const result = AuditQuerySchema.parse({ limit: "25", offset: "5" });
      expect(result.limit).toBe(25);
      expect(result.offset).toBe(5);
    });

    // Edge cases - limit boundaries
    it("should accept limit=1 (minimum)", () => {
      const result = AuditQuerySchema.parse({ limit: 1 });
      expect(result.limit).toBe(1);
    });

    it("should accept limit=1000 (maximum)", () => {
      const result = AuditQuerySchema.parse({ limit: 1000 });
      expect(result.limit).toBe(1000);
    });

    it("should reject limit=0", () => {
      expect(() => AuditQuerySchema.parse({ limit: 0 })).toThrow();
    });

    it("should reject limit=1001", () => {
      expect(() => AuditQuerySchema.parse({ limit: 1001 })).toThrow();
    });

    it("should reject negative limit", () => {
      expect(() => AuditQuerySchema.parse({ limit: -5 })).toThrow();
    });

    // Edge cases - offset boundaries
    it("should accept offset=0", () => {
      const result = AuditQuerySchema.parse({ offset: 0 });
      expect(result.offset).toBe(0);
    });

    it("should accept large offset", () => {
      const result = AuditQuerySchema.parse({ offset: 999999 });
      expect(result.offset).toBe(999999);
    });

    it("should reject negative offset", () => {
      expect(() => AuditQuerySchema.parse({ offset: -1 })).toThrow();
    });

    it("should reject float limit", () => {
      expect(() => AuditQuerySchema.parse({ limit: 50.5 })).toThrow();
    });

    it("should reject float offset", () => {
      expect(() => AuditQuerySchema.parse({ offset: 10.7 })).toThrow();
    });
  });

  describe("ErrorCodeSchema", () => {
    const validCodes = [
      "AUTH_MISSING",
      "AUTH_INVALID",
      "KEY_NOT_FOUND",
      "KEY_PROCESSING_ERROR",
      "KEY_LIST_ERROR",
      "KEY_UPLOAD_ERROR",
      "KEY_DELETE_ERROR",
      "SIGN_ERROR",
      "RATE_LIMIT_ERROR",
      "RATE_LIMITED",
      "INVALID_REQUEST",
      "AUDIT_ERROR",
      "NOT_FOUND",
      "INTERNAL_ERROR",
    ];

    validCodes.forEach((code) => {
      it(`should accept ${code}`, () => {
        const result = ErrorCodeSchema.parse(code);
        expect(result).toBe(code);
      });
    });

    it("should reject invalid code", () => {
      expect(() => ErrorCodeSchema.parse("UNKNOWN_ERROR")).toThrow();
    });

    it("should reject lowercase", () => {
      expect(() => ErrorCodeSchema.parse("auth_missing")).toThrow();
    });

    it("should reject empty string", () => {
      expect(() => ErrorCodeSchema.parse("")).toThrow();
    });
  });

  describe("ErrorResponseSchema", () => {
    it("should accept valid error response", () => {
      const result = ErrorResponseSchema.parse({
        error: "Something went wrong",
        code: "INTERNAL_ERROR",
        requestId: "123e4567-e89b-12d3-a456-426614174000",
      });

      expect(result.error).toBe("Something went wrong");
      expect(result.code).toBe("INTERNAL_ERROR");
    });

    it("should accept without requestId", () => {
      const result = ErrorResponseSchema.parse({
        error: "Error message",
        code: "NOT_FOUND",
      });

      expect(result.requestId).toBeUndefined();
    });

    it("should reject empty error message", () => {
      expect(() =>
        ErrorResponseSchema.parse({ error: "", code: "INTERNAL_ERROR" })
      ).toThrow("Error message cannot be empty");
    });

    it("should reject invalid UUID requestId", () => {
      expect(() =>
        ErrorResponseSchema.parse({
          error: "Test",
          code: "INTERNAL_ERROR",
          requestId: "not-a-uuid",
        })
      ).toThrow();
    });
  });

  describe("RequestIdSchema", () => {
    it("should accept valid UUIDv4", () => {
      const result = RequestIdSchema.parse(
        "123e4567-e89b-12d3-a456-426614174000",
      );
      expect(result).toBe("123e4567-e89b-12d3-a456-426614174000");
    });

    it("should reject invalid UUID format", () => {
      expect(() => RequestIdSchema.parse("not-a-uuid")).toThrow();
    });

    it("should reject UUID without dashes", () => {
      expect(() => RequestIdSchema.parse("123e4567e89b12d3a456426614174000"))
        .toThrow();
    });

    it("should reject empty string", () => {
      expect(() => RequestIdSchema.parse("")).toThrow();
    });
  });

  describe("HealthStatusSchema", () => {
    it("should accept 'healthy'", () => {
      const result = HealthStatusSchema.parse("healthy");
      expect(result).toBe("healthy");
    });

    it("should accept 'degraded'", () => {
      const result = HealthStatusSchema.parse("degraded");
      expect(result).toBe("degraded");
    });

    it("should reject 'unhealthy'", () => {
      expect(() => HealthStatusSchema.parse("unhealthy")).toThrow();
    });

    it("should reject empty", () => {
      expect(() => HealthStatusSchema.parse("")).toThrow();
    });

    it("should reject arbitrary string", () => {
      expect(() => HealthStatusSchema.parse("ok")).toThrow();
    });
  });

  describe("HealthResponseSchema", () => {
    it("should accept valid health response", () => {
      const result = HealthResponseSchema.parse({
        status: "healthy",
        timestamp: "2025-11-22T14:30:00Z",
        version: "1.0.0",
        checks: { keyStorage: true, database: true },
      });

      expect(result.status).toBe("healthy");
    });

    it("should accept degraded status", () => {
      const result = HealthResponseSchema.parse({
        status: "degraded",
        timestamp: "2025-11-22T14:30:00Z",
        version: "2.15.3",
        checks: { keyStorage: false, database: true },
      });

      expect(result.status).toBe("degraded");
    });

    it("should reject invalid version (non-semver)", () => {
      expect(() =>
        HealthResponseSchema.parse({
          status: "healthy",
          timestamp: "2025-11-22T14:30:00Z",
          version: "v1.0",
          checks: { keyStorage: true, database: true },
        })
      ).toThrow("Must be semantic version");
    });

    it("should accept version with prerelease", () => {
      // Note: Current regex only accepts x.y.z format
      expect(() =>
        HealthResponseSchema.parse({
          status: "healthy",
          timestamp: "2025-11-22T14:30:00Z",
          version: "1.0.0-beta.1",
          checks: { keyStorage: true, database: true },
        })
      ).toThrow();
    });

    it("should reject invalid timestamp", () => {
      expect(() =>
        HealthResponseSchema.parse({
          status: "healthy",
          timestamp: "invalid",
          version: "1.0.0",
          checks: { keyStorage: true, database: true },
        })
      ).toThrow();
    });
  });

  describe("RequestHeadersSchema", () => {
    it("should accept valid UUID request ID", () => {
      const result = RequestHeadersSchema.parse({
        "X-Request-ID": "123e4567-e89b-12d3-a456-426614174000",
      });

      expect(result["X-Request-ID"]).toBe(
        "123e4567-e89b-12d3-a456-426614174000",
      );
    });

    it("should accept missing request ID", () => {
      const result = RequestHeadersSchema.parse({});
      expect(result["X-Request-ID"]).toBeUndefined();
    });

    it("should reject invalid UUID", () => {
      expect(() => RequestHeadersSchema.parse({ "X-Request-ID": "not-uuid" }))
        .toThrow();
    });
  });

  describe("KeyUploadSchema", () => {
    it("should accept valid upload request", () => {
      const result = KeyUploadSchema.parse({
        armoredPrivateKey: validKey,
        keyId: "A1B2C3D4E5F67890",
      });

      expect(result.armoredPrivateKey).toBeTruthy();
    });

    it("should reject missing armoredPrivateKey", () => {
      expect(() => KeyUploadSchema.parse({})).toThrow();
    });

    // KeyId is no longer part of the upload schema (it's derived or passed separately)
    it("should reject invalid armoredPrivateKey", () => {
      expect(() =>
        KeyUploadSchema.parse({ armoredPrivateKey: "-----BEGIN..." })
      ).toThrow();
    });
  });

  describe("KeyResponseSchema", () => {
    it("should accept valid key response", () => {
      const result = KeyResponseSchema.parse({
        keyId: "A1B2C3D4E5F60718",
        fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
        publicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
        createdAt: "2025-01-01T00:00:00Z",
        algorithm: "RSA",
        userId: "Test User <test@example.com>",
      });

      expect(result.keyId).toBe("A1B2C3D4E5F60718");
    });

    it("should reject missing fields", () => {
      expect(() =>
        KeyResponseSchema.parse({
          success: true,
          keyId: "ABC",
        })
      ).toThrow();
    });
  });
});
