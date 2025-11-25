/** biome-ignore-all lint/style/noNonNullAssertion: This is a test file */
import { describe, expect, it } from "vitest";
import type { AuditLogEntry } from "~/schemas/audit";
import { D1QueryBuilder, transformAuditLogRow } from "~/utils/database";

// ============================================================================
// Tests for transformAuditLogRow
// ============================================================================

describe("transformAuditLogRow", () => {
  describe("success cases", () => {
    it("should transform valid D1 row with all fields", () => {
      const row = {
        id: "audit-001",
        timestamp: "2024-01-15T10:30:00Z",
        request_id: "req-123",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:owner/repo:ref:refs/heads/main",
        key_id: "KEY123",
        success: 1,
        error_code: null,
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result).toEqual({
        id: "audit-001",
        timestamp: "2024-01-15T10:30:00Z",
        requestId: "req-123",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:owner/repo:ref:refs/heads/main",
        keyId: "KEY123",
        success: true,
        errorCode: null,
        metadata: undefined,
      });
    });

    it("should convert success=1 to true", () => {
      const row = {
        id: "audit-002",
        timestamp: "2024-01-15T11:00:00Z",
        request_id: "req-456",
        action: "key_upload",
        issuer: "admin",
        subject: "admin-user",
        key_id: "KEY456",
        success: 1,
        error_code: null,
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result.success).toBe(true);
    });

    it("should convert success=0 to false", () => {
      const row = {
        id: "audit-003",
        timestamp: "2024-01-15T11:30:00Z",
        request_id: "req-789",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:test/test",
        key_id: "KEY789",
        success: 0,
        error_code: "AUTH_INVALID",
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result.success).toBe(false);
    });

    it("should convert success=true (boolean) to true", () => {
      const row = {
        id: "audit-004",
        timestamp: "2024-01-15T12:00:00Z",
        request_id: "req-999",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:test/repo",
        key_id: "KEYABC",
        success: true,
        error_code: null,
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result.success).toBe(true);
    });

    it("should convert success=false (boolean) to false", () => {
      const row = {
        id: "audit-005",
        timestamp: "2024-01-15T12:30:00Z",
        request_id: "req-000",
        action: "key_delete",
        issuer: "https://github.com",
        subject: "admin-action",
        key_id: "KEYDEF",
        success: false,
        error_code: "NOT_FOUND",
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result.success).toBe(false);
    });

    it("should include error_code when present", () => {
      const row = {
        id: "audit-006",
        timestamp: "2024-01-15T13:00:00Z",
        request_id: "req-111",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:test/repo",
        key_id: "KEYGHI",
        success: 0,
        error_code: "RATE_LIMIT",
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result.errorCode).toBe("RATE_LIMIT");
    });

    it("should set errorCode to null when error_code is null", () => {
      const row = {
        id: "audit-007",
        timestamp: "2024-01-15T13:30:00Z",
        request_id: "req-222",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:test/repo",
        key_id: "KEYJKL",
        success: 1,
        error_code: null,
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result.errorCode).toBeNull();
    });

    it("should include metadata when present", () => {
      const metadata = "{\"algorithm\":\"RSA\",\"bits\":4096}";
      const row = {
        id: "audit-008",
        timestamp: "2024-01-15T14:00:00Z",
        request_id: "req-333",
        action: "key_upload",
        issuer: "admin",
        subject: "admin-user",
        key_id: "KEYMNO",
        success: 1,
        error_code: null,
        metadata,
      };

      const result = transformAuditLogRow(row);

      expect(result.metadata).toBe(metadata);
    });

    it("should set metadata to undefined when null", () => {
      const row = {
        id: "audit-009",
        timestamp: "2024-01-15T14:30:00Z",
        request_id: "req-444",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:test/repo",
        key_id: "KEYPQR",
        success: 1,
        error_code: null,
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result.metadata).toBeUndefined();
    });

    it("should set metadata to undefined when empty string", () => {
      const row = {
        id: "audit-010",
        timestamp: "2024-01-15T15:00:00Z",
        request_id: "req-555",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:test/repo",
        key_id: "KEYSTU",
        success: 1,
        error_code: null,
        metadata: "",
      };

      const result = transformAuditLogRow(row);

      expect(result.metadata).toBeUndefined();
    });

    it("should handle all valid AuditAction types", () => {
      const actions = ["sign", "key_upload", "key_delete"] as const;

      for (const action of actions) {
        const row = {
          id: "audit-action",
          timestamp: "2024-01-15T15:30:00Z",
          request_id: "req-action",
          action,
          issuer: "test",
          subject: "test",
          key_id: "KEY",
          success: 1,
          error_code: null,
          metadata: null,
        };

        const result = transformAuditLogRow(row);
        expect(result.action).toBe(action);
      }
    });

    it("should handle all valid ErrorCode types", () => {
      const errorCodes = [
        "AUTH_REQUIRED",
        "AUTH_INVALID",
        "FORBIDDEN",
        "NOT_FOUND",
        "RATE_LIMIT",
        "KEY_NOT_FOUND",
        "SIGNATURE_FAILED",
        "INVALID_REQUEST",
        "DB_ERROR",
        "INTERNAL_ERROR",
        "UNSUPPORTED_MEDIA_TYPE",
        "VERIFICATION_FAILED",
        "PARSE_ERROR",
        "INVALID_SIGNATURE",
      ] as const;

      for (const errorCode of errorCodes) {
        const row = {
          id: "audit-error",
          timestamp: "2024-01-15T16:00:00Z",
          request_id: "req-error",
          action: "sign" as const,
          issuer: "test",
          subject: "test",
          key_id: "KEY",
          success: 0,
          error_code: errorCode,
          metadata: null,
        };

        const result = transformAuditLogRow(row);
        expect(result.errorCode).toBe(errorCode);
      }
    });

    it("should map snake_case fields to camelCase", () => {
      const row = {
        id: "audit-011",
        timestamp: "2024-01-15T16:30:00Z",
        request_id: "req-mapping",
        action: "sign",
        issuer: "https://github.com",
        subject: "repo:test/repo",
        key_id: "KEYVWX",
        success: 1,
        error_code: null,
        metadata: null,
      };

      const result = transformAuditLogRow(row);

      expect(result).toHaveProperty("requestId");
      expect(result).toHaveProperty("keyId");
      expect(result).toHaveProperty("errorCode");
      expect(result).not.toHaveProperty("request_id");
      expect(result).not.toHaveProperty("key_id");
      expect(result).not.toHaveProperty("error_code");
    });
  });

  describe("error cases", () => {
    it("should throw on missing required field (id)", () => {
      const row = {
        timestamp: "2024-01-15T17:00:00Z",
        request_id: "req-missing",
        action: "sign",
        issuer: "test",
        subject: "test",
        key_id: "KEY",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on missing required field (timestamp)", () => {
      const row = {
        id: "audit-012",
        request_id: "req-missing",
        action: "sign",
        issuer: "test",
        subject: "test",
        key_id: "KEY",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on missing required field (request_id)", () => {
      const row = {
        id: "audit-013",
        timestamp: "2024-01-15T17:30:00Z",
        action: "sign",
        issuer: "test",
        subject: "test",
        key_id: "KEY",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on missing required field (action)", () => {
      const row = {
        id: "audit-014",
        timestamp: "2024-01-15T18:00:00Z",
        request_id: "req-missing",
        issuer: "test",
        subject: "test",
        key_id: "KEY",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on missing required field (issuer)", () => {
      const row = {
        id: "audit-015",
        timestamp: "2024-01-15T18:30:00Z",
        request_id: "req-missing",
        action: "sign",
        subject: "test",
        key_id: "KEY",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on missing required field (subject)", () => {
      const row = {
        id: "audit-016",
        timestamp: "2024-01-15T19:00:00Z",
        request_id: "req-missing",
        action: "sign",
        issuer: "test",
        key_id: "KEY",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on missing required field (key_id)", () => {
      const row = {
        id: "audit-017",
        timestamp: "2024-01-15T19:30:00Z",
        request_id: "req-missing",
        action: "sign",
        issuer: "test",
        subject: "test",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on missing required field (success)", () => {
      const row = {
        id: "audit-018",
        timestamp: "2024-01-15T20:00:00Z",
        request_id: "req-missing",
        action: "sign",
        issuer: "test",
        subject: "test",
        key_id: "KEY",
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on invalid success type", () => {
      const row = {
        id: "audit-019",
        timestamp: "2024-01-15T20:30:00Z",
        request_id: "req-invalid",
        action: "sign",
        issuer: "test",
        subject: "test",
        key_id: "KEY",
        success: "true", // Invalid: should be number or boolean
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on invalid timestamp type", () => {
      const row = {
        id: "audit-020",
        timestamp: 1705340400000, // Invalid: should be string
        request_id: "req-invalid",
        action: "sign",
        issuer: "test",
        subject: "test",
        key_id: "KEY",
        success: 1,
        error_code: null,
        metadata: null,
      };

      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should throw on null row", () => {
      expect(() => transformAuditLogRow(null)).toThrow();
    });

    it("should throw on undefined row", () => {
      expect(() => transformAuditLogRow(undefined)).toThrow();
    });

    it("should throw on empty object", () => {
      expect(() => transformAuditLogRow({})).toThrow();
    });
  });
});

// ============================================================================
// Tests for D1QueryBuilder
// ============================================================================

describe("D1QueryBuilder", () => {
  describe("construction", () => {
    it("should initialize with base query", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const { query } = builder.build();

      expect(query).toBe("SELECT * FROM audit_logs");
    });

    it("should support method chaining", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("action", "sign")
        .orderBy("timestamp", "DESC")
        .limit(10);

      expect(builder).toBeInstanceOf(D1QueryBuilder);
    });
  });

  describe("where clause", () => {
    it("should add single where condition", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").where(
        "action",
        "sign",
      );
      const { query, params } = builder.build();

      expect(query).toContain("WHERE action = ?");
      expect(params).toEqual(["sign"]);
    });

    it("should support string values in where", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").where(
        "issuer",
        "https://github.com",
      );
      const { query, params } = builder.build();

      expect(query).toContain("WHERE issuer = ?");
      expect(params).toEqual(["https://github.com"]);
    });

    it("should support numeric values in where", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").where(
        "id",
        123,
      );
      const { query, params } = builder.build();

      expect(query).toContain("WHERE id = ?");
      expect(params).toEqual([123]);
    });

    it("should add multiple where conditions joined with AND", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("action", "sign")
        .where("issuer", "https://github.com");
      const { query, params } = builder.build();

      expect(query).toContain("WHERE action = ? AND issuer = ?");
      expect(params).toEqual(["sign", "https://github.com"]);
    });

    it("should add three or more where conditions", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("action", "sign")
        .where("issuer", "https://github.com")
        .where("success", 1);
      const { query, params } = builder.build();

      expect(query).toContain(
        "WHERE action = ? AND issuer = ? AND success = ?",
      );
      expect(params).toEqual(["sign", "https://github.com", 1]);
    });
  });

  describe("whereBetween clause", () => {
    it("should add BETWEEN condition", () => {
      const builder = new D1QueryBuilder(
        "SELECT * FROM audit_logs",
      ).whereBetween("timestamp", "2024-01-01", "2024-12-31");
      const { query, params } = builder.build();

      expect(query).toContain("WHERE timestamp BETWEEN ? AND ?");
      expect(params).toEqual(["2024-01-01", "2024-12-31"]);
    });

    it("should combine BETWEEN with other conditions", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("action", "sign")
        .whereBetween("timestamp", "2024-01-01", "2024-12-31");
      const { query, params } = builder.build();

      expect(query).toContain("WHERE action = ? AND timestamp BETWEEN ? AND ?");
      expect(params).toEqual(["sign", "2024-01-01", "2024-12-31"]);
    });

    it("should support multiple BETWEEN clauses", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .whereBetween("timestamp", "2024-01-01", "2024-12-31")
        .whereBetween("id", "100", "200");
      const { query, params } = builder.build();

      expect(query).toContain("timestamp BETWEEN ? AND ?");
      expect(query).toContain("id BETWEEN ? AND ?");
      expect(params).toEqual(["2024-01-01", "2024-12-31", "100", "200"]);
    });
  });

  describe("orderBy clause", () => {
    it("should add ORDER BY DESC by default", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").orderBy(
        "timestamp",
      );
      const { query } = builder.build();

      expect(query).toContain("ORDER BY timestamp DESC");
    });

    it("should add ORDER BY with specified direction (ASC)", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").orderBy(
        "timestamp",
        "ASC",
      );
      const { query } = builder.build();

      expect(query).toContain("ORDER BY timestamp ASC");
    });

    it("should add ORDER BY with specified direction (DESC)", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").orderBy(
        "timestamp",
        "DESC",
      );
      const { query } = builder.build();

      expect(query).toContain("ORDER BY timestamp DESC");
    });

    it("should support multiple orderBy (last one wins)", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .orderBy("timestamp", "DESC")
        .orderBy("id", "ASC");
      const { query } = builder.build();

      expect(query).toContain("ORDER BY timestamp DESC");
      expect(query).toContain("ORDER BY id ASC");
    });

    it("should place ORDER BY before LIMIT", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .orderBy("timestamp", "DESC")
        .limit(10);
      const { query } = builder.build();

      const orderByIdx = query.indexOf("ORDER BY");
      const limitIdx = query.indexOf("LIMIT");
      expect(orderByIdx).toBeLessThan(limitIdx);
    });
  });

  describe("limit clause", () => {
    it("should add LIMIT with offset 0 by default", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").limit(10);
      const { query, params } = builder.build();

      expect(query).toContain("LIMIT ? OFFSET ?");
      expect(params).toContain(10);
      expect(params).toContain(0);
    });

    it("should add LIMIT with specified offset", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").limit(
        20,
        5,
      );
      const { query, params } = builder.build();

      expect(query).toContain("LIMIT ? OFFSET ?");
      expect(params).toContain(20);
      expect(params).toContain(5);
    });

    it("should support pagination", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").limit(
        100,
        200,
      );
      const { params } = builder.build();

      expect(params).toEqual([100, 200]);
    });
  });

  describe("complex query building", () => {
    it("should build query with WHERE, ORDER BY, and LIMIT", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("action", "sign")
        .where("issuer", "https://github.com")
        .orderBy("timestamp", "DESC")
        .limit(50, 10);
      const { query, params } = builder.build();

      expect(query).toContain("SELECT * FROM audit_logs");
      expect(query).toContain("WHERE action = ? AND issuer = ?");
      expect(query).toContain("ORDER BY timestamp DESC");
      expect(query).toContain("LIMIT ? OFFSET ?");
      expect(params).toEqual(["sign", "https://github.com", 50, 10]);
    });

    it("should build query with WHERE BETWEEN, ORDER BY, and LIMIT", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .whereBetween("timestamp", "2024-01-01", "2024-12-31")
        .where("action", "sign")
        .orderBy("timestamp", "DESC")
        .limit(25, 5);
      const { query, params } = builder.build();

      expect(query).toContain("WHERE timestamp BETWEEN ? AND ? AND action = ?");
      expect(query).toContain("ORDER BY timestamp DESC");
      expect(query).toContain("LIMIT ? OFFSET ?");
      expect(params).toEqual(["2024-01-01", "2024-12-31", "sign", 25, 5]);
    });

    it("should build query with no WHERE clause", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .orderBy("timestamp", "DESC")
        .limit(10);
      const { query } = builder.build();

      expect(query).not.toContain("WHERE");
      expect(query).toContain("ORDER BY timestamp DESC");
      expect(query).toContain("LIMIT ? OFFSET ?");
    });

    it("should handle empty where conditions (no WHERE clause added)", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").orderBy(
        "timestamp",
      );
      const { query, params } = builder.build();

      expect(query).not.toContain("WHERE");
      expect(params).toEqual([]);
    });
  });

  describe("build method", () => {
    it("should return object with query and params", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").where(
        "action",
        "sign",
      );
      const result = builder.build();

      expect(result).toHaveProperty("query");
      expect(result).toHaveProperty("params");
      expect(typeof result.query).toBe("string");
      expect(Array.isArray(result.params)).toBe(true);
    });

    it("should build with WHERE clause appended", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").where(
        "action",
        "sign",
      );

      const result1 = builder.build();

      expect(result1.query).toContain("WHERE action = ?");
      expect(result1.params).toEqual(["sign"]);
    });

    it("should handle builder reuse (state persists)", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").where(
        "action",
        "sign",
      );

      const result1 = builder.build();
      builder.limit(10);
      const result2 = builder.build();

      expect(result1.query).not.toContain("LIMIT");
      expect(result2.query).toContain("LIMIT");
    });
  });

  describe("execute method", () => {
    it("should execute query with mock database", async () => {
      const mockResults: AuditLogEntry[] = [
        {
          id: "1",
          timestamp: "2024-01-15T10:30:00Z",
          requestId: "req-1",
          action: "sign",
          issuer: "https://github.com",
          subject: "repo:owner/repo",
          keyId: "KEY1",
          success: true,
        },
      ];

      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: mockResults }),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs").where(
        "action",
        "sign",
      );
      const results = await builder.execute(mockDb);

      expect(results).toEqual(mockResults);
    });

    it("should execute with transformer function", async () => {
      const rawResults = [
        {
          id: "1",
          timestamp: "2024-01-15T10:30:00Z",
          request_id: "req-1",
          action: "sign",
          issuer: "https://github.com",
          subject: "repo:owner/repo",
          key_id: "KEY1",
          success: 1,
          error_code: null,
          metadata: null,
        },
      ];

      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: rawResults }),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const results = await builder.execute(mockDb, transformAuditLogRow);

      expect(results).toHaveLength(1);
      expect(results[0]!.requestId).toBe("req-1");
      expect(results[0]!.success).toBe(true);
    });

    it("should return empty array when results is empty", async () => {
      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: [] }),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const results = await builder.execute(mockDb);

      expect(results).toEqual([]);
    });

    it("should return empty array when results is undefined", async () => {
      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: undefined }),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const results = await builder.execute(mockDb);

      expect(results).toEqual([]);
    });

    it("should return empty array when results is null", async () => {
      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: null }),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const results = await builder.execute(mockDb);

      expect(results).toEqual([]);
    });

    it("should pass all params to bind", async () => {
      const mockBind = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] }),
      });
      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: mockBind,
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("action", "sign")
        .where("issuer", "https://github.com")
        .limit(50, 10);

      await builder.execute(mockDb);

      expect(mockBind).toHaveBeenCalledWith(
        "sign",
        "https://github.com",
        50,
        10,
      );
    });

    it("should propagate database errors", async () => {
      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi
              .fn()
              .mockRejectedValue(new Error("Database connection failed")),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");

      await expect(builder.execute(mockDb)).rejects.toThrow(
        "Database connection failed",
      );
    });

    it("should handle transformer errors", async () => {
      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({
              results: [{ invalid: "row" }],
            }),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");

      await expect(
        builder.execute(mockDb, transformAuditLogRow),
      ).rejects.toThrow();
    });

    it("should apply transformer to multiple results", async () => {
      const rawResults = [
        {
          id: "1",
          timestamp: "2024-01-15T10:30:00Z",
          request_id: "req-1",
          action: "sign",
          issuer: "https://github.com",
          subject: "repo:owner/repo",
          key_id: "KEY1",
          success: 1,
          error_code: null,
          metadata: null,
        },
        {
          id: "2",
          timestamp: "2024-01-15T11:00:00Z",
          request_id: "req-2",
          action: "key_upload",
          issuer: "admin",
          subject: "admin-user",
          key_id: "KEY2",
          success: 1,
          error_code: null,
          metadata: null,
        },
      ];

      const mockDb = {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: rawResults }),
          }),
        }),
      } as unknown as D1Database;

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const results = await builder.execute(mockDb, transformAuditLogRow);

      expect(results).toHaveLength(2);
      expect(results[0]!.id).toBe("1");
      expect(results[1]!.id).toBe("2");
    });
  });
});

// Helper for vitest mocking
import { vi } from "vitest";
