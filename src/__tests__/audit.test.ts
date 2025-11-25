/** biome-ignore-all lint/style/noNonNullAssertion: This is a test file */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuditLogEntry } from "~/schemas/audit";
import { getAuditLogs, logAuditEvent } from "~/utils/audit";

// Mock D1Database
function createMockDb() {
  const mockRun = vi.fn().mockResolvedValue({ success: true });
  const mockAll = vi.fn().mockResolvedValue({ results: [] });
  const mockBind = vi.fn().mockReturnValue({ run: mockRun, all: mockAll });
  const mockPrepare = vi.fn().mockReturnValue({ bind: mockBind });

  return {
    prepare: mockPrepare,
    _mockRun: mockRun,
    _mockAll: mockAll,
    _mockBind: mockBind,
  } as unknown as D1Database & {
    _mockRun: ReturnType<typeof vi.fn>;
    _mockAll: ReturnType<typeof vi.fn>;
    _mockBind: ReturnType<typeof vi.fn>;
  };
}

describe("logAuditEvent", () => {
  beforeEach(() => {
    vi.spyOn(crypto, "randomUUID").mockReturnValue(
      "test-uuid-1234" as `${string}-${string}-${string}-${string}-${string}`,
    );
  });

  it("should insert audit log entry", async () => {
    const db = createMockDb();

    await logAuditEvent(db, {
      requestId: "req-123",
      action: "sign",
      issuer: "https://github.com",
      subject: "repo:owner/repo:ref:refs/heads/master",
      keyId: "KEY123",
      success: true,
    });

    expect(db.prepare).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO audit_logs"),
    );
    expect(db._mockBind).toHaveBeenCalledWith(
      "test-uuid-1234",
      expect.any(String), // timestamp
      "req-123",
      "sign",
      "https://github.com",
      "repo:owner/repo:ref:refs/heads/master",
      "KEY123",
      1, // success = true
      null, // errorCode
      null, // metadata
    );
    expect(db._mockRun).toHaveBeenCalled();
  });

  it("should include error code when provided", async () => {
    const db = createMockDb();

    await logAuditEvent(db, {
      requestId: "req-456",
      action: "sign",
      issuer: "https://github.com",
      subject: "repo:owner/repo",
      keyId: "KEY123",
      success: false,
      errorCode: "AUTH_INVALID",
    });

    expect(db._mockBind).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      "req-456",
      "sign",
      "https://github.com",
      "repo:owner/repo",
      "KEY123",
      0, // success = false
      "AUTH_INVALID",
      null,
    );
  });

  it("should include metadata when provided", async () => {
    const db = createMockDb();

    await logAuditEvent(db, {
      requestId: "req-789",
      action: "key_upload",
      issuer: "admin",
      subject: "admin-user",
      keyId: "KEY456",
      success: true,
      metadata: "{\"algorithm\":\"RSA\"}",
    });

    expect(db._mockBind).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      "req-789",
      "key_upload",
      "admin",
      "admin-user",
      "KEY456",
      1,
      null,
      "{\"algorithm\":\"RSA\"}",
    );
  });

  it("should throw when database fails (fail-closed)", async () => {
    const db = createMockDb();
    db._mockRun.mockRejectedValue(new Error("Database error"));

    // Should throw - fail closed behavior
    await expect(
      logAuditEvent(db, {
        requestId: "req-999",
        action: "sign",
        issuer: "test",
        subject: "test",
        keyId: "KEY",
        success: true,
      }),
    ).rejects.toThrow("Database error");
  });

  it("should throw on DB run failure (fail-closed)", async () => {
    const db = createMockDb();
    db._mockRun.mockImplementation(() => {
      throw new Error("DB Run Error");
    });

    await expect(
      logAuditEvent(db, {
        requestId: "req-fail",
        action: "sign",
        issuer: "test",
        subject: "test",
        keyId: "KEY",
        success: true,
      }),
    ).rejects.toThrow("DB Run Error");
  });

  it("should throw on non-Error exceptions (fail-closed)", async () => {
    const db = createMockDb();
    db._mockRun.mockImplementation(() => {
      throw "String error";
    });

    await expect(
      logAuditEvent(db, {
        requestId: "req-fail",
        action: "sign",
        issuer: "test",
        subject: "test",
        keyId: "KEY",
        success: true,
      }),
    ).rejects.toThrow();
  });
});

describe("getAuditLogs", () => {
  it("should return audit logs with default options", async () => {
    const mockResults: Partial<AuditLogEntry>[] = [
      {
        id: "1",
        timestamp: "2024-01-01T00:00:00Z",
        requestId: "req-1",
        action: "sign",
        issuer: "github",
        subject: "repo",
        keyId: "KEY1",
        success: true,
      },
    ];

    const db = createMockDb();
    db._mockAll.mockResolvedValue({
      results: mockResults.map((r) => ({
        ...r,
        request_id: r.requestId,
        key_id: r.keyId,
        success: r.success ? 1 : 0,
        error_code: null,
        metadata: null,
      })),
    });

    const logs = await getAuditLogs(db);

    expect(db.prepare).toHaveBeenCalledWith(
      expect.stringContaining("SELECT * FROM audit_logs"),
    );
    expect(db._mockBind).toHaveBeenCalledWith(100, 0); // default limit and offset
    expect(logs).toHaveLength(1);
    const firstLog = logs[0];
    expect(firstLog).toBeDefined();
    expect(firstLog!.requestId).toBe("req-1");
    expect(firstLog!.success).toBe(true);
  });

  it("should apply action filter", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    await getAuditLogs(db, { action: "sign" });

    expect(db.prepare).toHaveBeenCalledWith(
      expect.stringContaining("AND action = ?"),
    );
    expect(db._mockBind).toHaveBeenCalledWith("sign", 100, 0);
  });

  it("should apply subject filter with LIKE and ESCAPE clause", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    await getAuditLogs(db, { subject: "owner/repo" });

    expect(db.prepare).toHaveBeenCalledWith(
      expect.stringContaining("AND subject LIKE ? ESCAPE '\\'"),
    );
    expect(db._mockBind).toHaveBeenCalledWith("%owner/repo%", 100, 0);
  });

  it("should escape % wildcard in subject filter to prevent pattern injection", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    // Attacker tries to use % to match all records
    await getAuditLogs(db, { subject: "%" });

    expect(db.prepare).toHaveBeenCalledWith(
      expect.stringContaining("ESCAPE '\\'"),
    );
    // % should be escaped as \% so it matches literal %
    expect(db._mockBind).toHaveBeenCalledWith("%\\%%", 100, 0);
  });

  it("should escape _ wildcard in subject filter to prevent single-char matching", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    // Attacker tries to use _ to match any single character
    await getAuditLogs(db, { subject: "user_name" });

    // _ should be escaped as \_ so it matches literal underscore
    expect(db._mockBind).toHaveBeenCalledWith("%user\\_name%", 100, 0);
  });

  it("should escape backslash in subject filter", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    // Input containing backslash should be double-escaped
    await getAuditLogs(db, { subject: "path\\to\\file" });

    // Each \ becomes \\ in the escaped output
    expect(db._mockBind).toHaveBeenCalledWith("%path\\\\to\\\\file%", 100, 0);
  });

  it("should handle combined SQL injection attempt in subject", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    // Combined attack: wildcards + SQL injection attempt
    await getAuditLogs(db, { subject: "%'; DROP TABLE audit_logs; --" });

    // % escaped, _ in "audit_logs" escaped, SQL injection neutralized by parameterized query
    expect(db._mockBind).toHaveBeenCalledWith(
      "%\\%'; DROP TABLE audit\\_logs; --%",
      100,
      0,
    );
  });

  it("should apply date range filters", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    await getAuditLogs(db, { startDate: "2024-01-01", endDate: "2024-12-31" });

    expect(db.prepare).toHaveBeenCalledWith(
      expect.stringContaining("AND timestamp >= ?"),
    );
    expect(db.prepare).toHaveBeenCalledWith(
      expect.stringContaining("AND timestamp <= ?"),
    );
    expect(db._mockBind).toHaveBeenCalledWith(
      "2024-01-01",
      "2024-12-31",
      100,
      0,
    );
  });

  it("should apply custom limit and offset", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({ results: [] });

    await getAuditLogs(db, { limit: 50, offset: 100 });

    expect(db._mockBind).toHaveBeenCalledWith(50, 100);
  });

  it("should convert database row to AuditLogEntry", async () => {
    const db = createMockDb();
    db._mockAll.mockResolvedValue({
      results: [
        {
          id: "test-id",
          timestamp: "2024-01-15T10:30:00Z",
          request_id: "req-abc",
          action: "key_delete",
          issuer: "admin",
          subject: "admin-user",
          key_id: "KEY789",
          success: 0,
          error_code: "KEY_NOT_FOUND",
          metadata: "{\"reason\":\"expired\"}",
        },
      ],
    });

    const logs = await getAuditLogs(db);

    expect(logs[0]).toEqual({
      id: "test-id",
      timestamp: "2024-01-15T10:30:00Z",
      requestId: "req-abc",
      action: "key_delete",
      issuer: "admin",
      subject: "admin-user",
      keyId: "KEY789",
      success: false,
      errorCode: "KEY_NOT_FOUND",
      metadata: "{\"reason\":\"expired\"}",
    });
  });
});
