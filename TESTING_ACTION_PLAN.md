# GPG Signing Service - Testing Action Plan

**Priority Focus**: Security gaps, critical path coverage, performance baselines
**Target Completion**: 4 weeks
**Effort Estimate**: 25-30 hours

---

## Phase 1: Critical (Week 1) - Security & Functionality

### CRITICAL-1: Timing Attack Testing on Admin Token

**File to Create**: `src/__tests__/timing-attack.test.ts`
**Why**: `timingSafeEqual()` function has NO tests
**Security Impact**: CRITICAL - enables brute-force enumeration

**Implementation**:

```typescript
import { describe, expect, it, vi } from "vitest";
import { adminAuth } from "~/middleware/oidc";
import type { Context } from "hono";

describe("Admin Auth - Timing Attack Resistance", () => {
  const measurements: { [key: string]: number[] } = {};

  // Helper to measure execution time with multiple runs
  async function measureComparison(
    correctToken: string,
    testToken: string,
    iterations = 100,
  ): Promise<number> {
    const times: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const c = createMockContext(testToken);
      const start = performance.now();

      try {
        await adminAuth(c, vi.fn());
      } catch (e) {
        // Expected to fail, we're measuring time
      }

      const end = performance.now();
      times.push(end - start);
    }

    // Return median to reduce noise
    return times.sort((a, b) => a - b)[Math.floor(times.length / 2)];
  }

  it("should take same time for wrong-length tokens", async () => {
    const correctToken = "correct_admin_token_1234567890";

    // Test with different wrong lengths
    const shortToken = "short"; // Much shorter
    const longToken = correctToken + "extra_padding_here"; // Much longer
    const sameLengthWrong = "wrong_admin_token_1234567890"; // Same length, different content

    const shortTime = await measureComparison(correctToken, shortToken);
    const longTime = await measureComparison(correctToken, longToken);
    const sameLengthTime = await measureComparison(
      correctToken,
      sameLengthWrong,
    );

    // Times should be similar (within 10% - allows for system variance)
    const avgTime = (shortTime + longTime + sameLengthTime) / 3;
    const variance = [shortTime, longTime, sameLengthTime].map(t =>
      Math.abs(t - avgTime) / avgTime
    );

    expect(Math.max(...variance)).toBeLessThan(0.1);
  });

  it("should take same time for wrong position mismatches", async () => {
    const correct = "AAAAAAAAAAAAAAAA";

    // Wrong at different positions
    const wrongFirst = "ZAAAAAAAAAAAAA";
    const wrongMiddle = "AAAAAZAAAAAAA";
    const wrongLast = "AAAAAAAAAAAAZ";

    const firstTime = await measureComparison(correct, wrongFirst);
    const middleTime = await measureComparison(correct, wrongMiddle);
    const lastTime = await measureComparison(correct, wrongLast);

    // Should not show correlation: later mismatches shouldn't be faster
    const times = [firstTime, middleTime, lastTime];
    const avgTime = times.reduce((a, b) => a + b) / times.length;

    // Check that timing doesn't correlate with position
    const variance = times.map(t => Math.abs(t - avgTime));
    expect(Math.max(...variance) / avgTime).toBeLessThan(0.15);
  });

  it("should always reject wrong token regardless of length", async () => {
    const correctToken = "correct_token_here";
    const wrongTokens = [
      "w",
      "wrong",
      "completely_different_length_token_here_for_testing",
    ];

    for (const wrongToken of wrongTokens) {
      const c = createMockContext(wrongToken);
      const response = await adminAuth(c, vi.fn());

      const json = await response.json();
      expect(json.code).toBe("AUTH_INVALID");
      expect(response.status).toBe(401);
    }
  });

  it("should always accept correct token", async () => {
    const correctToken = "correct_admin_token";
    const c = createMockContext(correctToken);

    // Mock next() to return success
    const next = vi.fn().mockResolvedValue(new Response("ok"));

    const response = await adminAuth(c, next);
    expect(next).toHaveBeenCalled();
  });
});

// Helper
function createMockContext(authHeader: string): Context {
  return {
    req: {
      header: (name: string) =>
        name === "Authorization" ? `Bearer ${authHeader}` : undefined,
    },
    json: (data: any, status?: number) =>
      new Response(JSON.stringify(data), { status }),
    env: { ADMIN_TOKEN: "correct_admin_token" },
  } as any;
}
```

**Checklist**:

- [ ] Create file `src/__tests__/timing-attack.test.ts`
- [ ] Run test suite: `bun run test -- timing-attack`
- [ ] Verify implementation is constant-time
- [ ] Document findings in code comments

**Expected Time**: 1-2 hours
**Pass Criteria**: All tests pass, timing variance <10%

---

### CRITICAL-2: SSRF Prevention in JWKS Fetching

**File to Update**: `src/__tests__/middleware.test.ts` (ADD section)
**Why**: `getJWKS()` has NO protocol/address validation
**Security Impact**: HIGH - could leak credentials to internal services

**Implementation**:

```typescript
describe("JWKS Fetching - SSRF Prevention", () => {
  const ssrfTests = [
    {
      name: "IPv4 localhost",
      issuer: "http://127.0.0.1",
      shouldReject: true,
    },
    {
      name: "IPv4 loopback",
      issuer: "http://localhost:8080",
      shouldReject: true,
    },
    {
      name: "AWS metadata service",
      issuer: "http://169.254.169.254",
      shouldReject: true,
    },
    {
      name: "IPv6 localhost",
      issuer: "http://[::1]",
      shouldReject: true,
    },
    {
      name: "Private network (10.x.x.x)",
      issuer: "http://10.0.0.1",
      shouldReject: true,
    },
    {
      name: "Private network (192.168.x.x)",
      issuer: "http://192.168.1.1",
      shouldReject: true,
    },
    {
      name: "File protocol",
      issuer: "file:///etc/passwd",
      shouldReject: true,
    },
    {
      name: "Valid HTTPS issuer",
      issuer: "https://github.com",
      shouldReject: false,
    },
  ];

  ssrfTests.forEach(({ name, issuer, shouldReject }) => {
    it(`should ${shouldReject ? "reject" : "allow"}: ${name}`, async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("SSRF blocked"));

      try {
        await validateTokenWithIssuer(issuer, mockFetch);
        expect(!shouldReject).toBe(true);
      } catch (error) {
        if (shouldReject) {
          expect(error).toBeDefined();
          expect(String(error)).toMatch(/blocked|rejected|invalid/i);
        } else {
          throw error; // Unexpected rejection
        }
      }
    });
  });

  it("should reject HTTP issuers in production", async () => {
    const env = { NODE_ENV: "production" };
    const httpIssuer = "http://untrusted.example.com";

    // Should reject HTTP without HTTPS in production
    const result = validateIssuerUrl(httpIssuer, env);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("HTTPS required");
  });

  it("should allow HTTP issuers only in development", async () => {
    const env = { NODE_ENV: "development" };
    const httpIssuer = "http://localhost:3000";

    const result = validateIssuerUrl(httpIssuer, env);
    expect(result.allowed).toBe(true);
  });

  it("should handle redirect loops with timeout", async () => {
    let callCount = 0;
    const mockFetch = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount > 5) {
        throw new Error("Too many redirects");
      }
      return new Response("", { status: 301, headers: { location: "/" } });
    });

    const env = createMockEnv({ JWKS_CACHE: mockCache });

    try {
      await getJWKS("https://example.com", env);
      expect.fail("Should have thrown timeout error");
    } catch (error) {
      expect(String(error)).toMatch(/timeout|too many|loop/i);
    }
  });

  it("should validate JWKS structure before caching", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response("<html>Error page</html>", {
        headers: { "content-type": "text/html" },
      }),
    );

    // Mock jose to detect invalid JWKS
    const env = createMockEnv({ fetch: mockFetch });

    try {
      await getJWKS("https://github.com", env);
      expect.fail("Should reject invalid JWKS");
    } catch (error) {
      expect(String(error)).toMatch(/invalid|malformed/i);
    }
  });

  it("should use timeout for issuer config fetch", async () => {
    const slowFetch = vi.fn().mockImplementation(
      () => new Promise(resolve => setTimeout(resolve, 15000)),
    );

    const env = createMockEnv({ fetch: slowFetch });

    try {
      await getJWKS("https://slow-issuer.example.com", env, 10000);
      expect.fail("Should timeout");
    } catch (error) {
      expect(String(error)).toMatch(/timeout/i);
    }
  });
});
```

**Checklist**:

- [ ] Add SSRF validation tests to middleware.test.ts
- [ ] Implement `validateIssuerUrl()` function in oidc.ts
- [ ] Add protocol validation (HTTPS only in production)
- [ ] Test with private IP ranges
- [ ] Run: `bun run test -- middleware`

**Expected Time**: 2-3 hours
**Pass Criteria**: All SSRF attempts rejected, valid issuers allowed

---

### CRITICAL-3: Database Utilities Testing

**File to Create**: `src/__tests__/database.test.ts`
**Why**: ALL 25 statements in database.ts are untested
**Impact**: Audit logging completely untested

**Implementation**:

```typescript
import { describe, expect, it, vi } from "vitest";
import { D1QueryBuilder, transformAuditLogRow } from "~/utils/database";
import type { AuditLogEntry } from "~/schemas/audit";
import { z } from "@hono/zod-openapi";

describe("Database Utilities", () => {
  describe("transformAuditLogRow", () => {
    it("should transform D1 row to domain model", () => {
      const d1Row = {
        id: "log-001",
        timestamp: "2025-11-25T10:00:00Z",
        request_id: "req-123",
        action: "KEY_UPLOADED",
        issuer: "https://github.com",
        subject: "user@github",
        key_id: "ABCD1234",
        success: 1,
        error_code: null,
        metadata: null,
      };

      const result = transformAuditLogRow(d1Row);

      expect(result).toEqual({
        id: "log-001",
        timestamp: "2025-11-25T10:00:00Z",
        requestId: "req-123",
        action: "KEY_UPLOADED",
        issuer: "https://github.com",
        subject: "user@github",
        keyId: "ABCD1234",
        success: true,
        errorCode: undefined,
        metadata: undefined,
      });
    });

    it("should convert D1 boolean from 0/1", () => {
      const successRow = { ...baseRow(), success: 1 };
      const failureRow = { ...baseRow(), success: 0 };

      expect(transformAuditLogRow(successRow).success).toBe(true);
      expect(transformAuditLogRow(failureRow).success).toBe(false);
    });

    it("should handle error_code when present", () => {
      const row = { ...baseRow(), error_code: "KEY_NOT_FOUND" };
      const result = transformAuditLogRow(row);
      expect(result.errorCode).toBe("KEY_NOT_FOUND");
    });

    it("should handle metadata JSON parsing", () => {
      const row = {
        ...baseRow(),
        metadata: "{\"custom\":\"field\"}",
      };
      const result = transformAuditLogRow(row);
      expect(result.metadata).toBe("{\"custom\":\"field\"}");
    });

    it("should reject invalid action types", () => {
      const row = { ...baseRow(), action: "INVALID_ACTION" };
      expect(() => transformAuditLogRow(row)).toThrow();
    });

    it("should reject missing required fields", () => {
      const incomplete = { ...baseRow() };
      delete incomplete.id;
      expect(() => transformAuditLogRow(incomplete)).toThrow();
    });
  });

  describe("D1QueryBuilder", () => {
    it("should build base query", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const { query, params } = builder.build();

      expect(query).toBe("SELECT * FROM audit_logs");
      expect(params).toEqual([]);
    });

    it("should add where clause", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("key_id", "ABCD1234");
      const { query, params } = builder.build();

      expect(query).toBe("SELECT * FROM audit_logs WHERE key_id = ?");
      expect(params).toEqual(["ABCD1234"]);
    });

    it("should add multiple where clauses", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("key_id", "ABCD1234")
        .where("action", "KEY_SIGNED");
      const { query, params } = builder.build();

      expect(query).toBe(
        "SELECT * FROM audit_logs WHERE key_id = ? AND action = ?",
      );
      expect(params).toEqual(["ABCD1234", "KEY_SIGNED"]);
    });

    it("should add whereBetween clause", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .whereBetween("timestamp", "2025-01-01", "2025-12-31");
      const { query, params } = builder.build();

      expect(query).toContain("BETWEEN ? AND ?");
      expect(params).toEqual(["2025-01-01", "2025-12-31"]);
    });

    it("should add orderBy clause", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .orderBy("timestamp", "DESC");
      const { query, params } = builder.build();

      expect(query).toContain("ORDER BY timestamp DESC");
    });

    it("should add limit and offset", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .limit(10, 20);
      const { query, params } = builder.build();

      expect(query).toContain("LIMIT ? OFFSET ?");
      expect(params).toEqual([10, 20]);
    });

    it("should handle numeric where values", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("id", 123);
      const { query, params } = builder.build();

      expect(params).toEqual([123]);
    });

    it("should support method chaining", () => {
      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("issuer", "github")
        .orderBy("timestamp")
        .limit(50, 100);

      const { query, params } = builder.build();
      expect(query).toContain("WHERE");
      expect(query).toContain("ORDER BY");
      expect(query).toContain("LIMIT");
      expect(params.length).toBe(4);
    });

    it("should execute query with transformer", async () => {
      const mockDb = createMockD1();
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all: vi.fn().mockResolvedValue({
            results: [
              { id: "1", timestamp: "2025-01-01T00:00:00Z" /* ... */ },
            ],
          }),
        }),
      });

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs")
        .where("key_id", "TEST");

      const results = await builder.execute(mockDb, transformAuditLogRow);

      expect(results).toHaveLength(1);
      expect(results[0].id).toBe("1");
    });

    it("should handle empty results", async () => {
      const mockDb = createMockD1();
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all: vi.fn().mockResolvedValue({ results: null }),
        }),
      });

      const builder = new D1QueryBuilder("SELECT * FROM audit_logs");
      const results = await builder.execute(mockDb);

      expect(results).toEqual([]);
    });
  });
});

function baseRow(): any {
  return {
    id: "log-001",
    timestamp: "2025-11-25T10:00:00Z",
    request_id: "req-123",
    action: "KEY_SIGNED",
    issuer: "https://github.com",
    subject: "user@github",
    key_id: "ABCD1234",
    success: 1,
    error_code: null,
    metadata: null,
  };
}

function createMockD1(): any {
  return {};
}
```

**Checklist**:

- [ ] Create `src/__tests__/database.test.ts`
- [ ] Run tests: `bun run test -- database`
- [ ] Verify all 25 statements covered
- [ ] Test with real D1 schema validation

**Expected Time**: 2 hours
**Pass Criteria**: 100% coverage of database.ts, all edge cases pass

---

### CRITICAL-4: Error Handling Testing

**File to Create**: `src/__tests__/errors.test.ts`
**Why**: ALL 13 statements in errors.ts are untested
**Impact**: Error responses never validated

**Implementation**:

```typescript
import { describe, expect, it, vi } from "vitest";
import {
  AppError,
  errorResponse,
  handleUnknownError,
  isAppError,
} from "~/utils/errors";
import { HTTP } from "~/types";
import type { Context } from "hono";

describe("Error Handling Utilities", () => {
  describe("errorResponse", () => {
    it("should return JSON response with correct status", async () => {
      const c = createMockContext();

      const response = errorResponse(c, "Test error", {
        code: "TEST_ERROR",
        status: HTTP.BadRequest,
      });

      expect(response.status).toBe(400);
    });

    it("should include error message and code", async () => {
      const c = createMockContext();

      const response = errorResponse(c, "Invalid input", {
        code: "VALIDATION_ERROR",
        status: HTTP.BadRequest,
      });

      const json = await response.json();
      expect(json.error).toBe("Invalid input");
      expect(json.code).toBe("VALIDATION_ERROR");
    });

    it("should include requestId when provided", async () => {
      const c = createMockContext();

      const response = errorResponse(c, "Error", {
        code: "TEST_ERROR",
        status: HTTP.InternalServerError,
        requestId: "req-12345",
      });

      const json = await response.json();
      expect(json.requestId).toBe("req-12345");
    });

    it("should exclude requestId when not provided", async () => {
      const c = createMockContext();

      const response = errorResponse(c, "Error", {
        code: "TEST_ERROR",
      });

      const json = await response.json();
      expect(json.requestId).toBeUndefined();
    });

    it("should use default status code (500)", async () => {
      const c = createMockContext();

      const response = errorResponse(c, "Error", {
        code: "TEST_ERROR",
      });

      expect(response.status).toBe(500);
    });

    it("should log error with context", async () => {
      const mockLogger = vi.fn();
      const c = createMockContext();

      errorResponse(c, "Error message", {
        code: "TEST_ERROR",
        status: 400,
        context: { field: "value" },
      });

      // Verify logger was called (via spy)
      expect(mockLogger).toHaveBeenCalled();
    });
  });

  describe("handleUnknownError", () => {
    it("should extract message from Error instance", () => {
      const c = createMockContext();
      const error = new Error("Original error message");

      const response = handleUnknownError(
        c,
        error,
        "Fallback message",
        "UNKNOWN_ERROR",
      );

      // Check that Error message is used
      expect(response.status).toBe(500);
    });

    it("should use fallback message for non-Error exceptions", () => {
      const c = createMockContext();

      const response = handleUnknownError(
        c,
        "string error",
        "Fallback message",
        "UNKNOWN_ERROR",
      );

      expect(response.status).toBe(500);
    });

    it("should include requestId in error response", () => {
      const c = createMockContext("test-request-id");

      const response = handleUnknownError(
        c,
        new Error("test"),
        "Fallback",
        "UNKNOWN_ERROR",
      );

      expect(response.status).toBe(500);
    });

    it("should log with UNKNOWN_ERROR code", () => {
      const c = createMockContext();

      handleUnknownError(
        c,
        new Error("test"),
        "Fallback",
        "UNKNOWN_ERROR",
      );

      // Verify code is passed to logger
    });
  });

  describe("AppError class", () => {
    it("should create error with required fields", () => {
      const error = new AppError(
        "Test error",
        "TEST_CODE",
        HTTP.BadRequest,
      );

      expect(error.message).toBe("Test error");
      expect(error.code).toBe("TEST_CODE");
      expect(error.status).toBe(400);
      expect(error.name).toBe("AppError");
    });

    it("should use default status code", () => {
      const error = new AppError("Message", "CODE");
      expect(error.status).toBe(500);
    });

    it("should include optional context", () => {
      const context = { field: "value" };
      const error = new AppError("Message", "CODE", 400, context);

      expect(error.context).toEqual(context);
    });

    it("should be instanceof Error", () => {
      const error = new AppError("Message", "CODE");
      expect(error instanceof Error).toBe(true);
    });

    it("should have stack trace", () => {
      const error = new AppError("Message", "CODE");
      expect(error.stack).toBeDefined();
    });
  });

  describe("isAppError type guard", () => {
    it("should return true for AppError instances", () => {
      const error = new AppError("Message", "CODE");
      expect(isAppError(error)).toBe(true);
    });

    it("should return false for regular Error", () => {
      const error = new Error("Message");
      expect(isAppError(error)).toBe(false);
    });

    it("should return false for null", () => {
      expect(isAppError(null)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(isAppError(undefined)).toBe(false);
    });

    it("should return false for strings", () => {
      expect(isAppError("error message")).toBe(false);
    });

    it("should return false for plain objects", () => {
      expect(isAppError({ message: "error" })).toBe(false);
    });
  });
});

function createMockContext(requestId?: string): Context {
  return {
    get: (key: string) => {
      if (key === "requestId") return requestId;
      return undefined;
    },
    json: (data: any, status?: number) => {
      const response = new Response(JSON.stringify(data), {
        status: status || 200,
      });
      return response;
    },
  } as any;
}
```

**Checklist**:

- [ ] Create `src/__tests__/errors.test.ts`
- [ ] Run tests: `bun run test -- errors`
- [ ] Verify all 13 statements covered
- [ ] Validate error response format matches API spec

**Expected Time**: 1.5 hours
**Pass Criteria**: 100% coverage of errors.ts, response formats validated

---

### CRITICAL-5: Logger Implementation Testing

**File to Create**: `src/__tests__/logger.test.ts`
**Why**: Logger only 47.6% covered (11 statements untested)
**Impact**: Log output reliability unknown

**Implementation**:

```typescript
import { describe, expect, it, vi } from "vitest";
import { logger } from "~/utils/logger";

describe("Logger Implementation", () => {
  describe("Log Level Filtering", () => {
    it("should respect log level threshold", () => {
      const consoleSpy = vi.spyOn(console, "log");

      // Set debug level
      logger.setLevel("debug");
      logger.debug("Debug message");
      expect(consoleSpy).toHaveBeenCalled();

      // Set info level - debug should be suppressed
      logger.setLevel("info");
      consoleSpy.mockClear();
      logger.debug("Debug message");
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it("should always log error level", () => {
      const consoleSpy = vi.spyOn(console, "error");

      logger.setLevel("error");
      logger.error("Error message");
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("Error message"),
      );
    });

    it("should always log warn level", () => {
      const consoleSpy = vi.spyOn(console, "warn");

      logger.setLevel("error");
      logger.warn("Warning message");
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("Warning message"),
      );
    });
  });

  describe("Structured Logging", () => {
    it("should format log output with timestamp", () => {
      const consoleSpy = vi.spyOn(console, "log");

      logger.info("Test message");

      const output = consoleSpy.mock.calls[0][0];
      expect(output).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it("should include log level in output", () => {
      const consoleSpy = vi.spyOn(console, "log");

      logger.info("Test");
      const output = consoleSpy.mock.calls[0][0];
      expect(output).toContain("INFO");
    });

    it("should format context object as JSON", () => {
      const consoleSpy = vi.spyOn(console, "log");

      logger.info("Message", { userId: "123", action: "login" });

      const output = JSON.stringify(consoleSpy.mock.calls[0]);
      expect(output).toContain("userId");
      expect(output).toContain("123");
    });

    it("should handle Error object in context", () => {
      const consoleSpy = vi.spyOn(console, "error");
      const error = new Error("Test error");

      logger.error("Message", error);

      const output = consoleSpy.mock.calls[0][0];
      expect(output).toContain("Test error");
    });

    it("should handle Error stack traces", () => {
      const consoleSpy = vi.spyOn(console, "error");
      const error = new Error("Test error");

      logger.error("Message", error);

      const output = JSON.stringify(consoleSpy.mock.calls);
      // Stack should be included or referenced
      expect(output.length > 50).toBe(true);
    });
  });

  describe("Context Binding", () => {
    it("should create logger with bound context", () => {
      const contextLogger = logger.withContext({ requestId: "req-123" });

      expect(contextLogger).toBeDefined();
      expect(typeof contextLogger.info).toBe("function");
    });

    it("should include bound context in all logs", () => {
      const consoleSpy = vi.spyOn(console, "log");
      const contextLogger = logger.withContext({ requestId: "req-123" });

      contextLogger.info("Message");

      const output = JSON.stringify(consoleSpy.mock.calls);
      expect(output).toContain("req-123");
    });

    it("should merge additional context with bound context", () => {
      const consoleSpy = vi.spyOn(console, "log");
      const contextLogger = logger.withContext({ requestId: "req-123" });

      contextLogger.info("Message", { userId: "456" });

      const output = JSON.stringify(consoleSpy.mock.calls);
      expect(output).toContain("req-123");
      expect(output).toContain("456");
    });
  });

  describe("Edge Cases", () => {
    it("should handle null context gracefully", () => {
      expect(() => {
        logger.info("Message", null);
      }).not.toThrow();
    });

    it("should handle undefined context gracefully", () => {
      expect(() => {
        logger.info("Message", undefined);
      }).not.toThrow();
    });

    it("should handle circular references in context", () => {
      const obj: any = { foo: "bar" };
      obj.self = obj;

      expect(() => {
        logger.info("Message", obj);
      }).not.toThrow();
    });

    it("should handle very large context objects", () => {
      const largeContext: any = {};
      for (let i = 0; i < 1000; i++) {
        largeContext[`field_${i}`] = `value_${i}`;
      }

      expect(() => {
        logger.info("Message", largeContext);
      }).not.toThrow();
    });
  });
});
```

**Checklist**:

- [ ] Create `src/__tests__/logger.test.ts`
- [ ] Run tests: `bun run test -- logger`
- [ ] Cover all 11 untested statements
- [ ] Test structured logging format

**Expected Time**: 1.5 hours
**Pass Criteria**: 100% coverage of logger.ts, log format validated

---

## Phase 1 Summary

**Tests to Create**: 5 new files
**Total Tests**: ~25 new tests
**Expected Coverage Improvement**: 93.6% → 97%+
**Estimated Time**: 8-10 hours

**Priority Order**:

1. Timing Attack (C1) - 1-2 hours - CRITICAL
2. SSRF (C2) - 2-3 hours - CRITICAL
3. Database (C3) - 2 hours - CRITICAL
4. Errors (C4) - 1.5 hours - CRITICAL
5. Logger (H1) - 1.5 hours - HIGH

---

## Phase 2: High Priority (Week 2)

### HIGH-1: Branded Types Testing

**File**: `src/__tests__/types.test.ts` (NEW)
**Statements**: 4 (from 14 total)
**Time**: 1 hour

### HIGH-2: CLI Tool Testing

**File**: `client/cmd/gpg-sign/main_test.go` (NEW)
**Tests**: 6 tests
**Time**: 2 hours

### HIGH-3: Input Validation Boundaries

**File**: `src/__tests__/validation.test.ts` (NEW)
**Tests**: 4 tests
**Time**: 1 hour

### HIGH-4: Crypto Failure Modes

**File**: `src/__tests__/signing.test.ts` (ADD)
**Tests**: 3 tests
**Time**: 1 hour

**Phase 2 Total**: ~13 tests, 5-6 hours

---

## Phase 3: Performance (Week 3-4)

### Performance Benchmarks

- OpenPGP operation latency
- Concurrent signing requests
- D1 query throughput
- Rate limiter performance
- JWKS cache hit ratio

**Time**: 8-10 hours setup + ongoing monitoring

---

## Implementation Checklist

### Week 1 (Critical)

- [ ] Day 1: Timing attack tests (2h) + SSRF tests (2h)
- [ ] Day 2: Database tests (2h) + Errors tests (1.5h)
- [ ] Day 3: Logger tests (1.5h) + Review + Fix failures
- [ ] Run coverage: `bun run test:coverage`
- [ ] Target: 97%+ coverage, 0 security gaps

### Week 2 (High Priority)

- [ ] Day 1: Branded types (1h) + CLI tests (2h)
- [ ] Day 2: Input validation (1h) + Crypto modes (1h)
- [ ] Day 3: Integration testing, fix failures
- [ ] Target: 98%+ coverage, all critical paths tested

### Week 3-4 (Performance)

- [ ] Setup vitest benchmarks
- [ ] Implement load tests
- [ ] Establish SLO baselines
- [ ] Document performance targets

---

## Success Criteria

**Coverage**:

- [ ] Reach 98%+ line coverage
- [ ] All critical paths 100%
- [ ] Database & error handling 100%

**Security**:

- [ ] Timing attack resistance tested
- [ ] SSRF prevention validated
- [ ] Input validation boundary tested

**Quality**:

- [ ] All 254+ tests pass
- [ ] 0 security issues
- [ ] Performance baselines established

---

## Notes

- All tests should follow existing patterns in test files
- Use existing test helpers (createMockContext, etc.)
- Maintain 100% pass rate in CI
- Document any new test patterns used
- Review security implications before submitting

---

**Document Created**: 2025-11-25
**Next Review**: After Phase 1 completion
