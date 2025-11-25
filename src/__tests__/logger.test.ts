import type { Context } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HEADERS } from "~/types";

// Tests for development mode logging
describe("Logger - Development Mode", () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    // Set development mode before importing
    process.env.NODE_ENV = "development";
    // Clear module cache to reload with new environment
    vi.resetModules();
    consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
    vi.resetModules();
    process.env.NODE_ENV = "test";
  });

  it("should log debug messages in development mode", async () => {
    // Line 28, 37-38: debug console.log output in development
    const { logger: devLogger } = await import("~/utils/logger");
    const message = "Debug message";
    const context = { userId: "dev-user" };

    devLogger.debug(message, context);

    expect(consoleLogSpy).toHaveBeenCalledWith("[DEBUG]", message, context);
  });

  it("should log debug without context in development mode", async () => {
    // Line 28, 37-38: debug without context in development
    const { logger: devLogger } = await import("~/utils/logger");

    devLogger.debug("Debug only");

    expect(consoleLogSpy).toHaveBeenCalledWith("[DEBUG]", "Debug only", "");
  });

  it("should log info in development formatted output", async () => {
    // Line 28: info formatted for development mode
    const { logger: devLogger } = await import("~/utils/logger");
    const message = "Info in dev";
    const context = { action: "test" };

    devLogger.info(message, context);

    expect(consoleLogSpy).toHaveBeenCalledWith("[INFO]", message, context);
  });

  it("should log warn in development formatted output", async () => {
    // Line 28: warn formatted for development mode
    const { logger: devLogger } = await import("~/utils/logger");

    devLogger.warn("Warning in dev", { severity: "low" });

    expect(consoleLogSpy).toHaveBeenCalledWith("[WARN]", "Warning in dev", {
      severity: "low",
    });
  });

  it("should log error with stack trace in development mode", async () => {
    // Line 28, 55: error with stack trace in development mode
    const { logger: devLogger } = await import("~/utils/logger");
    const message = "Dev error";
    const error = new Error("Test error");

    devLogger.error(message, error);

    expect(consoleLogSpy).toHaveBeenCalled();
    const call = consoleLogSpy.mock.calls[0];
    expect(call?.[0]).toBe("[ERROR]");
    expect(call?.[1]).toBe(message);
    const logContext = call?.[2] as Record<string, unknown>;
    const errorObj = logContext?.error as Record<string, unknown>;
    expect(errorObj?.message).toBe("Test error");
    // Stack should be included in development mode
    expect(errorObj?.stack).toBeDefined();
    expect(String(errorObj?.stack)).toContain("Error: Test error");
  });

  it("should include error stack only in development mode", async () => {
    // Line 55: conditional stack trace based on isDevelopment
    const { logger: devLogger } = await import("~/utils/logger");
    const error = new TypeError("Type issue");

    devLogger.error("Type error", error);

    expect(consoleLogSpy).toHaveBeenCalled();
    const call = consoleLogSpy.mock.calls[0];
    const logContext = call?.[2] as Record<string, unknown>;
    const errorObj = logContext?.error as Record<string, unknown>;
    expect(errorObj?.stack).toBeDefined();
  });

  it("should format all log levels with prefix in development", async () => {
    // Line 28: all levels formatted with uppercase prefix
    const { logger: devLogger } = await import("~/utils/logger");

    devLogger.info("info msg");
    devLogger.warn("warn msg");
    devLogger.error("error msg");

    expect(consoleLogSpy).toHaveBeenCalledTimes(3);
    expect(consoleLogSpy.mock.calls[0]?.[0]).toBe("[INFO]");
    expect(consoleLogSpy.mock.calls[1]?.[0]).toBe("[WARN]");
    expect(consoleLogSpy.mock.calls[2]?.[0]).toBe("[ERROR]");
  });

  it("should not include context in JSON format in development", async () => {
    // Line 28, 31: development mode uses console.log directly, NOT JSON.stringify
    const { logger: devLogger } = await import("~/utils/logger");

    devLogger.info("Test", { key: "value" });

    expect(consoleLogSpy).toHaveBeenCalled();
    const call = consoleLogSpy.mock.calls[0];
    // In development, console.log is called with multiple arguments: [level, message, context]
    // NOT with a single JSON string like production
    expect(call).toHaveLength(3);
    expect(call?.[0]).toBe("[INFO]");
    expect(call?.[1]).toBe("Test");
    expect(call?.[2]).toEqual({ key: "value" });
  });
});

// Tests for production mode logging
describe("Logger", () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;
  let logger: any;

  beforeEach(async () => {
    // Import in production mode
    const loggerModule = await import("~/utils/logger");
    logger = loggerModule.logger;
    consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  describe("info level logging", () => {
    it("should log info message with context", () => {
      // Line 42, 24: info method and logEntry creation
      const message = "Info message";
      const context = { action: "sign", userId: "user123" };

      logger.info(message, context);

      expect(consoleLogSpy).toHaveBeenCalled();
      const call = consoleLogSpy.mock.calls[0]?.[0];
      expect(typeof call).toBe("string");

      // Parse JSON output (production mode)
      const parsed = JSON.parse(call as string);
      expect(parsed.level).toBe("info");
      expect(parsed.message).toBe(message);
      expect(parsed.action).toBe("sign");
      expect(parsed.userId).toBe("user123");
      expect(parsed.timestamp).toBeDefined();
    });

    it("should log info without context", () => {
      // Line 42: info without context parameter
      const message = "Info message only";

      logger.info(message);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.level).toBe("info");
      expect(parsed.message).toBe(message);
      expect(parsed.timestamp).toBeDefined();
    });

    it("should include multiple context fields in info log", () => {
      // Line 24: logEntry with context spread
      const message = "Multi-field context";
      const context = {
        userId: "user1",
        action: "sign",
        requestId: "req123",
        customField: "value",
      };

      logger.info(message, context);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.userId).toBe("user1");
      expect(parsed.action).toBe("sign");
      expect(parsed.requestId).toBe("req123");
      expect(parsed.customField).toBe("value");
    });
  });

  describe("warn level logging", () => {
    it("should log warn message with context", () => {
      // Line 46, 24: warn method and logEntry creation
      const message = "Warning occurred";
      const context = { severity: "high", component: "auth" };

      logger.warn(message, context);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.level).toBe("warn");
      expect(parsed.message).toBe(message);
      expect(parsed.severity).toBe("high");
      expect(parsed.component).toBe("auth");
    });

    it("should log warn without context", () => {
      // Line 46: warn without context
      const message = "Warning message";

      logger.warn(message);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.level).toBe("warn");
      expect(parsed.message).toBe(message);
    });
  });

  describe("error level logging", () => {
    it("should log error with Error object", () => {
      // Line 49-60: error method with Error object handling
      const message = "Error occurred";
      const error = new Error("Test error message");
      const context = { requestId: "req789" };

      logger.error(message, error, context);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.level).toBe("error");
      expect(parsed.message).toBe(message);
      expect(parsed.requestId).toBe("req789");
      expect(parsed.error).toBeDefined();
      expect(parsed.error.message).toBe("Test error message");
      expect(parsed.error.name).toBe("Error");
      // Stack should not be included in production mode
      expect(parsed.error.stack).toBeUndefined();
    });

    it("should log error with custom Error type", () => {
      // Line 56: error.name property for custom errors
      const message = "Type error";
      const error = new TypeError("Type mismatch");

      logger.error(message, error);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.error.name).toBe("TypeError");
      expect(parsed.error.message).toBe("Type mismatch");
    });

    it("should handle non-Error object as error parameter", () => {
      // Line 58: error instanceof Error check fails
      const message = "Unknown error";
      const unknownError = "string error";

      logger.error(message, unknownError);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.error).toBe("string error");
    });

    it("should handle null as error parameter", () => {
      // Line 52-58: null value handling
      const message = "Error with null";

      logger.error(message, null);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.error).toBeNull();
    });

    it("should handle undefined as error parameter", () => {
      // Line 52-58: undefined value handling
      const message = "Error with undefined";

      logger.error(message, undefined);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.error).toBeUndefined();
    });

    it("should log error without error object", () => {
      // Line 49: error method without error parameter
      const message = "Error message only";

      logger.error(message);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.level).toBe("error");
      expect(parsed.message).toBe(message);
    });

    it("should log error without context", () => {
      // Line 49: error without context parameter
      const message = "Error no context";
      const error = new Error("test");

      logger.error(message, error);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.message).toBe(message);
      expect(parsed.error.message).toBe("test");
    });

    it("should merge error context with additional context", () => {
      // Line 50-60: context and errorContext merging
      const message = "Error with merged context";
      const error = new Error("Base error");
      const context = { userId: "user1", action: "sign" };

      logger.error(message, error, context);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.userId).toBe("user1");
      expect(parsed.action).toBe("sign");
      expect(parsed.error.message).toBe("Base error");
    });
  });

  describe("debug level logging", () => {
    it("should skip debug logging in production", () => {
      // Line 36-38: debug method skipped in production
      logger.debug("Debug message", { userId: "user1" });

      // Debug should not be logged in production mode
      expect(consoleLogSpy).not.toHaveBeenCalled();
    });

    it("should skip debug without context", () => {
      // Line 36-38: debug skipped
      logger.debug("Another debug");

      expect(consoleLogSpy).not.toHaveBeenCalled();
    });
  });

  describe("timestamp and log structure", () => {
    it("should include ISO timestamp in every log", () => {
      // Line 22: timestamp generation
      logger.info("Message with timestamp");

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.timestamp).toBeDefined();
      // Verify ISO format
      expect(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(parsed.timestamp),
      ).toBe(true);
    });

    it("should include level in every log", () => {
      // Line 24: level included in logEntry
      logger.warn("Test message");

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.level).toBe("warn");
    });

    it("should include message in every log", () => {
      // Line 24: message included in logEntry
      const message = "Important message";
      logger.info(message);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.message).toBe(message);
    });
  });

  describe("LoggerWithContext", () => {
    let mockCtx: Context;

    beforeEach(() => {
      mockCtx = {
        get: vi.fn(),
        req: {
          header: vi.fn(),
        },
      } as unknown as Context;
    });

    describe("withContext initialization", () => {
      it("should create LoggerWithContext from context requestId", () => {
        // Line 67: requestId from c.get
        const requestId = "ctx-request-123";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);

        const loggerWithCtx = logger.withContext(mockCtx);

        expect(mockCtx.get).toHaveBeenCalledWith("requestId");
        expect(loggerWithCtx).toBeDefined();
        expect(typeof loggerWithCtx.info).toBe("function");
      });

      it("should fallback to request header for requestId", () => {
        // Line 67: fallback to c.req.header
        const requestId = "header-request-456";
        vi.mocked(mockCtx.get).mockReturnValue(undefined);
        (mockCtx.req.header as ReturnType<typeof vi.fn>).mockReturnValue(
          requestId,
        );

        const loggerWithCtx = logger.withContext(mockCtx);

        expect(mockCtx.req.header).toHaveBeenCalledWith(HEADERS.REQUEST_ID);
        expect(loggerWithCtx).toBeDefined();
      });

      it("should create with undefined requestId if both sources empty", () => {
        // Line 67: both c.get and c.req.header return undefined
        vi.mocked(mockCtx.get).mockReturnValue(undefined);
        (mockCtx.req.header as ReturnType<typeof vi.fn>).mockReturnValue(
          undefined,
        );

        const loggerWithCtx = logger.withContext(mockCtx);

        expect(loggerWithCtx).toBeDefined();
      });

      it("should prioritize context over header", () => {
        // Line 67: c.get returns non-falsy before trying c.req.header
        vi.mocked(mockCtx.get).mockReturnValue("context-id");
        (mockCtx.req.header as ReturnType<typeof vi.fn>).mockReturnValue(
          "header-id",
        );

        logger.withContext(mockCtx);

        // header should not be called because get returned a value
        expect(mockCtx.req.header).not.toHaveBeenCalled();
      });
    });

    describe("LoggerWithContext debug", () => {
      it("should pass debug message with merged context", () => {
        // Line 78-79: debug with context merging
        const requestId = "req-debug";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);
        const loggerWithCtx = logger.withContext(mockCtx);

        // Debug should still be skipped in production mode
        loggerWithCtx.debug("Debug message", { userId: "user1" });

        expect(consoleLogSpy).not.toHaveBeenCalled();
      });
    });

    describe("LoggerWithContext info", () => {
      it("should log info with merged context", () => {
        // Line 82-83: info with context merging
        const requestId = "req-info-123";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.info("Info message", { action: "sign" });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe(requestId);
        expect(parsed.action).toBe("sign");
        expect(parsed.message).toBe("Info message");
      });

      it("should log info without additional context", () => {
        // Line 82-83: info without additionalContext
        const requestId = "req-info-456";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.info("Info only");

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe(requestId);
        expect(parsed.message).toBe("Info only");
      });

      it("should merge context from withContext and info call", () => {
        // Line 79: spread operator merging
        vi.mocked(mockCtx.get).mockReturnValue("req-123");
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.info("Message", { userId: "user1", action: "verify" });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe("req-123");
        expect(parsed.userId).toBe("user1");
        expect(parsed.action).toBe("verify");
      });
    });

    describe("LoggerWithContext warn", () => {
      it("should log warn with merged context", () => {
        // Line 86-87: warn with context merging
        const requestId = "req-warn-123";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.warn("Warning", { severity: "high" });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe(requestId);
        expect(parsed.severity).toBe("high");
        expect(parsed.level).toBe("warn");
      });

      it("should log warn without additional context", () => {
        // Line 86-87: warn without additionalContext
        vi.mocked(mockCtx.get).mockReturnValue("req-warn-456");
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.warn("Warning message");

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe("req-warn-456");
        expect(parsed.level).toBe("warn");
      });

      it("should override context with additional warn context", () => {
        // Line 87: additionalContext overrides
        vi.mocked(mockCtx.get).mockReturnValue("original-req");
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.warn("Warning", { requestId: "overridden-req" });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe("overridden-req");
      });
    });

    describe("LoggerWithContext error", () => {
      it("should log error with merged context and error object", () => {
        // Line 90-98: error with full context merging
        const requestId = "req-error-123";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);
        const loggerWithCtx = logger.withContext(mockCtx);
        const error = new Error("Test error");

        loggerWithCtx.error("Error message", error, { userId: "user1" });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe(requestId);
        expect(parsed.userId).toBe("user1");
        expect(parsed.error.message).toBe("Test error");
        expect(parsed.level).toBe("error");
      });

      it("should log error without error object", () => {
        // Line 90-98: error without Error parameter
        const requestId = "req-error-456";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.error("Error message", undefined, { userId: "user2" });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe(requestId);
        expect(parsed.userId).toBe("user2");
        expect(parsed.message).toBe("Error message");
      });

      it("should log error without additional context", () => {
        // Line 90-98: error without additionalContext
        const requestId = "req-error-789";
        vi.mocked(mockCtx.get).mockReturnValue(requestId);
        const loggerWithCtx = logger.withContext(mockCtx);
        const error = new Error("Critical");

        loggerWithCtx.error("Critical error", error);

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe(requestId);
        expect(parsed.error.message).toBe("Critical");
      });

      it("should merge context from withContext and error call", () => {
        // Line 95-97: context spread merging in error
        vi.mocked(mockCtx.get).mockReturnValue("req-123");
        const loggerWithCtx = logger.withContext(mockCtx);
        const error = new Error("Test");

        loggerWithCtx.error("Error", error, { userId: "u1", action: "delete" });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe("req-123");
        expect(parsed.userId).toBe("u1");
        expect(parsed.action).toBe("delete");
        expect(parsed.error.message).toBe("Test");
      });

      it("should allow additional context to override withContext context", () => {
        // Line 95-97: additionalContext override
        vi.mocked(mockCtx.get).mockReturnValue("original");
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.error("Error", new Error("test"), {
          requestId: "override",
        });

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.requestId).toBe("override");
      });

      it("should handle Error object in context-based logging", () => {
        // Line 52-59: Error object handling in LoggerWithContext
        vi.mocked(mockCtx.get).mockReturnValue("req-err");
        const loggerWithCtx = logger.withContext(mockCtx);
        const typeError = new ReferenceError("Variable not found");

        loggerWithCtx.error("Reference error occurred", typeError);

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.error.name).toBe("ReferenceError");
        expect(parsed.error.message).toBe("Variable not found");
      });

      it("should handle non-Error object in context-based error logging", () => {
        // Line 58: non-Error object handling in LoggerWithContext
        vi.mocked(mockCtx.get).mockReturnValue("req-err");
        const loggerWithCtx = logger.withContext(mockCtx);

        loggerWithCtx.error("Unknown error", "string error value");

        expect(consoleLogSpy).toHaveBeenCalled();
        const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        expect(parsed.error).toBe("string error value");
      });
    });

    describe("LoggerWithContext multiple calls", () => {
      it("should maintain independent context across instances", () => {
        // Line 68: new LoggerWithContext instance
        vi.mocked(mockCtx.get).mockReturnValue("req-1");
        const loggerWithCtx1 = logger.withContext(mockCtx);

        const mockCtx2 = {
          get: vi.fn(() => "req-2"),
          req: { header: vi.fn() },
        } as unknown as Context;
        const loggerWithCtx2 = logger.withContext(mockCtx2);

        loggerWithCtx1.info("From logger 1");
        loggerWithCtx2.info("From logger 2");

        expect(consoleLogSpy).toHaveBeenCalledTimes(2);
        const parsed1 = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
        const parsed2 = JSON.parse(consoleLogSpy.mock.calls[1]?.[0] as string);
        expect(parsed1.requestId).toBe("req-1");
        expect(parsed2.requestId).toBe("req-2");
      });
    });
  });

  describe("Singleton instance", () => {
    it("should export singleton logger instance", () => {
      // Line 103: singleton export
      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe("function");
      expect(typeof logger.warn).toBe("function");
      expect(typeof logger.error).toBe("function");
      expect(typeof logger.debug).toBe("function");
      expect(typeof logger.withContext).toBe("function");
    });
  });

  describe("Edge cases", () => {
    it("should handle empty message string", () => {
      logger.info("");

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.message).toBe("");
    });

    it("should handle message with special characters", () => {
      const message = "Message with \"quotes\" and \\ backslash";

      logger.warn(message);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.message).toBe(message);
    });

    it("should handle context with null values", () => {
      logger.info("Message", { field: null });

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.field).toBeNull();
    });

    it("should handle context with nested objects", () => {
      const context = { nested: { deep: { value: "test" } } };

      logger.info("Message", context);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.nested.deep.value).toBe("test");
    });

    it("should handle multiple sequential logs", () => {
      logger.info("First");
      logger.warn("Second");
      logger.error("Third", new Error("err"));

      expect(consoleLogSpy).toHaveBeenCalledTimes(3);
      const parsed1 = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      const parsed2 = JSON.parse(consoleLogSpy.mock.calls[1]?.[0] as string);
      const parsed3 = JSON.parse(consoleLogSpy.mock.calls[2]?.[0] as string);
      expect(parsed1.level).toBe("info");
      expect(parsed2.level).toBe("warn");
      expect(parsed3.level).toBe("error");
    });

    it("should handle Error with custom error types", () => {
      const rangeError = new RangeError("Out of range");

      logger.error("Range error", rangeError);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.error.name).toBe("RangeError");
      expect(parsed.error.message).toBe("Out of range");
    });

    it("should handle Error with empty message", () => {
      const error = new Error("");

      logger.error("Error message", error);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      expect(parsed.error.message).toBe("");
    });

    it("should handle large context objects", () => {
      const largeContext = {
        field1: "value1",
        field2: "value2",
        field3: "value3",
        field4: "value4",
        field5: "value5",
      };

      logger.info("Message", largeContext);

      expect(consoleLogSpy).toHaveBeenCalled();
      const parsed = JSON.parse(consoleLogSpy.mock.calls[0]?.[0] as string);
      Object.entries(largeContext).forEach(([key, value]) => {
        expect(parsed[key]).toBe(value);
      });
    });
  });
});
