import type { Context } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { HTTP } from "~/types";
import {
  AppError,
  errorResponse,
  handleUnknownError,
  isAppError,
} from "~/utils/errors";
import { logger } from "~/utils/logger";

// Mock logger to verify error logging
vi.mock("~/utils/logger", () => ({
  logger: {
    error: vi.fn(),
  },
}));

/**
 * Helper to create a mock Hono Context
 */
function createMockContext(requestId?: string): Context {
  const context = {
    json: vi.fn((data, status) => {
      return new Response(JSON.stringify(data), {
        status: status || 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
    get: vi.fn((key) => {
      if (key === "requestId") {
        return requestId;
      }
      return undefined;
    }),
  } as unknown as Context;

  return context;
}

describe("errors.ts - Error handling utilities", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("errorResponse()", () => {
    it("should return JSON response with error, code, and status", async () => {
      const c = createMockContext();
      const message = "Test error message";

      errorResponse(c, message, {
        code: "INTERNAL_ERROR",
        status: HTTP.InternalServerError,
      });

      expect(c.json).toHaveBeenCalledWith(
        {
          error: message,
          code: "INTERNAL_ERROR",
        },
        HTTP.InternalServerError,
      );
    });

    it("should include requestId in response when provided", async () => {
      const c = createMockContext("req-123");
      const message = "Test error";

      errorResponse(c, message, {
        code: "AUTH_MISSING",
        status: HTTP.Unauthorized,
        requestId: "req-123",
      });

      expect(c.json).toHaveBeenCalledWith(
        {
          error: message,
          code: "AUTH_MISSING",
          requestId: "req-123",
        },
        HTTP.Unauthorized,
      );
    });

    it("should not include requestId when not provided", async () => {
      const c = createMockContext();
      const message = "Error without request ID";

      errorResponse(c, message, {
        code: "NOT_FOUND",
        status: HTTP.NotFound,
      });

      const callArgs = (c.json as any).mock.calls[0][0];
      expect(callArgs).not.toHaveProperty("requestId");
      expect(callArgs).toEqual({
        error: message,
        code: "NOT_FOUND",
      });
    });

    it("should use default status (500) when not provided", async () => {
      const c = createMockContext();

      errorResponse(c, "Error", {
        code: "SIGN_ERROR",
      });

      expect(c.json).toHaveBeenCalledWith(
        expect.any(Object),
        HTTP.InternalServerError,
      );
    });

    it("should log error with code and status", async () => {
      const c = createMockContext();
      const message = "Logged error";

      errorResponse(c, message, {
        code: "KEY_NOT_FOUND",
        status: HTTP.NotFound,
      });

      expect(logger.error).toHaveBeenCalledWith(
        message,
        undefined,
        expect.objectContaining({
          code: "KEY_NOT_FOUND",
          status: HTTP.NotFound,
        }),
      );
    });

    it("should log error with context when provided", async () => {
      const c = createMockContext();
      const message = "Error with context";
      const context = { userId: "user-123", action: "signing" };

      errorResponse(c, message, {
        code: "RATE_LIMIT_ERROR",
        status: HTTP.TooManyRequests,
        context,
      });

      expect(logger.error).toHaveBeenCalledWith(
        message,
        undefined,
        expect.objectContaining({
          code: "RATE_LIMIT_ERROR",
          status: HTTP.TooManyRequests,
          userId: "user-123",
          action: "signing",
        }),
      );
    });

    it("should log error with requestId in context", async () => {
      const c = createMockContext("req-456");

      errorResponse(c, "Error", {
        code: "AUDIT_ERROR",
        requestId: "req-456",
      });

      expect(logger.error).toHaveBeenCalledWith(
        "Error",
        undefined,
        expect.objectContaining({
          requestId: "req-456",
        }),
      );
    });

    it("should support all valid error codes", () => {
      const c = createMockContext();
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
      ] as const;

      validCodes.forEach((code) => {
        vi.clearAllMocks();
        errorResponse(c, `Error for ${code}`, { code });
        expect(c.json).toHaveBeenCalled();
      });
    });

    it("should handle empty error message", () => {
      const c = createMockContext();

      errorResponse(c, "", {
        code: "INTERNAL_ERROR",
      });

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "",
        }),
        expect.any(Number),
      );
    });

    it("should handle very long error message", () => {
      const c = createMockContext();
      const longMessage = "A".repeat(10000);

      errorResponse(c, longMessage, {
        code: "INTERNAL_ERROR",
      });

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: longMessage,
        }),
        expect.any(Number),
      );
    });

    it("should handle special characters in error message", () => {
      const c = createMockContext();
      const specialMessage = "Error: \"quotes\", 'single', \\backslash\\ <tag>";

      errorResponse(c, specialMessage, {
        code: "INVALID_REQUEST",
      });

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: specialMessage,
        }),
        expect.any(Number),
      );
    });

    it("should handle context with nested objects", () => {
      const c = createMockContext();
      const context = {
        nested: {
          deep: {
            value: "test",
          },
        },
        array: [1, 2, 3],
      };

      errorResponse(c, "Error", {
        code: "KEY_PROCESSING_ERROR",
        context,
      });

      expect(logger.error).toHaveBeenCalledWith(
        "Error",
        undefined,
        expect.objectContaining(context),
      );
    });

    it("should use various HTTP status codes", () => {
      const c = createMockContext();
      const statusCodes = [
        HTTP.BadRequest,
        HTTP.Unauthorized,
        HTTP.Forbidden,
        HTTP.NotFound,
        HTTP.TooManyRequests,
        HTTP.InternalServerError,
      ];

      statusCodes.forEach((status) => {
        vi.clearAllMocks();
        errorResponse(c, "Error", {
          code: "INTERNAL_ERROR",
          status,
        });
        expect(c.json).toHaveBeenCalledWith(expect.any(Object), status);
      });
    });
  });

  describe("handleUnknownError()", () => {
    it("should extract message from Error object", () => {
      const c = createMockContext("req-789");
      const error = new Error("Something went wrong");

      handleUnknownError(c, error, "fallback message", "INTERNAL_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "Something went wrong",
        }),
        HTTP.InternalServerError,
      );
    });

    it("should use fallback message when error is not Error instance", () => {
      const c = createMockContext("req-999");

      handleUnknownError(c, "string error", "fallback message", "SIGN_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "fallback message",
        }),
        HTTP.InternalServerError,
      );
    });

    it("should use fallback message when error is null", () => {
      const c = createMockContext();

      handleUnknownError(c, null, "fallback null error", "KEY_NOT_FOUND");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "fallback null error",
        }),
        expect.any(Number),
      );
    });

    it("should use fallback message when error is undefined", () => {
      const c = createMockContext();

      handleUnknownError(c, undefined, "fallback undefined", "AUDIT_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "fallback undefined",
        }),
        expect.any(Number),
      );
    });

    it("should use fallback message for object that is not Error", () => {
      const c = createMockContext();
      const obj = { message: "not an error object" };

      handleUnknownError(c, obj, "fallback for object", "INVALID_REQUEST");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "fallback for object",
        }),
        expect.any(Number),
      );
    });

    it("should always use 500 status code", () => {
      const c = createMockContext();
      const error = new Error("test");

      handleUnknownError(c, error, "fallback", "INTERNAL_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.any(Object),
        HTTP.InternalServerError,
      );
    });

    it("should include requestId when available from context", () => {
      const c = createMockContext("req-123");
      const error = new Error("test error");

      handleUnknownError(c, error, "fallback", "KEY_PROCESSING_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          requestId: "req-123",
        }),
        expect.any(Number),
      );
    });

    it("should log error with error object", () => {
      const c = createMockContext();
      const error = new Error("logged error");

      handleUnknownError(c, error, "fallback", "RATE_LIMIT_ERROR");

      expect(logger.error).toHaveBeenCalledWith(
        "Unhandled error",
        error,
        expect.objectContaining({
          code: "RATE_LIMIT_ERROR",
        }),
      );
    });

    it("should log with provided error code", () => {
      const c = createMockContext();
      const error = new Error("test");

      handleUnknownError(c, error, "fallback", "AUTH_INVALID");

      expect(logger.error).toHaveBeenCalledWith(
        "Unhandled error",
        expect.any(Object),
        expect.objectContaining({
          code: "AUTH_INVALID",
        }),
      );
    });

    it("should include requestId in logging", () => {
      const c = createMockContext("req-log-123");
      const error = new Error("test");

      handleUnknownError(c, error, "fallback", "KEY_NOT_FOUND");

      expect(logger.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Object),
        expect.objectContaining({
          requestId: "req-log-123",
        }),
      );
    });

    it("should handle Error with empty message", () => {
      const c = createMockContext();
      const error = new Error("");

      handleUnknownError(c, error, "fallback", "INTERNAL_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "",
        }),
        expect.any(Number),
      );
    });

    it("should handle custom Error subclass", () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = "CustomError";
        }
      }

      const c = createMockContext();
      const error = new CustomError("custom error message");

      handleUnknownError(c, error, "fallback", "SIGN_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "custom error message",
        }),
        expect.any(Number),
      );
    });

    it("should handle number as error", () => {
      const c = createMockContext();

      handleUnknownError(c, 42, "fallback for number", "INVALID_REQUEST");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "fallback for number",
        }),
        expect.any(Number),
      );
    });

    it("should handle boolean as error", () => {
      const c = createMockContext();

      handleUnknownError(c, false, "fallback for boolean", "INTERNAL_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "fallback for boolean",
        }),
        expect.any(Number),
      );
    });

    it("should return Response from errorResponse", () => {
      const c = createMockContext();
      const error = new Error("test");

      const response = handleUnknownError(
        c,
        error,
        "fallback",
        "INTERNAL_ERROR",
      );

      expect(response).toBeDefined();
      expect(typeof response).toBe("object");
    });
  });

  describe("AppError class", () => {
    it("should create error with message and code", () => {
      const error = new AppError("Test error", "KEY_NOT_FOUND");

      expect(error.message).toBe("Test error");
      expect(error.code).toBe("KEY_NOT_FOUND");
      expect(error.name).toBe("AppError");
    });

    it("should use default status code when not provided", () => {
      const error = new AppError("Error", "INTERNAL_ERROR");

      expect(error.status).toBe(HTTP.InternalServerError);
    });

    it("should accept custom status code", () => {
      const error = new AppError("Not found", "KEY_NOT_FOUND", HTTP.NotFound);

      expect(error.status).toBe(HTTP.NotFound);
    });

    it("should accept context object", () => {
      const context = { userId: "user-456" };
      const error = new AppError(
        "Error with context",
        "AUDIT_ERROR",
        HTTP.InternalServerError,
        context,
      );

      expect(error.context).toEqual(context);
    });

    it("should be instanceof Error", () => {
      const error = new AppError("Test", "INTERNAL_ERROR");

      expect(error).toBeInstanceOf(Error);
    });

    it("should extend Error properly", () => {
      const error = new AppError("Test", "SIGN_ERROR");

      expect(error.stack).toBeDefined();
      expect(typeof error.stack).toBe("string");
    });

    it("should support all error codes", () => {
      const codes = [
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
      ] as const;

      codes.forEach((code) => {
        const error = new AppError("Message", code);
        expect(error.code).toBe(code);
      });
    });

    it("should preserve message through serialization", () => {
      const error = new AppError("Test message", "KEY_UPLOAD_ERROR");
      const json = JSON.stringify({
        message: error.message,
        code: error.code,
      });

      const parsed = JSON.parse(json);
      expect(parsed.message).toBe("Test message");
      expect(parsed.code).toBe("KEY_UPLOAD_ERROR");
    });

    it("should handle empty message", () => {
      const error = new AppError("", "INTERNAL_ERROR");

      expect(error.message).toBe("");
    });

    it("should handle special characters in message", () => {
      const msg = "Error: \"test\" 'quote' \\backslash\\";
      const error = new AppError(msg, "INVALID_REQUEST");

      expect(error.message).toBe(msg);
    });

    it("should handle very long message", () => {
      const longMsg = "A".repeat(5000);
      const error = new AppError(longMsg, "INTERNAL_ERROR");

      expect(error.message).toBe(longMsg);
    });

    it("should handle context with complex nested structure", () => {
      const context = {
        nested: { deep: { value: "test" } },
        array: [1, 2, 3],
        bool: true,
      };
      const error = new AppError("Error", "AUDIT_ERROR", 500, context);

      expect(error.context).toEqual(context);
    });

    it("should support various HTTP status codes", () => {
      const statusCodes = [
        HTTP.BadRequest,
        HTTP.Unauthorized,
        HTTP.Forbidden,
        HTTP.NotFound,
        HTTP.TooManyRequests,
        HTTP.InternalServerError,
      ];

      statusCodes.forEach((status) => {
        const error = new AppError("Error", "INTERNAL_ERROR", status);
        expect(error.status).toBe(status);
      });
    });

    it("should have code property defined", () => {
      const error = new AppError("Test", "SIGN_ERROR");

      // Code should be defined and accessible
      expect(error.code).toBe("SIGN_ERROR");
      expect(Object.getOwnPropertyDescriptor(error, "code")).toBeDefined();
    });

    it("should have status property defined", () => {
      const error = new AppError(
        "Test",
        "SIGN_ERROR",
        HTTP.InternalServerError,
      );

      // Status should be defined and accessible
      expect(error.status).toBe(HTTP.InternalServerError);
      expect(Object.getOwnPropertyDescriptor(error, "status")).toBeDefined();
    });

    it("should have context property defined", () => {
      const context = { key: "value" };
      const error = new AppError(
        "Test",
        "SIGN_ERROR",
        HTTP.InternalServerError,
        context,
      );

      // Context should be defined and accessible
      expect(error.context).toEqual(context);
      expect(Object.getOwnPropertyDescriptor(error, "context")).toBeDefined();
    });
  });

  describe("isAppError() type guard", () => {
    it("should return true for AppError instance", () => {
      const error = new AppError("Test", "INTERNAL_ERROR");

      expect(isAppError(error)).toBe(true);
    });

    it("should return false for regular Error", () => {
      const error = new Error("Test");

      expect(isAppError(error)).toBe(false);
    });

    it("should return false for string", () => {
      expect(isAppError("error message")).toBe(false);
    });

    it("should return false for null", () => {
      expect(isAppError(null)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(isAppError(undefined)).toBe(false);
    });

    it("should return false for number", () => {
      expect(isAppError(42)).toBe(false);
    });

    it("should return false for object with error-like properties", () => {
      const fakeError = {
        message: "Fake",
        code: "INTERNAL_ERROR",
        status: 500,
      };

      expect(isAppError(fakeError)).toBe(false);
    });

    it("should return false for Error subclass that is not AppError", () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = "CustomError";
        }
      }

      const error = new CustomError("Test");
      expect(isAppError(error)).toBe(false);
    });

    it("should work in conditional blocks for type narrowing", () => {
      const error: unknown = new AppError("Test", "SIGN_ERROR");

      if (isAppError(error)) {
        // TypeScript should narrow type to AppError here
        expect(error.code).toBe("SIGN_ERROR");
        expect(error.status).toBe(HTTP.InternalServerError);
      } else {
        throw new Error("Should be AppError");
      }
    });

    it("should work with mixed error types", () => {
      const appError = new AppError("App error", "INTERNAL_ERROR");
      const regularError = new Error("Regular error");
      const stringError = "String error";

      const errors: unknown[] = [appError, regularError, stringError];

      const appErrors = errors.filter(isAppError);
      expect(appErrors).toHaveLength(1);
      expect(appErrors[0]).toBe(appError);
    });
  });

  describe("Integration scenarios", () => {
    it("should handle AppError in handleUnknownError", () => {
      const c = createMockContext("req-int-1");
      const appError = new AppError(
        "App error message",
        "KEY_NOT_FOUND",
        HTTP.NotFound,
      );

      handleUnknownError(c, appError, "fallback", "INTERNAL_ERROR");

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "App error message",
        }),
        HTTP.InternalServerError,
      );
    });

    it("should create AppError and use with errorResponse", () => {
      const c = createMockContext("req-int-2");
      const appError = new AppError(
        "Processing failed",
        "KEY_PROCESSING_ERROR",
        HTTP.BadRequest,
      );

      errorResponse(c, appError.message, {
        code: appError.code,
        status: appError.status,
        ...(appError.context && { context: appError.context }),
      });

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "Processing failed",
          code: "KEY_PROCESSING_ERROR",
        }),
        HTTP.BadRequest,
      );
    });

    it("should handle error in try-catch and convert to response", () => {
      const c = createMockContext("req-int-3");

      try {
        throw new AppError("Operation failed", "SIGN_ERROR", HTTP.BadRequest);
      } catch (error) {
        if (isAppError(error)) {
          errorResponse(c, error.message, {
            code: error.code,
            status: error.status,
            requestId: "req-int-3",
          });
        }
      }

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "Operation failed",
          code: "SIGN_ERROR",
        }),
        HTTP.BadRequest,
      );
    });

    it("should chain error handling with context preservation", () => {
      const c = createMockContext("req-chain");
      const context = { userId: "user-123", action: "sign" };

      const error = new AppError(
        "Signing failed",
        "SIGN_ERROR",
        HTTP.BadRequest,
        context,
      );

      errorResponse(c, error.message, {
        code: error.code,
        status: error.status,
        requestId: "req-chain",
        ...(error.context && { context: error.context }),
      });

      expect(c.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "Signing failed",
          code: "SIGN_ERROR",
          requestId: "req-chain",
        }),
        HTTP.BadRequest,
      );

      expect(logger.error).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({
          requestId: "req-chain",
          userId: "user-123",
          action: "sign",
        }),
      );
    });
  });
});
