import type { Context } from "hono";
import { describe, expect, it, vi } from "vitest";
import { scheduleBackgroundTask } from "~/utils/execution";
import { logger } from "~/utils/logger";

describe("scheduleBackgroundTask", () => {
  it("uses waitUntil when executionCtx is present", async () => {
    // Arrange
    const mockWaitUntil = vi.fn();
    const mockPromise = Promise.resolve("success");
    const ctx = {
      executionCtx: { waitUntil: mockWaitUntil },
    } as unknown as Context;

    // Act
    await scheduleBackgroundTask(ctx, "test-request-id", mockPromise);

    // Assert - waitUntil called with error-wrapped promise
    expect(mockWaitUntil).toHaveBeenCalledTimes(1);
    const calledPromise = mockWaitUntil.mock.calls[0]?.[0];
    expect(calledPromise).toBeInstanceOf(Promise);
  });

  it("awaits promise when executionCtx is missing", async () => {
    // Arrange
    let resolved = false;
    const mockPromise = Promise.resolve().then(() => {
      resolved = true;
    });
    const ctx = { executionCtx: undefined } as unknown as Context;

    // Act
    await scheduleBackgroundTask(ctx, "test-request-id", mockPromise);

    // Assert - promise was awaited (resolved flag set)
    expect(resolved).toBe(true);
  });

  it("handles rejected promises with error logging", async () => {
    // Arrange
    const loggerSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
    const error = new Error("Background task failed");
    const mockPromise = Promise.reject(error);
    const ctx = { executionCtx: undefined } as unknown as Context;

    // Act - should not throw
    await scheduleBackgroundTask(ctx, "req-123", mockPromise);

    // Assert - error logged with requestId
    expect(loggerSpy).toHaveBeenCalledWith(
      "Background task failed",
      expect.objectContaining({ requestId: "req-123", error: error.message }),
    );
    loggerSpy.mockRestore();
  });
});
