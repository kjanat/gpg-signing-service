import type { Context } from "hono";

/**
 * Schedules a promise for background execution using executionCtx.waitUntil.
 * Automatically handles errors by logging them to console.
 * Falls back to await if executionCtx is unavailable (test environments).
 *
 * @param ctx - Hono context with optional executionCtx
 * @param requestId - Request ID for error logging context
 * @param promise - Promise to execute
 * @returns Promise<void> that resolves when background task is scheduled or completed
 */
export async function scheduleBackgroundTask(
  ctx: Context,
  requestId: string,
  promise: Promise<unknown>,
): Promise<void> {
  const taskWithErrorHandling = promise.catch((error) => {
    console.log("DEBUG: scheduleBackgroundTask catch block entered", {
      requestId,
      error,
    });
    console.error("Background task failed:", { requestId, error });
  });

  console.log("DEBUG: scheduleBackgroundTask called", {
    requestId,
    hasExecutionCtx: !!ctx.executionCtx,
  });

  if (ctx.executionCtx) {
    ctx.executionCtx.waitUntil(taskWithErrorHandling);
  } else {
    await taskWithErrorHandling;
  }
}
