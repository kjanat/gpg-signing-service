/**
 * Error handling utilities
 */

import type { Context } from "hono";
import type { ErrorCode } from "~/schemas/errors";
import { HTTP } from "~/types";
import { logger } from "./logger";

interface ErrorOptions {
  code: ErrorCode;
  status?: number;
  requestId?: string;
  context?: Record<string, unknown>;
}

/**
 * Standardized error response
 */
export function errorResponse(
  c: Context,
  message: string,
  options: ErrorOptions,
) {
  const {
    code,
    status = HTTP.InternalServerError,
    requestId,
    context,
  } = options;

  // Log the error
  logger.error(message, undefined, {
    code,
    status,
    ...(requestId && { requestId }),
    ...context,
  });

  // Return standardized response
  return c.json(
    { error: message, code, ...(requestId && { requestId }) },
    status as Parameters<typeof c.json>[1], // Cast to Hono's expected status type
  );
}

/**
 * Handle unknown errors
 */
export function handleUnknownError(
  c: Context,
  error: unknown,
  fallbackMessage: string,
  code: ErrorCode,
): Response {
  const message = error instanceof Error ? error.message : fallbackMessage;
  const requestId = c.get("requestId");

  logger.error("Unhandled error", error, { code, requestId });

  return errorResponse(c, message, {
    code,
    requestId,
    status: HTTP.InternalServerError,
  });
}

/**
 * Create typed error class
 */
export class AppError extends Error {
  constructor(
    message: string,
    public readonly code: ErrorCode,
    public readonly status = HTTP.InternalServerError,
    public readonly context?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AppError";
  }
}

/**
 * Type guard for AppError
 */
export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}
