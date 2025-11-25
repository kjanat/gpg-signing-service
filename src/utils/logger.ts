/**
 * Structured logger for production use
 * Provides consistent logging with proper levels and context
 */

import type { Context } from "hono";
import { HEADERS } from "~/types";

export type LogLevel = "debug" | "info" | "warn" | "error";

interface LogContext {
  requestId?: string;
  userId?: string;
  action?: string;
  [key: string]: unknown;
}

class Logger {
  private isDevelopment = process.env.NODE_ENV === "development";

  private log(level: LogLevel, message: string, context?: LogContext) {
    const timestamp = new Date().toISOString();

    const logEntry = { timestamp, level, message, ...context };

    // In production, use structured logging
    if (this.isDevelopment) {
      console.log(`[${level.toUpperCase()}]`, message, context || "");
    } else {
      // In production, emit JSON for log aggregation services
      console.log(JSON.stringify(logEntry));
    }
  }

  debug(message: string, context?: LogContext) {
    if (this.isDevelopment) {
      this.log("debug", message, context);
    }
  }

  info(message: string, context?: LogContext) {
    this.log("info", message, context);
  }

  warn(message: string, context?: LogContext) {
    this.log("warn", message, context);
  }

  error(message: string, error?: Error | unknown, context?: LogContext) {
    const errorContext = {
      ...context,
      error:
        error instanceof Error
          ? {
              message: error.message,
              stack: this.isDevelopment ? error.stack : undefined,
              name: error.name,
            }
          : error,
    };
    this.log("error", message, errorContext);
  }

  /**
   * Create a logger instance with request context
   */
  withContext(c: Context): LoggerWithContext {
    const requestId = c.get("requestId") || c.req.header(HEADERS.REQUEST_ID);
    return new LoggerWithContext(this, { requestId });
  }
}

class LoggerWithContext {
  constructor(
    private logger: Logger,
    private context: LogContext,
  ) {}

  debug(message: string, additionalContext?: LogContext) {
    this.logger.debug(message, { ...this.context, ...additionalContext });
  }

  info(message: string, additionalContext?: LogContext) {
    this.logger.info(message, { ...this.context, ...additionalContext });
  }

  warn(message: string, additionalContext?: LogContext) {
    this.logger.warn(message, { ...this.context, ...additionalContext });
  }

  error(
    message: string,
    error?: Error | unknown,
    additionalContext?: LogContext,
  ) {
    this.logger.error(message, error, {
      ...this.context,
      ...additionalContext,
    });
  }
}

// Singleton logger instance
export const logger = new Logger();
