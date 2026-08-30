/**
 * Structured logger for production use
 * Provides consistent logging with proper levels and context
 */

import type { Context } from "hono";
import { HEADERS } from "#types";
import { captureError } from "#utils/sentry";

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

	/**
	 * Error-level log, and the one place this service reports to Sentry.
	 *
	 * The `console.log` below is emitted first and unchanged — Workers Logs and
	 * Logpush see byte-for-byte what they saw before this method learned to
	 * report anywhere. `captureError` is additive, and is a no-op unless a
	 * `SENTRY_DSN` is configured.
	 *
	 * Every error path in the service already funnels through here, including
	 * `app.onError` and `handleUnknownError`, which is why this is the chokepoint
	 * rather than the global handler: `LoggerWithContext.error` delegates to this
	 * method, so a request-scoped logger reports once, not twice.
	 */
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

		captureError(message, error, {
			...context,
			// `code` is this codebase's name for what Sentry should call
			// `errorCode`; the tag is what an alert filters on.
			...(typeof context?.code === "string" && { errorCode: context.code }),
		});
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

	error(message: string, error?: Error | unknown, additionalContext?: LogContext) {
		this.logger.error(message, error, {
			...this.context,
			...additionalContext,
		});
	}
}

// Singleton logger instance
export const logger = new Logger();
