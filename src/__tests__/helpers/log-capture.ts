/**
 * Reading back what the service actually logged.
 *
 * `Logger.error` is `(message, error?, context?)`, and calling it with one
 * object — `logger.error(msg, { requestId, error })` — type-checks, runs, and
 * produces a log line that looks close enough to right to survive review. It is
 * not: the object lands as the *error* payload, so the request id is nested one
 * level down and `captureError` is handed `context: undefined`, which strips
 * the only field correlating a Sentry report with the delivery it came from.
 *
 * Nothing about that is visible from a response, so it is asserted from the
 * structured line: production `Logger.log` emits one JSON document per call to
 * `console.log`, and a test that parses it can require the request id to be
 * where a log aggregator looks for it rather than where a mistake put it.
 */

import { expect } from "vitest";

/** One structured log line, as a log aggregator would receive it. */
export interface LogEntry {
	level?: string;
	message?: string;
	requestId?: string;
	error?: unknown;
	[key: string]: unknown;
}

/**
 * Run `body` with `console.log` captured, and return the structured lines.
 *
 * Development-mode lines are multi-argument and are ignored: only the JSON
 * documents production emits are parsed, which is what Workers Logs and
 * Logpush receive.
 *
 * @param body - The work whose logging is under test
 * @returns Every structured line emitted while it ran
 */
export async function captureLogEntries(body: () => Promise<unknown>): Promise<LogEntry[]> {
	const lines: string[] = [];
	const original = console.log;
	console.log = (...args: unknown[]) => {
		if (args.length === 1 && typeof args[0] === "string") {
			lines.push(args[0]);
		}
	};

	try {
		await body();
	} finally {
		console.log = original;
	}

	return lines.flatMap((line) => {
		try {
			return [JSON.parse(line) as LogEntry];
		} catch {
			return [];
		}
	});
}

/**
 * The one line whose message starts with `prefix`.
 *
 * By prefix rather than equality so a test does not have to restate a whole
 * sentence written for an operator, and asserts a single match so a suite
 * cannot silently start checking the wrong line.
 *
 * @param entries - Lines from {@link captureLogEntries}
 * @param prefix - Start of the message to find
 * @returns The matching line
 */
export function logLine(entries: LogEntry[], prefix: string): LogEntry {
	const matches = entries.filter((entry) => typeof entry.message === "string" && entry.message.startsWith(prefix));

	expect(matches).toHaveLength(1);

	return matches[0] as LogEntry;
}
