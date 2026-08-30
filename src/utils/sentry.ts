/**
 * The Sentry boundary.
 *
 * Everything this service is willing to tell a third party about a failure goes
 * through this module: the option object both entry points build from, the
 * scrubber every event and breadcrumb passes through on the way out, and the
 * three capture helpers the rest of the code calls. One module, so "is this
 * redacted?" has exactly one answer to read.
 *
 * Two properties are load-bearing.
 *
 * **Optional.** `SENTRY_DSN` unset — or set to whitespace — is a real no-op.
 * The options say `enabled: false`, carry no DSN, no tunnel, no debug logging,
 * sample no traces and install no integrations at all: nothing wraps `console`,
 * nothing reads a request body, and nothing is sent anywhere. `console.log`
 * reaches Workers Logs byte-for-byte as it does without this module, and
 * `audit_logs` is written the same way.
 *
 * That is a statement about *output*, not about the call stack. `withSentry`
 * and `instrumentDurableObjectWithSentry` install their wrappers before any
 * option is read, so with no DSN the env and Durable Object storage handles are
 * still proxies and the D1 statements still carry span shims. They record into
 * a client that does not exist, so nothing is emitted and nothing is kept — but
 * "nothing is installed" would be a stronger claim than the code makes, and the
 * whole test suite runs on this branch to check the claim that is true.
 *
 * **Scrubbed.** This is a signing service. The scrubber redacts by key name and
 * by value shape, recursively, over the whole event — request data, extras,
 * contexts, breadcrumbs, exception messages, nested objects — and additionally
 * over the literal values of this deployment's own secrets, which is the only
 * check that cannot be defeated by a secret arriving under a name nobody
 * predicted. Key ids, fingerprints, issuers and subject prefixes are left
 * alone: they are already public through `/public-key`, `GET /admin/subjects`
 * and the audit trail, and they are most of the diagnostic value.
 */

import type { Breadcrumb, CloudflareOptions, ErrorEvent, Event } from "@sentry/cloudflare";
import * as Sentry from "@sentry/cloudflare";
import type { Env } from "#types";
import { HEADERS } from "#types";

/** What every redaction leaves behind. One token, so a test can grep for it. */
export const REDACTED = "[redacted]";

/** Fraction of requests traced when a DSN is configured and no override is set. */
export const DEFAULT_TRACES_SAMPLE_RATE = 0.1;

/** Depth at which the recursive scrubber stops descending. */
const MAX_SCRUB_DEPTH = 12;

/**
 * Keys whose value is never safe to ship, matched on a normalized form of the
 * name so `KEY_PASSPHRASE`, `keyPassphrase` and `key-passphrase` are one entry.
 */
const DENIED_KEYS: ReadonlySet<string> = new Set([
	"adminreadonlytoken",
	"admintoken",
	"apikey",
	"armoredkey",
	"armoredprivatekey",
	"authheader",
	"authorization",
	"bearer",
	"cookie",
	"credential",
	"credentials",
	"idtoken",
	"jwt",
	"keypassphrase",
	"passphrase",
	"password",
	"privatekey",
	"privatekeypem",
	"proxyauthorization",
	"refreshtoken",
	"secret",
	"sentrydsn",
	"servicetoken",
	"setcookie",
	"token",
	"tokens",
	"xapikey",
	HEADERS.AUTHORIZATION.toLowerCase(),
]);

/**
 * Substrings that condemn a key whatever it is embedded in.
 *
 * Deliberately narrow. `tokenHash` survives — the stored hash is the one form
 * of a service token that is safe to look at, and it is how an operator ties a
 * refusal to a row — so "token" is not on this list.
 */
const DENIED_KEY_FRAGMENTS: readonly string[] = ["passphrase", "password", "privatekey", "secret", "authorization"];

/**
 * The leading run of RFC 7235 `token68` characters — what an actually-presented
 * `Bearer`/`Basic` credential is spelled with.
 *
 * This is the syntax check that replaces the old length floor. A floor made
 * shortness the security boundary, which meant a genuinely short credential in
 * free text survived; matching credential *syntax* instead keeps documentation
 * prose readable without letting anything real through, because a placeholder
 * (`<token>`, `$ADMIN_TOKEN`, `{{ secrets.X }}`) does not start with a token68
 * character at all.
 */
const TOKEN68_HEAD = /^[A-Za-z0-9\-._~+/]+/;

/**
 * Redact one `Bearer`/`Basic` credential, keeping the scheme.
 *
 * Two shapes are deliberately spared, and only these two:
 *
 * - a candidate with no token68 prefix — `Bearer <token>`, `Bearer $TOKEN` —
 *   which is documentation, not a credential;
 * - `name="value"`, which is a `WWW-Authenticate` auth-param such as
 *   `Bearer realm="gpg-signing-service"` — a challenge the service *emits*, not
 *   a credential a caller presented.
 *
 * Everything else redacts regardless of length, so `Bearer x` goes, and so does
 * a credential embedded in a stringified JSON blob (`"Bearer abc123"}`), where
 * the trailing punctuation is preserved rather than used as an excuse to skip.
 */
function redactCredential(match: string, scheme: string, candidate: string): string {
	const head = TOKEN68_HEAD.exec(candidate)?.[0];
	if (!head) return match;

	const afterHead = candidate.slice(head.length);
	if (afterHead.startsWith('="')) return match;

	// Base64 padding belongs to the credential, not to the text after it.
	const padding = /^=+/.exec(afterHead)?.[0] ?? "";
	return `${scheme} ${REDACTED}${afterHead.slice(padding.length)}`;
}

/**
 * Value shapes redacted wherever they appear, including inside a string that is
 * mostly something else — a log line, an exception message, a URL.
 *
 * The armor pattern accepts an unterminated block on purpose: a private key
 * truncated by a message-length limit is still a private key.
 */
const VALUE_PATTERNS: readonly { pattern: RegExp; replacement: (match: string, ...groups: string[]) => string }[] = [
	// Armored/PEM private key material, PGP or X.509.
	{
		pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE[A-Z0-9 ]*-----[\s\S]*?(?:-----END [A-Z0-9 ]*-----|$)/g,
		replacement: () => REDACTED,
	},
	// A JWT, which is how every raw OIDC token arrives. Any base64url JOSE
	// header encodes to `eyJ`.
	{ pattern: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?/g, replacement: () => REDACTED },
	// A service token. `gst_` + base64url entropy; see `service-tokens.ts`.
	{ pattern: /\bgst_[A-Za-z0-9_-]{8,}/g, replacement: () => REDACTED },
	// A presented credential of any scheme, of any length. See `redactCredential`.
	{ pattern: /\b(Bearer|Basic)\s+(\S+)/gi, replacement: redactCredential },
];

/** Normalize a key for denylist comparison: case and separators do not matter. */
function normalizeKey(key: string): string {
	return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Whether a property name is one whose value must never leave the Worker. */
export function isDeniedKey(key: string): boolean {
	const normalized = normalizeKey(key);
	if (DENIED_KEYS.has(normalized)) return true;
	return DENIED_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment));
}

/**
 * The deployment's own secret values, longest first.
 *
 * Every configured, non-empty value is included. There is no length floor: a
 * short `ADMIN_TOKEN` is still this deployment's `ADMIN_TOKEN`, and exempting
 * it would mean the one rule that catches a secret arriving under an
 * unanticipated name quietly stops applying to the deployments least able to
 * afford it. Nothing in this repository imposes a minimum on those values, so
 * this module cannot assume one. If a degenerate secret — `"x"` — redacts a lot
 * of an event into noise, that is the correct failure: unreadable beats leaked,
 * and the fix belongs in the operator's secret, not here.
 *
 * Only values that are empty or entirely whitespace are dropped, because those
 * are not configured secrets at all: `""` matches at every position and would
 * replace the event with nothing but redaction markers, describing no
 * deployment's real state.
 *
 * A value with surrounding whitespace contributes both forms. `SENTRY_DSN` is
 * compared trimmed everywhere else, so the trimmed spelling is the one that
 * would appear in an error from the SDK.
 *
 * Longest first so that a secret containing another as a substring is redacted
 * whole rather than leaving its tail behind.
 */
export function collectEnvSecrets(env: Partial<Env>): string[] {
	const collected = new Set<string>();

	for (const value of [env.KEY_PASSPHRASE, env.ADMIN_TOKEN, env.ADMIN_READONLY_TOKEN, env.SENTRY_DSN]) {
		if (typeof value !== "string" || value.trim().length === 0) continue;
		collected.add(value);
		collected.add(value.trim());
	}

	return [...collected].sort((a, b) => b.length - a.length);
}

/** Escape a literal secret for use inside a RegExp. */
function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Redact every known secret shape, and every literal deployment secret, from a
 * single string. This is the only place a string is rewritten; the recursive
 * walker below just decides which strings reach it.
 */
export function redactString(value: string, secrets: readonly string[] = []): string {
	let result = value;
	for (const { pattern, replacement } of VALUE_PATTERNS) {
		// Fresh RegExp per call: the module-level literals carry /g, and a shared
		// `lastIndex` makes `replace` skip matches on every other invocation.
		result = result.replace(new RegExp(pattern.source, pattern.flags), replacement);
	}
	// Literal secrets last, so a value that survived the shape rules — because it
	// is short, or spelled unlike anything above — is still swept out.
	for (const secret of secrets) {
		result = result.replace(new RegExp(escapeRegExp(secret), "g"), REDACTED);
	}
	return result;
}

/**
 * Walk any value and return a scrubbed copy.
 *
 * Copies rather than mutates so a caller's object — an `extra` bag that is also
 * the live context of a request — is never altered by having been reported.
 * Repeat visits are cut with a seen-set and depth is capped, because an event is
 * arbitrary user data and neither is under this module's control.
 *
 * The seen-set is walk-global and never popped, so it cuts *any* second visit to
 * the same object, not only a cycle: an object referenced from two breadcrumbs,
 * or under two `extra` keys, is `[redacted]` the second time. That is the
 * conservative direction — a shared subtree is described once rather than
 * skipped — but it does mean a `[redacted]` here can mean "seen already" as well
 * as "secret". Sentry's own `normalize` has the same property and writes
 * `[Circular ~]`; this one deliberately does not distinguish, because a marker
 * that says which branch fired is a marker that says something about the data.
 */
export function scrubValue<T>(value: T, secrets: readonly string[] = [], depth = 0, seen = new WeakSet<object>()): T {
	if (typeof value === "string") return redactString(value, secrets) as T;
	if (value === null || typeof value !== "object") return value;
	if (depth >= MAX_SCRUB_DEPTH) return REDACTED as T;
	if (seen.has(value)) return REDACTED as T;
	seen.add(value);

	if (Array.isArray(value)) {
		return value.map((entry) => scrubValue(entry, secrets, depth + 1, seen)) as T;
	}

	// Anything with its own identity — Date, RegExp, a Headers instance, a class
	// instance — is returned as-is, by reference and unscrubbed, rather than
	// shredded into a plain object.
	//
	// This is safe because of the order the SDK runs things, not because of
	// anything checked here: `normalizeEvent` runs before `beforeSend` and has
	// already flattened `extra`, `contexts`, `user` and `breadcrumb.data` into
	// plain objects, so by the time the walker sees them there is nothing exotic
	// left holding a secret. `event.request` and `event.tags` are not normalized,
	// but the SDK builds both out of plain objects and strings. A future shape
	// that puts a secret inside a class instance under one of those keys would
	// pass through here untouched.
	const prototype = Object.getPrototypeOf(value) as unknown;
	if (prototype !== Object.prototype && prototype !== null) return value;

	const result: Record<string, unknown> = {};
	for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
		result[key] = isDeniedKey(key) ? REDACTED : scrubValue(entry, secrets, depth + 1, seen);
	}
	return result as T;
}

/** Scrub one breadcrumb: its message text and its structured data. */
export function scrubBreadcrumb(breadcrumb: Breadcrumb, secrets: readonly string[] = []): Breadcrumb {
	return scrubValue(breadcrumb, secrets);
}

/**
 * Scrub one event.
 *
 * Runs the whole event through the recursive walker — which covers
 * `request.headers`, `request.data`, `extra`, `contexts`, `tags`, `user`,
 * `breadcrumbs[].data` and `exception.values[].value` without needing to name
 * them — and then removes the two fields whose presence is itself the leak:
 * cookies, and any captured request body.
 */
export function scrubEvent<T extends Event>(event: T, secrets: readonly string[] = []): T {
	const scrubbed = scrubValue(event, secrets);

	if (scrubbed.request) {
		// A signing service's request bodies carry armored key material on the
		// admin upload route and the caller's payload everywhere else. Neither is
		// ours to forward, so the body never travels even in redacted form.
		delete scrubbed.request.cookies;
		delete scrubbed.request.data;
	}

	return scrubbed;
}

/**
 * The property the SDK sets on an exception it has captured, and refuses to
 * capture twice.
 *
 * `logger.error` is meant to be this service's single reporting chokepoint, and
 * `honoIntegration({ shouldHandleError: () => false })` closes the one door the
 * SDK offers a knob for. It is not the only door: `withSentry` also wraps
 * `scheduled`, and `instrumentDurableObjectWithSentry` wraps each object's
 * `fetch` and `alarm`. Those capture whatever escapes them unconditionally,
 * with no option to turn it off — and the cron handler deliberately rethrows
 * after logging, so the invocation is recorded as failed.
 *
 * That rethrow does not raise a second event, because `captureException` marks
 * the exception object with this property and returns early the next time it
 * sees it. The invariant therefore already holds for the ordinary case, where
 * `logger.error` was handed the same `Error` that is being rethrown.
 *
 * It does not hold when it was handed something else. `toReportableError` builds
 * a fresh `Error` for a non-`Error` value, and the SDK then marks the fresh one
 * — leaving the object that is actually rethrown unmarked, and worth a second,
 * untagged event. `markCaptured` closes that case.
 */
const ALREADY_CAPTURED = "__sentry_captured__";

/**
 * Tell the SDK this value has been reported, so its own wrappers do not report
 * it again.
 *
 * Non-enumerable, as the SDK sets it, so no integration serializes it into an
 * event. Primitives cannot carry a property at all — a thrown string that is
 * rethrown past a wrapper is still worth two events — and neither can a frozen
 * object, which is why this cannot throw.
 */
function markCaptured(value: unknown): void {
	if (typeof value !== "object" || value === null) return;
	try {
		Object.defineProperty(value, ALREADY_CAPTURED, { value: true, enumerable: false });
	} catch {
		// Frozen or sealed. The duplicate is noise, not a reason to fail a report.
	}
}

/** Whether this deployment reports to Sentry at all. */
export function isSentryConfigured(env: Partial<Env>): boolean {
	return typeof env.SENTRY_DSN === "string" && env.SENTRY_DSN.trim().length > 0;
}

/**
 * Read the trace sample rate, defaulting rather than failing.
 *
 * Unlike `KEY_EXPIRY_WARN_DAYS`, a mistyped sample rate is not worth refusing a
 * request over — the consequence of the default is a different amount of
 * telemetry, not a wrong signature — so anything unparseable falls back.
 */
function tracesSampleRate(env: Partial<Env>): number {
	const raw = env.SENTRY_TRACES_SAMPLE_RATE?.trim();
	if (!raw) return DEFAULT_TRACES_SAMPLE_RATE;
	const parsed = Number(raw);
	if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) return DEFAULT_TRACES_SAMPLE_RATE;
	return parsed;
}

/**
 * The single option object both the fetch handler and the Durable Objects
 * initialize from.
 *
 * The scrubbing hooks are installed on *both* branches, configured or not. They
 * cost nothing when nothing is sent, and an unconditional hook is one that
 * cannot be bypassed by some future path that reaches the client another way.
 */
export function buildSentryOptions(env: Partial<Env>): CloudflareOptions {
	const enabled = isSentryConfigured(env);
	const dsn = env.SENTRY_DSN?.trim();
	const secrets = collectEnvSecrets(env);

	return {
		// `getFinalOptions` fills any key left `undefined` from `env` — including
		// `dsn` — so the disabled branch has to say "" rather than omit it. An
		// empty string is falsy everywhere the SDK reads a DSN, and it is the only
		// spelling that wins against `userOptions.dsn ?? getEnvVar(env, ...)`.
		dsn: enabled && dsn ? dsn : "",
		enabled,
		// Never the caller's IP, headers-as-user, or cookies. The identities this
		// service handles are CI workloads, and the parts of them worth having —
		// issuer, subject, key id — are attached explicitly as tags instead.
		sendDefaultPii: false,
		tracesSampleRate: enabled ? tracesSampleRate(env) : 0,
		...(env.ENVIRONMENT ? { environment: env.ENVIRONMENT } : {}),
		// Development-only event forwarding, and it bypasses the DSN check. Pinned
		// off so a stray `SENTRY_SPOTLIGHT` variable cannot turn a deployment that
		// configured no DSN into one that ships events somewhere.
		spotlight: false,
		// The other half of that invariant. `getFinalOptions` reads `SENTRY_TUNNEL`
		// into `tunnel`, which replaces the envelope destination outright — the
		// events would go somewhere the DSN never named. Pinned to "" (falsy
		// wherever the SDK reads it, and unlike `undefined` it beats the `??` that
		// would otherwise reach for the variable) so the configured DSN is the only
		// thing that decides where anything is sent.
		tunnel: "",
		// `SENTRY_DEBUG` makes the SDK log to the console. Harmless when a DSN is
		// configured and occasionally what an operator wants, but on the disabled
		// branch it would break the one property this whole module promises: that
		// an unset DSN leaves Workers Logs exactly as it found them.
		...(enabled ? {} : { debug: false }),
		...(enabled
			? {
					integrations: (defaults) => [
						...defaults.filter((integration) => integration.name !== "HttpServer" && integration.name !== "Hono"),
						// Request bodies are never collected. See `scrubEvent`.
						Sentry.httpServerIntegration({ maxRequestBodySize: "none" }),
						// The SDK's Hono support captures from `app.onError` on its own.
						// `logger.error` is this service's single capture chokepoint — it
						// is what knows the `requestId`, `action` and `errorCode` — so the
						// automatic one is turned off rather than left to emit a second,
						// untagged event for every 500.
						Sentry.honoIntegration({ shouldHandleError: () => false }),
					],
				}
			: // No DSN, no integrations: no console wrapping, no fetch patching, no
				// request-body reader. This is what makes the disabled branch a real
				// no-op rather than a quiet one — without it the SDK installs all
				// three on a deployment that configured nothing. The SDK's entry-point
				// wrappers still run (see the module header); what they would feed is
				// what is missing here.
				{ defaultIntegrations: false as const, integrations: [] }),
		beforeSend: (event: ErrorEvent) => scrubEvent(event, secrets),
		beforeSendTransaction: (event) => scrubEvent(event, secrets),
		beforeBreadcrumb: (breadcrumb: Breadcrumb) => scrubBreadcrumb(breadcrumb, secrets),
	};
}

/** The callback shape `withSentry` and `instrumentDurableObjectWithSentry` take. */
export const sentryOptions = (env: Env): CloudflareOptions => buildSentryOptions(env);

/**
 * Context a capture carries.
 *
 * The three named fields become Sentry tags, which is what makes them
 * searchable and alertable; everything else rides along as `extra`. All of it
 * passes through `beforeSend` regardless.
 */
export interface CaptureContext {
	/** The id the caller was handed, and the thread from a CI log to an event. */
	requestId?: string | undefined;
	/** An `AuditAction` where the audit vocabulary has one. */
	action?: string | undefined;
	/** An `ErrorCode` where the refusal has one. */
	errorCode?: string | undefined;
	[key: string]: unknown;
}

const TAG_KEYS = ["requestId", "action", "errorCode"] as const;

function splitContext(context: CaptureContext): {
	tags: Record<string, string>;
	extra: Record<string, unknown>;
} {
	const tags: Record<string, string> = {};
	const extra: Record<string, unknown> = {};

	for (const [key, value] of Object.entries(context)) {
		if (value === undefined) continue;
		if ((TAG_KEYS as readonly string[]).includes(key)) {
			tags[key] = String(value);
		} else {
			extra[key] = value;
		}
	}

	return { tags, extra };
}

/**
 * Whether a capture would go anywhere.
 *
 * The SDK's own capture functions are already no-ops without a bound client, so
 * this is belt and braces — but it is the guard that makes "an unset DSN
 * reports nothing" a property of *this* module, testable here, rather than one
 * inherited from a dependency's internals.
 */
function reportingClient(): Sentry.CloudflareClient | undefined {
	const client = Sentry.getClient<Sentry.CloudflareClient>();
	if (!client) return undefined;
	if (client.getOptions().enabled === false) return undefined;
	if (!client.getDsn()) return undefined;
	return client;
}

/**
 * Turn whatever reached `logger.error`'s error slot into something Sentry can
 * render.
 *
 * Most call sites pass a real `Error` and it is used as-is. `app.onError` does
 * not: it passes a bag holding the message and the stack as strings, because
 * that is the shape its log line has always had. Rather than change an
 * operator-visible log to suit a reporting backend, that bag is reassembled
 * here — the underlying message joins the title, and the original stack is
 * reattached so the event carries real frames rather than a one-line trace
 * pointing at this function.
 */
function toReportableError(message: string, error: unknown): Error {
	if (error instanceof Error) return error;

	const bag = typeof error === "object" && error !== null ? (error as Record<string, unknown>) : undefined;
	const detail = typeof bag?.error === "string" ? bag.error : undefined;
	const reportable = new Error(detail ? `${message}: ${detail}` : message);
	reportable.name = "LoggedError";
	if (typeof bag?.stack === "string") reportable.stack = bag.stack;
	return reportable;
}

/**
 * Report an error-level log to Sentry. The single chokepoint; `logger.error`
 * is its only caller.
 *
 * Returns the event id, or `undefined` when nothing was reported — which is
 * what the disabled-DSN test asserts on.
 */
export function captureError(message: string, error: unknown, context: CaptureContext = {}): string | undefined {
	if (!reportingClient()) return undefined;

	const { tags, extra } = splitContext(context);
	const eventId = Sentry.captureException(toReportableError(message, error), {
		tags,
		extra: { ...extra, logMessage: message },
		level: "error",
	});

	// The SDK marked whatever `toReportableError` returned. When that was a fresh
	// `Error` built around a non-`Error` value, the value the caller is about to
	// rethrow is still unmarked. See `ALREADY_CAPTURED`.
	markCaptured(error);

	return eventId;
}

/**
 * Raise an alertable event for a refusal that is security-relevant on its own —
 * a killed credential still in use, a caller reaching for a key it is not
 * scoped to. These are the ones worth waking someone for, which is why they are
 * events and the routine refusals below are not.
 */
export function captureRefusalEvent(message: string, context: CaptureContext = {}): string | undefined {
	if (!reportingClient()) return undefined;

	const { tags, extra } = splitContext(context);
	return Sentry.captureMessage(message, {
		tags: { ...tags, refusal: "true" },
		extra,
		level: "warning",
	});
}

/**
 * Record a refusal as context rather than as an event.
 *
 * The issuers this service accepts are shared with every repository on their
 * platform, so an unknown subject is background traffic and a lapsed trust is
 * routine maintenance. Raising events for those would bury the two that matter.
 * As breadcrumbs they cost nothing and are still there, in order, on whatever
 * event does get raised.
 */
export function addRefusalBreadcrumb(message: string, data: Record<string, unknown> = {}): void {
	if (!reportingClient()) return;

	Sentry.addBreadcrumb({
		category: "auth.refusal",
		level: "warning",
		message,
		data,
	});
}
