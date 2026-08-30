/**
 * The scheduled key-expiry monitor, end to end inside the Worker.
 *
 * The suite is written against the two properties the architecture exists for,
 * not only against the happy path:
 *
 * - **No email unless there is news**, and an email for every class of news —
 *   expiring, expired, revoked, missing and unreadable.
 * - **No self-HTTP and no admin credential.** One test runs the whole monitor
 *   with `globalThis.fetch` replaced by a throwing stub and with both admin
 *   tokens stripped from the environment. Nothing about the monitor may depend
 *   on being able to call itself.
 *
 * Key material is real throughout — generated, expired and revoked with openpgp
 * — because the verdicts under test are read out of that material rather than
 * out of a config file.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import type { Env } from "#types";
import { fetchKeyStorage } from "#utils/durable-objects";
import type { AlertMail, MailSender } from "#utils/key-expiry-monitor";
import { bindingMailSender, mailConfig, runKeyExpiryMonitor } from "#utils/key-expiry-monitor";
import { logger } from "#utils/logger";
import { insertOIDCSubject } from "#utils/oidc-subjects";
import { insertServiceToken } from "#utils/service-tokens";

const DAY_MS = 24 * 60 * 60 * 1000;
const DAY_SECONDS = 24 * 60 * 60;

/** The production key from wrangler.toml, per issue #44 */
const PRODUCTION_KEY_ID = "62E75E54497815DD";
const SECOND_KEY_ID = "AAAABBBBCCCCDDDD";

const ALERT_FROM = "gpg-signing-service@kjanat.dev";
const ALERT_TO = "info@kajkowalski.nl";

/** A `send_email` binding that records instead of sending */
function recordingBinding() {
	const sent: { from: string; to: string; subject: string; text: string; html: string }[] = [];
	return {
		sent,
		binding: {
			send: vi.fn(async (message: Record<string, unknown>) => {
				sent.push(message as unknown as (typeof sent)[number]);
				return { messageId: `test-${sent.length}` };
			}),
		},
	};
}

/** A mail sender that records what it was handed */
function recordingSender(): { sent: AlertMail[]; send: MailSender } {
	const sent: AlertMail[] = [];
	return { sent, send: async (mail) => void sent.push(mail) };
}

/** The test environment, with the alerting path configured */
function monitorEnv(overrides: Partial<Record<string, unknown>> = {}): Env {
	return {
		...env,
		KEY_EXPIRY_ALERTS: recordingBinding().binding,
		KEY_EXPIRY_ALERT_FROM: ALERT_FROM,
		KEY_EXPIRY_ALERT_TO: ALERT_TO,
		...overrides,
	} as unknown as Env;
}

/** Put a key into the `KeyStorage` Durable Object, the way an upload would */
async function storeKey(keyId: string, armoredPrivateKey: string): Promise<void> {
	const response = await fetchKeyStorage(env as unknown as Env, "/store-key", {
		method: "POST",
		body: JSON.stringify({
			keyId,
			armoredPrivateKey,
			fingerprint: keyId.repeat(3).slice(0, 40),
			createdAt: new Date().toISOString(),
			algorithm: "eddsaLegacy",
		}),
	});
	expect(response.status).toBe(201);
}

/** An armored PGP key that lapses `days` from now, or never when omitted */
async function keyExpiringIn(days: number | null, email: string): Promise<string> {
	const { privateKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "ed25519Legacy",
		userIDs: [{ name: "Monitor", email }],
		...(days === null ? {} : { keyExpirationTime: days * DAY_SECONDS }),
		format: "armored",
	});
	return privateKey;
}

/** Empty the Durable Object of every key a previous test left behind */
async function clearKeys(): Promise<void> {
	const listed = await fetchKeyStorage(env as unknown as Env, "/list-keys");
	const { keys } = (await listed.json()) as { keys: { keyId: string }[] };
	for (const key of keys) {
		await fetchKeyStorage(env as unknown as Env, `/delete-key?keyId=${encodeURIComponent(key.keyId)}`, {
			method: "DELETE",
		});
	}
}

/**
 * Replace the key-storage Durable Object with a stub answering `status` on the
 * given path, so the failure branches are reachable without a broken database.
 */
function breakKeyStorage(path: string, status: number) {
	return vi.spyOn(env.KEY_STORAGE, "get").mockImplementation(
		() =>
			({
				fetch: async (request: Request) =>
					new URL(request.url).pathname === path
						? new Response("storage is unwell", { status })
						: new Response(JSON.stringify({ keys: [{ keyId: PRODUCTION_KEY_ID }] }), { status: 200 }),
			}) as unknown as DurableObjectStub,
	);
}

beforeAll(async () => {
	await env.AUDIT_DB.exec(
		"CREATE TABLE IF NOT EXISTS service_tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE, key_ids TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, last_used_at TEXT);",
	);
	await env.AUDIT_DB.exec(
		"CREATE TABLE IF NOT EXISTS oidc_subjects (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, issuer TEXT NOT NULL, subject_prefix TEXT NOT NULL, key_ids TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, last_used_at TEXT);",
	);
});

beforeEach(async () => {
	// Re-applied per test rather than once, because `afterEach` restores every
	// spy: the monitor logs a line per run and the suite asserts on what it
	// sent, not on what it printed.
	vi.spyOn(logger, "info").mockImplementation(() => undefined);
	vi.spyOn(logger, "warn").mockImplementation(() => undefined);
	vi.spyOn(logger, "error").mockImplementation(() => undefined);

	await env.AUDIT_DB.exec("DELETE FROM service_tokens;");
	await env.AUDIT_DB.exec("DELETE FROM oidc_subjects;");
	await clearKeys();
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("mailConfig", () => {
	it("names everything that is missing, so one run fixes the configuration", () => {
		expect(() => mailConfig({ ...env } as unknown as Env)).toThrow(
			/the KEY_EXPIRY_ALERTS send_email binding, the KEY_EXPIRY_ALERT_FROM variable, the KEY_EXPIRY_ALERT_TO variable are not configured/,
		);
	});

	it("reads as a sentence when only one piece is missing", () => {
		expect(() => mailConfig(monitorEnv({ KEY_EXPIRY_ALERT_TO: "   " }))).toThrow(
			/the KEY_EXPIRY_ALERT_TO variable is not configured/,
		);
	});

	it("returns the binding and the trimmed addresses", () => {
		const config = mailConfig(monitorEnv({ KEY_EXPIRY_ALERT_FROM: `  ${ALERT_FROM}  ` }));
		expect(config.from).toBe(ALERT_FROM);
		expect(config.to).toBe(ALERT_TO);
		expect(config.binding).toBeDefined();
	});
});

describe("bindingMailSender", () => {
	it("sends both bodies through the send_email binding, from and to the configured addresses", async () => {
		const { sent, binding } = recordingBinding();
		const send = bindingMailSender(monitorEnv({ KEY_EXPIRY_ALERTS: binding }));

		await send({ subject: "Subject", text: "plain", html: "<p>rich</p>" });

		expect(sent).toEqual([{ from: ALERT_FROM, to: ALERT_TO, subject: "Subject", text: "plain", html: "<p>rich</p>" }]);
	});

	it("refuses to build a sender at all when the configuration is incomplete", () => {
		// Checked when the sender is *built*, which the monitor does before it
		// reads any state — so a broken alerting path fails on a quiet week.
		expect(() => bindingMailSender({ ...env } as unknown as Env)).toThrow(/cannot send mail/);
	});
});

describe("runKeyExpiryMonitor: a clean deployment", () => {
	it("sends nothing when every active key is comfortably in date", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(400, "healthy@test.com"));
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.alerted).toBe(false);
		expect(mail.sent).toEqual([]);
		expect(result.rows).toMatchObject([{ keyId: PRODUCTION_KEY_ID, state: "ok" }]);
		expect(result.report.text).toContain("No active signing key expires within 60 days.");
	});

	it("sends nothing for a key that carries no expiry at all", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(null, "forever@test.com"));
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.rows).toMatchObject([{ state: "no-expiry" }]);
		expect(mail.sent).toEqual([]);
	});
});

describe("runKeyExpiryMonitor: every actionable class sends an email", () => {
	it("emails when a key enters the warning window", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(30, "soon@test.com"));
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.alerted).toBe(true);
		expect(mail.sent).toHaveLength(1);
		expect(mail.sent[0]?.subject).toMatch(
			new RegExp(`^\\[gpg-signing-service\\] Signing key ${PRODUCTION_KEY_ID} expiring in \\d+ days$`),
		);
		expect(mail.sent[0]?.text).toContain("Action required");
	});

	it("emails when a key has already lapsed", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(1, "lapsed@test.com"));
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), {
			now: new Date(Date.now() + 3 * DAY_MS),
			sendMail: mail.send,
		});

		expect(result.rows).toMatchObject([{ keyId: PRODUCTION_KEY_ID, state: "expired" }]);
		expect(mail.sent).toHaveLength(1);
		expect(mail.sent[0]?.subject).toContain("expired");
	});

	it("emails when a key is revoked, even though it has not expired", async () => {
		const armored = await keyExpiringIn(400, "revoked@test.com");
		const { privateKey } = await openpgp.revokeKey({
			key: await openpgp.readPrivateKey({ armoredKey: armored }),
			format: "armored",
		});
		await storeKey(PRODUCTION_KEY_ID, privateKey);
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.rows).toMatchObject([{ keyId: PRODUCTION_KEY_ID, state: "revoked" }]);
		expect(mail.sent).toHaveLength(1);
		expect(mail.sent[0]?.subject).toContain("revoked");
	});

	it("emails when a key the deployment is configured to sign with is absent", async () => {
		// Nothing stored at all, so KEY_ID names a key this deployment does not
		// hold: signing is already broken, not about to be.
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.rows).toMatchObject([
			{ keyId: PRODUCTION_KEY_ID, state: "missing", detail: expect.stringContaining("this deployment's KEY_ID") },
		]);
		expect(mail.sent).toHaveLength(1);
	});

	it("emails when a live grant names a key that no longer exists", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(400, "present@test.com"));
		await insertServiceToken(env.AUDIT_DB, {
			name: "ci",
			token: "gst_test",
			keyIds: [SECOND_KEY_ID],
			expiresAt: null,
		});
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.actionable).toMatchObject([
			{ keyId: SECOND_KEY_ID, state: "missing", detail: expect.stringContaining("granted to service-token:ci") },
		]);
		expect(mail.sent).toHaveLength(1);
	});

	it("emails when a stored key cannot be read at all", async () => {
		const spy = breakKeyStorage("/get-key", 500);
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.rows).toMatchObject([
			{ keyId: PRODUCTION_KEY_ID, state: "unknown", detail: "key storage answered 500 for this key" },
		]);
		expect(mail.sent).toHaveLength(1);
		spy.mockRestore();
	});

	it("emails when the stored material is not a key at all", async () => {
		await storeKey(PRODUCTION_KEY_ID, "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot a key\n-----END…");
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		expect(result.rows).toMatchObject([{ state: "unknown" }]);
		expect(mail.sent).toHaveLength(1);
	});
});

describe("runKeyExpiryMonitor: failures are operational failures", () => {
	it("surfaces a failed send rather than reporting a run that alerted nobody", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(30, "soon@test.com"));

		await expect(
			runKeyExpiryMonitor(monitorEnv(), {
				sendMail: () => Promise.reject(new Error("E_RATE_LIMIT_EXCEEDED")),
			}),
		).rejects.toThrow("E_RATE_LIMIT_EXCEEDED");
	});

	it("fails a clean run too when the alerting path is not configured", async () => {
		// The point of checking the mail configuration before the keys: a monitor
		// that cannot alert is already broken, and the week it has nothing to say
		// is the cheap week to find that out.
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(400, "healthy@test.com"));

		await expect(runKeyExpiryMonitor({ ...env, KEY_EXPIRY_ALERTS: undefined } as unknown as Env)).rejects.toThrow(
			/cannot send mail/,
		);
	});

	it("fails rather than reporting an empty set when storage cannot be listed", async () => {
		const spy = breakKeyStorage("/list-keys", 503);

		await expect(runKeyExpiryMonitor(monitorEnv(), { sendMail: recordingSender().send })).rejects.toThrow(
			/could not list stored keys: key storage answered 503/,
		);
		spy.mockRestore();
	});

	it("refuses a threshold that is not a positive whole number", async () => {
		await expect(
			runKeyExpiryMonitor(monitorEnv({ KEY_EXPIRY_WARN_DAYS: "soon" }), { sendMail: recordingSender().send }),
		).rejects.toThrow(/KEY_EXPIRY_WARN_DAYS must be a positive whole number/);
	});
});

describe("runKeyExpiryMonitor: the reviewed active-key semantics", () => {
	it("honours the configured warning threshold", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(90, "ninety@test.com"));
		const mail = recordingSender();

		const wide = await runKeyExpiryMonitor(monitorEnv({ KEY_EXPIRY_WARN_DAYS: "120" }), { sendMail: mail.send });
		expect(wide.rows).toMatchObject([{ state: "warning" }]);
		expect(mail.sent).toHaveLength(1);

		const narrow = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });
		expect(narrow.rows).toMatchObject([{ state: "ok" }]);
		expect(mail.sent).toHaveLength(1);
	});

	it("monitors a key an unrestricted grant reaches, and says storage is the boundary", async () => {
		await storeKey(SECOND_KEY_ID, await keyExpiringIn(400, "second@test.com"));
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "repo:kjanat/svc",
			issuer: "https://token.actions.githubusercontent.com",
			subjectPrefix: "repo:kjanat/svc",
			keyIds: [],
			expiresAt: null,
		});

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: recordingSender().send });

		expect(result.scope.unrestrictedGrants).toEqual(["oidc-subject:repo:kjanat/svc"]);
		expect(result.rows.map((row) => row.keyId).sort()).toEqual([PRODUCTION_KEY_ID, SECOND_KEY_ID].sort());
		expect(result.report.text).toContain("every stored key is signable");
	});

	it("drops a key whose only grant has been revoked, rather than warning about it forever", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(400, "default@test.com"));
		await storeKey(SECOND_KEY_ID, await keyExpiringIn(10, "retired@test.com"));
		await insertServiceToken(env.AUDIT_DB, {
			name: "retired",
			token: "gst_retired",
			keyIds: [SECOND_KEY_ID],
			expiresAt: null,
		});
		await env.AUDIT_DB.prepare("UPDATE service_tokens SET revoked_at = ? WHERE name = 'retired'")
			.bind(new Date().toISOString())
			.run();
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: mail.send });

		// The retired key is 10 days from lapsing and would be the loudest row in
		// the report — but nothing can sign with it, so it is not news.
		expect(result.rows.map((row) => row.keyId)).toEqual([PRODUCTION_KEY_ID]);
		expect(result.scope.retainedInactive).toEqual([SECOND_KEY_ID]);
		expect(mail.sent).toEqual([]);
	});

	it("keeps a key an expired grant no longer reaches out of the report", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(400, "default@test.com"));
		await storeKey(SECOND_KEY_ID, await keyExpiringIn(5, "lapsing@test.com"));
		await insertServiceToken(env.AUDIT_DB, {
			name: "stale",
			token: "gst_stale",
			keyIds: [SECOND_KEY_ID],
			expiresAt: new Date(Date.now() - DAY_MS).toISOString(),
		});

		const result = await runKeyExpiryMonitor(monitorEnv(), { sendMail: recordingSender().send });

		expect(result.scope.liveGrantCount).toBe(0);
		expect(result.scope.totalGrantCount).toBe(1);
		expect(result.rows.map((row) => row.keyId)).toEqual([PRODUCTION_KEY_ID]);
	});

	it("labels the deployment so two environments' mail reads apart", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(400, "staging@test.com"));

		const result = await runKeyExpiryMonitor(monitorEnv({ ENVIRONMENT: "staging" }), {
			sendMail: recordingSender().send,
		});

		expect(result.report.subject).toContain("[gpg-signing-service (staging)]");
		expect(result.scope.defaultKey).toEqual({ env: "staging", keyId: PRODUCTION_KEY_ID });
	});

	it("checks nothing, and says so, when the deployment declares no default key and grants nothing", async () => {
		const mail = recordingSender();

		const result = await runKeyExpiryMonitor(monitorEnv({ KEY_ID: "  " }), { sendMail: mail.send });

		expect(result.rows).toEqual([]);
		expect(result.report.text).toContain("No key was checked.");
		// An empty set is not an all-clear, but it is also not an alert: there is
		// no key to rotate. The report is what carries the warning.
		expect(mail.sent).toEqual([]);
	});
});

describe("runKeyExpiryMonitor: no self-HTTP and no admin credential", () => {
	it("runs with outbound fetch disabled and both admin tokens stripped", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(30, "internal@test.com"));
		const mail = recordingSender();

		const outbound = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
			throw new Error("the monitor must not make an HTTP request");
		});

		try {
			const result = await runKeyExpiryMonitor(
				monitorEnv({ ADMIN_TOKEN: undefined, ADMIN_READONLY_TOKEN: undefined }),
				{ sendMail: mail.send },
			);

			expect(result.rows).toMatchObject([{ keyId: PRODUCTION_KEY_ID, state: "warning" }]);
			expect(mail.sent).toHaveLength(1);
			expect(outbound).not.toHaveBeenCalled();
		} finally {
			outbound.mockRestore();
		}
	});
});

describe("the scheduled handler", () => {
	function controller(cron = "0 7 * * 2"): ScheduledController {
		return { cron, scheduledTime: Date.now(), noRetry: () => undefined };
	}

	it("mails through the send_email binding when a key needs attention", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(30, "cron@test.com"));
		const { sent, binding } = recordingBinding();
		const ctx = createExecutionContext();

		await app.scheduled(controller(), monitorEnv({ KEY_EXPIRY_ALERTS: binding }), ctx);
		await waitOnExecutionContext(ctx);

		expect(sent).toHaveLength(1);
		expect(sent[0]).toMatchObject({ from: ALERT_FROM, to: ALERT_TO });
		expect(sent[0]?.subject).toContain(PRODUCTION_KEY_ID);
		expect(sent[0]?.html).toContain("<table");
	});

	it("mails nothing on a clean run", async () => {
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(400, "cron-clean@test.com"));
		const { sent, binding } = recordingBinding();
		const ctx = createExecutionContext();

		await app.scheduled(controller(), monitorEnv({ KEY_EXPIRY_ALERTS: binding }), ctx);
		await waitOnExecutionContext(ctx);

		expect(sent).toEqual([]);
	});

	it("rethrows so the cron invocation is recorded as failed", async () => {
		// A run that could not send the mail it had to send has not monitored
		// anything; swallowing that is how a monitor becomes decoration.
		await storeKey(PRODUCTION_KEY_ID, await keyExpiringIn(30, "cron-fail@test.com"));
		const binding = { send: vi.fn(async () => Promise.reject(new Error("E_SENDER_NOT_VERIFIED"))) };
		const ctx = createExecutionContext();

		await expect(app.scheduled(controller(), monitorEnv({ KEY_EXPIRY_ALERTS: binding }), ctx)).rejects.toThrow(
			"E_SENDER_NOT_VERIFIED",
		);
		await waitOnExecutionContext(ctx);
	});

	it("leaves the HTTP surface untouched", async () => {
		// `scheduled` is attached to the Hono app, so the thing most likely to
		// break is the export the router and the OpenAPI generator hang off.
		const ctx = createExecutionContext();
		const response = await app.fetch(new Request("http://localhost/health"), env, ctx);
		await waitOnExecutionContext(ctx);

		expect([200, 503]).toContain(response.status);
		expect(typeof app.getOpenAPIDocument).toBe("function");
	});
});
