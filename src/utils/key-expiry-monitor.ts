/**
 * The scheduled signing-key expiry monitor
 *
 * Nothing in the sign path refuses a key that is about to lapse, so without
 * this the first sign of an expiry is every caller failing at once. A Cron
 * Trigger runs {@link runKeyExpiryMonitor} inside the same Worker that does the
 * signing, and it emails when — and only when — a key needs a human.
 *
 * Two properties are deliberate and worth stating, because they are what an
 * earlier design got wrong.
 *
 * **It reads its own state from the inside.** Storage comes from the
 * `KEY_STORAGE` Durable Object and the grants come from D1, through the same
 * modules the request path uses. It does not call its own `/admin/*` API, so it
 * needs neither `ADMIN_TOKEN` nor `ADMIN_READONLY_TOKEN` — a scheduled job that
 * had to authenticate to itself would mean a long-lived admin credential
 * existing somewhere for the monitor's sake alone.
 *
 * **The alerting path is checked before the keys are.** {@link mailConfig}
 * runs first, so a deployment whose email binding or addresses are missing
 * fails on a *quiet* week rather than on the one where it had something to say.
 * An alerter that cannot alert is already broken; the only question is whether
 * anyone finds out before it matters.
 */

import type { AnyStoredKey } from "#schemas/keys";
import { isX509Key } from "#schemas/keys";
import type { Env } from "#types";
import { fetchKeyStorage } from "#utils/durable-objects";
import type {
	ActiveKeySet,
	DeclaredDefaultKey,
	KeyExpiryRow,
	KeyGrant,
	ReportContext,
	ReportDocument,
} from "#utils/key-expiry";
import {
	actionableRows,
	classifyExpiry,
	keyMaterialExpiry,
	missingKeyRow,
	parseWarnDays,
	renderReport,
	resolveActiveKeys,
} from "#utils/key-expiry";
import { logger } from "#utils/logger";
import { listOIDCSubjects } from "#utils/oidc-subjects";
import { listServiceTokens } from "#utils/service-tokens";

/** Name this service calls itself by in a subject line */
const SERVICE_NAME = "gpg-signing-service";

/** An alert, in both bodies, ready for the mail boundary */
export type AlertMail = ReportDocument;

/**
 * Where an alert goes.
 *
 * A function rather than the binding itself so the tests can watch what would
 * have been sent without a live Email Service account — and so the one place
 * that talks to Cloudflare is one line long and separately assertable.
 */
export type MailSender = (mail: AlertMail) => Promise<void>;

/** The binding and addresses this deployment sends alerts through */
export interface MailConfig {
	binding: SendEmail;
	from: string;
	to: string;
}

/**
 * Read and check the alerting configuration.
 *
 * Ordinary Worker vars, not secrets: an address is not a credential, and
 * `wrangler secret put` on one would mean the repository could not show an
 * operator what their own monitor is configured to do. The `send_email`
 * binding's own `destination_address` and `allowed_sender_addresses`
 * restrictions are the enforcement; these are what the Worker asks for.
 *
 * @throws when the binding or either address is absent — see the module note on
 * why that is checked before anything about keys is read
 */
export function mailConfig(env: Env): MailConfig {
	const missing = [
		env.KEY_EXPIRY_ALERTS ? null : "the KEY_EXPIRY_ALERTS send_email binding",
		env.KEY_EXPIRY_ALERT_FROM?.trim() ? null : "the KEY_EXPIRY_ALERT_FROM variable",
		env.KEY_EXPIRY_ALERT_TO?.trim() ? null : "the KEY_EXPIRY_ALERT_TO variable",
	].filter((entry): entry is string => entry !== null);

	if (missing.length > 0) {
		throw new Error(
			`Key expiry monitor cannot send mail: ${missing.join(", ")} ${missing.length === 1 ? "is" : "are"} not configured.`,
		);
	}

	// Narrowed by the check above rather than asserted: `missing` is empty only
	// when all three are present, and each is optional on `Env` because a
	// deployment really can lack it.
	return {
		binding: env.KEY_EXPIRY_ALERTS as SendEmail,
		from: (env.KEY_EXPIRY_ALERT_FROM as string).trim(),
		to: (env.KEY_EXPIRY_ALERT_TO as string).trim(),
	};
}

/**
 * The real mail boundary: Cloudflare Email Service's `send_email` binding.
 *
 * `to` is passed explicitly even though the binding is `destination_address`-
 * restricted to the same value. The restriction is what makes a compromised
 * Worker unable to mail anyone else; passing the address is what makes the code
 * say where the alert goes without the reader having to open `wrangler.toml`.
 */
export function bindingMailSender(env: Env): MailSender {
	const { binding, from, to } = mailConfig(env);

	return async (mail) => {
		const { messageId } = await binding.send({
			from,
			to,
			subject: mail.subject,
			text: mail.text,
			html: mail.html,
		});
		logger.info("Key expiry alert sent", { action: "key-expiry-alert", messageId, to });
	};
}

/** What one run of the monitor found and did */
export interface MonitorResult {
	/** Every monitored key's verdict */
	rows: KeyExpiryRow[];
	/** The subset that needs a human */
	actionable: KeyExpiryRow[];
	/** How the monitored set was resolved, for the report and for the tests */
	scope: ActiveKeySet;
	/** The rendered report, sent or not */
	report: ReportDocument;
	/** Whether an alert was actually handed to the mail boundary */
	alerted: boolean;
}

/** Overrides the scheduled handler does not need but the tests do */
export interface MonitorOptions {
	/** The instant the run is relative to; defaults to now */
	now?: Date;
	/** Where alerts go; defaults to the `send_email` binding */
	sendMail?: MailSender;
}

/**
 * Run the monitor once.
 *
 * Resolves the keys this deployment can currently sign with, reads each one's
 * expiry out of its own material, and emails when any of them needs attention.
 *
 * A clean run sends nothing. That is the whole point of a threshold: an alert
 * that arrives every week is one nobody reads by the week it matters. The
 * result is returned either way, so the caller can log the verdict it did not
 * mail.
 *
 * @throws when the alerting path is misconfigured, when the deployment's own
 * state cannot be read, or when the send fails — all three mean the monitor did
 * not do its job, and a cron run that reports success in that state is worse
 * than no monitor at all
 */
export async function runKeyExpiryMonitor(env: Env, options: MonitorOptions = {}): Promise<MonitorResult> {
	const now = options.now ?? new Date();
	const warnDays = parseWarnDays(env.KEY_EXPIRY_WARN_DAYS);
	// Resolved before any state is read so a broken alerting path fails the run
	// it is cheap to fail — see the module note.
	const sendMail = options.sendMail ?? bindingMailSender(env);

	const scope = resolveActiveKeys({
		storedKeyIds: await storedKeyIds(env),
		defaultKey: defaultKeyOf(env),
		grants: await readGrants(env),
		now,
	});

	const rows: KeyExpiryRow[] = [];
	for (const key of scope.keys) {
		rows.push(
			key.stored ? classifyExpiry(key.keyId, await storedKeyExpiry(env, key.keyId), now, warnDays) : missingKeyRow(key),
		);
	}

	const context: ReportContext = { warnDays, now, service: serviceLabel(env), scope };
	const report = renderReport(rows, context);
	const actionable = actionableRows(rows);

	if (actionable.length === 0) {
		logger.info("Key expiry check clear", {
			action: "key-expiry-check",
			checked: rows.length,
			warnDays,
		});
		return { rows, actionable, scope, report, alerted: false };
	}

	logger.warn("Key expiry check found keys needing attention", {
		action: "key-expiry-check",
		checked: rows.length,
		actionable: actionable.map((row) => ({ keyId: row.keyId, state: row.state, daysRemaining: row.daysRemaining })),
		warnDays,
	});

	await sendMail(report);

	return { rows, actionable, scope, report, alerted: true };
}

/** How this deployment names itself, so two environments' alerts read apart */
function serviceLabel(env: Env): string {
	return env.ENVIRONMENT ? `${SERVICE_NAME} (${env.ENVIRONMENT})` : SERVICE_NAME;
}

/** This deployment's own default signing key, straight off its bindings */
function defaultKeyOf(env: Env): DeclaredDefaultKey {
	return {
		env: env.ENVIRONMENT ?? null,
		keyId: env.KEY_ID?.trim() ? env.KEY_ID.trim().toUpperCase() : null,
	};
}

/** Key ids the `KeyStorage` Durable Object holds */
async function storedKeyIds(env: Env): Promise<string[]> {
	const response = await fetchKeyStorage(env, "/list-keys");
	if (!response.ok) {
		throw new Error(`Key expiry monitor could not list stored keys: key storage answered ${response.status}`);
	}

	const { keys } = (await response.json()) as { keys: { keyId: string }[] };
	return keys.map((key) => key.keyId);
}

/**
 * Expiry of one stored key, read out of the material storage holds.
 *
 * An unreadable or absent key becomes an `unknown` row rather than an
 * exception: one damaged key must not cost the report the verdict on every
 * other key, and `unknown` is itself actionable, so nothing is swallowed.
 */
async function storedKeyExpiry(env: Env, keyId: string) {
	const response = await fetchKeyStorage(env, `/get-key?keyId=${encodeURIComponent(keyId)}`);
	if (!response.ok) {
		return { kind: "unknown", reason: `key storage answered ${response.status} for this key` } as const;
	}

	const stored = (await response.json()) as AnyStoredKey;
	return keyMaterialExpiry(isX509Key(stored) ? stored.certificatePem : stored.armoredPrivateKey);
}

/**
 * Every grant, of both kinds, as one list.
 *
 * Read through the same list functions the admin routes use, so a change to
 * what counts as a grant reaches the monitor without anyone remembering to
 * update a second query.
 */
async function readGrants(env: Env): Promise<KeyGrant[]> {
	const [subjects, tokens] = await Promise.all([listOIDCSubjects(env.AUDIT_DB), listServiceTokens(env.AUDIT_DB)]);

	return [
		...subjects.map(
			(subject): KeyGrant => ({
				kind: "oidc-subject",
				name: subject.name,
				keyIds: subject.keyIds,
				expiresAt: subject.expiresAt,
				revokedAt: subject.revokedAt,
			}),
		),
		...tokens.map(
			(token): KeyGrant => ({
				kind: "service-token",
				name: token.name,
				keyIds: token.keyIds,
				expiresAt: token.expiresAt,
				revokedAt: token.revokedAt,
			}),
		),
	];
}
