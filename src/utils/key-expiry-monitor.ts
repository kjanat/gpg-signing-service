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
 *
 * That ordering buys one more thing. Once the mail boundary has proved usable,
 * everything after it that can fail — an unreadable threshold, a Durable Object
 * that will not answer, a grant table that will not read — is reported to the
 * same inbox as a monitor that *could not run*, and then rethrown. A monitor
 * whose own breakage is quieter than the condition it watches for is a monitor
 * whose silence means nothing; see {@link reportSelfFailure} for what that
 * alert may and may not say, and why the sending sits outside the guarded work.
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
	MonitorFailureKind,
	ReportContext,
	ReportDocument,
} from "#utils/key-expiry";
import {
	actionableRows,
	classifyExpiry,
	keyMaterialExpiry,
	missingKeyRow,
	parseWarnDays,
	renderFailureReport,
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
 * Which of the monitor's two pieces of news an alert carries.
 *
 * A closed union, passed at the call site rather than derived at the boundary.
 * The two alerts read differently in an inbox but are the same shape in a log
 * line, and they mean opposite things: `key-expiry` is the monitor completing
 * and having something to say about the keys — one that needs a human, or no
 * active key to check at all — while `monitor-failure` is the monitor reporting
 * that it reached no verdict on any key because it could not run. Collapsing
 * them in Workers logs would make "the monitor sent something" unreadable as
 * either.
 *
 * The sender is told which; it does not read the rendered subject or body to
 * find out. Text is written for operators and may be reworded, so a log
 * classification that depended on it would be one rewrite away from lying.
 */
export type AlertKind = "key-expiry" | "monitor-failure";

/**
 * Whether a delivery attempt reached the operator or died at the boundary.
 *
 * Recorded next to {@link AlertKind} rather than instead of it, under the same
 * `action`, because "what did the monitor try to send?" and "did it get out?"
 * are two questions about one event. Answering them under two different
 * actions is what made the obvious query — everything the alert pipeline did —
 * go quiet in the one case an operator most needs it: when the mail binding
 * itself is the thing that has broken.
 */
export type AlertOutcome = "sent" | "failed";

/**
 * One delivery attempt, as the call site classifies it.
 *
 * The kind is still decided by the caller and never derived from the rendered
 * mail. A self-failure alert carries one field more: the stage the monitor
 * died in, which is the same closed {@link MonitorFailureKind} the fixed mail
 * copy is chosen from — a word from a four-value set, not an exception, not its
 * message, and not anything else read back out of the failure.
 */
export type AlertDelivery = { alert: "key-expiry" } | { alert: "monitor-failure"; failure: MonitorFailureKind };

/**
 * The message every delivery attempt is logged under.
 *
 * Fixed strings, one per {@link AlertKind} and {@link AlertOutcome}, so all
 * four classifications are stable enough to build a log query on and none of
 * them can pick up rendered content.
 */
const ALERT_MESSAGE: Record<AlertKind, Record<AlertOutcome, string>> = {
	"key-expiry": {
		sent: "Key expiry alert sent",
		failed: "Key expiry alert could not be sent",
	},
	"monitor-failure": {
		sent: "Key expiry monitor self-failure alert sent",
		failed: "Key expiry monitor self-failure alert could not be sent",
	},
};

/**
 * The fields one delivery attempt is logged under, whichever way it went.
 *
 * Built from the discriminator the caller passed and the configured recipient,
 * and from nothing else: never the subject, never either body, never the
 * exception. That is what makes the event safe to read in bulk — the mail is
 * the operator's copy, and the log line is only the fact that it was attempted.
 */
function alertEvent(delivery: AlertDelivery, outcome: AlertOutcome, to: string) {
	return {
		action: "key-expiry-alert",
		alert: delivery.alert,
		outcome,
		to,
		...(delivery.alert === "monitor-failure" ? { failure: delivery.failure } : {}),
	};
}

/**
 * Where an alert goes.
 *
 * A function rather than the binding itself so the tests can watch what would
 * have been sent without a live Email Service account — and so the one place
 * that talks to Cloudflare is one line long and separately assertable.
 *
 * The {@link AlertDelivery} rides along with the rendered mail so a sender can
 * classify the attempt without parsing it; see {@link bindingMailSender}.
 */
export type MailSender = (mail: AlertMail, delivery: AlertDelivery) => Promise<void>;

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
 *
 * It is also the one place a delivery attempt is observed. Both ways an attempt
 * can end are logged here, under the same `key-expiry-alert` action and told
 * apart by {@link AlertOutcome}, so `action = "key-expiry-alert"` is the whole
 * pipeline rather than only the half of it that worked. Only the observation
 * lives here: a rejected send rejects onward unchanged.
 */
export function bindingMailSender(env: Env): MailSender {
	const { binding, from, to } = mailConfig(env);

	return async (mail, delivery) => {
		let messageId: string;

		// `try`/`catch` rather than `.catch()` on the returned promise, because a
		// binding that throws where it was declared to reject would never reach a
		// rejection handler at all — and "the binding refused before it even had a
		// promise to reject with" is precisely the state this event exists to make
		// visible. The statement form covers both, so the invariant is the code's
		// rather than the runtime's to keep.
		try {
			({ messageId } = await binding.send({
				from,
				to,
				subject: mail.subject,
				text: mail.text,
				html: mail.html,
			}));
		} catch (error) {
			// Recorded and rethrown unchanged. The log is an observation, not a
			// handler: there is no retry, no fallback channel and no second send,
			// so a failed alert is still exactly as failed as it was — see the two
			// callers, both of which depend on this rejecting.
			//
			// The exception is deliberately not handed to the logger. A send error
			// is written by the mail provider, and this event has to stay safe to
			// read in bulk; `outcome` and `alert` already say what happened, and
			// the exception itself reaches the cron invocation intact.
			logger.error(ALERT_MESSAGE[delivery.alert].failed, undefined, alertEvent(delivery, "failed", to));
			throw error;
		}

		// `alert` is the discriminator the caller passed, not anything read back
		// out of `mail`: what was sent is the operator's copy, and the log line
		// records which of the two things the monitor had to say — never either
		// body, which is where the key ids and the deployment's state live.
		logger.info(ALERT_MESSAGE[delivery.alert].sent, { ...alertEvent(delivery, "sent", to), messageId });
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
	/**
	 * Whether the run resolved no active signing key at all.
	 *
	 * Separate from `actionable` because it is a different kind of news: there
	 * is no key to rotate, but nothing was verified either. It is its own field
	 * so the condition is assertable rather than inferred from `rows.length`.
	 */
	checkedNothing: boolean;
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
 * A run that resolved *no* active key is not a clean run and does send: it
 * checked nothing, so its silence would be a green light nothing earned. That
 * is the state every fresh deployment passes through, and the one a deployment
 * that loses its `KEY_ID` falls back into.
 *
 * @throws when the alerting path is misconfigured, when the deployment's own
 * state cannot be read, or when the send fails — all three mean the monitor did
 * not do its job, and a cron run that reports success in that state is worse
 * than no monitor at all. The second of those is additionally mailed first, on
 * a best-effort basis, and the original failure is what escapes either way.
 */
export async function runKeyExpiryMonitor(env: Env, options: MonitorOptions = {}): Promise<MonitorResult> {
	const now = options.now ?? new Date();
	// Resolved before anything else is read, so a broken alerting path fails the
	// run it is cheap to fail — see the module note — and so everything after
	// this line has a mail path that has already proved usable.
	const sendMail = options.sendMail ?? bindingMailSender(env);
	const service = serviceLabel(env);

	let checked: CheckedKeys;
	try {
		checked = await checkKeys(env, now);
	} catch (error) {
		// Best-effort, and outside the send path on purpose: the ordinary alert
		// below is sent after this block, so a failing `send_email` cannot land
		// here and try to report itself through the channel that just failed.
		await reportSelfFailure(sendMail, error, { service, now });
		throw failureCause(error);
	}

	const { warnDays, scope, rows } = checked;
	const context: ReportContext = { warnDays, now, service, scope };
	const report = renderReport(rows, context);
	const actionable = actionableRows(rows);
	const checkedNothing = rows.length === 0;

	if (actionable.length === 0 && !checkedNothing) {
		logger.info("Key expiry check clear", {
			action: "key-expiry-check",
			checked: rows.length,
			warnDays,
		});
		return { rows, actionable, scope, report, checkedNothing, alerted: false };
	}

	if (checkedNothing) {
		// A run that resolved no active key verified nothing, and "nothing to
		// report" and "nothing to check" are opposite pieces of news. Reported
		// through the same channel as any other finding, because the dashboard is
		// not a channel anyone watches and a green light earned by an empty set
		// is the failure this monitor exists to prevent.
		logger.warn("Key expiry check verified nothing: no active signing key was resolved", {
			action: "key-expiry-check",
			checked: 0,
			declaredKeyId: scope.defaultKey.keyId,
			liveGrantCount: scope.liveGrantCount,
			totalGrantCount: scope.totalGrantCount,
			warnDays,
		});
	} else {
		logger.warn("Key expiry check found keys needing attention", {
			action: "key-expiry-check",
			checked: rows.length,
			actionable: actionable.map((row) => ({ keyId: row.keyId, state: row.state, daysRemaining: row.daysRemaining })),
			warnDays,
		});
	}

	await sendMail(report, { alert: "key-expiry" });

	return { rows, actionable, scope, report, checkedNothing, alerted: true };
}

/** Everything the report needs, once the deployment's state has been read */
interface CheckedKeys {
	warnDays: number;
	scope: ActiveKeySet;
	rows: KeyExpiryRow[];
}

/**
 * A failure carrying the stage it happened in.
 *
 * The stage is recorded where the failure occurs rather than guessed from its
 * message afterwards. Sniffing an error's text to decide what to tell an
 * operator is how an unrelated failure ends up described as a threshold
 * problem, and how a message that was never meant to be read aloud gets read
 * aloud.
 */
class StagedFailure extends Error {
	readonly kind: MonitorFailureKind;
	/** The failure as thrown, which is what the cron invocation must still see */
	readonly failure: unknown;

	constructor(kind: MonitorFailureKind, failure: unknown) {
		super(`Key expiry monitor failed while reading ${kind}`);
		this.name = "StagedFailure";
		this.kind = kind;
		this.failure = failure;
	}
}

/** Run one stage, tagging anything it throws with what was being read */
async function inStage<T>(kind: MonitorFailureKind, run: () => Promise<T> | T): Promise<T> {
	try {
		return await run();
	} catch (error) {
		// Stages do not nest, so nothing arriving here is already tagged.
		throw new StagedFailure(kind, error);
	}
}

/** Which class of failure to report; anything untagged is the generic one */
function failureKindOf(error: unknown): MonitorFailureKind {
	return error instanceof StagedFailure ? error.kind : "report";
}

/** The failure as originally thrown, so the rethrow loses nothing */
function failureCause(error: unknown): unknown {
	return error instanceof StagedFailure ? error.failure : error;
}

/**
 * Read the deployment's state and reach a verdict on every active key.
 *
 * Split out of {@link runKeyExpiryMonitor} because this is exactly the work
 * that can fail *after* the mail boundary has proved usable, and so exactly the
 * work worth reporting by mail when it does. The sending happens in the caller;
 * nothing here sends, which is what makes recursion structurally impossible
 * rather than merely guarded against.
 */
async function checkKeys(env: Env, now: Date): Promise<CheckedKeys> {
	const warnDays = await inStage("threshold", () => parseWarnDays(env.KEY_EXPIRY_WARN_DAYS));
	const stored = await inStage("key-storage", () => storedKeyIds(env));
	const grants = await inStage("grants", () => readGrants(env));

	const scope = await inStage("report", () =>
		resolveActiveKeys({ storedKeyIds: stored, defaultKey: defaultKeyOf(env), grants, now }),
	);

	const rows: KeyExpiryRow[] = [];
	for (const key of scope.keys) {
		rows.push(
			key.stored
				? classifyExpiry(key.keyId, await inStage("key-storage", () => storedKeyExpiry(env, key.keyId)), now, warnDays)
				: missingKeyRow(key),
		);
	}

	return { warnDays, scope, rows };
}

/**
 * Tell the operator the monitor itself could not run.
 *
 * Best effort by design. The alert is an extra channel, not a replacement for
 * the throw: if this send fails too, the failure that broke the run is still
 * the one that escapes, because a mail problem must not be allowed to overwrite
 * the diagnosis of the problem it was reporting.
 */
async function reportSelfFailure(
	sendMail: MailSender,
	error: unknown,
	context: { service: string; now: Date },
): Promise<void> {
	const kind = failureKindOf(error);
	logger.error("Key expiry monitor could not complete", failureCause(error), {
		action: "key-expiry-check",
		failure: kind,
	});

	try {
		await sendMail(renderFailureReport(kind, context), { alert: "monitor-failure", failure: kind });
	} catch (sendError) {
		logger.error("Key expiry monitor could not report its own failure", sendError, {
			action: "key-expiry-check",
			failure: kind,
		});
	}
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
