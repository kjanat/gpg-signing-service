/**
 * Signing-key expiry inspection
 *
 * Two questions, kept apart on purpose.
 *
 * **Which keys count?** Not "every key in storage" — an operator may retain a
 * superseded key deliberately, and warning about that is a false alarm that
 * teaches people to mute the monitor. Not "every `KEY_ID` in `wrangler.toml`"
 * either — that variable is only the *default* when a caller names no key, and
 * `routes/sign.ts` lets any caller sign with any key its grant permits. The set
 * this module computes is therefore the set the sign path would actually
 * accept: the checked environment's `KEY_ID`, plus every key a **live** grant
 * (a trusted OIDC subject row or a service token) permits, intersected with
 * what the deployment holds. See {@link resolveActiveKeys}.
 *
 * **When does a key lapse?** That is a property of the key material, not a fact
 * anyone should be retyping into a config file: a hand-maintained date is a
 * claim about a key that drifts the moment the key is extended or rotated.
 * Expiry is therefore parsed out of the key itself — the armored PGP public key
 * or the X.509 certificate served by `GET /admin/keys/{keyId}/public`.
 *
 * This module is deliberately free of I/O. It takes key material, admin-API
 * data and an explicit `now`, and returns plain data, so
 * `scripts/check-key-expiry.ts` owns the network and the filesystem and the
 * tests stay deterministic.
 */

import { parseCertificatePemOrThrow } from "micro509";
import * as openpgp from "openpgp";
import { TIME } from "#types/time";

/** Days before expiry at which a key starts being reported, absent an override */
export const DEFAULT_WARN_DAYS = 60;

/** Environment variable that overrides {@link DEFAULT_WARN_DAYS} */
export const WARN_DAYS_ENV = "KEY_EXPIRY_WARN_DAYS";

/**
 * Rotation procedure the report links to.
 *
 * Absolute rather than repo-relative: the report is rendered into GitHub issue
 * bodies and job summaries, and a relative path resolves against the issue or
 * run URL there rather than against the repository.
 */
export const KEY_ROTATION_DOCS_URL =
	"https://github.com/kjanat/gpg-signing-service/blob/master/docs/self-hosting.md#key-rotation";

/**
 * Parse the warning threshold.
 *
 * Rejects anything that is not a positive whole number rather than silently
 * falling back to the default: a typo'd threshold that quietly becomes 60 is a
 * check that lies about what it enforced.
 */
export function parseWarnDays(raw: string | undefined): number {
	if (raw === undefined || raw.trim() === "") return DEFAULT_WARN_DAYS;

	const value = Number(raw.trim());
	if (!Number.isInteger(value) || value <= 0) {
		throw new Error(`${WARN_DAYS_ENV} must be a positive whole number of days, got ${JSON.stringify(raw)}`);
	}

	return value;
}

/** Whole days from `now` until `expiresAt`, floored, negative once lapsed */
export function daysUntil(expiresAt: Date, now: Date): number {
	return Math.floor((expiresAt.getTime() - now.getTime()) / TIME.DAY);
}

// ---------------------------------------------------------------------------
// The deployment's default key
// ---------------------------------------------------------------------------

/** What `wrangler.toml` says one environment signs with by default */
export interface DeclaredDefaultKey {
	/** The wrangler environment read; `null` for the top-level one */
	env: string | null;
	/** `KEY_ID` for that environment, uppercased, or `null` when it declares none */
	keyId: string | null;
	/** Whether that environment exists in the file at all */
	envExists: boolean;
}

/** Table header line, `[vars]` or `[[env.staging.routes]]`, with its path */
const TOML_TABLE = /^[^\S\n]*\[\[?([^\][\s]+)\]\]?/;

/** `KEY_ID = "…"` inside whichever table is currently open */
const TOML_KEY_ID = /^[^\S\n]*KEY_ID[^\S\n]*=[^\S\n]*["']([^"']*)["']/;

/**
 * Read one environment's default signing key out of `wrangler.toml`.
 *
 * Scoped to a single environment on purpose. Collecting `KEY_ID` from every
 * `[env.*.vars]` block at once and then checking one deployment reports the
 * *other* environment's key as missing, every run, forever — and a monitor that
 * cries wolf gets muted. Today production and staging happen to share a key, so
 * the bug would be invisible until the day they do not.
 *
 * Wrangler does not inherit `vars` into named environments (the file says so
 * itself, beside the bindings), so there is deliberately no fallback to the
 * top-level table: an environment that declares no `KEY_ID` has none, and the
 * report says that rather than borrowing production's.
 *
 * @param wranglerToml - Contents of `wrangler.toml`
 * @param env - Named environment, or `null`/omitted for the top-level one
 * @returns The declared default key, and whether the environment exists
 */
export function extractDefaultKeyId(wranglerToml: string, env: string | null = null): DeclaredDefaultKey {
	const varsTable = env === null ? "vars" : `env.${env}.vars`;
	const envPrefix = env === null ? null : `env.${env}`;

	// The top-level environment always exists; a named one has to be seen.
	let envExists = env === null;
	let keyId: string | null = null;
	let table = "";

	for (const line of wranglerToml.split("\n")) {
		// Comments are stripped before anything else, so a commented-out
		// `# KEY_ID = "…"` is not read as configuration.
		if (/^[^\S\n]*#/.test(line)) continue;

		const header = TOML_TABLE.exec(line);
		if (header?.[1]) {
			table = header[1];
			if (envPrefix !== null && (table === envPrefix || table.startsWith(`${envPrefix}.`))) {
				envExists = true;
			}
			continue;
		}

		if (table !== varsTable) continue;

		const declared = TOML_KEY_ID.exec(line);
		if (declared?.[1]) keyId = declared[1].toUpperCase();
	}

	return { env, keyId, envExists };
}

// ---------------------------------------------------------------------------
// The grants that decide which keys are reachable
// ---------------------------------------------------------------------------

/** Which credential table a grant came from */
export type GrantKind = "oidc-subject" | "service-token";

/**
 * A credential's signing policy, as `GET /admin/subjects` and
 * `GET /admin/tokens` return it.
 *
 * `keyIds: null` is the load-bearing case: both auth paths read it as *every*
 * key, so one such live grant makes storage the activation boundary after all.
 */
export interface KeyGrant {
	kind: GrantKind;
	name: string;
	/** Key ids this credential may sign with; `null` means every stored key */
	keyIds: string[] | null;
	expiresAt: string | null;
	revokedAt: string | null;
}

/**
 * Can this grant authorize a signature right now?
 *
 * Mirrors the server's own test — `verifyServiceToken` and `resolveOIDCSubject`
 * both apply exactly this rule — including its treatment of an unparseable
 * `expiresAt`: `Date.parse` yields `NaN`, every comparison against it is false,
 * and the row is honoured. Re-deriving a stricter rule here would report a key
 * as unmonitored that the sign path would still sign with.
 */
export function isGrantLive(grant: KeyGrant, now: Date): boolean {
	if (grant.revokedAt) return false;
	return !(grant.expiresAt && Date.parse(grant.expiresAt) < now.getTime());
}

/** Why a key is in the monitored set */
export type ActivationReason =
	/** It is the checked environment's `KEY_ID` */
	| "default"
	/** A live grant names it explicitly */
	| "grant"
	/** A live grant pins no key ids, so it reaches every stored key */
	| "unrestricted-grant";

/** One key this deployment can currently sign with */
export interface ActiveKey {
	keyId: string;
	/** Sorted, deduplicated reasons this key counts as active */
	reasons: ActivationReason[];
	/** Live credentials that reach it, `kind:name`, sorted */
	grants: string[];
	/** Whether the deployment actually holds it */
	stored: boolean;
}

/** The monitored set, with everything needed to justify it in the report */
export interface ActiveKeySet {
	/** Keys to check, sorted by key id */
	keys: ActiveKey[];
	/** Stored keys no live grant reaches: retained, unreachable, not monitored */
	retainedInactive: string[];
	/** Live grants that pin no key ids, `kind:name`, sorted */
	unrestrictedGrants: string[];
	/** How many grants were live at `now`, of any scope */
	liveGrantCount: number;
	/** How many grants were read in total, live or not */
	totalGrantCount: number;
	/** The checked environment's declared default, echoed for the report */
	defaultKey: DeclaredDefaultKey;
}

/** Uppercase a key id so grants, storage and config compare as one namespace */
function normalizeKeyId(keyId: string): string {
	return keyId.trim().toUpperCase();
}

/**
 * Compute the keys this deployment can sign with right now.
 *
 * The rule, in the order the sign path applies it:
 *
 * 1. A caller may name any key (`?keyId=`), defaulting to the environment's
 *    `KEY_ID` — so the default is always in the set, and is reported `missing`
 *    when the deployment does not hold it.
 * 2. A grant with an explicit allowlist admits exactly those key ids. One that
 *    names a key the deployment lacks is a broken grant, and is reported the
 *    same way.
 * 3. A grant with no allowlist admits every *stored* key. This is the only case
 *    in which storage is the activation boundary, and it is detected rather
 *    than assumed.
 * 4. Everything else in storage is retained but unreachable, and is left out of
 *    the report entirely rather than warned about.
 *
 * Dead grants are excluded by {@link isGrantLive}, so revoking or expiring the
 * last credential that reached a key drops it from the monitored set on the
 * next run, with no second list to remember to prune.
 */
export function resolveActiveKeys(input: {
	storedKeyIds: readonly string[];
	defaultKey: DeclaredDefaultKey;
	grants: readonly KeyGrant[];
	now: Date;
}): ActiveKeySet {
	const stored = new Set(input.storedKeyIds.map(normalizeKeyId));
	const live = input.grants.filter((grant) => isGrantLive(grant, input.now));
	const unrestricted = live.filter((grant) => grant.keyIds === null);

	const active = new Map<string, { reasons: Set<ActivationReason>; grants: Set<string> }>();
	const entryFor = (keyId: string) => {
		let entry = active.get(keyId);
		if (!entry) {
			entry = { reasons: new Set(), grants: new Set() };
			active.set(keyId, entry);
		}
		return entry;
	};
	const label = (grant: KeyGrant) => `${grant.kind}:${grant.name}`;

	// An unrestricted grant reaches every key the deployment *holds* — and only
	// those, since `?keyId=` on a key that was never uploaded is a 404, not a
	// signature. So this widens over storage, never over the grant lists.
	for (const grant of unrestricted) {
		for (const keyId of stored) {
			const entry = entryFor(keyId);
			entry.reasons.add("unrestricted-grant");
			entry.grants.add(label(grant));
		}
	}

	for (const grant of live) {
		for (const keyId of grant.keyIds ?? []) {
			const entry = entryFor(normalizeKeyId(keyId));
			entry.reasons.add("grant");
			entry.grants.add(label(grant));
		}
	}

	// Last, so the default is in the set even on a deployment that has no live
	// grant at all: it is what this environment is configured to sign with, and
	// its lapsing is news the moment anyone is trusted again.
	if (input.defaultKey.keyId) {
		entryFor(input.defaultKey.keyId).reasons.add("default");
	}

	const keys = [...active.entries()]
		.map(([keyId, entry]) => ({
			keyId,
			reasons: [...entry.reasons].sort(),
			grants: [...entry.grants].sort(),
			stored: stored.has(keyId),
		}))
		.sort((a, b) => a.keyId.localeCompare(b.keyId));

	return {
		keys,
		retainedInactive: [...stored].filter((keyId) => !active.has(keyId)).sort(),
		unrestrictedGrants: unrestricted.map(label).sort(),
		liveGrantCount: live.length,
		totalGrantCount: input.grants.length,
		defaultKey: input.defaultKey,
	};
}

// ---------------------------------------------------------------------------
// Expiry, read out of the key material
// ---------------------------------------------------------------------------

/**
 * Outcome of inspecting one key.
 *
 * `missing` is not an expiry state as such — it marks a key this deployment is
 * configured or authorized to sign with but does not hold, which is the same
 * kind of "signing is about to break" news as an expiry and belongs in the same
 * report.
 */
export type KeyExpiryState = "ok" | "warning" | "expired" | "revoked" | "no-expiry" | "unknown" | "missing";

/** States that mean a human has to do something */
const ACTIONABLE_STATES: ReadonlySet<KeyExpiryState> = new Set<KeyExpiryState>([
	"warning",
	"expired",
	"revoked",
	"unknown",
	"missing",
]);

/** Expiry as read out of key material */
export type KeyExpiry =
	| { kind: "date"; expiresAt: Date }
	/** The key carries no expiration date and never lapses */
	| { kind: "never" }
	/**
	 * The key is revoked. Revocation is not expiry, but it stops verifiers
	 * accepting the signature just as completely, and an unexpired revoked key
	 * would otherwise be reported as healthy.
	 */
	| { kind: "revoked" }
	/** The key material parsed but its expiry could not be established */
	| { kind: "unknown"; reason: string };

/** One row of the expiry report */
export interface KeyExpiryRow {
	keyId: string;
	state: KeyExpiryState;
	/** ISO-8601 expiry, or `null` when there is no date to show */
	expiresAt: string | null;
	/** Whole days from `now` until expiry; negative once lapsed */
	daysRemaining: number | null;
	/** Why the state is `unknown` or `missing`, for the report */
	detail?: string;
}

/**
 * Effective expiry of an armored PGP public key.
 *
 * A commit is signed by the key's signing (sub)key, which can lapse before the
 * primary key does, so the effective expiry is the earlier of the two. The
 * signing key is looked up with `date: null` to switch off openpgp's validity
 * filtering — an already-expired signing key still has to appear in the report,
 * and the default lookup would refuse to return it.
 */
export async function pgpKeyExpiry(armoredKey: string): Promise<KeyExpiry> {
	let key: openpgp.Key;
	try {
		key = await openpgp.readKey({ armoredKey });
	} catch (error) {
		return { kind: "unknown", reason: `could not read PGP key: ${String(error)}` };
	}

	// `getExpirationTime()` reads the self-signature's expiration subpacket and
	// says nothing about revocation, so a revoked key that has not yet reached
	// its expiry date would otherwise be reported as `ok`.
	if (await key.isRevoked()) return { kind: "revoked" };

	const primary = await key.getExpirationTime();

	let signing: OpenPgpExpiration;
	try {
		const signingKey = await key.getSigningKey(undefined, null);
		signing = signingKey === key ? primary : await signingKey.getExpirationTime();
	} catch (error) {
		// Date checks are switched off above, so this lookup does not fail merely
		// because a key lapsed — an expired key still resolves and still gets its
		// `expired` row. It fails when there is no signing key to resolve at all:
		// the signing subkey is revoked, or none was ever bound. Falling back to
		// the primary key's expiry there reports a healthy date for a key whose
		// signatures every verifier now rejects, which is the same lie an
		// unchecked primary-key revocation used to tell one level up.
		return {
			kind: "unknown",
			reason: `no usable signing key: ${error instanceof Error ? error.message : String(error)}`,
		};
	}

	return effectiveExpiry(primary, signing);
}

/** What openpgp's `getExpirationTime()` can hand back */
export type OpenPgpExpiration = Date | typeof Infinity | null;

/**
 * Reduce a primary key's and its signing key's expirations to one verdict.
 *
 * Split out from {@link pgpKeyExpiry} because openpgp's `null` — no valid
 * self-certification, so the key is malformed — cannot be produced by any key
 * it will also read back, and a rule this consequential should be asserted
 * directly rather than left to a case no fixture can reach. Revocation is
 * handled before this point, by {@link pgpKeyExpiry}.
 */
export function effectiveExpiry(primary: OpenPgpExpiration, signing: OpenPgpExpiration): KeyExpiry {
	if (primary === null) {
		return { kind: "unknown", reason: "PGP primary key has no valid self-certification (malformed)" };
	}

	const effective = earlier(primary, signing ?? primary);

	return neverExpires(effective) ? { kind: "never" } : { kind: "date", expiresAt: effective };
}

/** Expiry of a PEM X.509 certificate, taken from its `notAfter` */
export function x509CertificateExpiry(certificatePem: string): KeyExpiry {
	try {
		return { kind: "date", expiresAt: parseCertificatePemOrThrow(certificatePem).notAfter };
	} catch (error) {
		return { kind: "unknown", reason: `could not parse X.509 certificate: ${String(error)}` };
	}
}

/**
 * Read the expiry out of whatever `GET /admin/keys/{keyId}/public` returned.
 *
 * That endpoint serves an armored PGP public key for PGP keys and a PEM
 * certificate chain for X.509 keys, so the material is dispatched on its armor
 * header rather than on a caller-supplied type.
 */
export function keyMaterialExpiry(material: string): Promise<KeyExpiry> | KeyExpiry {
	if (material.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		return pgpKeyExpiry(material);
	}
	if (material.includes("-----BEGIN CERTIFICATE-----")) {
		return x509CertificateExpiry(material);
	}

	return { kind: "unknown", reason: "response was neither a PGP public key block nor a PEM certificate" };
}

/** Turn an expiry into a report row, relative to `now` and the threshold */
export function classifyExpiry(keyId: string, expiry: KeyExpiry, now: Date, warnDays: number): KeyExpiryRow {
	if (expiry.kind === "never") {
		return { keyId, state: "no-expiry", expiresAt: null, daysRemaining: null };
	}
	if (expiry.kind === "revoked") {
		return { keyId, state: "revoked", expiresAt: null, daysRemaining: null, detail: "key is revoked" };
	}
	if (expiry.kind === "unknown") {
		return { keyId, state: "unknown", expiresAt: null, daysRemaining: null, detail: expiry.reason };
	}

	const expiresAt = expiry.expiresAt.toISOString();
	const daysRemaining = daysUntil(expiry.expiresAt, now);

	if (expiry.expiresAt.getTime() <= now.getTime()) {
		return { keyId, state: "expired", expiresAt, daysRemaining };
	}

	// Inclusive: a key exactly `warnDays` out is already inside the window.
	return { keyId, state: daysRemaining <= warnDays ? "warning" : "ok", expiresAt, daysRemaining };
}

/**
 * A key this deployment would sign with but does not hold.
 *
 * The detail names *why* it was expected, because the two causes need opposite
 * fixes: a `KEY_ID` pointing at nothing is a deployment that never received its
 * key, while a grant naming nothing is a credential that outlived the key it
 * was scoped to.
 */
export function missingKeyRow(key: ActiveKey): KeyExpiryRow {
	const causes: string[] = [];
	if (key.reasons.includes("default")) causes.push("this environment's KEY_ID");
	if (key.reasons.includes("grant")) causes.push(`granted to ${key.grants.join(", ")}`);

	return {
		keyId: key.keyId,
		state: "missing",
		expiresAt: null,
		daysRemaining: null,
		detail: `${causes.join("; ") || "expected"}, but the deployment does not hold it`,
	};
}

/** Rows that need a human: anything expiring soon, lapsed, unreadable or absent */
export function actionableRows(rows: readonly KeyExpiryRow[]): KeyExpiryRow[] {
	return rows.filter((row) => ACTIONABLE_STATES.has(row.state));
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const STATE_LABELS: Record<KeyExpiryState, string> = {
	ok: "✅ ok",
	warning: "⚠️ expiring",
	expired: "🚨 expired",
	revoked: "🚨 revoked",
	"no-expiry": "♾️ no expiry",
	unknown: "❓ unknown",
	missing: "🚨 missing",
};

/** `n` with a unit, pluralised, so no report ever reads `1 days` */
function plural(count: number, unit: string): string {
	return `${count} ${unit}${count === 1 ? "" : "s"}`;
}

/** Human-readable one-liner for a row's remaining lifetime */
function describeRemaining(row: KeyExpiryRow): string {
	if (row.daysRemaining === null) return "—";
	if (row.daysRemaining < 0) return `${plural(Math.abs(row.daysRemaining), "day")} ago`;
	return plural(row.daysRemaining, "day");
}

/** At most two names, then a count, so one broad grant cannot flood the table */
function summarizeGrants(grants: readonly string[]): string {
	const shown = grants.slice(0, 2).map((grant) => `\`${grant}\``);
	const rest = grants.length - shown.length;
	return rest > 0 ? `${shown.join(", ")} +${rest} more` : shown.join(", ");
}

/**
 * Why this key is being watched, for the report's own column.
 *
 * Stated per key rather than once at the top because the answer differs per
 * key, and it is the difference that is actionable: a key held only by an
 * unrestricted grant is one scoped grant away from leaving the report.
 */
export function describeActivation(key: ActiveKey): string {
	const parts: string[] = [];
	if (key.reasons.includes("default")) parts.push("`KEY_ID` default");
	if (key.reasons.includes("grant")) parts.push(`granted to ${summarizeGrants(key.grants)}`);
	else if (key.reasons.includes("unrestricted-grant")) parts.push(`any-key grant ${summarizeGrants(key.grants)}`);
	return parts.join("; ") || "—";
}

/** Report context, kept explicit so the rendered Markdown is reproducible */
export interface ReportContext {
	warnDays: number;
	now: Date;
	serviceUrl: string;
	/** The resolved monitored set, which the report has to be able to justify */
	scope: ActiveKeySet;
}

/**
 * Render the Markdown report written to stdout, `$GITHUB_STEP_SUMMARY` and the
 * notification issue body. Sorted soonest-expiry-first so the row that matters
 * is the first one read.
 */
export function renderReport(rows: readonly KeyExpiryRow[], context: ReportContext): string {
	const sorted = [...rows].sort(compareBySeverity);
	const actionable = actionableRows(sorted);
	const activations = new Map(context.scope.keys.map((key) => [key.keyId, describeActivation(key)]));
	const envLabel = context.scope.defaultKey.env ?? "top-level";

	const lines = [
		"## Signing key expiry",
		"",
		`Monitored ${plural(sorted.length, "active signing key")} on ${context.serviceUrl} ` +
			`(wrangler environment \`${envLabel}\`) at ${context.now.toISOString()}, ` +
			`warning ${plural(context.warnDays, "day")} ahead of expiry.`,
		"",
		"| Key ID | Status | Expires | Remaining | Active because |",
		"| --- | --- | --- | --- | --- |",
	];

	for (const row of sorted) {
		lines.push(
			`| \`${row.keyId}\` | ${STATE_LABELS[row.state]} | ${row.expiresAt ?? "—"} | ${describeRemaining(row)} | ` +
				`${activations.get(row.keyId) ?? "—"} |`,
		);
	}

	lines.push("");

	if (actionable.length === 0) {
		lines.push(`No active signing key expires within ${plural(context.warnDays, "day")}.`);
	} else {
		lines.push("### Action required", "");
		for (const row of actionable) {
			const detail = row.detail ? ` — ${row.detail}` : "";
			lines.push(`- \`${row.keyId}\`: ${STATE_LABELS[row.state]} (${describeRemaining(row)})${detail}`);
		}
		lines.push("", `Rotate or extend the affected keys — see [Key rotation](${KEY_ROTATION_DOCS_URL}).`);
	}

	lines.push("", ...renderScopeNotes(context.scope));

	return `${lines.join("\n")}\n`;
}

/**
 * Spell out how the monitored set was chosen, and where it is imprecise.
 *
 * In the report rather than only in the docs because the report is what gets
 * read — in a GitHub issue, months later, by whoever is on call. A set this
 * derived is worth nothing if its reader cannot tell what it excluded.
 */
function renderScopeNotes(scope: ActiveKeySet): string[] {
	const lines = [
		"<details><summary>Which keys count as active</summary>",
		"",
		"A key is monitored when this deployment could sign with it right now: the checked",
		"environment's `KEY_ID` default, plus every key a live grant — a trusted OIDC subject",
		"or a service token — permits. Grants that are revoked or expired are ignored, and",
		"stored keys no live grant reaches are deliberately left out, so retaining a",
		"superseded key raises nothing.",
		"",
		`Read ${plural(scope.totalGrantCount, "grant")}, of which ${scope.liveGrantCount} live.`,
	];

	if (scope.defaultKey.keyId === null) {
		lines.push(
			"",
			`⚠️ The \`${scope.defaultKey.env ?? "top-level"}\` environment declares no \`KEY_ID\`, so callers that name` +
				" no key cannot sign at all. Only granted keys are monitored.",
		);
	}

	if (scope.unrestrictedGrants.length > 0) {
		lines.push(
			"",
			`⚠️ ${plural(scope.unrestrictedGrants.length, "live grant")} ` +
				`${scope.unrestrictedGrants.length === 1 ? "pins" : "pin"} no key ids, so **every stored key is ` +
				`signable** and storage is the activation boundary: ${summarizeGrants(scope.unrestrictedGrants)}. ` +
				"Scope those grants to key ids to narrow this report.",
		);
	}

	if (scope.retainedInactive.length > 0) {
		lines.push(
			"",
			`Not monitored — stored but no live grant reaches ${scope.retainedInactive.length === 1 ? "it" : "them"}: ` +
				`${scope.retainedInactive.map((keyId) => `\`${keyId}\``).join(", ")}.`,
		);
	}

	lines.push(
		"",
		"Known limits: the set is a snapshot, so a grant added after this run is not covered",
		"until the next one; `KEY_ID` is read from `wrangler.toml` in this repository, which a",
		"deployment whose vars were changed elsewhere can disagree with; and a grant is trusted",
		"to mean what it says, so a key id it names that no longer exists is reported `missing`",
		"rather than dropped.",
		"",
		"</details>",
	);

	return lines;
}

/** Worst-first ordering: actionable rows above healthy ones, soonest expiry first */
function compareBySeverity(a: KeyExpiryRow, b: KeyExpiryRow): number {
	const rank = (row: KeyExpiryRow) => (ACTIONABLE_STATES.has(row.state) ? 0 : 1);
	if (rank(a) !== rank(b)) return rank(a) - rank(b);

	if (a.daysRemaining !== null && b.daysRemaining !== null) return a.daysRemaining - b.daysRemaining;
	if (a.daysRemaining !== null) return -1;
	if (b.daysRemaining !== null) return 1;

	return a.keyId.localeCompare(b.keyId);
}

/**
 * openpgp signals "this never expires" with the number `Infinity` rather than a
 * `Date`, and `typeof Infinity` is plain `number`, so narrowing needs a guard.
 */
function neverExpires(value: Date | typeof Infinity): value is typeof Infinity {
	return value === Infinity;
}

/** Earlier of two openpgp expiry values, where `Infinity` means "never" */
function earlier(a: Date | typeof Infinity, b: Date | typeof Infinity): Date | typeof Infinity {
	if (neverExpires(a)) return b;
	if (neverExpires(b)) return a;
	return a.getTime() <= b.getTime() ? a : b;
}
