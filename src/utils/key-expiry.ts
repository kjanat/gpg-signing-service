/**
 * Signing-key expiry inspection
 *
 * The expiry of a signing key is a property of the key material, not a fact
 * anyone should be retyping into a config file: a hand-maintained date is a
 * claim about a key that drifts the moment the key is extended or rotated.
 * Everything here therefore derives expiry by parsing the key itself — the
 * armored PGP public key or the X.509 certificate served by
 * `GET /admin/keys/{keyId}/public`.
 *
 * This module is deliberately free of I/O. It takes key material, key IDs and
 * an explicit `now` and returns plain data, so `scripts/check-key-expiry.ts`
 * owns the network and the filesystem and the tests stay deterministic.
 */

import { parseCertificatePemOrThrow } from "micro509";
import * as openpgp from "openpgp";
import { TIME } from "#types/time";

/** Days before expiry at which a key starts being reported, absent an override */
export const DEFAULT_WARN_DAYS = 60;

/** Environment variable that overrides {@link DEFAULT_WARN_DAYS} */
export const WARN_DAYS_ENV = "KEY_EXPIRY_WARN_DAYS";

/**
 * Outcome of inspecting one key.
 *
 * `missing` is not an expiry state as such — it marks a key that
 * `wrangler.toml` declares but the deployment does not hold, which is the same
 * kind of "signing is about to break" news as an expiry and belongs in the same
 * report.
 */
export type KeyExpiryState = "ok" | "warning" | "expired" | "no-expiry" | "unknown" | "missing";

/** States that mean a human has to do something */
const ACTIONABLE_STATES: ReadonlySet<KeyExpiryState> = new Set<KeyExpiryState>([
	"warning",
	"expired",
	"unknown",
	"missing",
]);

/** Expiry as read out of key material */
export type KeyExpiry =
	| { kind: "date"; expiresAt: Date }
	/** The key carries no expiration date and never lapses */
	| { kind: "never" }
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

/**
 * Extract every signing key ID `wrangler.toml` declares.
 *
 * `KEY_ID` under `[vars]` (and each `[env.*.vars]`) is the deployment's own
 * statement of which key it signs with, so it is already the manifest of active
 * keys — reading it means the check needs no second list to keep in sync.
 */
export function extractDeclaredKeyIds(wranglerToml: string): string[] {
	const declared = new Set<string>();

	for (const match of wranglerToml.matchAll(/^[^\S\n]*KEY_ID[^\S\n]*=[^\S\n]*["']([0-9A-Fa-f]{16})["']/gm)) {
		const keyId = match[1];
		if (keyId) declared.add(keyId.toUpperCase());
	}

	return [...declared].sort();
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

	const primary = await key.getExpirationTime();

	let signing: OpenPgpExpiration = primary;
	try {
		const signingKey = await key.getSigningKey(undefined, null);
		if (signingKey !== key) signing = await signingKey.getExpirationTime();
	} catch {
		// No signing-capable (sub)key at all; the primary key's expiry is still
		// worth reporting, so fall through rather than failing the whole check.
	}

	return effectiveExpiry(primary, signing);
}

/** What openpgp's `getExpirationTime()` can hand back */
export type OpenPgpExpiration = Date | typeof Infinity | null;

/**
 * Reduce a primary key's and its signing key's expirations to one verdict.
 *
 * Split out from {@link pgpKeyExpiry} because openpgp's `null` — no valid
 * self-certification, so the key is revoked or malformed — cannot be produced
 * by any key it will also read back, and a rule this consequential should be
 * asserted directly rather than left to a case no fixture can reach.
 */
export function effectiveExpiry(primary: OpenPgpExpiration, signing: OpenPgpExpiration): KeyExpiry {
	if (primary === null) {
		return { kind: "unknown", reason: "PGP primary key has no valid self-certification (revoked or malformed)" };
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

/** A key `wrangler.toml` declares but the deployment does not hold */
export function missingKeyRow(keyId: string): KeyExpiryRow {
	return {
		keyId,
		state: "missing",
		expiresAt: null,
		daysRemaining: null,
		detail: "declared in wrangler.toml but not present on the deployment",
	};
}

/** Rows that need a human: anything expiring soon, lapsed, unreadable or absent */
export function actionableRows(rows: readonly KeyExpiryRow[]): KeyExpiryRow[] {
	return rows.filter((row) => ACTIONABLE_STATES.has(row.state));
}

const STATE_LABELS: Record<KeyExpiryState, string> = {
	ok: "✅ ok",
	warning: "⚠️ expiring",
	expired: "🚨 expired",
	"no-expiry": "♾️ no expiry",
	unknown: "❓ unknown",
	missing: "🚨 missing",
};

/** Human-readable one-liner for a row's remaining lifetime */
function describeRemaining(row: KeyExpiryRow): string {
	if (row.daysRemaining === null) return "—";
	if (row.daysRemaining < 0) return `${Math.abs(row.daysRemaining)} days ago`;
	return `${row.daysRemaining} days`;
}

/** Report context, kept explicit so the rendered Markdown is reproducible */
export interface ReportContext {
	warnDays: number;
	now: Date;
	serviceUrl: string;
}

/**
 * Render the Markdown report written to stdout, `$GITHUB_STEP_SUMMARY` and the
 * notification issue body. Sorted soonest-expiry-first so the row that matters
 * is the first one read.
 */
export function renderReport(rows: readonly KeyExpiryRow[], context: ReportContext): string {
	const sorted = [...rows].sort(compareBySeverity);
	const actionable = actionableRows(sorted);

	const lines = [
		"## Signing key expiry",
		"",
		`Checked ${sorted.length} key${sorted.length === 1 ? "" : "s"} on ${context.serviceUrl} at ` +
			`${context.now.toISOString()}, warning ${context.warnDays} days ahead of expiry.`,
		"",
		"| Key ID | Status | Expires | Remaining |",
		"| --- | --- | --- | --- |",
	];

	for (const row of sorted) {
		lines.push(
			`| \`${row.keyId}\` | ${STATE_LABELS[row.state]} | ${row.expiresAt ?? "—"} | ${describeRemaining(row)} |`,
		);
	}

	lines.push("");

	if (actionable.length === 0) {
		lines.push(`No signing key expires within ${context.warnDays} days.`);
	} else {
		lines.push("### Action required", "");
		for (const row of actionable) {
			const detail = row.detail ? ` — ${row.detail}` : "";
			lines.push(`- \`${row.keyId}\`: ${STATE_LABELS[row.state]} (${describeRemaining(row)})${detail}`);
		}
		lines.push("", "Rotate or extend the affected keys — see [Key rotation](docs/self-hosting.md#key-rotation).");
	}

	return `${lines.join("\n")}\n`;
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
