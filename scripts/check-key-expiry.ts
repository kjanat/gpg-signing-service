#!/usr/bin/env bun
/// <reference types="bun" />

/**
 * Report every active signing key that is at or near expiry.
 *
 * "Active" is derived, not declared. The deployment is asked what it holds
 * (`GET /admin/keys`) and who may use it (`GET /admin/subjects`,
 * `GET /admin/tokens`); `wrangler.toml` supplies the checked environment's
 * `KEY_ID` default. `resolveActiveKeys` reduces those to the set the sign path
 * would actually accept, and each key's expiry is then read out of its own
 * material via `GET /admin/keys/{keyId}/public`. Nothing here is hand
 * maintained, so nothing here can drift.
 *
 * Every call this makes is a `GET`, so it runs on `ADMIN_READONLY_TOKEN` — the
 * credential that `adminAuth` accepts on `GET`/`HEAD` admin routes and refuses
 * on every state-changing one. `ADMIN_TOKEN` is deliberately not read here and
 * is not accepted as a fallback: it would also authorize deleting a signing
 * key, minting a service token and rewriting the trust list, and a fallback
 * would hand the monitor that authority silently, on the one run where the
 * read-only secret was missing. Refusing is the whole point of the split.
 *
 * Configuration (all environment variables):
 *   SIGNING_SERVICE_URL   Base URL of the deployment to check. Required.
 *   ADMIN_READONLY_TOKEN  Read-only admin bearer. Required.
 *   KEY_EXPIRY_WARN_DAYS  Warn this many days ahead of expiry. Default 60.
 *   WRANGLER_ENV          Environment whose `KEY_ID` to read. Default top-level.
 *
 * Exit codes: 0 all clear, 1 one or more keys need attention, 2 the check
 * could not run. The workflow branches on the `actionable` step output rather
 * than the exit code, so a warning does not read as a broken job.
 */

import path from "node:path";
import {
	type ActiveKey,
	actionableRows,
	classifyExpiry,
	extractDefaultKeyId,
	type KeyExpiryRow,
	type KeyGrant,
	keyMaterialExpiry,
	missingKeyRow,
	parseWarnDays,
	renderReport,
	resolveActiveKeys,
} from "#utils/key-expiry";

const EXIT_ACTIONABLE = 1;
const EXIT_CANNOT_RUN = 2;

/** The parts of the admin list responses this script relies on */
interface KeyListResponse {
	keys: { keyId: string }[];
}
interface SubjectListResponse {
	subjects: { name: string; keyIds: string[] | null; expiresAt: string | null; revokedAt: string | null }[];
}
interface TokenListResponse {
	tokens: { name: string; keyIds: string[] | null; expiresAt: string | null; revokedAt: string | null }[];
}

function requireEnv(name: string): string {
	const value = process.env[name]?.trim();
	if (!value) {
		throw new Error(`${name} is not set; the expiry check needs it to reach the admin API`);
	}
	return value;
}

/**
 * The read-only admin bearer, and a refusal to quietly accept the full one.
 *
 * `ADMIN_TOKEN` in the environment is the likely shape of the mistake — it is
 * what this check used before the read-only credential existed, and it works.
 * That is exactly why it is named and refused rather than ignored: silently
 * falling back would give a weekly scheduled job the authority to delete a
 * signing key, and nothing in the run's output would say so.
 */
function readOnlyAdminToken(): string {
	const readOnly = process.env.ADMIN_READONLY_TOKEN?.trim();
	if (readOnly) return readOnly;

	if (process.env.ADMIN_TOKEN?.trim()) {
		throw new Error(
			"ADMIN_READONLY_TOKEN is not set, but ADMIN_TOKEN is. The expiry check only reads, so it takes the " +
				"read-only credential and will not fall back to the full one. Provision it with " +
				"`wrangler secret put ADMIN_READONLY_TOKEN` (a value distinct from ADMIN_TOKEN) and pass that instead.",
		);
	}

	throw new Error("ADMIN_READONLY_TOKEN is not set; the expiry check needs it to read the admin API");
}

/**
 * The credential fault a status code most likely means, so an exit-2 run says
 * what to fix instead of only what failed.
 *
 * A 401 here is nearly always the read-only secret existing in Actions but not
 * on the Worker: `adminAuth` skips the second comparison outright when
 * `ADMIN_READONLY_TOKEN` is unset, so a perfectly good repository secret is
 * refused as an invalid bearer. A 403 cannot happen on a `GET` and so means the
 * scope boundary moved. A 500 is the equal-secrets refusal, whose diagnosis the
 * service deliberately keeps out of the response body and in its own log.
 */
function credentialHint(status: number): string {
	if (status === 401) {
		return " — ADMIN_READONLY_TOKEN was refused; check the deployment has it set (`wrangler secret put ADMIN_READONLY_TOKEN`) and that it matches the secret this run was given";
	}
	if (status === 403) {
		return " — the read-only credential was refused the scope for a GET, which should not happen; check adminAuth's READ_ONLY_METHODS";
	}
	if (status === 500) {
		return " — if the deployment's ADMIN_READONLY_TOKEN equals its ADMIN_TOKEN the whole admin surface is refused; the reason is in the Worker log";
	}
	return "";
}

/** GET an admin route, failing loudly rather than reporting a key as healthy */
async function adminFetch(baseUrl: string, route: string, token: string): Promise<Response> {
	const response = await fetch(new URL(route, baseUrl), {
		headers: { Authorization: `Bearer ${token}` },
	});

	if (!response.ok) {
		throw new Error(`GET ${route} failed: ${response.status} ${response.statusText}${credentialHint(response.status)}`);
	}

	return response;
}

/** GET an admin route and parse it as JSON */
async function adminJson<T>(baseUrl: string, route: string, token: string): Promise<T> {
	return (await (await adminFetch(baseUrl, route, token)).json()) as T;
}

/** Append the report to the workflow summary when running under Actions */
async function writeStepSummary(report: string): Promise<void> {
	const summaryPath = process.env.GITHUB_STEP_SUMMARY;
	if (!summaryPath) return;

	const existing = await Bun.file(summaryPath)
		.text()
		.catch(() => "");
	await Bun.write(summaryPath, `${existing}${report}`);
}

/** Emit step outputs so the workflow can branch without re-parsing the report */
async function writeStepOutputs(outputs: Record<string, string>): Promise<void> {
	const outputPath = process.env.GITHUB_OUTPUT;
	if (!outputPath) return;

	// Multiline values need a heredoc delimiter that cannot appear in the value.
	const delimiter = `EOF_${crypto.randomUUID()}`;
	const rendered = Object.entries(outputs)
		.map(([key, value]) =>
			value.includes("\n") ? `${key}<<${delimiter}\n${value}\n${delimiter}\n` : `${key}=${value}\n`,
		)
		.join("");

	const existing = await Bun.file(outputPath)
		.text()
		.catch(() => "");
	await Bun.write(outputPath, `${existing}${rendered}`);
}

/**
 * Every credential that can authorize a signature, from both auth paths.
 *
 * A failure here aborts the run rather than degrading, unlike a single
 * unreadable key: without the grant tables the *scope* of the check is unknown,
 * and a report over a set this script is not sure of is worse than no report.
 * Exit code 2 says "could not run", which is what happened.
 */
async function fetchGrants(serviceUrl: string, adminToken: string): Promise<KeyGrant[]> {
	const [subjects, tokens] = await Promise.all([
		adminJson<SubjectListResponse>(serviceUrl, "/admin/subjects", adminToken),
		adminJson<TokenListResponse>(serviceUrl, "/admin/tokens", adminToken),
	]);

	return [
		...subjects.subjects.map((row): KeyGrant => ({ kind: "oidc-subject", ...row })),
		...tokens.tokens.map((row): KeyGrant => ({ kind: "service-token", ...row })),
	];
}

/** Read one active key's expiry, degrading to an actionable row on failure */
async function inspectKey(
	key: ActiveKey,
	serviceUrl: string,
	adminToken: string,
	now: Date,
	warnDays: number,
): Promise<KeyExpiryRow> {
	if (!key.stored) return missingKeyRow(key);

	// One key the deployment lists but will not serve must not suppress the
	// warnings for every other key, so it becomes an (actionable) `unknown` row
	// instead of aborting the run.
	try {
		const material = await (await adminFetch(serviceUrl, `/admin/keys/${key.keyId}/public`, adminToken)).text();
		return classifyExpiry(key.keyId, await keyMaterialExpiry(material), now, warnDays);
	} catch (error) {
		const reason = error instanceof Error ? error.message : String(error);
		return classifyExpiry(key.keyId, { kind: "unknown", reason }, now, warnDays);
	}
}

async function main(): Promise<number> {
	const serviceUrl = requireEnv("SIGNING_SERVICE_URL");
	const adminToken = readOnlyAdminToken();
	const warnDays = parseWarnDays(process.env.KEY_EXPIRY_WARN_DAYS);
	const env = process.env.WRANGLER_ENV?.trim() || null;
	const now = new Date();

	const wranglerToml = await Bun.file(path.resolve(import.meta.dir, "..", "wrangler.toml")).text();
	const defaultKey = extractDefaultKeyId(wranglerToml, env);
	if (!defaultKey.envExists) {
		throw new Error(`WRANGLER_ENV=${env} names no environment in wrangler.toml`);
	}

	const listed = await adminJson<KeyListResponse>(serviceUrl, "/admin/keys", adminToken);
	const scope = resolveActiveKeys({
		storedKeyIds: listed.keys.map((key) => key.keyId),
		defaultKey,
		grants: await fetchGrants(serviceUrl, adminToken),
		now,
	});

	const rows: KeyExpiryRow[] = [];
	for (const key of scope.keys) {
		rows.push(await inspectKey(key, serviceUrl, adminToken, now, warnDays));
	}

	const report = renderReport(rows, { warnDays, now, serviceUrl, scope });
	const actionable = actionableRows(rows);

	console.log(report);
	await writeStepSummary(report);
	await writeStepOutputs({
		actionable: String(actionable.length > 0),
		"actionable-count": String(actionable.length),
		"monitored-count": String(scope.keys.length),
		report,
	});

	return actionable.length > 0 ? EXIT_ACTIONABLE : 0;
}

try {
	process.exit(await main());
} catch (error) {
	console.error(`Key expiry check could not run: ${error instanceof Error ? error.message : String(error)}`);
	process.exit(EXIT_CANNOT_RUN);
}
