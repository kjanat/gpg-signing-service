#!/usr/bin/env bun
/// <reference types="bun" />

/**
 * Report every active signing key that is at or near expiry.
 *
 * Key IDs are discovered, not declared twice: the live deployment is asked for
 * the keys it actually holds (`GET /admin/keys`), and `wrangler.toml`'s
 * `KEY_ID` vars are cross-checked against that list so a configured key the
 * deployment has lost is reported too. Each key's expiry is then read out of
 * its own material via `GET /admin/keys/{keyId}/public`.
 *
 * Configuration (all environment variables):
 *   SIGNING_SERVICE_URL   Base URL of the deployment to check. Required.
 *   ADMIN_TOKEN           Bearer token for the admin routes. Required.
 *   KEY_EXPIRY_WARN_DAYS  Warn this many days ahead of expiry. Default 60.
 *
 * Exit codes: 0 all clear, 1 one or more keys need attention, 2 the check
 * could not run. The workflow branches on the `actionable` step output rather
 * than the exit code, so a warning does not read as a broken job.
 */

import path from "node:path";
import {
	actionableRows,
	classifyExpiry,
	extractDeclaredKeyIds,
	type KeyExpiryRow,
	keyMaterialExpiry,
	missingKeyRow,
	parseWarnDays,
	renderReport,
} from "#utils/key-expiry";

const EXIT_ACTIONABLE = 1;
const EXIT_CANNOT_RUN = 2;

/** Shape of the `GET /admin/keys` response this script relies on */
interface KeyListResponse {
	keys: { keyId: string }[];
}

function requireEnv(name: string): string {
	const value = process.env[name]?.trim();
	if (!value) {
		throw new Error(`${name} is not set; the expiry check needs it to reach the admin API`);
	}
	return value;
}

/** GET an admin route, failing loudly rather than reporting a key as healthy */
async function adminFetch(baseUrl: string, route: string, token: string): Promise<Response> {
	const response = await fetch(new URL(route, baseUrl), {
		headers: { Authorization: `Bearer ${token}` },
	});

	if (!response.ok) {
		throw new Error(`GET ${route} failed: ${response.status} ${response.statusText}`);
	}

	return response;
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

async function main(): Promise<number> {
	const serviceUrl = requireEnv("SIGNING_SERVICE_URL");
	const adminToken = requireEnv("ADMIN_TOKEN");
	const warnDays = parseWarnDays(process.env.KEY_EXPIRY_WARN_DAYS);
	const now = new Date();

	const wranglerToml = await Bun.file(path.resolve(import.meta.dir, "..", "wrangler.toml")).text();
	const declared = extractDeclaredKeyIds(wranglerToml);

	const listed = (await (await adminFetch(serviceUrl, "/admin/keys", adminToken)).json()) as KeyListResponse;
	const liveKeyIds = listed.keys.map((key) => key.keyId.toUpperCase());

	const rows: KeyExpiryRow[] = [];
	for (const keyId of liveKeyIds) {
		// One key the deployment lists but will not serve must not suppress the
		// warnings for every other key, so it becomes an (actionable) `unknown`
		// row instead of aborting the run.
		try {
			const material = await (await adminFetch(serviceUrl, `/admin/keys/${keyId}/public`, adminToken)).text();
			rows.push(classifyExpiry(keyId, await keyMaterialExpiry(material), now, warnDays));
		} catch (error) {
			rows.push(
				classifyExpiry(
					keyId,
					{ kind: "unknown", reason: error instanceof Error ? error.message : String(error) },
					now,
					warnDays,
				),
			);
		}
	}

	// A key wrangler.toml points the Worker at, that the deployment does not
	// hold, breaks signing just as surely as an expired one.
	for (const keyId of declared) {
		if (!liveKeyIds.includes(keyId)) rows.push(missingKeyRow(keyId));
	}

	const report = renderReport(rows, { warnDays, now, serviceUrl });
	const actionable = actionableRows(rows);

	console.log(report);
	await writeStepSummary(report);
	await writeStepOutputs({
		actionable: String(actionable.length > 0),
		"actionable-count": String(actionable.length),
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
