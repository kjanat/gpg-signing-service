#!/usr/bin/env bun
/**
 * Reads the `Strict-Transport-Security` header a live deployment actually
 * serves and compares it against the policy the Worker sets.
 *
 * This is the one security header no test in `src/__tests__/` can vouch for.
 * Every other one leaves the Worker and arrives unchanged, so asserting it on a
 * `fetch` through the app is the same as asserting it on the wire. HSTS does
 * not: a Cloudflare zone with **HTTP Strict Transport Security** enabled under
 * SSL/TLS -> Edge Certificates rewrites the header at the edge, and the caller
 * receives the zone's value as the response's only `Strict-Transport-Security`.
 * `middleware.test.ts` therefore passes while the delivered policy is something
 * else entirely, which is issue #133 — a year in the source, 180 days on the
 * wire, and no signal anywhere between them.
 *
 * So this runs against a deployment rather than against the app, and it is a
 * probe rather than part of the test suite: it needs the network and a URL, and
 * `task t` has neither. `/verify-live` invokes it; `task verify:hsts` is the
 * hand-run form.
 *
 * Usage:
 *   bun scripts/check-live-hsts.ts [base-url]
 *
 * The base URL defaults to $GPG_SIGN_URL, then to the public deployment. Exits
 * non-zero if any probed route's delivered policy carries a finding, so it can
 * gate. The judgement itself lives in `#utils/hsts`, where it is unit-tested;
 * this file is only the transport.
 */

import { auditHstsPolicy, HSTS_POLICY } from "#utils/hsts";

/** Routes chosen to span the app's response shapes: JSON, a document, an HTML page, and a refusal. */
const PROBE_PATHS = ["/health", "/doc", "/ui", "/public-key"] as const;

const DEFAULT_BASE_URL = "https://gpg.kajkowalski.nl";

async function main(): Promise<number> {
	const baseUrl = (process.argv[2] ?? process.env.GPG_SIGN_URL ?? DEFAULT_BASE_URL).replace(/\/+$/, "");

	console.log(`Intended policy: ${HSTS_POLICY}`);
	console.log(`Probing ${baseUrl}\n`);

	let failed = false;
	// Sequential: four requests, and interleaved output would be unreadable for
	// no gain worth having.
	for (const path of PROBE_PATHS) {
		let header: string | null;
		try {
			const response = await fetch(`${baseUrl}${path}`, { redirect: "manual" });
			header = response.headers.get("Strict-Transport-Security");
		} catch (error) {
			console.log(`  ${path.padEnd(12)} UNREACHABLE  ${error instanceof Error ? error.message : String(error)}`);
			failed = true;
			continue;
		}

		const audit = auditHstsPolicy(header);
		console.log(`  ${path.padEnd(12)} ${audit.ok ? "OK  " : "DRIFT"}  ${audit.observed ?? "(no header)"}`);
		for (const finding of audit.findings) console.log(`    ${finding.code}: ${finding.message}`);
		if (!audit.ok) failed = true;
	}

	if (failed) {
		console.log(
			"\nThe delivered policy is not the one this repository sets. Only one" +
				"\nStrict-Transport-Security header reaches the caller, so a value that is" +
				"\nnot the Worker's was substituted at the edge: check the zone's setting at" +
				"\nSSL/TLS -> Edge Certificates -> HTTP Strict Transport Security. This is an" +
				"\noperator action in the Cloudflare dashboard, not a code change — see" +
				"\ndocs/security-model.md#effective-headers-at-the-edge.",
		);
		return 1;
	}

	console.log("\nDelivered policy matches the Worker's on every probed route.");
	return 0;
}

process.exit(await main());
