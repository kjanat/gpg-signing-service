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
 * The base URL defaults to $GPG_SIGN_URL, then to the public deployment.
 *
 * Exit codes are distinct on purpose, because two of these are not the same
 * news: `1` is drift — a deployment answered, and the policy it delivered is
 * not the Worker's. `2` is that a probe could not be judged at all (the host
 * was unreachable, or answered in a shape this file does not claim to cover),
 * which is a broken probe run rather than evidence about the header.
 *
 * The judgement itself lives in `#utils/hsts`, where it is unit-tested; this
 * file is only the transport.
 */

import { auditHstsPolicy, HSTS_POLICY } from "#utils/hsts";

/**
 * Whether a probe expects the request to be served or refused.
 *
 * `securityHeaders` runs on the way out of every route, error paths included,
 * so a refusal has to carry the same policy a success does — and the earlier
 * probe set claimed to cover "a refusal" while every path in it returned 200.
 * Asserting the shape keeps the claim honest: if `/sign` ever stops refusing an
 * unauthenticated caller, this file stops pretending it tested that it does.
 */
type ProbeShape = "served" | "refused";

interface Probe {
	method: "GET" | "POST";
	path: string;
	/** What this probe is here to cover, printed so the set explains itself. */
	covers: string;
	expect: ProbeShape;
}

/**
 * Routes chosen to span the response shapes the middleware has to cover: JSON,
 * a document, an HTML page, a plain-text body, an authenticated route's refusal
 * and the not-found handler.
 *
 * The last two are the ones worth explaining. `POST /sign` with no
 * `Authorization` is answered by `callerAuth` before any signing, storage or
 * audit work happens, so it exercises a route-level refusal without touching a
 * key or writing a row; the unrouted path is answered by `app.notFound`, which
 * is the furthest a response can get from a handler and still pass back through
 * `securityHeaders`.
 */
const PROBES: readonly Probe[] = [
	{ method: "GET", path: "/health", covers: "JSON status", expect: "served" },
	{ method: "GET", path: "/doc", covers: "OpenAPI document", expect: "served" },
	{ method: "GET", path: "/ui", covers: "HTML page", expect: "served" },
	{ method: "GET", path: "/public-key", covers: "armoured key body", expect: "served" },
	{ method: "POST", path: "/sign", covers: "unauthenticated refusal", expect: "refused" },
	{ method: "GET", path: "/no-such-route", covers: "not-found handler", expect: "refused" },
] as const;

const DEFAULT_BASE_URL = "https://gpg.kajkowalski.nl";

/** Reads as the response shape a caller got, not as the status class alone. */
function observedShape(status: number): ProbeShape | "unexpected" {
	if (status >= 200 && status < 300) return "served";
	if (status >= 400 && status < 500) return "refused";
	return "unexpected";
}

async function main(): Promise<number> {
	const baseUrl = (process.argv[2] ?? process.env.GPG_SIGN_URL ?? DEFAULT_BASE_URL).replace(/\/+$/, "");

	console.log(`Intended policy: ${HSTS_POLICY}`);
	console.log(`Probing ${baseUrl}\n`);

	let drifted = false;
	let unusable = false;
	// Sequential: six requests, and interleaved output would be unreadable for
	// no gain worth having.
	for (const probe of PROBES) {
		const label = `${probe.method} ${probe.path}`.padEnd(22);
		let response: Response;
		try {
			response = await fetch(`${baseUrl}${probe.path}`, { method: probe.method, redirect: "manual" });
		} catch (error) {
			console.log(`  ${label} UNREACHABLE  ${error instanceof Error ? error.message : String(error)}`);
			unusable = true;
			continue;
		}

		const shape = observedShape(response.status);
		const audit = auditHstsPolicy(response.headers.get("Strict-Transport-Security"));
		console.log(
			`  ${label} ${String(response.status).padEnd(4)} ${audit.ok ? "OK   " : "DRIFT"}  ${audit.observed ?? "(no header)"}`,
		);
		for (const finding of audit.findings) console.log(`    ${finding.code}: ${finding.message}`);

		if (shape !== probe.expect) {
			console.log(
				`    PROBE_SHAPE: this probe covers a ${probe.expect} response (${probe.covers}), but ${probe.path} answered ${response.status}. ` +
					"The set no longer covers what it claims; fix the probe, not the report.",
			);
			unusable = true;
		}
		if (!audit.ok) drifted = true;
	}

	if (drifted) {
		console.error(
			"\nThe delivered policy is not the one this repository sets. Check the" +
				"\nzone's setting at SSL/TLS -> Edge Certificates -> HTTP Strict Transport" +
				"\nSecurity, and any response-header transform rule on the zone. This is an" +
				"\noperator action in the Cloudflare dashboard, not a code change — see" +
				"\ndocs/security-model.md#effective-headers-at-the-edge.",
		);
		return 1;
	}
	if (unusable) {
		console.error(
			"\nNo drift found, but at least one probe could not be judged — see above. Nothing here is evidence yet.",
		);
		return 2;
	}

	console.log("\nEvery probed route delivered the Worker's policy.");
	return 0;
}

process.exit(await main());
