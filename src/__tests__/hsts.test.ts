/**
 * The HSTS policy is the one security header this repository cannot prove by
 * testing the app.
 *
 * `middleware.test.ts` asserts that a response out of `app.fetch` carries
 * `max-age=31536000; includeSubDomains; preload`, and it is right — the Worker
 * really does emit that. It is also not evidence of anything a caller sees: a
 * Cloudflare zone with HSTS configured replaces the header at the edge and the
 * response arrives carrying the zone's value as its only
 * `Strict-Transport-Security`. That is issue #133, where the live deployment
 * served 180 days for months while every test here stayed green.
 *
 * So this suite tests the *judgement* applied to a live header, not the header
 * this process produces. `scripts/check-live-hsts.ts` supplies the network half
 * and is deliberately not exercised here: it needs a deployment, and the point
 * of splitting the two is that the decision below can be pinned without one.
 *
 * The case that matters most is `zone override`: exactly the value observed in
 * production, which must be reported as drift on both counts — short window,
 * and a `preload` the list will refuse.
 */

import { describe, expect, it } from "vitest";
import { auditHstsPolicy, HSTS_MAX_AGE, HSTS_POLICY, HSTS_PRELOAD_MIN_MAX_AGE, parseHstsPolicy } from "#utils/hsts";
// Inlined at build time by Vite: the Workers pool has no filesystem, so this is
// the only way a test running inside it can read a document from the repo.
import securityModel from "../../docs/security-model.md?raw";

/** The value the live zone substituted for the Worker's, verbatim (#133). */
const ZONE_OVERRIDE = "max-age=15552000; includeSubDomains; preload";

describe("parseHstsPolicy", () => {
	it("parses the policy the Worker sets", () => {
		expect(parseHstsPolicy(HSTS_POLICY)).toEqual({
			maxAge: HSTS_MAX_AGE,
			includeSubDomains: true,
			preload: true,
		});
	});

	it.each([null, undefined, "", "   "])("returns null for %p", (header) => {
		expect(parseHstsPolicy(header)).toBeNull();
	});

	it("treats directive names as case-insensitive", () => {
		expect(parseHstsPolicy("Max-Age=31536000; IncludeSubDomains; PRELOAD")).toEqual({
			maxAge: HSTS_MAX_AGE,
			includeSubDomains: true,
			preload: true,
		});
	});

	it("accepts the RFC 6797 quoted-string form of max-age", () => {
		expect(parseHstsPolicy('max-age="31536000"')?.maxAge).toBe(HSTS_MAX_AGE);
	});

	it("tolerates surrounding and interior whitespace", () => {
		expect(parseHstsPolicy("  max-age = 600 ;  includeSubDomains  ")).toEqual({
			maxAge: 600,
			includeSubDomains: true,
			preload: false,
		});
	});

	it("ignores directives it does not know", () => {
		expect(parseHstsPolicy("max-age=600; nonsense=1")).toEqual({
			maxAge: 600,
			includeSubDomains: false,
			preload: false,
		});
	});

	it("keeps a real max-age=0, which is a policy and not an absence", () => {
		expect(parseHstsPolicy("max-age=0")?.maxAge).toBe(0);
	});

	it.each([
		["non-numeric", "max-age=forever; includeSubDomains"],
		["negative", "max-age=-1"],
		["fractional", "max-age=1.5"],
		["valueless", "max-age"],
	])("reports an unusable %s max-age as null rather than zero", (_label, header) => {
		expect(parseHstsPolicy(header)?.maxAge).toBeNull();
	});
});

describe("auditHstsPolicy", () => {
	it("passes the policy the Worker sets", () => {
		const audit = auditHstsPolicy(HSTS_POLICY);
		expect(audit.ok).toBe(true);
		expect(audit.matchesIntent).toBe(true);
		expect(audit.findings).toEqual([]);
	});

	it("passes a stronger policy than the Worker's, but does not call it the intended one", () => {
		const audit = auditHstsPolicy("max-age=63072000; includeSubDomains; preload");
		expect(audit.ok).toBe(true);
		expect(audit.matchesIntent).toBe(false);
	});

	it("tolerates whitespace around an otherwise-identical header", () => {
		const audit = auditHstsPolicy(`  ${HSTS_POLICY}  `);
		expect(audit.ok).toBe(true);
		expect(audit.matchesIntent).toBe(true);
	});

	// The negative case this whole file exists for.
	it("flags the live zone override on both counts", () => {
		const audit = auditHstsPolicy(ZONE_OVERRIDE);

		expect(audit.ok).toBe(false);
		expect(audit.matchesIntent).toBe(false);
		expect(audit.observed).toBe(ZONE_OVERRIDE);
		expect(audit.policy).toEqual({ maxAge: 15_552_000, includeSubDomains: true, preload: true });
		expect(audit.findings.map((f) => f.code)).toEqual(["MAX_AGE_BELOW_INTENDED", "PRELOAD_BELOW_FLOOR"]);
		// The messages are what an operator reads out of the probe, so they have
		// to name both numbers rather than say "mismatch".
		expect(audit.findings[0]?.message).toContain("15552000");
		expect(audit.findings[0]?.message).toContain(String(HSTS_MAX_AGE));
		expect(audit.findings[1]?.message).toContain(String(HSTS_PRELOAD_MIN_MAX_AGE));
	});

	it("flags preload under the floor even when max-age is one second short", () => {
		const audit = auditHstsPolicy(`max-age=${HSTS_PRELOAD_MIN_MAX_AGE - 1}; includeSubDomains; preload`);
		expect(audit.findings.map((f) => f.code)).toContain("PRELOAD_BELOW_FLOOR");
	});

	it("does not flag preload when a short policy does not advertise it", () => {
		const audit = auditHstsPolicy("max-age=15552000; includeSubDomains");
		expect(audit.findings.map((f) => f.code)).toEqual(["MAX_AGE_BELOW_INTENDED"]);
	});

	it("flags a missing includeSubDomains", () => {
		const audit = auditHstsPolicy(`max-age=${HSTS_MAX_AGE}; preload`);
		expect(audit.findings.map((f) => f.code)).toEqual(["MISSING_INCLUDE_SUBDOMAINS"]);
	});

	it.each([null, undefined, ""])("reports a missing header (%p) and stops there", (header) => {
		const audit = auditHstsPolicy(header);
		expect(audit.ok).toBe(false);
		expect(audit.observed).toBeNull();
		expect(audit.policy).toBeNull();
		expect(audit.matchesIntent).toBe(false);
		// One finding, not four: an absent header cannot also be missing
		// includeSubDomains, and listing it that way buries the real defect.
		expect(audit.findings.map((f) => f.code)).toEqual(["MISSING_HEADER"]);
	});

	it("reports an unusable max-age, and treats preload over it as inert", () => {
		const audit = auditHstsPolicy("max-age=forever; includeSubDomains; preload");
		expect(audit.findings.map((f) => f.code)).toEqual(["NO_MAX_AGE", "PRELOAD_BELOW_FLOOR"]);
		expect(audit.findings[1]?.message).toContain("absent");
	});
});

describe("the documented edge boundary", () => {
	// docs/security-model.md is where a reader of security.ts is sent when they
	// ask what callers actually receive. #133 was possible because that answer
	// was written down nowhere, so its absence is a test failure.
	it("has a section explaining that a zone can replace the Worker's header", () => {
		expect(securityModel).toContain("## Effective headers at the edge");
		expect(securityModel).toContain("Strict-Transport-Security");
		expect(securityModel).toMatch(/zone[\s\S]{0,200}replaces/i);
	});

	it("names the check that reads the delivered value", () => {
		expect(securityModel).toContain("task verify:hsts");
	});

	it("states the preload floor the Worker's max-age satisfies", () => {
		expect(securityModel).toContain(String(HSTS_PRELOAD_MIN_MAX_AGE));
		expect(securityModel).toContain("hstspreload.org");
	});
});
