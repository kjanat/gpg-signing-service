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
 * and a `preload` the list will refuse. The rest of the negative cases are
 * headers a browser honours differently than a naive parse would, and each one
 * of them fails in the same direction if it is read wrongly: a policy that is
 * not in force reported as one that is.
 */

import { describe, expect, it } from "vitest";
import {
	auditHstsPolicy,
	HSTS_MAX_AGE,
	HSTS_POLICY,
	HSTS_PRELOAD_MIN_MAX_AGE,
	parseHstsPolicy,
	splitHeaderValues,
} from "#utils/hsts";
// Inlined at build time by Vite: the Workers pool has no filesystem, so this is
// the only way a test running inside it can read a document from the repo.
import securityModel from "../../docs/security-model.md?raw";

/** The value the live zone substituted for the Worker's, verbatim (#133). */
const ZONE_OVERRIDE = "max-age=15552000; includeSubDomains; preload";

/** The Worker's policy, parsed: no duplicates, nothing unrecognised. */
const INTENDED_PARSE = {
	maxAge: HSTS_MAX_AGE,
	includeSubDomains: true,
	preload: true,
	duplicatedDirectives: [],
	unknownDirectives: [],
};

describe("parseHstsPolicy", () => {
	it("parses the policy the Worker sets", () => {
		expect(parseHstsPolicy(HSTS_POLICY)).toEqual(INTENDED_PARSE);
	});

	it.each([null, undefined, "", "   "])("returns null for %p", (header) => {
		expect(parseHstsPolicy(header)).toBeNull();
	});

	it("treats directive names as case-insensitive", () => {
		expect(parseHstsPolicy("Max-Age=31536000; IncludeSubDomains; PRELOAD")).toEqual(INTENDED_PARSE);
	});

	it("accepts the RFC 6797 quoted-string form of max-age", () => {
		expect(parseHstsPolicy('max-age="31536000"')?.maxAge).toBe(HSTS_MAX_AGE);
	});

	it("tolerates surrounding and interior whitespace", () => {
		expect(parseHstsPolicy("  max-age = 600 ;  includeSubDomains  ")).toEqual({
			maxAge: 600,
			includeSubDomains: true,
			preload: false,
			duplicatedDirectives: [],
			unknownDirectives: [],
		});
	});

	it("records directives it does not know rather than silently dropping them", () => {
		expect(parseHstsPolicy("max-age=600; nonsense=1")).toEqual({
			maxAge: 600,
			includeSubDomains: false,
			preload: false,
			duplicatedDirectives: [],
			unknownDirectives: ["nonsense"],
		});
	});

	it("does not treat empty directives from stray semicolons as unknown", () => {
		expect(parseHstsPolicy(`;${HSTS_POLICY};;`)).toEqual(INTENDED_PARSE);
	});

	it("keeps a real max-age=0, which is a policy and not an absence", () => {
		expect(parseHstsPolicy("max-age=0")?.maxAge).toBe(0);
	});

	it("names a repeated directive and refuses to let the last one win", () => {
		// Last-wins would report a compliant year here, off a header RFC 6797 §6.1
		// requires a UA to ignore in full.
		const policy = parseHstsPolicy("max-age=300; includeSubDomains; preload; max-age=31536000");
		expect(policy?.maxAge).toBe(300);
		expect(policy?.duplicatedDirectives).toEqual(["max-age"]);
	});

	it("lists a directive repeated three times only once", () => {
		expect(parseHstsPolicy("max-age=1; max-age=2; max-age=3")?.duplicatedDirectives).toEqual(["max-age"]);
	});

	it("names every repeated directive, not only max-age", () => {
		expect(
			parseHstsPolicy("max-age=1; preload; preload; includeSubDomains; includeSubDomains")?.duplicatedDirectives,
		).toEqual(["preload", "includesubdomains"]);
	});

	it.each([
		["non-numeric", "max-age=forever; includeSubDomains"],
		["negative", "max-age=-1"],
		["fractional", "max-age=1.5"],
		["valueless", "max-age"],
		// Everything below is a shape `Number` reads as a large, valid integer and
		// RFC 6797 §6.1's `1*DIGIT` does not. Getting these wrong fails in the one
		// direction that matters: a header no browser honours would be reported as
		// a policy stronger than intended, and the probe would exit 0 on it.
		["hexadecimal", "max-age=0x1E000000; includeSubDomains; preload"],
		["exponent-notation", "max-age=1e10; includeSubDomains; preload"],
		["sign-prefixed", "max-age=+31536000; includeSubDomains; preload"],
	])("reports an unusable %s max-age as null rather than zero", (_label, header) => {
		expect(parseHstsPolicy(header)?.maxAge).toBeNull();
	});

	it("does not let a grammar-breaking max-age pass the audit as a stronger policy", () => {
		// `Number("0x1E000000")` is 503316480 — comfortably over the intended year,
		// so a `Number`-based parse reports no drift at all on a header that in a
		// real browser grants no HSTS whatsoever.
		const audit = auditHstsPolicy("max-age=0x1E000000; includeSubDomains; preload");
		expect(audit.ok).toBe(false);
		expect(audit.findings.map((f) => f.code)).toEqual(["NO_MAX_AGE", "PRELOAD_BELOW_FLOOR"]);
	});
});

describe("splitHeaderValues", () => {
	it("returns one value for a single policy", () => {
		expect(splitHeaderValues(HSTS_POLICY)).toEqual([HSTS_POLICY]);
	});

	it("splits the comma-joined form Headers.get returns for repeated headers", () => {
		expect(splitHeaderValues(`${HSTS_POLICY}, ${ZONE_OVERRIDE}`)).toEqual([HSTS_POLICY, ZONE_OVERRIDE]);
	});

	it("does not split on a comma inside a quoted-string value", () => {
		expect(splitHeaderValues('max-age="31536000"; report="a,b"')).toEqual(['max-age="31536000"; report="a,b"']);
	});

	it("drops empty values, so a stray comma is not a second policy", () => {
		expect(splitHeaderValues(`${HSTS_POLICY},`)).toEqual([HSTS_POLICY]);
	});
});

describe("auditHstsPolicy", () => {
	it("passes the policy the Worker sets", () => {
		const audit = auditHstsPolicy(HSTS_POLICY);
		expect(audit.ok).toBe(true);
		expect(audit.findings).toEqual([]);
	});

	// The audit is about the policy in force, not about how it was typed. Every
	// spelling below is the Worker's policy under RFC 6797 and must pass, or the
	// probe would report drift on a deployment that has none.
	it.each([
		["reordered directives", "preload; includeSubDomains; max-age=31536000"],
		["upper-cased directive names", "MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD"],
		["a quoted max-age", 'max-age="31536000"; includeSubDomains; preload'],
		["comma-free padding and stray semicolons", "  max-age = 31536000 ;; includeSubDomains ; preload ; "],
	])("passes an RFC-equivalent spelling: %s", (_label, header) => {
		const audit = auditHstsPolicy(header);
		expect(audit.findings).toEqual([]);
		expect(audit.ok).toBe(true);
	});

	it("tolerates whitespace around an otherwise-identical header", () => {
		expect(auditHstsPolicy(`  ${HSTS_POLICY}  `).ok).toBe(true);
	});

	// The gap this repair pass closes: `ok` answers "is the policy in force the
	// Worker's?", and a two-year window is not. A check that passed this would be
	// blind to the whole substitution class — a zone transform rule can write
	// any value, not only a weaker one.
	it("reports a stronger-but-different policy as drift", () => {
		const audit = auditHstsPolicy("max-age=63072000; includeSubDomains; preload");
		expect(audit.ok).toBe(false);
		expect(audit.findings.map((f) => f.code)).toEqual(["MAX_AGE_ABOVE_INTENDED"]);
		expect(audit.findings[0]?.message).toContain("63072000");
		expect(audit.findings[0]?.message).toContain(String(HSTS_MAX_AGE));
	});

	it("reports a policy one second longer than intended, so the boundary is not open", () => {
		const audit = auditHstsPolicy(`max-age=${HSTS_MAX_AGE + 1}; includeSubDomains; preload`);
		expect(audit.findings.map((f) => f.code)).toEqual(["MAX_AGE_ABOVE_INTENDED"]);
	});

	// The negative case this whole file exists for.
	it("flags the live zone override on both counts", () => {
		const audit = auditHstsPolicy(ZONE_OVERRIDE);

		expect(audit.ok).toBe(false);
		expect(audit.observed).toBe(ZONE_OVERRIDE);
		expect(audit.policy).toEqual({
			maxAge: 15_552_000,
			includeSubDomains: true,
			preload: true,
			duplicatedDirectives: [],
			unknownDirectives: [],
		});
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
		expect(audit.findings.map((f) => f.code)).toEqual(["MAX_AGE_BELOW_INTENDED", "MISSING_PRELOAD"]);
	});

	it("flags a missing includeSubDomains", () => {
		const audit = auditHstsPolicy(`max-age=${HSTS_MAX_AGE}; preload`);
		expect(audit.findings.map((f) => f.code)).toEqual(["MISSING_INCLUDE_SUBDOMAINS"]);
	});

	it("flags a dropped preload, which the Worker sets on every response", () => {
		const audit = auditHstsPolicy(`max-age=${HSTS_MAX_AGE}; includeSubDomains`);
		expect(audit.ok).toBe(false);
		expect(audit.findings.map((f) => f.code)).toEqual(["MISSING_PRELOAD"]);
	});

	it("flags a directive the Worker never writes, however harmless a UA finds it", () => {
		const audit = auditHstsPolicy(`${HSTS_POLICY}; report-uri="https://example.test"`);
		expect(audit.ok).toBe(false);
		expect(audit.findings.map((f) => f.code)).toEqual(["UNEXPECTED_DIRECTIVE"]);
		expect(audit.findings[0]?.message).toContain("report-uri");
	});

	it.each([null, undefined, ""])("reports a missing header (%p) and stops there", (header) => {
		const audit = auditHstsPolicy(header);
		expect(audit.ok).toBe(false);
		expect(audit.observed).toBeNull();
		expect(audit.policy).toBeNull();
		// One finding, not four: an absent header cannot also be missing
		// includeSubDomains, and listing it that way buries the real defect.
		expect(audit.findings.map((f) => f.code)).toEqual(["MISSING_HEADER"]);
	});

	it("reports a header that is punctuation only as carrying no policy", () => {
		const audit = auditHstsPolicy(", ,");
		expect(audit.ok).toBe(false);
		expect(audit.policy).toBeNull();
		expect(audit.findings.map((f) => f.code)).toEqual(["MISSING_HEADER"]);
	});

	it("reports an unusable max-age, and treats preload over it as inert", () => {
		const audit = auditHstsPolicy("max-age=forever; includeSubDomains; preload");
		expect(audit.findings.map((f) => f.code)).toEqual(["NO_MAX_AGE", "PRELOAD_BELOW_FLOOR"]);
		expect(audit.findings[1]?.message).toContain("absent");
	});

	describe("a repeated directive", () => {
		// RFC 6797 §6.1 permits each directive once and requires a UA to ignore a
		// header that repeats one, so the effective policy is *no* policy — which
		// is the worst outcome the probe can be handed and the easiest to misread
		// as the best one.
		it("fails the audit rather than reporting the later value", () => {
			const audit = auditHstsPolicy("max-age=300; includeSubDomains; preload; max-age=31536000");
			expect(audit.ok).toBe(false);
			expect(audit.findings.map((f) => f.code)).toEqual(["DUPLICATE_DIRECTIVE"]);
			expect(audit.findings[0]?.message).toContain("max-age");
		});

		it("fails even when every value in it is the intended one", () => {
			const audit = auditHstsPolicy(`${HSTS_POLICY}; max-age=${HSTS_MAX_AGE}`);
			expect(audit.ok).toBe(false);
			expect(audit.findings.map((f) => f.code)).toEqual(["DUPLICATE_DIRECTIVE"]);
		});

		it("does not also report findings about a window that is not in force", () => {
			// A weaker duplicate could raise MAX_AGE_BELOW_INTENDED as well; naming
			// a protection window on a header browsers discard would be false.
			const audit = auditHstsPolicy("max-age=300; max-age=300; includeSubDomains; preload");
			expect(audit.findings.map((f) => f.code)).toEqual(["DUPLICATE_DIRECTIVE"]);
		});
	});

	describe("more than one header on the response", () => {
		// `Headers.get` joins repeated headers with a comma, so this is exactly
		// what a probe sees when the edge *appends* its policy instead of
		// replacing the Worker's — the case the previous parse read as one policy
		// with a directive named `preload, max-age=15552000`, and passed.
		it("refuses to claim an effective policy from the appended zone override", () => {
			const audit = auditHstsPolicy(`${HSTS_POLICY}, ${ZONE_OVERRIDE}`);
			expect(audit.ok).toBe(false);
			expect(audit.policy).toBeNull();
			expect(audit.findings.map((f) => f.code)).toEqual(["MULTIPLE_HEADERS"]);
			expect(audit.findings[0]?.message).toContain(ZONE_OVERRIDE);
		});

		it("refuses even when both values are the intended policy", () => {
			// Identical values still mean two headers, which the Worker never sends.
			const audit = auditHstsPolicy(`${HSTS_POLICY}, ${HSTS_POLICY}`);
			expect(audit.ok).toBe(false);
			expect(audit.findings.map((f) => f.code)).toEqual(["MULTIPLE_HEADERS"]);
		});

		it("refuses when the Worker's policy is the second value rather than the first", () => {
			const audit = auditHstsPolicy(`${ZONE_OVERRIDE}, ${HSTS_POLICY}`);
			expect(audit.ok).toBe(false);
			expect(audit.findings.map((f) => f.code)).toEqual(["MULTIPLE_HEADERS"]);
		});
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

	it("says that a stronger delivered policy is drift too", () => {
		// The one thing a reader could otherwise reasonably assume the check does
		// not do, and the reason `ok` is not "no weaker than intended".
		expect(securityModel).toMatch(/stronger[\s\S]{0,400}drift/i);
	});
});
