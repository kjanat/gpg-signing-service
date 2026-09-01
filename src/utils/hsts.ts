/**
 * The HSTS policy this service intends to serve, and a checker for the one a
 * caller actually receives.
 *
 * Those are two different things, which is the entire reason this file exists.
 * `securityHeaders` sets `Strict-Transport-Security` on every response and
 * `middleware.test.ts` proves that it does — but a Cloudflare zone with **HTTP
 * Strict Transport Security** enabled under SSL/TLS -> Edge Certificates
 * rewrites the header on the way out, and the caller then sees the zone's value
 * with no trace of the Worker's. Issue #133 is exactly that: the Worker asks
 * for a year, every live route answers 180 days, and there is only ever one
 * header on the response, so nothing about the reply hints that a substitution
 * happened.
 *
 * The middleware constant is therefore a statement of intent, not evidence. The
 * delivered policy can only be read off a live response, which is what
 * `auditHstsPolicy` is for: `scripts/check-live-hsts.ts` feeds it the observed
 * header and it names the drift. See
 * [the edge boundary](../../docs/security-model.md#effective-headers-at-the-edge).
 *
 * The audit asks one question — *is the policy in force the Worker's?* — and a
 * header only passes when it is. A **stronger** delivered policy fails too:
 * `max-age=63072000` is not this repository's policy, and a check that let it
 * through would be blind to the substitution class it exists to catch, which is
 * "something between the Worker and the caller rewrote this header", not
 * "someone weakened it". What the audit does not demand is a particular
 * spelling: directive order, casing, whitespace and RFC 6797's quoted-string
 * form all describe the same policy, and all pass.
 */

/** One year in seconds: the `max-age` the Worker asks for. */
export const HSTS_MAX_AGE = 31_536_000;

/**
 * The `max-age` floor that <https://hstspreload.org> enforces on submissions.
 *
 * It happens to equal {@link HSTS_MAX_AGE} today, but it is a separate number
 * with a separate owner: one is this deployment's choice, the other is the
 * list's admission requirement. Below this floor `preload` is inert — it
 * declares an intent the policy cannot support, because the list will refuse
 * the domain.
 */
export const HSTS_PRELOAD_MIN_MAX_AGE = 31_536_000;

/** The exact header value `securityHeaders` sets. */
export const HSTS_POLICY = `max-age=${HSTS_MAX_AGE}; includeSubDomains; preload`;

/** A parsed `Strict-Transport-Security` value. */
export interface HstsPolicy {
	/** Seconds, or `null` when the directive is absent or unparseable. */
	maxAge: number | null;
	includeSubDomains: boolean;
	preload: boolean;
	/**
	 * Lower-cased names that appeared more than once.
	 *
	 * RFC 6797 §6.1 allows each directive at most once and requires a UA to
	 * ignore a header that repeats one, so a non-empty list here means the
	 * *effective* policy is no policy at all, whatever the other fields say.
	 */
	duplicatedDirectives: string[];
	/**
	 * Lower-cased names that are not part of the Worker's policy.
	 *
	 * A UA ignores what it does not recognise, so these do not change the policy
	 * in force — but the Worker sets none of them, so their presence is evidence
	 * the header on the wire was not written by this service.
	 */
	unknownDirectives: string[];
}

/** What went wrong, in a form a caller can branch on rather than grep for. */
export type HstsFindingCode =
	| "MISSING_HEADER"
	| "MULTIPLE_HEADERS"
	| "DUPLICATE_DIRECTIVE"
	| "NO_MAX_AGE"
	| "MAX_AGE_BELOW_INTENDED"
	| "MAX_AGE_ABOVE_INTENDED"
	| "PRELOAD_BELOW_FLOOR"
	| "MISSING_INCLUDE_SUBDOMAINS"
	| "MISSING_PRELOAD"
	| "UNEXPECTED_DIRECTIVE";

export interface HstsFinding {
	code: HstsFindingCode;
	message: string;
}

export interface HstsAudit {
	/**
	 * True when the policy the caller received is the Worker's, in any RFC 6797
	 * spelling of it. Anything else — weaker, stronger, ambiguous, or invalid —
	 * is drift and carries at least one finding.
	 */
	ok: boolean;
	/** The header as received, `null` when the response carried none. */
	observed: string | null;
	/** The parse, or `null` when there was nothing unambiguous to parse. */
	policy: HstsPolicy | null;
	findings: HstsFinding[];
}

/**
 * RFC 6797 lets a directive value be a quoted-string, and Cloudflare's own
 * dashboard writes one unquoted, so both shapes have to survive the parse.
 */
function directiveValue(raw: string): string {
	const trimmed = raw.trim();
	return /^"(.*)"$/.exec(trimmed)?.[1] ?? trimmed;
}

/**
 * Split a header string into the field values it was joined from.
 *
 * `Headers.get` returns repeated headers comma-joined, so `"max-age=31536000;
 * includeSubDomains; preload, max-age=15552000; includeSubDomains; preload"` is
 * what a *fetch* sees when the edge **appends** its policy instead of replacing
 * the Worker's. Nothing in the joined string says how many headers there were,
 * and the two halves state different policies — so the probe has to notice
 * rather than parse the first one and report a single effective policy it
 * cannot actually vouch for.
 *
 * A comma is safe to split on: RFC 6797 directive values are a `token` or a
 * quoted-string, and only the latter may contain one.
 */
export function splitHeaderValues(header: string): string[] {
	const values: string[] = [];
	let current = "";
	let quoted = false;

	for (const character of header) {
		if (character === '"') quoted = !quoted;
		if (character === "," && !quoted) {
			values.push(current);
			current = "";
			continue;
		}
		current += character;
	}
	values.push(current);

	return values.map((value) => value.trim()).filter((value) => value !== "");
}

/**
 * Parse one `Strict-Transport-Security` field value.
 *
 * Total, so the audit never has to reason about a null it has already ruled
 * out; {@link parseHstsPolicy} is the nullable public form.
 */
function parseDirectives(value: string): HstsPolicy {
	const policy: HstsPolicy = {
		maxAge: null,
		includeSubDomains: false,
		preload: false,
		duplicatedDirectives: [],
		unknownDirectives: [],
	};
	const seen = new Set<string>();

	for (const directive of value.split(";")) {
		// Split on the first `=` rather than destructuring `split("=")`, so a
		// value that contains one survives and both halves are known strings.
		const separator = directive.indexOf("=");
		const name = (separator === -1 ? directive : directive.slice(0, separator)).trim().toLowerCase();
		// A trailing or doubled `;` yields an empty name. It is punctuation, not a
		// directive, so it is neither unknown nor a duplicate of the last empty one.
		if (name === "") continue;

		if (seen.has(name)) {
			// First occurrence wins over last, deliberately — but only so the parse
			// is deterministic. A repeated directive voids the whole header under
			// RFC 6797 §6.1, and `auditHstsPolicy` reports that rather than any
			// number read out of it. Last-wins would have been actively misleading:
			// `max-age=300; ...; max-age=31536000` would have been reported as a
			// compliant year on a header no browser accepts at all.
			if (!policy.duplicatedDirectives.includes(name)) policy.duplicatedDirectives.push(name);
			continue;
		}
		seen.add(name);

		const directiveArgument = separator === -1 ? "" : directiveValue(directive.slice(separator + 1));

		switch (name) {
			case "max-age": {
				// RFC 6797 §6.1 spells max-age-value as `1*DIGIT`, and a header that
				// breaks the grammar is one browsers discard whole — no HSTS at all.
				// `Number` is far more generous than that: it reads `0x1E000000`,
				// `1e10` and `+31536000` as perfectly good integers, so an audit
				// built on it would call a policy granting *no* protection stronger
				// than the intended one and pass. Match the grammar, not `Number`.
				// This also covers the valueless `max-age`, where `Number("")` is 0
				// — the one policy that actively revokes HSTS.
				if (/^\d+$/.test(directiveArgument)) policy.maxAge = Number(directiveArgument);
				break;
			}
			case "includesubdomains":
				policy.includeSubDomains = true;
				break;
			case "preload":
				policy.preload = true;
				break;
			default:
				policy.unknownDirectives.push(name);
				break;
		}
	}

	return policy;
}

/**
 * Parse a `Strict-Transport-Security` value, or return `null` when there is
 * none.
 *
 * Directive names are case-insensitive per RFC 6797 §6.1, and a header whose
 * `max-age` is missing or non-numeric is one every browser discards — so that
 * is reported as `maxAge: null` rather than as a zero, which would be a real
 * and very different policy.
 */
export function parseHstsPolicy(header: string | null | undefined): HstsPolicy | null {
	if (header === null || header === undefined || header.trim() === "") return null;
	return parseDirectives(header);
}

/**
 * Compare an observed `Strict-Transport-Security` header against the policy
 * this service intends to serve.
 *
 * `PRELOAD_BELOW_FLOOR` is reported separately from `MAX_AGE_BELOW_INTENDED`
 * even though one live header can raise both, because they are different
 * defects with different fixes. A short `max-age` is a weaker-than-stated
 * protection window; `preload` under the floor is a claim that cannot come
 * true, and it stays false whatever this repository decides its own `max-age`
 * should be. `MAX_AGE_ABOVE_INTENDED` is a third thing again: not a weakness,
 * but proof that the value on the wire is not the one the source sets.
 */
export function auditHstsPolicy(header: string | null | undefined): HstsAudit {
	const observed = header === null || header === undefined || header.trim() === "" ? null : header.trim();
	const findings: HstsFinding[] = [];

	if (observed === null) {
		findings.push({
			code: "MISSING_HEADER",
			message: "No Strict-Transport-Security header on the response; the Worker sets one on every route.",
		});
		return { ok: false, observed, policy: null, findings };
	}

	const values = splitHeaderValues(observed);
	const [single] = values;

	if (single === undefined) {
		findings.push({
			code: "MISSING_HEADER",
			message: `Strict-Transport-Security is ${JSON.stringify(observed)}, which carries no policy at all.`,
		});
		return { ok: false, observed, policy: null, findings };
	}

	if (values.length > 1) {
		findings.push({
			code: "MULTIPLE_HEADERS",
			message:
				`Strict-Transport-Security arrived as ${values.length} comma-joined values (${values.map((value) => JSON.stringify(value)).join(", ")}), ` +
				"so something appended a policy rather than replacing one. RFC 6797 §8.1 says a UA honours the first, but which header was first cannot be read off the joined string, so no single effective policy can be claimed here.",
		});
		return { ok: false, observed, policy: null, findings };
	}

	const policy = parseDirectives(single);

	if (policy.duplicatedDirectives.length > 0) {
		findings.push({
			code: "DUPLICATE_DIRECTIVE",
			message: `${policy.duplicatedDirectives.join(", ")} appears more than once in ${JSON.stringify(observed)}; RFC 6797 §6.1 allows each directive once, so a UA ignores this header entirely and no HSTS is in force.`,
		});
		// Nothing below would be true of a header browsers discard: reporting
		// "max-age below intended" on it would name a window that is not in force.
		return { ok: false, observed, policy, findings };
	}

	if (policy.maxAge === null) {
		findings.push({
			code: "NO_MAX_AGE",
			message: `No usable max-age directive in ${JSON.stringify(observed)}; browsers discard a policy without one.`,
		});
	} else if (policy.maxAge < HSTS_MAX_AGE) {
		findings.push({
			code: "MAX_AGE_BELOW_INTENDED",
			message: `max-age is ${policy.maxAge}s, but the Worker sets ${HSTS_MAX_AGE}s — something between the Worker and the caller replaced the header.`,
		});
	} else if (policy.maxAge > HSTS_MAX_AGE) {
		findings.push({
			code: "MAX_AGE_ABOVE_INTENDED",
			message: `max-age is ${policy.maxAge}s, but the Worker sets ${HSTS_MAX_AGE}s — a longer window is still not this service's policy, so something between the Worker and the caller replaced the header.`,
		});
	}

	if (policy.preload && (policy.maxAge === null || policy.maxAge < HSTS_PRELOAD_MIN_MAX_AGE)) {
		findings.push({
			code: "PRELOAD_BELOW_FLOOR",
			message: `preload is advertised with max-age ${policy.maxAge ?? "absent"}, below the ${HSTS_PRELOAD_MIN_MAX_AGE}s hstspreload.org floor, so the token is inert.`,
		});
	}

	if (!policy.includeSubDomains) {
		findings.push({
			code: "MISSING_INCLUDE_SUBDOMAINS",
			message: "includeSubDomains is absent, but the Worker sets it.",
		});
	}

	if (!policy.preload) {
		findings.push({
			code: "MISSING_PRELOAD",
			message: "preload is absent, but the Worker sets it.",
		});
	}

	if (policy.unknownDirectives.length > 0) {
		findings.push({
			code: "UNEXPECTED_DIRECTIVE",
			message: `${policy.unknownDirectives.join(", ")} is not part of the Worker's policy; a UA ignores it, but the Worker never writes it, so the header was rewritten in transit.`,
		});
	}

	return { ok: findings.length === 0, observed, policy, findings };
}
