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
}

/** What went wrong, in a form a caller can branch on rather than grep for. */
export type HstsFindingCode =
	| "MISSING_HEADER"
	| "NO_MAX_AGE"
	| "MAX_AGE_BELOW_INTENDED"
	| "PRELOAD_BELOW_FLOOR"
	| "MISSING_INCLUDE_SUBDOMAINS";

export interface HstsFinding {
	code: HstsFindingCode;
	message: string;
}

export interface HstsAudit {
	/** True when the observed header carries no findings at all. */
	ok: boolean;
	/** The header as received, `null` when the response carried none. */
	observed: string | null;
	/** The parse, or `null` when there was nothing to parse. */
	policy: HstsPolicy | null;
	/** True only when the observed value is byte-identical to {@link HSTS_POLICY}. */
	matchesIntent: boolean;
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

	const policy: HstsPolicy = { maxAge: null, includeSubDomains: false, preload: false };

	for (const directive of header.split(";")) {
		// Split on the first `=` rather than destructuring `split("=")`, so a
		// value that contains one survives and both halves are known strings.
		const separator = directive.indexOf("=");
		const name = (separator === -1 ? directive : directive.slice(0, separator)).trim().toLowerCase();
		const value = separator === -1 ? "" : directiveValue(directive.slice(separator + 1));

		switch (name) {
			case "max-age": {
				// `Number("")` is 0, so a valueless `max-age` would otherwise parse
				// as the one policy that actively *revokes* HSTS. Guard first.
				const seconds = Number(value);
				if (value !== "" && Number.isInteger(seconds) && seconds >= 0) policy.maxAge = seconds;
				break;
			}
			case "includesubdomains":
				policy.includeSubDomains = true;
				break;
			case "preload":
				policy.preload = true;
				break;
			default:
				break;
		}
	}

	return policy;
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
 * should be.
 */
export function auditHstsPolicy(header: string | null | undefined): HstsAudit {
	const observed = header === null || header === undefined || header.trim() === "" ? null : header.trim();
	const policy = parseHstsPolicy(observed);
	const findings: HstsFinding[] = [];

	if (policy === null) {
		findings.push({
			code: "MISSING_HEADER",
			message: "No Strict-Transport-Security header on the response; the Worker sets one on every route.",
		});
		return { ok: false, observed, policy, matchesIntent: false, findings };
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

	return { ok: findings.length === 0, observed, policy, matchesIntent: observed === HSTS_POLICY, findings };
}
