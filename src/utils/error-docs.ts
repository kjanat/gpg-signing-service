/**
 * Where an error code is documented, and how a caller gets there.
 *
 * The link on an error is read in the worst place a link can be read: a CI log
 * that wrapped at 80 columns, got truncated by the collapsed-step view, and was
 * then pasted into chat. A 90-character deep link into a README anchor does not
 * survive that trip, and nobody retypes one off a screen. So the field carries
 * the shortest thing that can identify the error — the code itself — and the
 * service redirects:
 *
 *     https://gpg.example/e/AUTH_SUBJECT_UNTRUSTED  ->  docs/errors.md#auth_subject_untrusted
 *
 * Two properties fall out of that. The link stays correct when the docs move,
 * because only `ERROR_DOCS_URL` has to change; and the error code is the only
 * thing in the URL that has to be right, which is the thing the response
 * already got right.
 */

import type { ErrorCode } from "#schemas/errors";

/** Path prefix the short links use. Kept to two characters on purpose. */
export const ERROR_DOC_PREFIX = "/e/";

/**
 * Where `/e/:code` sends a caller when the deployment names no other target.
 *
 * A permalink into the repository rather than a docs site: this service is
 * deployed by whoever runs it, and the reference travels with the source. Set
 * `ERROR_DOCS_URL` to point at your own copy.
 */
export const DEFAULT_ERROR_DOCS_URL = "https://github.com/kjanat/gpg-signing-service/blob/master/docs/errors.md";

/**
 * The parts of a request context these helpers touch.
 *
 * Structural rather than `Context<{ Bindings: Env }>` so the functions compose
 * with any of this app's several context shapes — the OpenAPI router's differs
 * from a bare middleware's in its `Variables` — and so a test can call them
 * with an object literal instead of standing up a Hono context.
 */
export interface DocsContext {
	env?: DocsEnv | undefined;
	req: { url: string };
}

/** Env fields this module reads. Narrower than `Env` so tests can pass a literal. */
export interface DocsEnv {
	/** Public origin of this service, when it differs from what the request saw. */
	SERVICE_BASE_URL?: string;
	/** Document the `/e/:code` links redirect into. */
	ERROR_DOCS_URL?: string;
}

/** Trim any trailing slashes so joins never produce `//`. */
function withoutTrailingSlash(url: string): string {
	return url.replace(/\/+$/, "");
}

/**
 * The origin to build short links from.
 *
 * Derived from the request by default, so a fresh deployment emits working
 * links with nothing configured — including `*.workers.dev` previews, which no
 * static setting would have named. `SERVICE_BASE_URL` overrides it for the case
 * the request cannot answer: a proxy that terminates TLS under a different
 * hostname, where `c.req.url` is the internal one.
 *
 * @param c - Request context
 * @returns Origin with no trailing slash, e.g. `https://gpg.kajkowalski.nl`
 */
export function serviceBaseUrl(c: DocsContext): string {
	const configured = c.env?.SERVICE_BASE_URL;
	if (configured) {
		return withoutTrailingSlash(configured);
	}
	return new URL(c.req.url).origin;
}

/**
 * The short link for one code.
 *
 * @param c - Request context
 * @param code - The code the response carries
 * @returns e.g. `https://gpg.kajkowalski.nl/e/AUTH_SUBJECT_UNTRUSTED`
 */
export function errorDocsUrl(c: DocsContext, code: string): string {
	return `${serviceBaseUrl(c)}${ERROR_DOC_PREFIX}${code}`;
}

/**
 * Where a short link redirects to.
 *
 * The anchor is the code lowercased, which is what a Markdown heading of the
 * code renders as on GitHub — so `docs/errors.md` needs no anchor bookkeeping
 * beyond having a `## AUTH_SUBJECT_UNTRUSTED` heading per code.
 *
 * @param env - Deployment bindings
 * @param code - A documented code, or undefined for the reference's top
 * @returns Absolute URL into the error reference
 */
export function errorDocsTarget(env: DocsEnv | undefined, code?: ErrorCode): string {
	const base = withoutTrailingSlash(env?.ERROR_DOCS_URL || DEFAULT_ERROR_DOCS_URL);
	return code ? `${base}#${code.toLowerCase()}` : base;
}
