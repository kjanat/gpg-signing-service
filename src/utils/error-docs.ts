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
 * A link into the repository rather than a docs site: this service is deployed
 * by whoever runs it, and the reference travels with the source. `master`
 * rather than a pinned SHA for the same reason — the reference is meant to move
 * with the code that emits the codes. Durability is the redirect's job, not this
 * value's: only `/e/<CODE>` is ever printed into a log, so this can change
 * without stranding anything already archived. Set `ERROR_DOCS_URL` to point at
 * your own copy.
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
 * static setting would have named.
 *
 * That default is the caller's `Host`, though, and `docs` is the one field in
 * the envelope that a human is invited to click. A request with a forged `Host`
 * gets back a link on a hostname of its sender's choosing. Cloudflare routing
 * constrains which hostnames reach a Worker at all, and the response goes back
 * to the sender that forged it rather than to anyone else — so this is not a
 * way to attack a third party. It is still a wrong link in a log, and
 * `SERVICE_BASE_URL` is the way to make the field say the same thing on every
 * request no matter what arrives in the header. Set it on any deployment with a
 * name of its own; it costs one line in `wrangler.toml`.
 *
 * A configured value that is not an absolute http(s) URL is ignored rather than
 * emitted: `docs` is declared `z.url()` and a relative or `javascript:` value
 * would either fail the schema or ship a link nobody should click. Falling back
 * to the request loses the pinning and keeps the field correct, which is the
 * right way round for a field that only ever advises.
 *
 * Only the origin of a configured value is kept. `/e/:code` is mounted at the
 * root of this Worker, so a `SERVICE_BASE_URL` of `https://gpg.example/service`
 * would advertise `https://gpg.example/service/e/SIGN_ERROR` — a 404 on a
 * deployment whose route is `https://gpg.example/e/SIGN_ERROR`. Trimming to the
 * origin means the setting cannot describe a path the service does not serve,
 * and the same trim disposes of a query or fragment that would otherwise be
 * spliced into the middle of the link. The port survives, because it is part of
 * the origin and a deployment behind one genuinely answers there.
 *
 * @param c - Request context
 * @returns Origin with no trailing slash, e.g. `https://gpg.kajkowalski.nl`
 */
export function serviceBaseUrl(c: DocsContext): string {
	const configured = c.env?.SERVICE_BASE_URL;
	return (configured ? absoluteHttpUrl(configured) : null)?.origin ?? new URL(c.req.url).origin;
}

/** `value` parsed, if it is an absolute `http:` or `https:` URL; otherwise null. */
function absoluteHttpUrl(value: string): URL | null {
	try {
		const parsed = new URL(value);
		return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed : null;
	} catch {
		return null;
	}
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
	// Validated for the same reason SERVICE_BASE_URL is, and with more at stake:
	// that one only fills a field a reader may click, while this one is the
	// `Location` of a 302 the service sends. A relative or non-http(s) value here
	// makes `/e/<CODE>` — the link printed into every error — redirect somewhere
	// no browser should follow. Falling back to the default keeps the redirect
	// landing on real documentation, which is the point of the route.
	const configured = env?.ERROR_DOCS_URL;
	const base = withoutTrailingSlash(configured && absoluteHttpUrl(configured) ? configured : DEFAULT_ERROR_DOCS_URL);
	return code ? `${base}#${code.toLowerCase()}` : base;
}
