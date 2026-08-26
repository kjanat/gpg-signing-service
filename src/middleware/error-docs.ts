/**
 * Puts a `docs` link on every error this service answers.
 *
 * Done as a middleware rather than at each `c.json` call site for one reason:
 * "every error" has to survive the next person adding a route. There are two
 * dozen refusal sites across the routes, the auth middlewares, the 404 handler
 * and `onError`, and a helper they are each *supposed* to call is a rule that
 * holds until someone writes `c.json({ error, code }, 400)` from memory — which
 * is what the existing code does everywhere, and what reads naturally. Filling
 * the field in on the way out makes the guarantee structural: a body with a
 * `code` gets a link whether or not its author thought about it.
 *
 * Only JSON bodies at 4xx/5xx that already carry a `code` are touched, so
 * signatures (`text/plain`), armored keys and every success response pass
 * through untouched — including the streamed ones, which are never buffered
 * here because the content-type check comes first.
 */

import type { MiddlewareHandler } from "hono";
import type { Env, Variables } from "#types";
import { HTTP } from "#types";
import { errorDocsUrl } from "#utils/error-docs";

/** Smallest status this middleware considers an error. */
const FIRST_ERROR_STATUS = HTTP.BadRequest;

/** Does this response carry a JSON body? */
function isJson(response: Response): boolean {
	return response.headers.get("content-type")?.includes("application/json") ?? false;
}

export const errorDocs: MiddlewareHandler<{
	Bindings: Env;
	Variables: Variables;
}> = async (c, next) => {
	await next();

	const response = c.res;
	if (response.status < FIRST_ERROR_STATUS || !isJson(response)) {
		return;
	}

	// A body that is not an object, or not JSON at all despite the header, is
	// left exactly as it was. This middleware exists to add a field, never to
	// change what a caller receives beyond that.
	let body: unknown;
	const cloned = response.clone();
	try {
		body = await cloned.json();
	} catch {
		return;
	}

	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		return;
	}

	const envelope = body as Record<string, unknown>;
	// No code, nothing to link to. `docs` already present means a handler had
	// something more specific to say than the code alone; do not overwrite it.
	if (typeof envelope.code !== "string" || !envelope.code || typeof envelope.docs === "string") {
		return;
	}

	// Carried over so nothing else about the response changes — the rate-limit
	// headers on a 429, the `WWW-Authenticate` challenge on a 401. `content-length`
	// is the exception: the body just grew by the length of the link, and a stale
	// value there truncates the response at the client.
	const headers = new Headers(response.headers);
	headers.delete("content-length");

	c.res = new Response(JSON.stringify({ ...envelope, docs: errorDocsUrl(c, envelope.code) }), {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
};
