/**
 * Every error carries a link to its own documentation, and the link is short.
 *
 * The two halves are tested separately because they fail separately: the
 * middleware is what makes the guarantee universal (a route that forgets still
 * gets a link), and `/e/:code` is what makes the link short enough to survive
 * the CI log it is printed into.
 */

import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import app from "#index";
import { errorDocs } from "#middleware/error-docs";
import { ERROR_CODES } from "#schemas/errors";
import { DEFAULT_ERROR_DOCS_URL, errorDocsTarget, errorDocsUrl, serviceBaseUrl } from "#utils/error-docs";
// The reference itself, so the suite can check that the link each code hands
// out lands somewhere. Vite inlines it at build time, which is the only way to
// read a file from inside the Workers pool.
import errorReference from "../../docs/errors.md?raw";

async function request(path: string, options: RequestInit = {}, overrides?: Partial<Env>): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request(`https://sign.test${path}`, options),
		overrides ? { ...env, ...overrides } : env,
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

async function body<T>(response: Response): Promise<T> {
	return (await response.json()) as T;
}

describe("docs links on error responses", () => {
	it("puts a docs link on an error nobody wrote one for", async () => {
		// The 404 handler builds its body by hand, like most refusal sites in this
		// codebase. That is the point: the guarantee cannot depend on every author
		// remembering a helper.
		const response = await request("/no-such-route");

		expect(response.status).toBe(404);
		expect(await body<{ code: string; docs: string }>(response)).toMatchObject({
			code: "NOT_FOUND",
			docs: "https://sign.test/e/NOT_FOUND",
		});
	});

	it("derives the link from the origin the request arrived on", async () => {
		// So a fresh deployment — including a *.workers.dev preview no static
		// setting could have named — emits working links with nothing configured.
		const response = await request("/sign", { method: "POST", body: "data" });

		expect(response.status).toBe(401);
		expect((await body<{ docs: string }>(response)).docs).toBe("https://sign.test/e/AUTH_MISSING");
	});

	it("prefers SERVICE_BASE_URL when the request cannot name the public origin", async () => {
		// A proxy that terminates TLS under another hostname leaves `c.req.url`
		// pointing at something internal, which is a link nobody can follow.
		const response = await request(
			"/sign",
			{ method: "POST", body: "data" },
			{ SERVICE_BASE_URL: "https://gpg.example/" },
		);

		expect((await body<{ docs: string }>(response)).docs).toBe("https://gpg.example/e/AUTH_MISSING");
	});

	it("roots the link at the configured origin even when the base URL names a path", async () => {
		// `/e/:code` is served from the root, so a base URL of
		// `https://gpg.example/service` must not push the link down a path the
		// deployment does not answer on.
		const response = await request(
			"/sign",
			{ method: "POST", body: "data" },
			{ SERVICE_BASE_URL: "https://gpg.example/service" },
		);

		expect((await body<{ docs: string }>(response)).docs).toBe("https://gpg.example/e/AUTH_MISSING");
	});

	it("leaves successful responses alone", async () => {
		const response = await request("/health");

		expect(await body<{ status: string }>(response)).not.toHaveProperty("docs");
	});

	it("keeps the challenge and the request id that came with the refusal", async () => {
		// The middleware rebuilds the response to add one field. Everything else
		// about it — RFC 9110's mandatory challenge, the id an operator greps for
		// — has to survive that rebuild.
		const response = await request("/sign", { method: "POST", body: "data" });

		expect(response.headers.get("WWW-Authenticate")).toBe('Bearer realm="gpg-signing-service"');
		expect(response.headers.get("X-Request-ID")).toBeTruthy();
		expect((await body<{ requestId: string }>(response)).requestId).toBe(response.headers.get("X-Request-ID"));
	});

	it("keeps the security headers on a rewritten error", async () => {
		// The middleware sits outside `securityHeaders`, so the response it hands
		// back is the one the browser sees. Losing these to a rewrite would be a
		// security regression paid for a documentation link.
		const response = await request("/no-such-route");

		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(response.headers.get("X-Frame-Options")).toBe("DENY");
	});

	it("does not claim a content-length the enlarged body no longer has", async () => {
		// Adding the link grows the body; a carried-over length would truncate it
		// at the client, which is the one way this middleware could corrupt a
		// response rather than improve it.
		const response = await request("/no-such-route");
		const text = await response.text();

		// Asserted as absent rather than as "absent or correct": the middleware
		// deletes the header and nothing puts one back, so a conditional here
		// would be an assertion that never fires — coverage on the summary and
		// nothing underneath it.
		expect(response.headers.get("content-length")).toBeNull();
		expect(JSON.parse(text)).toHaveProperty("docs");
	});
});

describe("the middleware leaves alone what it cannot improve", () => {
	/** A minimal app whose one route answers exactly `response`. */
	function appAnswering(response: Response) {
		return new Hono().use("*", errorDocs).get("/", () => response);
	}

	async function answer(response: Response): Promise<Response> {
		return appAnswering(response).fetch(new Request("https://sign.test/"), env as unknown as Env);
	}

	it("passes through a body that is not JSON despite its header", async () => {
		// An upstream proxy answering an HTML error page under a JSON content
		// type. Rewriting that would replace a readable page with a parse failure.
		const got = await answer(
			new Response("<html>gateway error</html>", {
				status: 502,
				headers: { "content-type": "application/json" },
			}),
		);

		expect(await got.text()).toBe("<html>gateway error</html>");
	});

	it("leaves a foreign code unlinked rather than minting a link that 404s", async () => {
		// The case this describe block exists for: a body this service did not
		// author. An intermediary answering with its own envelope has a `code`,
		// but not one `/e/:code` will honour — and the route refuses it, so a
		// `docs` field here would cost the caller a round trip to discover the
		// documentation does not exist. Nothing else about the response changes.
		const got = await answer(
			new Response(JSON.stringify({ error: "upstream timed out", code: "UPSTREAM_TIMEOUT" }), {
				status: 504,
				headers: { "content-type": "application/json" },
			}),
		);

		expect(await got.json()).toEqual({ error: "upstream timed out", code: "UPSTREAM_TIMEOUT" });

		// The other half of the same claim, stated where it can fail: the route
		// really does refuse that code, so an emitted link would have been dead.
		expect((await request("/e/UPSTREAM_TIMEOUT")).status).toBe(404);
	});

	it("passes through JSON that is not an envelope", async () => {
		for (const payload of ["[]", '"just a string"', "null", "42"]) {
			const got = await answer(new Response(payload, { status: 500, headers: { "content-type": "application/json" } }));

			expect(await got.text()).toBe(payload);
		}
	});

	it("passes through a response with no content type", async () => {
		// Never buffered, never parsed: the type check comes first, so a streamed
		// or typeless body is not read at all.
		// A bodyless refusal carries no content type at all, so there is nothing
		// to inspect and nothing to add.
		const got = await answer(new Response(null, { status: 503 }));

		expect(got.headers.get("content-type")).toBeNull();
		expect(await got.text()).toBe("");
	});

	it("passes through an error body with no code to link to", async () => {
		const got = await answer(
			new Response(JSON.stringify({ error: "something" }), {
				status: 400,
				headers: { "content-type": "application/json" },
			}),
		);

		expect(await got.json()).toEqual({ error: "something" });
	});

	it("does not carry over a content-length the enlarged body has outgrown", async () => {
		// Hono's `c.res` setter merges the *old* response's headers over the new
		// one (context.ts:120), so deleting `content-length` from the Headers this
		// middleware builds is not on its own enough — the stale value comes
		// straight back, and the client truncates the body at it. The upstream
		// bodies this middleware is written to tolerate are exactly the ones that
		// declare a length.
		const payload = JSON.stringify({ error: "upstream said no", code: "SIGN_ERROR" });
		const got = await answer(
			new Response(payload, {
				status: 502,
				headers: {
					"content-type": "application/json",
					"content-length": String(new TextEncoder().encode(payload).length),
				},
			}),
		);

		const declared = got.headers.get("content-length");
		const text = await got.text();

		expect(JSON.parse(text)).toHaveProperty("docs");
		// What the middleware guarantees, stated directly. The disjunction this
		// replaces was satisfied by the `null` arm alone, so it could have gone on
		// passing while the length arm stopped meaning anything.
		expect(declared).toBeNull();
	});

	it("does not overwrite a link a handler chose for itself", async () => {
		// The generic link is a floor, not a ceiling: a handler with somewhere
		// more specific to send the caller keeps it.
		const got = await answer(
			new Response(JSON.stringify({ error: "x", code: "SIGN_ERROR", docs: "https://elsewhere.test/why" }), {
				status: 500,
				headers: { "content-type": "application/json" },
			}),
		);

		expect((await got.json<{ docs: string }>()).docs).toBe("https://elsewhere.test/why");
	});
});

describe("GET /e/:code", () => {
	it("redirects every documented code into the reference", async () => {
		// Every code, not a sample: a code whose link 404s is worse than no link,
		// because the caller spends the trip finding that out.
		for (const code of ERROR_CODES) {
			const response = await request(`/e/${code}`);

			expect(response.status).toBe(302);
			expect(response.headers.get("Location")).toBe(`${DEFAULT_ERROR_DOCS_URL}#${code.toLowerCase()}`);
		}
	});

	it("has a section to land on for every code", () => {
		// A link that 404s is worse than no link: the caller spends the trip to
		// find that out. The redirect derives its anchor by lowercasing the code,
		// and GitHub derives the same anchor from a heading of the code, so a
		// heading per code is the whole contract — and this is what stops a new
		// code shipping without one.
		const missing = ERROR_CODES.filter((code) => !new RegExp(`^#{2,4} ${code}$`, "m").test(errorReference));

		expect(missing).toEqual([]);
	});

	it("accepts the lowercase form somebody retyped from a log", async () => {
		const response = await request("/e/auth_subject_untrusted");

		expect(response.status).toBe(302);
		expect(response.headers.get("Location")).toBe(`${DEFAULT_ERROR_DOCS_URL}#auth_subject_untrusted`);
	});

	it("follows ERROR_DOCS_URL when the docs are hosted elsewhere", async () => {
		const response = await request("/e/SIGN_ERROR", {}, { ERROR_DOCS_URL: "https://docs.example/errors/" });

		expect(response.headers.get("Location")).toBe("https://docs.example/errors#sign_error");
	});

	it("ignores an ERROR_DOCS_URL that is not an absolute http(s) URL", async () => {
		// This value becomes the `Location` of a 302 the service sends, which is a
		// stronger reason to validate it than SERVICE_BASE_URL had — that one only
		// fills a field. Falling back to the default keeps the redirect landing on
		// real documentation.
		for (const bad of ["docs/errors.md", "javascript:alert(1)", "not a url at all"]) {
			const response = await request("/e/SIGN_ERROR", {}, { ERROR_DOCS_URL: bad });

			expect(response.status).toBe(302);
			expect(response.headers.get("Location")).toBe(`${DEFAULT_ERROR_DOCS_URL}#sign_error`);
		}
	});

	it("says an unknown code is unknown instead of landing somewhere plausible", async () => {
		// A silent redirect to the reference's top reads as "the docs don't cover
		// my error", which sends the reader looking for a documentation bug
		// instead of a typo.
		const response = await request("/e/NOPE");

		expect(response.status).toBe(404);
		const payload = await body<{ error: string; hint: string; docs: string }>(response);
		expect(payload.error).toContain("NOPE");
		expect(payload.hint).toContain(DEFAULT_ERROR_DOCS_URL);
		// And it is itself an error response, so the middleware links it too.
		expect(payload.docs).toBe("https://sign.test/e/NOT_FOUND");
	});

	it("needs no credential", async () => {
		// A caller reading a refusal has, by construction, nothing that works.
		const response = await request("/e/AUTH_MISSING");

		expect(response.status).toBe(302);
	});
});

describe("error-docs helpers", () => {
	it("does not double the slash when a base URL carries one", () => {
		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "https://a.test///" }, req: { url: "https://b.test/x" } })).toBe(
			"https://a.test",
		);
		expect(errorDocsUrl({ env: {}, req: { url: "https://b.test/x?y=1" } }, "SIGN_ERROR")).toBe(
			"https://b.test/e/SIGN_ERROR",
		);
	});

	it("ignores a SERVICE_BASE_URL that is not an absolute http(s) URL", () => {
		// `docs` is declared `z.url()` and is the one field a human is invited to
		// click. A relative value would not parse; a `javascript:` one should not
		// be handed to anybody. Falling back to the request keeps the link correct
		// and only loses the pinning, which is the right way round.
		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "gpg.example" }, req: { url: "https://b.test/x" } })).toBe(
			"https://b.test",
		);
		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "javascript:alert(1)" }, req: { url: "https://b.test/x" } })).toBe(
			"https://b.test",
		);
	});

	it("keeps only the origin of a configured base URL", () => {
		// `/e/:code` is mounted at the root of this Worker. A base URL carrying a
		// path would advertise `https://gpg.example/service/e/SIGN_ERROR`, which is
		// a 404 on a deployment routed at `https://gpg.example/e/SIGN_ERROR` — the
		// one failure mode a setting whose whole job is to make the link right
		// cannot have. A query or a fragment is worse still: both would land in the
		// middle of the link, before the code.
		const req = { url: "https://b.test/x" };

		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "https://gpg.example/service" }, req })).toBe(
			"https://gpg.example",
		);
		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "https://gpg.example/service/" }, req })).toBe(
			"https://gpg.example",
		);
		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "https://gpg.example/?tenant=a" }, req })).toBe(
			"https://gpg.example",
		);
		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "https://gpg.example/#top" }, req })).toBe("https://gpg.example");
		expect(errorDocsUrl({ env: { SERVICE_BASE_URL: "https://gpg.example/service?a=1#top" }, req }, "SIGN_ERROR")).toBe(
			"https://gpg.example/e/SIGN_ERROR",
		);
	});

	it("keeps a port, which is part of where the service answers", () => {
		// The trim is to the origin, not to the hostname: a deployment behind
		// `:8787` genuinely serves `/e/<CODE>` there, and dropping the port would
		// break exactly the local and self-hosted setups the setting exists for.
		const req = { url: "https://b.test/x" };

		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "http://localhost:8787/base/" }, req })).toBe(
			"http://localhost:8787",
		);
		expect(errorDocsUrl({ env: { SERVICE_BASE_URL: "http://localhost:8787" }, req }, "SIGN_ERROR")).toBe(
			"http://localhost:8787/e/SIGN_ERROR",
		);
		// The default port for the scheme is not part of the origin, so it goes.
		expect(serviceBaseUrl({ env: { SERVICE_BASE_URL: "https://gpg.example:443/service" }, req })).toBe(
			"https://gpg.example",
		);
	});

	it("points at the reference's top when no code is named", () => {
		expect(errorDocsTarget(undefined)).toBe(DEFAULT_ERROR_DOCS_URL);
		expect(errorDocsTarget({ ERROR_DOCS_URL: "" })).toBe(DEFAULT_ERROR_DOCS_URL);
	});

	it("drops a fragment on ERROR_DOCS_URL rather than appending after it", () => {
		// The anchor is this function's to write. Keeping a configured one emits
		// `#top#sign_error`, which matches no heading, so the browser silently
		// lands on the top of the reference — the reader is told nothing about
		// having missed the section the redirect exists to reach. The path is
		// still kept: that value names a document, unlike SERVICE_BASE_URL.
		expect(errorDocsTarget({ ERROR_DOCS_URL: "https://docs.example/errors#top" }, "SIGN_ERROR")).toBe(
			"https://docs.example/errors#sign_error",
		);
		expect(errorDocsTarget({ ERROR_DOCS_URL: "https://docs.example/errors/#top" }, "SIGN_ERROR")).toBe(
			"https://docs.example/errors#sign_error",
		);
		// A query is not an anchor and survives — it can be what addresses the
		// document at all on a docs host that versions by parameter.
		expect(errorDocsTarget({ ERROR_DOCS_URL: "https://docs.example/errors?v=2" }, "SIGN_ERROR")).toBe(
			"https://docs.example/errors?v=2#sign_error",
		);
		expect(errorDocsTarget({ ERROR_DOCS_URL: "https://docs.example/errors#top" })).toBe("https://docs.example/errors");
	});
});
