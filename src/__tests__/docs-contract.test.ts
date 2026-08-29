/**
 * The documentation is part of the client interface, so it is tested like one.
 *
 * `error-docs.test.ts` next door asserts that every code has a *section* to land
 * on. This suite asserts that what those sections and the API guide *say* is
 * still true of the code: the statuses, the shape of the examples, and the two
 * places the envelope guarantee has an exception. Each of these was wrong at
 * least once — a prose claim drifts silently, because nothing fails when it
 * stops matching.
 *
 * Read as a contract rather than as a spelling check: every assertion here
 * fails only when a *response* changed and a document did not.
 */

import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import app from "#index";
import { ERROR_CODES, ErrorResponseSchema, RateLimitErrorSchema } from "#schemas/errors";
// Inlined at build time by Vite: the Workers pool has no filesystem, so this is
// the only way a test running inside it can read a document from the repo.
import apiGuide from "../../API.md?raw";
import errorReference from "../../docs/errors.md?raw";
import troubleshooting from "../../docs/troubleshooting.md?raw";

async function request(path: string, options: RequestInit = {}): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(new Request(`https://sign.test${path}`, options), env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

/** Every ```json fence in a document, parsed. */
function jsonExamples(markdown: string): Record<string, unknown>[] {
	return [...markdown.matchAll(/```json\n([\s\S]*?)```/g)]
		.map(([, block]) => JSON.parse(block as string) as unknown)
		.filter((value): value is Record<string, unknown> => typeof value === "object" && value !== null);
}

/**
 * The status API.md's error-code table gives each code.
 *
 * Rows read `| \`CODE\` | \`401\` | … |`.
 */
function statusesFromApiTable(): Map<string, number> {
	const rows = apiGuide.matchAll(/^\|\s*`([A-Z_]+)`\s*\|\s*`(\d{3})`\s*\|/gm);
	return new Map([...rows].map(([, code, status]) => [code as string, Number(status)]));
}

/**
 * The status `docs/errors.md` gives each code.
 *
 * Every section opens `### CODE` and then `**401.** …`, which is the reference's
 * whole convention for stating one.
 */
function statusesFromReference(): Map<string, number> {
	const sections = errorReference.matchAll(/^#{2,4} ([A-Z_]+)\n+\*\*(\d{3})\.\*\*/gm);
	return new Map([...sections].map(([, code, status]) => [code as string, Number(status)]));
}

/** GitHub's heading-to-anchor rule, which is what `/e/:code` and every relative link rely on. */
function slug(heading: string): string {
	return heading
		.toLowerCase()
		.replace(/[^\w\- ]+/g, "")
		.trim()
		.replace(/ +/g, "-");
}

describe("the documented status of every code", () => {
	it("is the one API.md and the error reference both give it", () => {
		const fromApi = statusesFromApiTable();
		const fromReference = statusesFromReference();

		// Sorted so a failure reads as a set difference rather than as an ordering
		// accident: the table's order is editorial and the enum's is historical.
		expect([...fromApi.keys()].sort()).toEqual([...ERROR_CODES].sort());
		expect([...fromReference.keys()].sort()).toEqual([...ERROR_CODES].sort());

		// `KEY_NOT_ALLOWED` was missing from API.md's table entirely while the
		// reference documented it as a 403, which is the shape of drift this
		// catches: one document knows and the other does not.
		for (const code of ERROR_CODES) {
			expect({ code, status: fromApi.get(code) }).toEqual({ code, status: fromReference.get(code) });
		}
	});
});

describe("every error example in the documentation", () => {
	// A caller copies these. An example that would not validate is a caller
	// building a parser against a body the service never sends.
	const documents = {
		"API.md": apiGuide,
		"docs/errors.md": errorReference,
		"docs/troubleshooting.md": troubleshooting,
	};

	for (const [name, markdown] of Object.entries(documents)) {
		it(`is a body ${name} could actually have received`, () => {
			const errors = jsonExamples(markdown).filter((example) => typeof example.code === "string");

			// Guards the guard: a regex that stopped matching would leave this
			// suite passing with nothing to check.
			expect(errors.length).toBeGreaterThan(0);

			for (const example of errors) {
				expect({ code: example.code, isKnown: ERROR_CODES.includes(example.code as never) }).toEqual({
					code: example.code,
					isKnown: true,
				});

				// `errorDocs` stamps this onto every coded body on the way out, so an
				// example without one shows a caller a response the service does not
				// send — and hides the field they are meant to follow.
				expect({ code: example.code, docs: typeof example.docs }).toEqual({
					code: example.code,
					docs: "string",
				});

				const schema = "retryAfter" in example ? RateLimitErrorSchema : ErrorResponseSchema;
				expect(schema.safeParse(example).error?.issues ?? []).toEqual([]);
			}
		});
	}
});

describe("the envelope guarantee's exceptions", () => {
	it("leaves the degraded /health body without a code or a docs link", async () => {
		// The one non-2xx JSON body in the service that is not an error envelope:
		// a HealthResponse reporting a failed check, not a refusal of the request.
		// `errorDocs` has no code to build a link from, so it passes it through —
		// which is why the documents may not promise `docs` on "every error".
		const original = env.KEY_STORAGE.idFromName;
		env.KEY_STORAGE.idFromName = () => {
			throw new Error("Key storage failure");
		};

		try {
			const response = await request("/health");

			expect(response.status).toBe(503);
			const body = await response.json<Record<string, unknown>>();
			expect(body).toMatchObject({ status: "degraded" });
			expect(body).not.toHaveProperty("code");
			expect(body).not.toHaveProperty("docs");
		} finally {
			env.KEY_STORAGE.idFromName = original;
		}
	});

	it("keeps requestId out of the 429 envelope, where the header is the only source", () => {
		// Asserted on the schema because that is what declares the 429 body — the
		// route builds it from `error`, `code` and `retryAfter` and nothing else.
		// `docs/errors.md` and `docs/troubleshooting.md` both tell callers to read
		// `X-Request-ID` here; this is what stops the field appearing without them
		// noticing, and stops the advice going stale if it ever does.
		expect(Object.keys(RateLimitErrorSchema.shape).sort()).toEqual(["code", "docs", "error", "hint", "retryAfter"]);
	});

	it("answers an unrouted path with a docs link and no requestId", async () => {
		// The `mostly` in the envelope table, made concrete. The 404 handler builds
		// its body by hand and does not read the context, so the id reaches the
		// caller on the header alone.
		const response = await request("/no-such-route");

		expect(response.status).toBe(404);
		const body = await response.json<Record<string, unknown>>();
		expect(body.docs).toBe("https://sign.test/e/NOT_FOUND");
		expect(body).not.toHaveProperty("requestId");
		expect(response.headers.get("X-Request-ID")).toMatch(/^[0-9a-f-]{36}$/);
	});
});

describe("relative links into the error reference", () => {
	it("land on a heading that exists", () => {
		// The reference is linked from three documents by anchor, and an anchor is
		// derived from a heading nobody thinks of as an identifier. A renamed
		// section silently 404s every link into it.
		const headings = new Set(
			[...errorReference.matchAll(/^#{1,4} (.+)$/gm)].map(([, heading]) => slug(heading as string)),
		);

		const broken: string[] = [];
		for (const [name, markdown] of Object.entries({
			"API.md": apiGuide,
			"docs/errors.md": errorReference,
			"docs/troubleshooting.md": troubleshooting,
		})) {
			for (const [, anchor] of markdown.matchAll(/\]\((?:\.\.\/)?(?:docs\/)?errors\.md#([\w-]+)\)/g)) {
				if (!headings.has(anchor as string)) {
					broken.push(`${name} -> #${anchor}`);
				}
			}
			// Same-document links, which errors.md uses to cross-reference codes.
			if (name === "docs/errors.md") {
				for (const [, anchor] of markdown.matchAll(/\]\(#([\w-]+)\)/g)) {
					if (!headings.has(anchor as string)) {
						broken.push(`${name} -> #${anchor}`);
					}
				}
			}
		}

		expect(broken).toEqual([]);
	});
});
