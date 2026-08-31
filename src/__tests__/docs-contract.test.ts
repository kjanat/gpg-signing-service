/**
 * The documentation is part of the client interface, so it is tested like one.
 *
 * `error-docs.test.ts` next door asserts that every code has a *section* to land
 * on. This suite asserts that what those sections and the API guide *say* is
 * still true of the code. Each claim below was wrong at least once — a prose
 * claim drifts silently, because nothing fails when it stops matching.
 *
 * What is proven here, and by what:
 *
 * - **The two documents and the enum agree on every status.** API.md's table,
 *   the reference's `**NNN.**` openings and `ERROR_CODES` are compared as sets.
 *   This is document-against-document: it catches one guide knowing a code the
 *   other does not, which is how `KEY_NOT_ALLOWED` went missing from the table.
 *   On its own it proves nothing about runtime — both documents can agree with
 *   each other and with the enum while the handler sends something else.
 * - **…and the codes in `statusProbes` agree with a live response.** Each sends
 *   a real request through the app and asserts the status and `code` that come
 *   back are the ones the reference gives. This is the half that fails when a
 *   *handler* changes rather than a document.
 * - **Every code is on one side of that line deliberately.** `unpinnedStatuses`
 *   names the suite that covers each of the rest, and the partition is
 *   asserted, so a code cannot be added without deciding which side it is on.
 *   The suite names are checked against the files rather than trusted: two of
 *   them were wrong the day they were written, which is this document's own
 *   failure mode wearing a `.ts` extension.
 * - **Every documented error example** parses as the schema it claims to be and
 *   carries a `docs`.
 * - **The envelope's exceptions** — the degraded `/health` body, the 429 and
 *   404 without a `requestId`, the validator's `issues` array — are pinned
 *   against live responses or against the schema that declares the body.
 * - **The shell example's `503` branch** names every code the reference sorts
 *   onto that status. It said there was one; there are two, and they disagree
 *   about carrying a `Retry-After`.
 * - **Every relative anchor** into the reference, from any document that writes
 *   one, lands on a heading that exists.
 *
 * Not proven here: that a code is reachable at all, that a `hint` says what the
 * reference says it says, or that the unpinned statuses are right. Those belong
 * to the route suites, which own the fixtures they need.
 */

import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import app from "#index";
import type { ErrorCode } from "#schemas/errors";
import { ERROR_CODES, ErrorResponseSchema, RateLimitErrorSchema } from "#schemas/errors";
// Inlined at build time by Vite: the Workers pool has no filesystem, so this is
// the only way a test running inside it can read a document from the repo.
import apiGuide from "../../API.md?raw";
import apiOverview from "../../docs/api.md?raw";
import authenticationGuide from "../../docs/authentication.md?raw";
import errorReference from "../../docs/errors.md?raw";
import selfHosting from "../../docs/self-hosting.md?raw";
import troubleshooting from "../../docs/troubleshooting.md?raw";
// The shell example sorts a response by status alone, so its branch comments
// are where a status carrying two codes gets described — or mis-described.
import signCommitExample from "../../examples/bash/sign-commit.sh?raw";
import readme from "../../README.md?raw";

/**
 * Every test file in this directory, keyed by name.
 *
 * Globbed rather than read, for the same reason the documents above are
 * imported: the Workers pool has no filesystem. This is what lets
 * `unpinnedStatuses` name a suite and have the name mean something.
 */
const suites: Record<string, string> = Object.fromEntries(
	Object.entries(import.meta.glob<string>("./*.test.ts", { query: "?raw", import: "default", eager: true })).map(
		([path, source]) => [path.replace(/^\.\//, ""), source],
	),
);

async function request(path: string, options: RequestInit = {}): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(new Request(`https://sign.test${path}`, options), env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

/** An admin request that will be authenticated, so the failure under test is the one asked for. */
function adminRequest(path: string): Promise<Response> {
	return request(path, { headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` } });
}

/**
 * Every ```json fence in a document, parsed.
 *
 * `name` exists for the failure message. An unparseable fence is a broken
 * document rather than a broken test, and a bare `SyntaxError` from
 * `JSON.parse` names neither the document nor the block it came from — which is
 * every fence in three files to search by hand.
 */
function jsonExamples(name: string, markdown: string): Record<string, unknown>[] {
	return [...markdown.matchAll(/```json\n([\s\S]*?)```/g)]
		.map(([, block]) => {
			try {
				return JSON.parse(block as string) as unknown;
			} catch (error) {
				throw new Error(
					`${name}: a \`\`\`json fence does not parse (${error instanceof Error ? error.message : String(error)}).\n${block}`,
					{ cause: error },
				);
			}
		})
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

/**
 * A refusal this suite can provoke with nothing but a request and the admin
 * tokens the test environment already configures — both of them: the scope
 * probe below is refused *because* the bearer it presents is the read-only one.
 *
 * Deliberately cheap. A probe that needed a JWKS mock, a trust row and a stubbed
 * Durable Object would be a second copy of the route suite that owns those
 * fixtures, and it would fail for reasons that have nothing to do with the
 * documentation — which is how a contract test stops being read.
 */
const statusProbes: { code: ErrorCode; what: string; send: () => Promise<Response> }[] = [
	{
		code: "AUTH_MISSING",
		what: "an admin route with no Authorization header",
		send: () => request("/admin/audit"),
	},
	{
		code: "AUTH_INVALID",
		what: "an admin route with a bearer that is not the admin token",
		send: () => request("/admin/audit", { headers: { Authorization: "Bearer not-the-admin-token" } }),
	},
	{
		code: "NOT_FOUND",
		what: "a path no route matches",
		send: () => request("/no-such-route"),
	},
	{
		code: "NOT_FOUND",
		what: "`/e/<CODE>` for a code this service does not define",
		send: () => request("/e/NOPE"),
	},
	{
		code: "KEY_NOT_FOUND",
		what: "`/public-key` for an id nothing is stored under",
		send: () => request("/public-key?keyId=FFFFFFFFFFFFFFFF"),
	},
	{
		code: "INVALID_REQUEST",
		what: "a query the route's schema rejects",
		send: () => adminRequest("/admin/audit?limit=-1"),
	},
	{
		code: "AUTH_SCOPE_INSUFFICIENT",
		what: "a state-changing admin route with the read-only admin bearer",
		// The scope check is in the admin auth middleware, so this is refused
		// before the route touches the key store: no seeded key, no stub, and the
		// id in the path never has to exist.
		send: () =>
			request("/admin/keys/FFFFFFFFFFFFFFFF", {
				method: "DELETE",
				headers: { Authorization: `Bearer ${env.ADMIN_READONLY_TOKEN}` },
			}),
	},
	{
		code: "INTERNAL_ERROR",
		what: "a handler that throws, caught by `app.onError`",
		send: async () => {
			// `/public-key` does not guard the Durable Object lookup, so this reaches
			// the app-level handler rather than a route's own catch — which is the
			// path `INTERNAL_ERROR` documents.
			const original = env.KEY_STORAGE.idFromName;
			env.KEY_STORAGE.idFromName = () => {
				throw new Error("Key storage failure");
			};
			try {
				return await request("/public-key");
			} finally {
				env.KEY_STORAGE.idFromName = original;
			}
		},
	},
];

/**
 * The codes no probe above reaches, and what covers them instead.
 *
 * Each of these needs a fixture — a signed token and a JWKS mock, a trust row in
 * D1, a Durable Object stubbed into failure — that belongs to the suite named
 * beside it. Written out rather than derived so that adding a code to the enum
 * fails this file until someone decides whether it is cheap to reach.
 */
const unpinnedStatuses: Record<string, { suite: string; needs: string }> = {
	AUTH_SUBJECT_UNTRUSTED: { suite: "middleware.test.ts", needs: "a verified token with no trust row" },
	KEY_NOT_ALLOWED: { suite: "sign.test.ts", needs: "a trust row carrying a key allowlist" },
	KEY_PROCESSING_ERROR: { suite: "admin.test.ts", needs: "damaged key material in storage" },
	KEY_LIST_ERROR: { suite: "admin.test.ts", needs: "the key-storage DO stubbed into failure" },
	KEY_UPLOAD_ERROR: { suite: "admin.test.ts", needs: "the key-storage DO stubbed into failure" },
	KEY_DELETE_ERROR: { suite: "admin.test.ts", needs: "the key-storage DO stubbed into failure" },
	SIGN_ERROR: { suite: "sign.test.ts", needs: "a stored key and a signing failure" },
	RATE_LIMITED: { suite: "sign.test.ts", needs: "the limiter stubbed into denial" },
	RATE_LIMIT_ERROR: { suite: "sign.test.ts", needs: "the limiter stubbed into failure" },
	AUDIT_ERROR: { suite: "admin.test.ts", needs: "D1 stubbed into failure" },
	SERVICE_DEGRADED: { suite: "middleware.test.ts", needs: "an unreachable JWKS or store" },
	SERVICE_MISCONFIGURED: { suite: "middleware.test.ts", needs: "an ALLOWED_ISSUERS entry the SSRF guard refuses" },
	PAYLOAD_TOO_LARGE: { suite: "github-webhook.test.ts", needs: "the integration enabled and an oversize delivery" },
};

describe("the status a code actually arrives with", () => {
	const documented = statusesFromReference();

	for (const probe of statusProbes) {
		it(`is the documented ${documented.get(probe.code)} for ${probe.code}: ${probe.what}`, async () => {
			const response = await probe.send();
			const body = await response.json<Record<string, unknown>>();

			// Asserted as one object so a failure names both halves: a handler that
			// changed status and one that changed code look nothing alike to fix.
			expect({ code: body.code, status: response.status }).toEqual({
				code: probe.code,
				status: documented.get(probe.code),
			});
		});
	}

	it("is pinned against a live response, or named as covered elsewhere", () => {
		const pinned = new Set(statusProbes.map((probe) => probe.code));

		expect(ERROR_CODES.filter((code) => !pinned.has(code)).sort()).toEqual(Object.keys(unpinnedStatuses).sort());
	});

	it("names a suite that exists and asserts the code", () => {
		// A pointer at a file is a claim about the code, and an unchecked claim
		// about the code is what this whole suite exists to stop. Three of these
		// were wrong when the map was written — `AUTH_SUBJECT_UNTRUSTED` and
		// `SERVICE_MISCONFIGURED` named a suite that never mentions them, and
		// `AUDIT_ERROR` named one that does not exercise it — and the partition
		// assertion above passed anyway, because it only reads the keys.
		//
		// Substring rather than "asserts the status": the codes here need fixtures
		// this file deliberately does not own, so what is checkable from outside is
		// that the suite named is one that has heard of the code. That is exactly
		// enough to catch a pointer aimed at the wrong file.
		const wrong: string[] = [];
		for (const [code, { suite }] of Object.entries(unpinnedStatuses)) {
			const source = suites[suite];
			if (source === undefined) {
				wrong.push(`${code} -> ${suite} (no such suite in this directory)`);
			} else if (!source.includes(code)) {
				wrong.push(`${code} -> ${suite} (never mentions it)`);
			}
		}

		expect(wrong).toEqual([]);
	});
});

describe("the shell example's 503 branch", () => {
	/** The body of a `case` arm in `sign_commit`'s retry loop, comments included. */
	function branchFor(status: number): string {
		const arm = signCommitExample.match(new RegExp(`\\n\\t+${status}\\)\\n([\\s\\S]*?);;`));
		if (arm === null) throw new Error(`sign-commit.sh has no ${status} branch`);
		return arm[1] as string;
	}

	it("names every code the reference sorts onto a 503", () => {
		// The example branches on status, so one arm can be reached by codes that
		// want different things — and its comment is the only place that says so.
		// It claimed every 503 was SERVICE_DEGRADED and carried a `Retry-After`;
		// RATE_LIMIT_ERROR is the other one and sends neither, which is the whole
		// reason the arm falls back to DEFAULT_RETRY_WAIT.
		//
		// Only the 503 is pinned. The 429 arm has a single code and nothing to get
		// wrong about it, and pinning a comment that has no distinction to draw
		// would be the busywork this suite is trying not to be.
		const branch = branchFor(503);
		const documented = [...statusesFromReference()].filter(([, status]) => status === 503).map(([code]) => code);

		expect(documented.length).toBeGreaterThan(1);
		expect(documented.filter((code) => !branch.includes(code))).toEqual([]);
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
			const errors = jsonExamples(name, markdown).filter((example) => typeof example.code === "string");

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

	it("adds an issues array to a validation 400, and echoes no value in it", async () => {
		// `issues` is the one envelope field a route does not build: the OpenAPI
		// validator's `defaultHook` attaches it. Documented because
		// `docs/troubleshooting.md` sends a reader to `issues[].path` to catch a
		// shell-quoting mistake — advice that needs the array to be there, and
		// needs the *path* rather than the message to be the informative part.
		const response = await adminRequest("/admin/audit?limit=-1");

		expect(response.status).toBe(400);
		const body = await response.json<{ code: string; docs?: string; issues?: Record<string, unknown>[] }>();
		expect(body.code).toBe("INVALID_REQUEST");
		expect(typeof body.docs).toBe("string");
		expect(body.issues?.length).toBeGreaterThan(0);

		for (const issue of body.issues ?? []) {
			expect(Object.keys(issue).sort()).toEqual(expect.arrayContaining(["code", "message", "path"]));
			// Zod drops the offending value from a finalized issue unless
			// `reportInput` is set, and nothing here sets it. That is what makes the
			// array safe to hand back: it names which field failed and what was
			// expected, never what the caller sent. A `keyIds` element that came
			// from an unexpanded shell variable is a path, not a secret.
			expect(issue).not.toHaveProperty("input");
		}
	});
});

describe("relative links into the error reference", () => {
	it("land on a heading that exists", () => {
		// The reference is linked by anchor from every document below, and an
		// anchor is derived from a heading nobody thinks of as an identifier. A
		// renamed section silently 404s every link into it. The set is every
		// document in the repository that writes such a link today, rather than
		// only the ones this PR edited: a link rots the same whichever document
		// holds it, and `self-hosting.md` acquired one on master while this
		// branch was open.
		const headings = new Set(
			[...errorReference.matchAll(/^#{1,4} (.+)$/gm)].map(([, heading]) => slug(heading as string)),
		);

		const broken: string[] = [];
		for (const [name, markdown] of Object.entries({
			"API.md": apiGuide,
			"README.md": readme,
			"docs/api.md": apiOverview,
			"docs/authentication.md": authenticationGuide,
			"docs/errors.md": errorReference,
			"docs/self-hosting.md": selfHosting,
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
