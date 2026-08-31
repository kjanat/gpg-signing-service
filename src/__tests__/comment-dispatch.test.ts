/**
 * The entrypoint that starts an agent, and the ways starting one must not be
 * causable.
 *
 * Every earlier webhook slice either refused or acted on the repository itself.
 * This one acts *outside* the service: it starts an Actions run holding
 * `contents: write`, `id-token: write` and every repository secret. So the
 * suite is written against the ways that goes wrong, and four of them would
 * pass a confirmatory test:
 *
 * - **A handler that authorized nobody would look perfect while the owner
 *   tested it.** So the happy path is asserted alongside a read-only
 *   collaborator, an outside account, a lookup that 403s and a lookup that
 *   answers about somebody else — all through the same endpoint, all required
 *   to start nothing.
 * - **A handler that took the repository from the payload would ask GitHub the
 *   right question about the wrong repository.** So the fetch stub *refuses*
 *   every path outside the authorized one, and the cross-repository tests name
 *   a different repository in the payload than the allowlist pairs.
 * - **A handler that committed the delivery id after dispatching would look
 *   correct until a response was lost.** So the ambiguous outcomes are asserted
 *   by redelivering them and requiring that nothing is dispatched a second
 *   time, and the definitely-refused one by redelivering it and requiring that
 *   something is.
 * - **A loop check written against the comment's text would pass every test
 *   that did not write the loop.** So the bot cases are the exact payload shape
 *   the dispatched session's own completion comment produces.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import { dispatchBudgetIdentity } from "#routes/github-webhook";
import type { WebhookAuthorization } from "#types";
import {
	authorizeActor,
	commentDispatchEnabled,
	dispatchCommentRequest,
	planCommentDispatch,
	requireDispatchTarget,
	TRIGGER_PHRASE,
} from "#utils/comment-dispatch";
import { GITHUB_API_ORIGIN, GitHubAppError } from "#utils/github-app";
import { RepositoryClient } from "#utils/github-repo";
import { SIGNATURE_PREFIX } from "#utils/github-webhook";

const SECRET = "test-webhook-secret";
const INSTALLATION = 12_345_678;
const REPOSITORY = "kjanat/gpg-signing-service";
const OTHER_REPOSITORY = "kjanat/other-repo";
const OWNER = "kjanat";
const WORKFLOW = "claude.yml";
const REF = "master";

/**
 * A real RSA key for the App, so the token exchange mints a real JWT.
 *
 * Generated once rather than pinned: what is under test is the path, not the
 * key, and a private key checked into a test file is a private key checked into
 * a repository. Minted at the top level because the unit suites build a
 * `RepositoryClient` too, and `getInstallationToken` imports the key before it
 * ever reaches the stubbed `fetch`.
 */
let APP_PRIVATE_KEY = "";

beforeAll(async () => {
	APP_PRIVATE_KEY = await generateAppKey();
});

/** A `<installation, repository>` grant, as the allowlist would resolve one. */
function grant(repository = REPOSITORY): WebhookAuthorization {
	return { scope: "repository", installationId: INSTALLATION, repository, keyId: null };
}

// ---------------------------------------------------------------------------
// Reading the payload
// ---------------------------------------------------------------------------

/** An `issue_comment` delivery, as GitHub sends one. */
function commentPayload(
	overrides: {
		action?: string;
		body?: unknown;
		commentId?: unknown;
		issueNumber?: unknown;
		author?: unknown;
		sender?: unknown;
		viaApp?: unknown;
		pullRequest?: boolean;
		repository?: string;
	} = {},
) {
	const author = "author" in overrides ? overrides.author : { login: OWNER, type: "User" };

	return {
		action: overrides.action ?? "created",
		issue: {
			number: "issueNumber" in overrides ? overrides.issueNumber : 26,
			...(overrides.pullRequest ? { pull_request: { url: "https://api.github.com/x" } } : {}),
		},
		comment: {
			id: "commentId" in overrides ? overrides.commentId : 5_479_945_207,
			body: "body" in overrides ? overrides.body : "@claude please do the thing",
			user: author,
			...("viaApp" in overrides ? { performed_via_github_app: overrides.viaApp } : {}),
		},
		sender: "sender" in overrides ? overrides.sender : author,
		installation: { id: INSTALLATION },
		repository: { full_name: overrides.repository ?? REPOSITORY },
	};
}

describe("planCommentDispatch", () => {
	it("reads a new comment that invokes the phrase", () => {
		const plan = planCommentDispatch(commentPayload());

		expect(plan).toEqual({
			act: true,
			plan: { issueNumber: 26, commentId: 5_479_945_207, actor: OWNER, isPullRequest: false },
		});
	});

	it("marks a comment on a pull request as one", () => {
		const plan = planCommentDispatch(commentPayload({ pullRequest: true }));

		expect(plan.act && plan.plan.isPullRequest).toBe(true);
	});

	it.each(["edited", "deleted"])("refuses a %s comment", (action) => {
		// The sharp one. An `edited` delivery is a comment somebody changed, and
		// accepting it would mean a year-old comment can be edited into a fresh
		// request — and edited again, each edit a new delivery id the replay ledger
		// has no reason to refuse.
		expect(planCommentDispatch(commentPayload({ action }))).toEqual({ act: false, reason: "not_created" });
	});

	it("refuses a comment without the phrase", () => {
		expect(planCommentDispatch(commentPayload({ body: "looks good to me" }))).toEqual({
			act: false,
			reason: "no_trigger_phrase",
		});
	});

	it("accepts the phrase in any case, matching the entrypoint it replaces", () => {
		// GitHub expression `contains()` folds case and the harness greps with -i.
		// A dispatch path that were stricter would silently drop requests the old
		// trigger accepted.
		expect(planCommentDispatch(commentPayload({ body: "@CLAUDE do it" })).act).toBe(true);
		expect(TRIGGER_PHRASE).toBe("@claude");
	});

	it("refuses a comment written by a bot", () => {
		// The exact shape the dispatched session's own completion comment has. This
		// is the loop, and it is caught on the identity GitHub attaches rather than
		// on anything the body says.
		const bot = { login: "claude", type: "Bot" };

		expect(planCommentDispatch(commentPayload({ author: bot, sender: bot }))).toEqual({
			act: false,
			reason: "actor_is_not_human",
		});
	});

	it("refuses a comment whose sender is a bot even when the author looks human", () => {
		expect(planCommentDispatch(commentPayload({ sender: { login: "some-app", type: "Bot" } })).act).toBe(false);
	});

	it("refuses a comment posted through a GitHub App", () => {
		expect(planCommentDispatch(commentPayload({ viaApp: { id: 42, slug: "some-app" } }))).toEqual({
			act: false,
			reason: "actor_is_not_human",
		});
	});

	it("accepts a comment whose performed_via_github_app is explicitly null", () => {
		// Which is what GitHub sends for an ordinary web-UI comment. Refusing null
		// as well would refuse every real request.
		expect(planCommentDispatch(commentPayload({ viaApp: null })).act).toBe(true);
	});

	it("refuses when the sender is not the comment's author", () => {
		expect(planCommentDispatch(commentPayload({ sender: { login: "someone-else", type: "User" } }))).toEqual({
			act: false,
			reason: "unreadable_actor",
		});
	});

	it("accepts a sender spelled with different case than the author", () => {
		expect(planCommentDispatch(commentPayload({ sender: { login: "KJANAT", type: "User" } })).act).toBe(true);
	});

	it.each([
		["a missing type", { login: OWNER }],
		["a login with a slash", { login: "kjanat/x", type: "User" }],
		["a login that is not a string", { login: 7, type: "User" }],
		["an empty login", { login: "", type: "User" }],
		["a login starting with a hyphen", { login: "-kjanat", type: "User" }],
		["a login over 39 characters", { login: "a".repeat(40), type: "User" }],
		["a non-object", "kjanat"],
		["null", null],
	])("refuses %s as an actor", (_label, author) => {
		expect(planCommentDispatch(commentPayload({ author, sender: author })).act).toBe(false);
	});

	it.each([
		["a missing issue number", { issueNumber: undefined as unknown as number }],
		["a zero issue number", { issueNumber: 0 }],
		["a negative issue number", { issueNumber: -1 }],
		["a string issue number", { issueNumber: "26" }],
		["a fractional comment id", { commentId: 1.5 }],
		["a body that is not a string", { body: 42 }],
	])("refuses %s", (_label, overrides) => {
		expect(planCommentDispatch(commentPayload(overrides)).act).toBe(false);
	});

	it.each([undefined, null, "a string", [], {}, { action: "created" }])("refuses the payload %s", (payload) => {
		expect(planCommentDispatch(payload).act).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// The configured target
// ---------------------------------------------------------------------------

describe("requireDispatchTarget", () => {
	it("returns the operator's workflow and ref", () => {
		expect(
			requireDispatchTarget({ GITHUB_APP_DISPATCH_WORKFLOW: " claude.yml ", GITHUB_APP_DISPATCH_REF: " master " }),
		).toEqual({ workflow: WORKFLOW, ref: REF });
	});

	it.each([
		["neither set", {}],
		["only the workflow", { GITHUB_APP_DISPATCH_WORKFLOW: WORKFLOW }],
		["only the ref", { GITHUB_APP_DISPATCH_REF: REF }],
		["an empty workflow", { GITHUB_APP_DISPATCH_WORKFLOW: "  ", GITHUB_APP_DISPATCH_REF: REF }],
	])("refuses %s as misconfigured", (_label, config) => {
		// No default, deliberately: a default workflow would be this service picking
		// which of somebody's workflows a comment may start.
		let thrown: unknown;
		try {
			requireDispatchTarget(config);
		} catch (error) {
			thrown = error;
		}

		expect(thrown).toBeInstanceOf(GitHubAppError);
		expect((thrown as GitHubAppError).misconfigured).toBe(true);
	});

	it.each(["../../etc/passwd", ".github/workflows/claude.yml", "claude", "claude.txt", "-claude.yml", "claude.yml/x"])(
		"refuses %s as a workflow name",
		(workflow) => {
			expect(() =>
				requireDispatchTarget({ GITHUB_APP_DISPATCH_WORKFLOW: workflow, GITHUB_APP_DISPATCH_REF: REF }),
			).toThrow(GitHubAppError);
		},
	);

	it.each(["claude.yml", "claude.yaml", "claude-agent.yml", "claude_agent.yml"])("accepts %s", (workflow) => {
		expect(
			requireDispatchTarget({ GITHUB_APP_DISPATCH_WORKFLOW: workflow, GITHUB_APP_DISPATCH_REF: REF }).workflow,
		).toBe(workflow);
	});

	it.each(["--upload-pack=x", "refs/heads/../x", "", "a b"])("refuses %s as a ref", (ref) => {
		expect(() =>
			requireDispatchTarget({ GITHUB_APP_DISPATCH_WORKFLOW: WORKFLOW, GITHUB_APP_DISPATCH_REF: ref }),
		).toThrow(GitHubAppError);
	});

	it.each(["master", "main", "release/2026-08", "v1.2.3"])("accepts %s as a ref", (ref) => {
		expect(requireDispatchTarget({ GITHUB_APP_DISPATCH_WORKFLOW: WORKFLOW, GITHUB_APP_DISPATCH_REF: ref }).ref).toBe(
			ref,
		);
	});
});

describe("commentDispatchEnabled", () => {
	it.each([undefined, "false", "1", "yes", "TRUE", "True", " true"])("stays off for %s", (value) => {
		expect(commentDispatchEnabled(value === undefined ? {} : { GITHUB_APP_COMMENT_DISPATCH: value })).toBe(false);
	});

	it("is on for exactly true", () => {
		expect(commentDispatchEnabled({ GITHUB_APP_COMMENT_DISPATCH: "true" })).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Authorizing the actor against GitHub
// ---------------------------------------------------------------------------

/** A client bound to the authorized pair, over a stubbed `fetch`. */
function clientOver(handler: (request: Request) => Response | Promise<Response>): RepositoryClient {
	vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
		const request = new Request(input as RequestInfo, init as RequestInit);
		const url = new URL(request.url);

		if (url.pathname.endsWith("/access_tokens")) {
			return Promise.resolve(
				Response.json({ token: "ghs_installation_token", expires_at: new Date(Date.now() + 3_600_000).toISOString() }),
			);
		}

		return Promise.resolve(handler(request)) as Promise<Response>;
	});

	return RepositoryClient.forAuthorization(appEnv(), grant()) as RepositoryClient;
}

/** The bindings an acting delivery needs, with the App credentials populated. */
function appEnv(overrides: Record<string, unknown> = {}) {
	return { ...env, ...enabled(`${INSTALLATION}:${REPOSITORY}`), ...overrides } as typeof env;
}

describe("authorizeActor", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	it.each(["admin", "write"])("allows %s", async (permission) => {
		const client = clientOver(() => Response.json({ permission, user: { login: OWNER } }));

		await expect(authorizeActor(client, OWNER)).resolves.toEqual({ allowed: true, permission });
	});

	it.each(["read", "none", "triage", "maintain", "WRITE", "admin,write"])("refuses %s", async (permission) => {
		// `read` covers triage and `write` covers maintain in this field's legacy
		// vocabulary, so a literal `maintain` or `triage` is a value GitHub does not
		// send here — and an unrecognised value is not a grant, because mapping an
		// unknown role onto the permissive side is how a new role name silently
		// becomes write access. `WRITE` pins that the comparison is not case-folded
		// into a yes, and `admin,write` that it is not a substring test.
		const client = clientOver(() => Response.json({ permission, user: { login: OWNER } }));

		await expect(authorizeActor(client, OWNER)).resolves.toEqual({
			allowed: false,
			reason: "actor_not_permitted",
			status: null,
		});
	});

	it("refuses a login GitHub has never heard of", async () => {
		// 404 is the ordinary answer for everybody who has ever commented on a
		// public repository, so it is `none` rather than an error.
		const client = clientOver(() => new Response("{}", { status: 404 }));

		await expect(authorizeActor(client, "a-stranger")).resolves.toMatchObject({
			allowed: false,
			reason: "actor_not_permitted",
		});
	});

	it("fails closed when the installation may not read collaborators", async () => {
		const client = clientOver(() => new Response("{}", { status: 403 }));

		await expect(authorizeActor(client, OWNER)).resolves.toEqual({
			allowed: false,
			reason: "permission_lookup_failed",
			status: 403,
		});
	});

	it("fails closed on an answer about a different user", async () => {
		// A renamed account, a redirect, anything. An answer about somebody else is
		// not an answer, and taking it would authorize this comment with another
		// account's access.
		const client = clientOver(() => Response.json({ permission: "admin", user: { login: "someone-else" } }));

		await expect(authorizeActor(client, OWNER)).resolves.toMatchObject({
			allowed: false,
			reason: "permission_lookup_failed",
		});
	});

	it("allows an answer whose login differs only in case", async () => {
		const client = clientOver(() => Response.json({ permission: "admin", user: { login: "KJanat" } }));

		await expect(authorizeActor(client, OWNER)).resolves.toMatchObject({ allowed: true });
	});

	it.each([
		["no permission field", { role_name: "maintain" }],
		["an empty permission", { permission: "", user: { login: OWNER } }],
		["a permission that is not a string", { permission: 7, user: { login: OWNER } }],
	])("fails closed on %s", async (_label, answer) => {
		// An answer this service cannot read is not an answer, and reading it as
		// "no permission, carry on" would be carrying on past the gate.
		const client = clientOver(() => Response.json(answer));

		await expect(authorizeActor(client, OWNER)).resolves.toMatchObject({ reason: "permission_lookup_failed" });
	});

	it("asks about the authorized repository and nothing else", async () => {
		const paths: string[] = [];
		const client = clientOver((request) => {
			paths.push(new URL(request.url).pathname);
			return Response.json({ permission: "admin", user: { login: OWNER } });
		});

		await authorizeActor(client, OWNER);

		// The client takes no repository argument at all; this asserts the path it
		// built from the operator's string, and that it stayed on the pinned host.
		expect(paths).toEqual([`/repos/${REPOSITORY}/collaborators/${OWNER}/permission`]);
	});
});

// ---------------------------------------------------------------------------
// The dispatch itself
// ---------------------------------------------------------------------------

/** Hooks that record the order the two boundaries were crossed in. */
function hooks(budget: "ok" | "limited" | "unavailable" = "ok") {
	const order: string[] = [];

	return {
		order,
		hooks: {
			reserveBudget: async () => {
				order.push("budget");
				return budget;
			},
			beforeDispatch: async () => {
				order.push("commit");
			},
		},
	};
}

describe("dispatchCommentRequest", () => {
	const plan = { issueNumber: 26, commentId: 99, actor: OWNER, isPullRequest: false };

	beforeEach(() => {
		vi.restoreAllMocks();
	});

	it("sends the operator's workflow and ref, and ids rather than any comment text", async () => {
		let sent: { path: string; body: unknown } | null = null;
		const client = clientOver(async (request) => {
			const url = new URL(request.url);
			if (url.pathname.endsWith("/permission")) {
				return Response.json({ permission: "admin", user: { login: OWNER } });
			}
			sent = { path: url.pathname, body: await request.json() };
			return new Response(null, { status: 204 });
		});

		const { hooks: h, order } = hooks();
		const result = await dispatchCommentRequest(client, { workflow: WORKFLOW, ref: REF }, plan, "delivery-1", h);

		expect(result).toMatchObject({ outcome: "dispatched", workflow: WORKFLOW, ref: REF, retryable: false });
		expect(sent).toEqual({
			path: `/repos/${REPOSITORY}/actions/workflows/${WORKFLOW}/dispatches`,
			body: {
				ref: REF,
				inputs: { issue_number: "26", comment_id: "99", requested_by: OWNER, delivery_id: "delivery-1" },
			},
		});
		// No comment body anywhere in the inputs. A body arriving as a workflow
		// input is a body one `${{ }}` away from a command line.
		expect(JSON.stringify(sent)).not.toContain("please do the thing");
		// Budget first, then the lookup, then the commit, then the request.
		expect(order).toEqual(["budget", "commit"]);
	});

	it("spends the budget before the permission lookup", async () => {
		// The lookup is the first GitHub call an arbitrary commenter can cause, so
		// it is what the budget has to sit in front of. A budget behind it bounds
		// the dispatches and not the calls.
		let reached = 0;
		const client = clientOver(() => {
			reached += 1;
			return Response.json({ permission: "admin", user: { login: OWNER } });
		});

		const result = await dispatchCommentRequest(
			client,
			{ workflow: WORKFLOW, ref: REF },
			plan,
			"d",
			hooks("limited").hooks,
		);

		expect(result).toMatchObject({ outcome: "failed", reason: "rate_limited", retryable: true });
		expect(reached).toBe(0);
	});

	it("stays retryable when the limiter cannot be reached", async () => {
		const client = clientOver(() => Response.json({ permission: "admin", user: { login: OWNER } }));

		await expect(
			dispatchCommentRequest(client, { workflow: WORKFLOW, ref: REF }, plan, "d", hooks("unavailable").hooks),
		).resolves.toMatchObject({ reason: "budget_unavailable", retryable: true });
	});

	it("does not reach the commit boundary when the actor is refused", async () => {
		const { hooks: h, order } = hooks();
		const client = clientOver(() => Response.json({ permission: "read", user: { login: OWNER } }));

		const result = await dispatchCommentRequest(client, { workflow: WORKFLOW, ref: REF }, plan, "d", h);

		expect(result).toEqual({ outcome: "skipped", reason: "actor_not_permitted", retryable: false });
		expect(order).toEqual(["budget"]);
	});

	it("hands the delivery back when GitHub definitely created nothing", async () => {
		// A 4xx is GitHub stating it made no run: an unknown workflow, a ref it is
		// not on, a permission never granted. All operator-fixable.
		for (const status of [404, 403, 422]) {
			const client = clientOver((request) =>
				new URL(request.url).pathname.endsWith("/permission")
					? Response.json({ permission: "admin", user: { login: OWNER } })
					: new Response("{}", { status }),
			);

			await expect(
				dispatchCommentRequest(client, { workflow: WORKFLOW, ref: REF }, plan, "d", hooks().hooks),
			).resolves.toMatchObject({ outcome: "failed", reason: "dispatch_refused", retryable: true, status });
		}
	});

	it.each([500, 502, 503])("keeps the delivery spent when GitHub answered %s", async (status) => {
		// A 5xx could have applied. There is no idempotency key on this endpoint, so
		// the ambiguous direction is at-most-once.
		const client = clientOver((request) =>
			new URL(request.url).pathname.endsWith("/permission")
				? Response.json({ permission: "admin", user: { login: OWNER } })
				: new Response("{}", { status }),
		);

		await expect(
			dispatchCommentRequest(client, { workflow: WORKFLOW, ref: REF }, plan, "d", hooks().hooks),
		).resolves.toMatchObject({ outcome: "failed", reason: "dispatch_unknown", retryable: false, status });
	});

	it("keeps the delivery spent when the answer never came back", async () => {
		// The case the whole ordering exists for: the request left, the answer was
		// lost. Indistinguishable from a request that never arrived, and resolved
		// the way that cannot start two agents.
		const { hooks: h, order } = hooks();
		const client = clientOver((request) => {
			if (new URL(request.url).pathname.endsWith("/permission")) {
				return Response.json({ permission: "admin", user: { login: OWNER } });
			}
			throw new Error("connection reset");
		});

		const result = await dispatchCommentRequest(client, { workflow: WORKFLOW, ref: REF }, plan, "d", h);

		expect(result).toMatchObject({ outcome: "failed", reason: "dispatch_unknown", retryable: false });
		// The commit was taken before the request left, which is what makes that
		// answer available at all.
		expect(order).toEqual(["budget", "commit"]);
	});

	it.each([200, 204])("treats %s as acceptance", async (status) => {
		// GitHub used to answer 204 with no body and now answers 200 with the run it
		// created. Neither status is asserted to be the one.
		const client = clientOver((request) =>
			new URL(request.url).pathname.endsWith("/permission")
				? Response.json({ permission: "admin", user: { login: OWNER } })
				: new Response(status === 204 ? null : "{}", { status }),
		);

		await expect(
			dispatchCommentRequest(client, { workflow: WORKFLOW, ref: REF }, plan, "d", hooks().hooks),
		).resolves.toMatchObject({ outcome: "dispatched" });
	});
});

// ---------------------------------------------------------------------------
// Through the endpoint
// ---------------------------------------------------------------------------

async function generateAppKey(): Promise<string> {
	const pair = (await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
	let binary = "";
	for (const byte of der) {
		binary += String.fromCharCode(byte);
	}

	return `-----BEGIN PRIVATE KEY-----\n${btoa(binary).replace(/(.{64})/g, "$1\n")}\n-----END PRIVATE KEY-----\n`;
}

/** Everything a delivery needs to reach the acting handler. */
function enabled(allowlist: string) {
	return {
		GITHUB_APP_ENABLED: "true",
		GITHUB_WEBHOOK_SECRET: SECRET,
		GITHUB_APP_ALLOWED_REPOSITORIES: allowlist,
		GITHUB_APP_ID: "123456",
		GITHUB_APP_PRIVATE_KEY: APP_PRIVATE_KEY,
	};
}

/** The three vars that turn dispatching on. */
const DISPATCHING = {
	GITHUB_APP_COMMENT_DISPATCH: "true",
	GITHUB_APP_DISPATCH_WORKFLOW: WORKFLOW,
	GITHUB_APP_DISPATCH_REF: REF,
};

async function hmac(body: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(SECRET),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));

	return SIGNATURE_PREFIX + [...mac].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * A GitHub stub that refuses anything outside the authorized repository.
 *
 * The refusal is the assertion. A handler that read `payload.repository` would
 * build a client for the other repository and reach a 500 here, rather than
 * quietly succeeding against a stub that answered every path.
 */
function stubGitHub(options: { permission?: string; dispatch?: () => Response } = {}) {
	const calls: { method: string; path: string; body?: unknown }[] = [];

	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const request = new Request(input as RequestInfo, init as RequestInit);
		const url = new URL(request.url);

		if (url.origin !== GITHUB_API_ORIGIN) {
			throw new Error(`off-host request to ${url.origin}`);
		}

		if (url.pathname.endsWith("/access_tokens")) {
			return Response.json({
				token: "ghs_installation_token",
				expires_at: new Date(Date.now() + 3_600_000).toISOString(),
			});
		}

		if (!url.pathname.startsWith(`/repos/${REPOSITORY}/`)) {
			throw new Error(`request outside the authorized repository: ${url.pathname}`);
		}

		const body = request.method === "POST" ? await request.clone().json() : undefined;
		calls.push({ method: request.method, path: url.pathname, body });

		if (url.pathname.endsWith("/permission")) {
			// The login is echoed back from the path, as GitHub does. A stub that
			// always answered about the owner would make the "answered about somebody
			// else" refusal fire on every non-owner test for the wrong reason.
			const asked = url.pathname.split("/").at(-2) ?? OWNER;
			return Response.json({ permission: options.permission ?? "admin", user: { login: asked } });
		}

		if (url.pathname.includes("/actions/workflows/")) {
			return options.dispatch ? options.dispatch() : new Response(null, { status: 204 });
		}

		throw new Error(`unexpected path ${url.pathname}`);
	});

	return {
		calls: () => calls,
		dispatches: () => calls.filter((call) => call.path.includes("/actions/workflows/")),
		reset: () => calls.splice(0, calls.length),
	};
}

/** Deliver an `issue_comment` to the real endpoint, through the real pipeline. */
async function deliverComment(options: {
	payload: unknown;
	allowlist?: string;
	deliveryId?: string;
	overrides?: Record<string, unknown>;
}): Promise<{ response: Response; body: Record<string, unknown>; text: string }> {
	const body = JSON.stringify(options.payload);
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request("https://sign.test/github/webhook", {
			method: "POST",
			body,
			headers: {
				"Content-Type": "application/json",
				"X-Hub-Signature-256": await hmac(body),
				"X-GitHub-Event": "issue_comment",
				"X-GitHub-Delivery": options.deliveryId ?? crypto.randomUUID(),
			},
		}),
		{
			...env,
			...enabled(options.allowlist ?? `${INSTALLATION}:${REPOSITORY}`),
			...DISPATCHING,
			// A permissive limiter by default. The budget is ten a minute and these
			// suites deliver more than that between them, so leaving the real bucket
			// in place would make an unrelated test fail with `rate_limited` — which
			// reads as the budget working and is actually the suite interfering with
			// itself. The three tests that are *about* the budget supply their own.
			...limiterAnswering(() => Response.json({ allowed: true, remaining: 9, resetAt: Date.now() + 60_000 })),
			...options.overrides,
		},
		ctx,
	);
	await waitOnExecutionContext(ctx);

	const text = await response.clone().text();

	return { response, body: JSON.parse(text) as Record<string, unknown>, text };
}

/** A limiter whose dispatch bucket answers what the test says. */
function limiterAnswering(dispatchMeter: () => Response) {
	return {
		RATE_LIMITER: {
			idFromName: () => ({}),
			get: () => ({
				fetch: (request: Request) => {
					const identity = new URL(request.url).searchParams.get("identity") ?? "";
					if (identity.startsWith("github-dispatch:")) {
						return Promise.resolve(dispatchMeter());
					}
					return Promise.resolve(Response.json({ allowed: true, remaining: 99, resetAt: Date.now() + 60_000 }));
				},
			}),
		},
	};
}

describe("through the endpoint", () => {
	beforeAll(async () => {
		// The audit table with the constraint migration 0007 leaves behind. Written
		// out rather than relaxed to TEXT, so an insert of `comment_dispatch` is
		// checked against the same closed set production checks it against — a
		// migration that forgot the value fails here rather than in D1.
		await env.AUDIT_DB.prepare(
			`CREATE TABLE IF NOT EXISTS audit_logs (
				id TEXT PRIMARY KEY,
				timestamp TEXT NOT NULL,
				request_id TEXT NOT NULL,
				action TEXT NOT NULL CHECK (action IN (
					'sign', 'key_upload', 'key_rotate', 'token_create', 'token_revoke',
					'subject_create', 'subject_revoke', 'push_sign', 'check_report', 'comment_dispatch'
				)),
				issuer TEXT NOT NULL,
				subject TEXT NOT NULL,
				key_id TEXT NOT NULL,
				success INTEGER NOT NULL DEFAULT 0,
				error_code TEXT,
				metadata TEXT
			)`,
		).run();
	});

	beforeEach(() => {
		vi.restoreAllMocks();
	});

	it("dispatches for a commenter with write access", async () => {
		const github = stubGitHub();

		const { response, body } = await deliverComment({ payload: commentPayload() });

		expect(response.status).toBe(200);
		expect(body).toMatchObject({ handled: true, dispatched: true, duplicate: false });
		expect(github.dispatches()).toHaveLength(1);
		expect(github.dispatches()[0]?.body).toMatchObject({ ref: REF });
	});

	it("makes no GitHub call at all when dispatching is off", async () => {
		// Not merely "does not dispatch". An upgraded deployment that has not
		// granted `Actions: write` must behave exactly as it did before, and the
		// assertion is against the network rather than against the module.
		const github = stubGitHub();

		const { response, body } = await deliverComment({
			payload: commentPayload(),
			overrides: { GITHUB_APP_COMMENT_DISPATCH: "false" },
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("dispatch_disabled");
		expect(github.calls()).toHaveLength(0);
	});

	it("costs a read-only commenter no dispatch and starts nothing", async () => {
		const github = stubGitHub({ permission: "read" });

		const { response, body } = await deliverComment({ payload: commentPayload() });

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("actor_not_permitted");
		expect(github.dispatches()).toHaveLength(0);
		// The lookup happened and nothing else did.
		expect(github.calls().map((call) => call.path)).toEqual([`/repos/${REPOSITORY}/collaborators/${OWNER}/permission`]);
	});

	it("costs an outside account nothing beyond the lookup", async () => {
		const github = stubGitHub({ permission: "none" });

		const { body } = await deliverComment({
			payload: commentPayload({ author: { login: "a-stranger", type: "User" } }),
		});

		expect(body.skipped).toBe("actor_not_permitted");
		expect(github.dispatches()).toHaveLength(0);
	});

	it("asks GitHub about the authorized repository, not the one the payload names", async () => {
		// Cross-repository confusion. The stub throws on any path outside the
		// allowlisted repository, so a handler that read `payload.repository` would
		// 500 here rather than pass.
		const github = stubGitHub();

		const { response } = await deliverComment({
			payload: commentPayload({ repository: REPOSITORY }),
			allowlist: `${INSTALLATION}:${REPOSITORY}`,
		});

		expect(response.status).toBe(200);
		expect(github.calls().every((call) => call.path.startsWith(`/repos/${REPOSITORY}/`))).toBe(true);
	});

	it("refuses a comment about a repository paired with another installation", async () => {
		const github = stubGitHub();

		const { response } = await deliverComment({
			payload: commentPayload(),
			allowlist: `999:${REPOSITORY}`,
		});

		expect(response.status).toBe(401);
		expect(github.calls()).toHaveLength(0);
	});

	it("refuses a comment about a repository nobody allowlisted", async () => {
		const github = stubGitHub();

		const { response } = await deliverComment({
			payload: commentPayload({ repository: OTHER_REPOSITORY }),
			allowlist: `${INSTALLATION}:${REPOSITORY}`,
		});

		expect(response.status).toBe(401);
		expect(github.calls()).toHaveLength(0);
	});

	it("refuses to dispatch when the operator named no workflow", async () => {
		const github = stubGitHub();
		const id = crypto.randomUUID();

		const { response } = await deliverComment({
			payload: commentPayload(),
			deliveryId: id,
			overrides: { GITHUB_APP_DISPATCH_WORKFLOW: undefined, GITHUB_APP_DISPATCH_REF: undefined },
		});

		expect(response.status).toBe(500);
		expect(github.calls()).toHaveLength(0);

		// And it stays redeliverable, because setting the two vars and redelivering
		// is exactly the recovery.
		const second = await deliverComment({ payload: commentPayload(), deliveryId: id });
		expect(second.body.duplicate).toBe(false);
		expect(github.dispatches()).toHaveLength(1);
	});

	it("answers a repeat without dispatching again", async () => {
		const github = stubGitHub();
		const id = crypto.randomUUID();
		const payload = commentPayload();

		const first = await deliverComment({ payload, deliveryId: id });
		expect(first.body.dispatched).toBe(true);

		const second = await deliverComment({ payload, deliveryId: id });
		expect(second.response.status).toBe(200);
		expect(second.body.duplicate).toBe(true);
		expect(github.dispatches()).toHaveLength(1);
	});

	it("dispatches exactly once for concurrent copies of one delivery", async () => {
		// The case that matters: a double-click on Redeliver, or somebody sending
		// the same bytes twice on purpose. Two agent sessions on one request is two
		// sessions pushing to one branch.
		const github = stubGitHub();
		const id = crypto.randomUUID();
		const payload = commentPayload();

		const results = await Promise.all(Array.from({ length: 8 }, () => deliverComment({ payload, deliveryId: id })));

		expect(github.dispatches()).toHaveLength(1);
		expect(results.filter((result) => result.body.dispatched === true)).toHaveLength(1);
		expect(results.filter((result) => result.body.duplicate === true)).toHaveLength(7);
	});

	it("stays redeliverable after GitHub definitely created nothing", async () => {
		const github = stubGitHub({ dispatch: () => new Response("{}", { status: 404 }) });
		const id = crypto.randomUUID();

		const first = await deliverComment({ payload: commentPayload(), deliveryId: id });
		expect(first.response.status).toBe(500);
		expect(github.dispatches()).toHaveLength(1);

		// The workflow is added to the ref, and the redelivery is a real retry.
		vi.restoreAllMocks();
		const retried = stubGitHub();
		const second = await deliverComment({ payload: commentPayload(), deliveryId: id });

		expect(second.body.duplicate).toBe(false);
		expect(second.body.dispatched).toBe(true);
		expect(retried.dispatches()).toHaveLength(1);
	});

	it("does not re-dispatch after an answer was lost", async () => {
		const github = stubGitHub({
			dispatch: () => {
				throw new Error("connection reset");
			},
		});
		const id = crypto.randomUUID();

		const first = await deliverComment({ payload: commentPayload(), deliveryId: id });
		expect(first.response.status).toBe(500);
		expect(github.dispatches()).toHaveLength(1);

		vi.restoreAllMocks();
		const retried = stubGitHub();
		const second = await deliverComment({ payload: commentPayload(), deliveryId: id });

		expect(second.body.duplicate).toBe(true);
		expect(retried.dispatches()).toHaveLength(0);
	});

	it("stays redeliverable when the actor lookup could not be made", async () => {
		vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
			const url = new URL(new Request(input as RequestInfo, init as RequestInit).url);
			if (url.pathname.endsWith("/access_tokens")) {
				return Response.json({ token: "t", expires_at: new Date(Date.now() + 3_600_000).toISOString() });
			}
			return new Response("{}", { status: 500 });
		});
		const id = crypto.randomUUID();

		const first = await deliverComment({ payload: commentPayload(), deliveryId: id });
		expect(first.response.status).toBe(500);

		vi.restoreAllMocks();
		const retried = stubGitHub();
		const second = await deliverComment({ payload: commentPayload(), deliveryId: id });

		expect(second.body.duplicate).toBe(false);
		expect(retried.dispatches()).toHaveLength(1);
	});

	it("stays redeliverable when the repository is over its dispatch budget", async () => {
		const github = stubGitHub();
		const id = crypto.randomUUID();

		const { response } = await deliverComment({
			payload: commentPayload(),
			deliveryId: id,
			overrides: limiterAnswering(() =>
				Response.json({ allowed: false, remaining: 0, resetAt: Date.now() + 30_000 }, { status: 429 }),
			),
		});

		expect(response.status).toBe(429);
		expect(github.calls()).toHaveLength(0);

		github.reset();
		const second = await deliverComment({ payload: commentPayload(), deliveryId: id });
		expect(second.body.duplicate).toBe(false);
		expect(github.dispatches()).toHaveLength(1);
	});

	it("fails closed and stays redeliverable when the limiter is unreachable", async () => {
		const github = stubGitHub();

		const { response } = await deliverComment({
			payload: commentPayload(),
			overrides: limiterAnswering(() => new Response("boom", { status: 500 })),
		});

		expect(response.status).toBe(500);
		expect(github.calls()).toHaveLength(0);
	});

	it("meters dispatches in a bucket of their own", () => {
		// Disjoint from the signing budget and from the per-IP webhook meter, and
		// built entirely from the authorization decision so a payload cannot move
		// itself into a fresh bucket.
		const identity = dispatchBudgetIdentity(grant());

		expect(identity).toContain("github-dispatch:");
		expect(identity).toContain(String(INSTALLATION));
		expect(identity).toContain(REPOSITORY);
	});

	it("starts nothing for the session's own completion comment", async () => {
		// End to end, through the pipeline, with the exact payload the dispatched
		// run's `gh issue comment` produces. This is the loop.
		const github = stubGitHub();
		const bot = { login: "claude", type: "Bot" };

		const { response, body } = await deliverComment({
			payload: commentPayload({
				author: bot,
				sender: bot,
				body: "**Claude finished @kjanat's task** — see @claude above",
				viaApp: { id: 1, slug: "claude" },
			}),
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("actor_is_not_human");
		expect(github.calls()).toHaveLength(0);
	});

	it("starts nothing for a delivery that names no repository", async () => {
		// `installation` scope: the delivery names an allowlisted installation and
		// no repository, so there is no pair and no client to build. GitHub does not
		// send an `issue_comment` shaped like this, and a signed payload can be —
		// which is the whole reason the check is on the authorization decision
		// rather than on the event name.
		const github = stubGitHub();
		const payload: Record<string, unknown> = { ...commentPayload() };
		delete payload.repository;

		const { response, body } = await deliverComment({ payload });

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("not_repository_scope");
		expect(github.calls()).toHaveLength(0);
	});

	it("dispatches for a comment on a pull request and records it as one", async () => {
		stubGitHub();

		const { body } = await deliverComment({ payload: commentPayload({ pullRequest: true }) });

		expect(body.dispatched).toBe(true);

		const row = await env.AUDIT_DB.prepare(
			"SELECT metadata FROM audit_logs WHERE action = 'comment_dispatch' ORDER BY rowid DESC LIMIT 1",
		).first<{ metadata: string }>();

		expect(JSON.parse(row?.metadata ?? "{}")).toMatchObject({ pullRequest: true });
	});

	it("starts nothing for an edited comment", async () => {
		const github = stubGitHub();

		const { body } = await deliverComment({ payload: commentPayload({ action: "edited" }) });

		expect(body.skipped).toBe("not_created");
		expect(github.calls()).toHaveLength(0);
	});

	it("never puts the installation token in the response", async () => {
		stubGitHub();

		const { text } = await deliverComment({ payload: commentPayload() });

		expect(text).not.toContain("ghs_installation_token");
		expect(text).not.toContain("PRIVATE KEY");
	});

	it("writes one comment_dispatch row per decision", async () => {
		stubGitHub();
		const before = await env.AUDIT_DB.prepare(
			"SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'comment_dispatch'",
		).first<{ n: number }>();

		await deliverComment({ payload: commentPayload() });

		const after = await env.AUDIT_DB.prepare(
			"SELECT subject, key_id, success, metadata FROM audit_logs WHERE action = 'comment_dispatch' ORDER BY rowid DESC LIMIT 1",
		).first<{ subject: string; key_id: string; success: number; metadata: string }>();

		expect(after?.subject).toBe(REPOSITORY);
		// No key is involved in dispatching, which is a different statement from
		// admin's "a key was involved and we could not name it".
		expect(after?.key_id).toBe("none");
		expect(after?.success).toBe(1);
		expect(JSON.parse(after?.metadata ?? "{}")).toMatchObject({ workflow: WORKFLOW, ref: REF, actor: OWNER });
		// And the metadata carries nothing it should not.
		expect(after?.metadata).not.toContain("ghs_");
		expect(before).toBeTruthy();
	});
});
