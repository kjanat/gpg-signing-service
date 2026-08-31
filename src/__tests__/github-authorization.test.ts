/**
 * Who a verified delivery is allowed to be about.
 *
 * The HMAC suite next door proves a delivery came from a holder of the webhook
 * secret. This one is about the thing that is easy to mistake for the same
 * question and is not: **one App has one webhook secret and many
 * installations**, so a delivery for a repository this deployment has no
 * business touching carries exactly the same valid signature as one for the
 * repository it was set up for. On a service whose purpose is to sign things,
 * conflating those is how a webhook secret becomes authority over every
 * repository the App is installed on.
 *
 * These tests are written against the ways that authority leaks, not against
 * the shape of the code that prevents it:
 *
 * - **Cross-installation confusion.** Two independent lists — allowed
 *   installations, allowed repositories — authorize every *combination* of
 *   their members, which is a grant nobody wrote. So the tests pair a
 *   legitimately allowlisted installation with a legitimately allowlisted
 *   repository belonging to a *different* one, and require a refusal. A design
 *   with two lists passes every other test in this file.
 * - **The payload naming its own subject.** A handler that reads
 *   `repository.full_name` is back to letting the delivery choose, one layer
 *   further in — and doing so having passed a check, which is worse than no
 *   check. So the decision's `repository` is asserted to be the *operator's*
 *   spelling even when the payload's differs only in case.
 * - **Permissive readings of a malformed subject.** Every one of these has an
 *   appealing wrong answer: an unreadable installation id read as "no
 *   installation", a typo'd allowlist entry skipped rather than refused, an
 *   unset allowlist read as "no restriction". Each is tested for the strict
 *   answer.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import app from "#gpg-signing-service";
import {
	ALLOWLIST_VAR,
	authorizeDelivery,
	deliverySubject,
	isRepositoryFullName,
	parseRepositoryAllowlist,
} from "#utils/github-authorization";
import { SIGNATURE_HEADER, SIGNATURE_PREFIX } from "#utils/github-webhook";
import { captureLogEntries, logLine } from "./helpers/log-capture";

const SECRET = "test-webhook-secret";

/** The installation and repository these tests grant, unless they say otherwise. */
const INSTALLATION = 12345678;
const REPOSITORY = "kjanat/gpg-signing-service";
const GRANT = `${INSTALLATION}:${REPOSITORY}`;

interface Envelope {
	error?: string;
	code?: string;
	hint?: string;
	received?: boolean;
	scope?: string;
	duplicate?: boolean;
}

/** The `sha256=…` value GitHub would send for these exact bytes. */
async function sign(body: string): Promise<string> {
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
 * A correctly signed delivery, with a delivery id no other request reuses.
 *
 * Fresh ids throughout, because a repeated one is answered as a duplicate — so
 * without this every assertion in this file would be one test away from
 * depending on execution order.
 */
async function deliver(
	payload: unknown,
	// `null` means "leave the variable unset", which `undefined` cannot: a
	// default parameter fires on undefined, so an unset-allowlist test written
	// the obvious way silently runs against the default grant and passes for the
	// wrong reason.
	allowlist: string | null = GRANT,
	event = "push",
	// Honoured only when it is a UUID, per `getRequestId` — so a test that wants
	// to find its own line in the log has to send one that is.
	requestId?: string,
): Promise<{ response: Response; body: Envelope }> {
	const body = JSON.stringify(payload);
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request("https://sign.test/github/webhook", {
			method: "POST",
			body,
			headers: {
				"Content-Type": "application/json",
				[SIGNATURE_HEADER]: await sign(body),
				"X-GitHub-Event": event,
				"X-GitHub-Delivery": crypto.randomUUID(),
				...(requestId === undefined ? {} : { "X-Request-ID": requestId }),
			},
		}),
		{
			...env,
			GITHUB_APP_ENABLED: "true",
			GITHUB_WEBHOOK_SECRET: SECRET,
			...(allowlist === null ? {} : { GITHUB_APP_ALLOWED_REPOSITORIES: allowlist }),
		},
		ctx,
	);
	await waitOnExecutionContext(ctx);

	return { response, body: (await response.json()) as Envelope };
}

/** A `push`-shaped payload naming an installation and a repository. */
function pushPayload(installationId: number, fullName: string) {
	return { installation: { id: installationId }, repository: { full_name: fullName, name: fullName.split("/")[1] } };
}

describe("allowlist parsing", () => {
	it("reads a single pair", () => {
		expect(parseRepositoryAllowlist(GRANT)).toEqual([
			{ installationId: INSTALLATION, repository: REPOSITORY.toLowerCase(), spelling: REPOSITORY },
		]);
	});

	it("reads several, and tolerates the whitespace an operator writes", () => {
		const parsed = parseRepositoryAllowlist(` 1:a/b ,\n 2:c/d ,`);

		expect(parsed.map((entry) => `${entry.installationId}:${entry.spelling}`)).toEqual(["1:a/b", "2:c/d"]);
	});

	it("grants nothing when it is unset", () => {
		// Not "no restriction". An unset policy is an empty policy — the reading
		// that treats a missing allowlist as an absent gate is the one that turns a
		// forgotten variable into an open door.
		expect(parseRepositoryAllowlist(undefined)).toEqual([]);
	});

	it("grants nothing when it is empty or only separators", () => {
		expect(parseRepositoryAllowlist("")).toEqual([]);
		expect(parseRepositoryAllowlist("  ,  , ")).toEqual([]);
	});

	it.each([
		["a bare repository with no installation", "kjanat/repo"],
		["an installation with no repository", "12345678:"],
		["a repository with no owner", "12345678:repo"],
		["three path segments", "12345678:a/b/c"],
		["a non-numeric installation", "abc:a/b"],
		["a negative installation", "-1:a/b"],
		["an installation of zero", "0:a/b"],
		["an installation past the safe integer range", "9007199254740993:a/b"],
		["a name starting with a separator", "1:.a/b"],
		["a wildcard", "1:*/*"],
		["a URL", "1:https://github.com/a/b"],
	])("refuses %s", (_name, entry) => {
		expect(() => parseRepositoryAllowlist(entry)).toThrow(ALLOWLIST_VAR);
	});

	it("refuses the whole list when one entry is malformed", () => {
		// Not "applies the entries that parsed". A typo must not silently drop a
		// grant, and it must certainly not silently widen one — and a parser that
		// skips what it cannot read does both, quietly, in a variable nobody reads
		// again.
		expect(() => parseRepositoryAllowlist(`${GRANT},not-an-entry,2:c/d`)).toThrow(ALLOWLIST_VAR);
	});

	it("names the offending entry, because the alternative is bisecting a variable by hand", () => {
		expect(() => parseRepositoryAllowlist(`${GRANT},oops`)).toThrow(/"oops"/);
	});
});

describe("repository full names", () => {
	it.each([
		"a/b",
		"kjanat/gpg-signing-service",
		"Org-1/repo.name_2",
		// A repository may begin with a character an owner may not. `.github` is
		// the one GitHub itself asks an organisation to create, so a pattern that
		// refuses it refuses deliveries about a repository most accounts have —
		// and, since a malformed allowlist entry refuses the whole list, bricks
		// every delivery for the operator who tries to allowlist it.
		"github/.github",
		"kjanat/_internal",
		"kjanat/-dash",
	])("accepts %s", (name) => {
		expect(isRepositoryFullName(name)).toBe(true);
	});

	it.each([
		["no slash", "kjanat"],
		["two slashes", "a/b/c"],
		["an empty owner", "/b"],
		["an empty name", "a/"],
		["a traversal", "a/../b"],
		// The two repository names that are not path segments. Everything else
		// starting with a dot is a real repository; these two are the reason the
		// leading character is checked at all.
		["a bare dot", "a/."],
		["a bare double dot", "a/.."],
		["a leading dot in the owner", ".a/b"],
		// Owner logins are alphanumerics and hyphens. Underscores and dots are
		// repository-name characters, not login characters.
		["an underscore in the owner", "a_b/c"],
		["a dot in the owner", "a.b/c"],
		["a scheme", "https://a/b"],
		["a space", "a b/c"],
		["a query string", "a/b?x=1"],
	])("refuses %s", (_label, name) => {
		// This value ends up in a URL path once a handler exists, so a name that is
		// accepted here and is not a repository is a hole rather than a nuisance.
		expect(isRepositoryFullName(name)).toBe(false);
	});
});

describe("reading what a payload claims", () => {
	it("tells an absent installation apart from an unreadable one", () => {
		// The whole reason presence and readability are tracked separately. Both
		// produce `installationId: null`, and they are opposite situations: one is
		// an event that is not about an installation, the other is an event about
		// one this service cannot name.
		expect(deliverySubject({})).toMatchObject({ installationPresent: false, installationId: null });
		expect(deliverySubject({ installation: {} })).toMatchObject({ installationPresent: true, installationId: null });
	});

	it("tells an absent repository apart from an unnameable one", () => {
		expect(deliverySubject({})).toMatchObject({ repositoryPresent: false, repositoryFullName: null });
		expect(deliverySubject({ repository: { name: "x" } })).toMatchObject({
			repositoryPresent: true,
			repositoryFullName: null,
		});
	});

	it.each([
		["a string id", { installation: { id: "42" } }],
		["a negative id", { installation: { id: -1 } }],
		["a fractional id", { installation: { id: 1.5 } }],
		["an id past the safe integer range", { installation: { id: 2 ** 53 } }],
		["a null id", { installation: { id: null } }],
	])("does not read %s as an installation", (_label, payload) => {
		expect(deliverySubject(payload).installationId).toBeNull();
	});

	it("does not read an array as an object", () => {
		// `typeof [] === "object"`, so a presence check written the obvious way
		// accepts `installation: []` and then reads `id` off it as undefined.
		expect(deliverySubject({ installation: [], repository: [] })).toMatchObject({
			installationId: null,
			repositoryFullName: null,
		});
	});

	it.each([null, undefined, 42, "a string", [], true])("survives a payload that is %s", (payload) => {
		expect(() => deliverySubject(payload)).not.toThrow();
	});
});

describe("the decision", () => {
	const allowlist = parseRepositoryAllowlist(GRANT);

	it("grants repository scope for an allowlisted pair", () => {
		const decision = authorizeDelivery(allowlist, pushPayload(INSTALLATION, REPOSITORY));

		expect(decision).toEqual({
			allowed: true,
			authorization: { scope: "repository", installationId: INSTALLATION, repository: REPOSITORY },
		});
	});

	it("hands back the operator's spelling, not the payload's", () => {
		// The anti-confusion property that survives into the handler. A handler
		// acting on `authorization.repository` is acting on a string an operator
		// typed; one reading the payload is letting the delivery name its own
		// subject with a check's blessing.
		const decision = authorizeDelivery(allowlist, pushPayload(INSTALLATION, "KJanat/GPG-Signing-Service"));

		expect(decision).toMatchObject({ allowed: true, authorization: { repository: REPOSITORY } });
	});

	it("refuses an allowlisted repository claimed by a different installation", () => {
		// **The cross-installation test.** Both halves are individually granted —
		// installation 99 is on the list, and so is `kjanat/gpg-signing-service` —
		// and the *pair* is not. Two independent lists pass this and should not.
		const pairs = parseRepositoryAllowlist(`${GRANT},99:kjanat/other`);

		expect(authorizeDelivery(pairs, pushPayload(99, REPOSITORY))).toEqual({
			allowed: false,
			reason: "pair_not_allowed",
		});
	});

	it("refuses an allowlisted installation naming a repository it was not paired with", () => {
		// The same confusion from the other end.
		const pairs = parseRepositoryAllowlist(`${GRANT},99:kjanat/other`);

		expect(authorizeDelivery(pairs, pushPayload(INSTALLATION, "kjanat/other"))).toEqual({
			allowed: false,
			reason: "pair_not_allowed",
		});
	});

	it("refuses a repository nobody granted", () => {
		expect(authorizeDelivery(allowlist, pushPayload(INSTALLATION, "attacker/evil"))).toEqual({
			allowed: false,
			reason: "pair_not_allowed",
		});
	});

	it("refuses everything when the allowlist is empty", () => {
		expect(authorizeDelivery([], pushPayload(INSTALLATION, REPOSITORY))).toMatchObject({ allowed: false });
		expect(authorizeDelivery([], { installation: { id: INSTALLATION } })).toMatchObject({ allowed: false });
	});

	it("refuses a repository that names no installation", () => {
		// Every delivery from an installed App carries `installation`. One that
		// does not, but names a repository, did not come from an installation of
		// this App — and there is nothing to scope the grant against.
		expect(authorizeDelivery(allowlist, { repository: { full_name: REPOSITORY } })).toEqual({
			allowed: false,
			reason: "repository_without_installation",
		});
	});

	it("refuses a repository it cannot name", () => {
		expect(
			authorizeDelivery(allowlist, { installation: { id: INSTALLATION }, repository: { name: "no-full-name" } }),
		).toEqual({ allowed: false, reason: "repository_unnameable" });
	});

	it("refuses an installation it cannot read rather than treating it as absent", () => {
		// The permissive reading — unreadable id, so no installation, so unscoped,
		// so accepted — is the appealing one, and it accepts a delivery that was
		// claiming an installation. Every shape below is refused instead.
		for (const installation of [{}, { id: "42" }, { id: -1 }, { id: 1.5 }, { id: null }]) {
			expect(authorizeDelivery(allowlist, { installation })).toEqual({
				allowed: false,
				reason: "installation_unreadable",
			});
		}
	});

	it("grants installation scope, and no repository, to an allowlisted installation", () => {
		expect(authorizeDelivery(allowlist, { installation: { id: INSTALLATION } })).toEqual({
			allowed: true,
			authorization: { scope: "installation", installationId: INSTALLATION, repository: null },
		});
	});

	it("refuses an installation on no entry", () => {
		expect(authorizeDelivery(allowlist, { installation: { id: 999 } })).toEqual({
			allowed: false,
			reason: "installation_not_allowed",
		});
	});

	it("grants nothing at all to a delivery that names neither", () => {
		// The App-level ping. Accepted so an operator can check the endpoint before
		// writing an allowlist, and it authorizes exactly what it named: nothing.
		expect(authorizeDelivery([], { zen: "Practicality beats purity." })).toEqual({
			allowed: true,
			authorization: { scope: "none", installationId: null, repository: null },
		});
	});

	it("never returns a repository below repository scope", () => {
		// The invariant a handler will lean on: `scope !== "repository"` means
		// there is no repository to act on, with no second field to check.
		const decisions = [
			authorizeDelivery(allowlist, { installation: { id: INSTALLATION } }),
			authorizeDelivery(allowlist, {}),
		];

		for (const decision of decisions) {
			expect(decision.allowed && decision.authorization.scope).not.toBe("repository");
			expect(decision.allowed && decision.authorization.repository).toBeNull();
		}
	});
});

describe("through the route", () => {
	it("accepts an allowlisted pair and reports repository scope", async () => {
		const { response, body } = await deliver(pushPayload(INSTALLATION, REPOSITORY));

		expect(response.status).toBe(202);
		expect(body).toMatchObject({ received: true, scope: "repository", duplicate: false });
	});

	it("refuses a repository under the wrong installation with 401 AUTH_SUBJECT_UNTRUSTED", async () => {
		// The same code the OIDC path uses for a credential that verified and an
		// identity that holds no trust, because that is the identical situation.
		// Not AUTH_INVALID: a caller reading this as a credential fault goes and
		// rotates a webhook secret that is working exactly as provisioned.
		const { response, body } = await deliver(pushPayload(99, REPOSITORY), `${GRANT},99:kjanat/other`);

		expect(response.status).toBe(401);
		expect(body.code).toBe("AUTH_SUBJECT_UNTRUSTED");
	});

	it("refuses everything repository-shaped when the allowlist is unset", async () => {
		const { response, body } = await deliver(pushPayload(INSTALLATION, REPOSITORY), null);

		expect(response.status).toBe(401);
		expect(body.code).toBe("AUTH_SUBJECT_UNTRUSTED");
	});

	it("still answers the App-level ping with no allowlist configured", async () => {
		// Setup has to be checkable before policy is written, or the first thing an
		// operator sees is a refusal they cannot distinguish from a broken secret.
		const { response, body } = await deliver({ zen: "Anything added dilutes everything else." }, null, "ping");

		expect(response.status).toBe(202);
		expect(body).toMatchObject({ scope: "none" });
	});

	it("does not name the allowlist's contents in the refusal", async () => {
		// The hint says which variable governs the decision, which an operator
		// needs. It does not say which half of the pair was wrong and does not
		// quote an entry — either would turn a refusal into a way to enumerate the
		// allowlist one delivery at a time.
		const { body } = await deliver(pushPayload(99, "attacker/evil"), `${GRANT},77:secret-org/secret-repo`);

		const serialized = JSON.stringify(body);
		expect(serialized).toContain(ALLOWLIST_VAR);
		expect(serialized).not.toContain("secret-org");
		expect(serialized).not.toContain("secret-repo");
		expect(serialized).not.toContain(String(INSTALLATION));
	});

	it("refuses every delivery when the allowlist itself is malformed", async () => {
		// A 500, not a 401: an operator opted in and the deployment cannot honour
		// it, and no better-formed delivery will change that. Answering 401 would
		// send them to check the App's secret, which is fine.
		const { response, body } = await deliver(pushPayload(INSTALLATION, REPOSITORY), `${GRANT},broken-entry`);

		expect(response.status).toBe(500);
		expect(body.code).toBe("SERVICE_MISCONFIGURED");
	});

	it("does not quote the malformed allowlist back to the sender", async () => {
		const { body } = await deliver(pushPayload(INSTALLATION, REPOSITORY), "77:secret-org/secret-repo,broken");

		expect(JSON.stringify(body)).not.toContain("secret-org");
	});

	it("runs after the signature check, so an unsigned request is never authorized", async () => {
		// Ordering, asserted from outside: a request with no signature is refused
		// with the authentication code even though its payload names a pair that
		// would have been granted. An authorization gate in front of the HMAC
		// would answer AUTH_SUBJECT_UNTRUSTED for the unallowlisted ones, which is
		// a subject oracle for anyone who can reach the URL.
		const payload = JSON.stringify(pushPayload(INSTALLATION, REPOSITORY));
		const ctx = createExecutionContext();
		const response = await app.fetch(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body: payload,
				headers: { "X-GitHub-Event": "push", "X-GitHub-Delivery": crypto.randomUUID() },
			}),
			{ ...env, GITHUB_APP_ENABLED: "true", GITHUB_WEBHOOK_SECRET: SECRET, GITHUB_APP_ALLOWED_REPOSITORIES: GRANT },
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(401);
		expect(((await response.json()) as Envelope).code).toBe("AUTH_MISSING");
	});
});

describe("what a refused configuration reports to the operator", () => {
	// The refusal body deliberately says almost nothing, so the log line is the
	// operator's whole diagnostic. These assert the line is the shape a log
	// aggregator and Sentry can use: the failure as an error, the request id as
	// context, at the top level where every other line in the service puts it.
	const PARSE_FAILURE = "GITHUB_APP_ALLOWED_REPOSITORIES could not be parsed";

	it("logs the parse failure with the request id in context and the throw as the error", async () => {
		const requestId = crypto.randomUUID();

		const entries = await captureLogEntries(() =>
			deliver(pushPayload(INSTALLATION, REPOSITORY), `${GRANT},broken-entry`, "push", requestId),
		);
		const line = logLine(entries, PARSE_FAILURE);

		expect(line.level).toBe("error");
		expect(line.requestId).toBe(requestId);
		expect(line.event).toBe("push");
		// The thrown `GitHubAppError`, serialised by `Logger.error` — not a
		// pre-stringified message, and not the context object.
		expect(line.error).toMatchObject({ name: "GitHubAppError" });
		expect(String((line.error as { message?: string }).message)).toContain("broken-entry");
	});

	it("does not nest the request id inside the error payload", async () => {
		// The regression this guards. `logger.error(msg, { requestId, error })`
		// type-checks and logs *something*, but the id ends up one level down and
		// `captureError` is handed no context at all, so the Sentry report cannot
		// be correlated with the delivery that caused it.
		const requestId = crypto.randomUUID();

		const entries = await captureLogEntries(() =>
			deliver(pushPayload(INSTALLATION, REPOSITORY), "broken-entry", "push", requestId),
		);
		const line = logLine(entries, PARSE_FAILURE);

		expect((line.error as Record<string, unknown>).requestId).toBeUndefined();
		expect((line.error as Record<string, unknown>).error).toBeUndefined();
	});

	it("still keeps the malformed entry out of the response it logged", async () => {
		// The log names the entry; the body must not. Asserted together with the
		// line above so the two cannot drift apart.
		const requestId = crypto.randomUUID();
		let body: Envelope | undefined;

		const entries = await captureLogEntries(async () => {
			({ body } = await deliver(
				pushPayload(INSTALLATION, REPOSITORY),
				"77:secret-org/secret-repo,broken",
				"push",
				requestId,
			));
		});

		expect(String((logLine(entries, PARSE_FAILURE).error as { message?: string }).message)).toContain("broken");
		expect(JSON.stringify(body)).not.toContain("broken");
	});
});
