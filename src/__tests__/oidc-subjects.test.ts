import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import app from "#gpg-signing-service";

import {
	insertOIDCSubject,
	listOIDCSubjects,
	resolveOIDCSubject,
	revokeOIDCSubject,
	subjectMatchesPrefix,
} from "#utils/oidc-subjects";

import { clearTrustedSubjects } from "./helpers/oidc-subjects";

const GITHUB = "https://token.actions.githubusercontent.com";
const GITLAB = "https://gitlab.com";

describe("subjectMatchesPrefix", () => {
	it("matches an exact subject", () => {
		expect(subjectMatchesPrefix("repo:me/svc", "repo:me/svc")).toBe(true);
	});

	it("matches a prefix that ends at a delimiter in the subject", () => {
		expect(subjectMatchesPrefix("repo:me/svc:ref:refs/heads/main", "repo:me/svc")).toBe(true);
	});

	it("matches the immutable subject form", () => {
		expect(subjectMatchesPrefix("repo:me@1/svc@2:ref:refs/heads/main", "repo:me@1/svc@2")).toBe(true);
	});

	it("treats a trailing-delimiter prefix as owner-wide", () => {
		expect(subjectMatchesPrefix("repo:me/anything:ref:refs/heads/main", "repo:me/")).toBe(true);
		expect(subjectMatchesPrefix("repo:me@1/anything@2:ref:x", "repo:me@1/")).toBe(true);
	});

	it("rejects a partial name match", () => {
		// The bug a naive startsWith would introduce.
		expect(subjectMatchesPrefix("repo:me/svc-evil:ref:refs/heads/main", "repo:me/svc")).toBe(false);
		expect(subjectMatchesPrefix("repo:meevil/svc", "repo:me")).toBe(false);
		expect(subjectMatchesPrefix("repo:meevil/svc", "repo:me/")).toBe(false);
	});

	it("rejects an unrelated subject and an empty prefix", () => {
		expect(subjectMatchesPrefix("repo:someoneelse/svc:ref:x", "repo:me/")).toBe(false);
		expect(subjectMatchesPrefix("repo:me/svc", "")).toBe(false);
	});
});

describe("OIDC subject policy store", () => {
	beforeEach(async () => {
		await clearTrustedSubjects(env.AUDIT_DB);
	});

	it("denies everything when no subject is trusted", async () => {
		// The property that matters most: an empty table is a closed door, not
		// an open one. Both our issuers are shared by every repo on their host.
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:anyone/anything:ref:x")).resolves.toBeNull();
	});

	it("resolves a trusted subject and returns its key scope", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "mine",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: ["D8BC04E534E7706F"],
			expiresAt: null,
		});

		const policy = await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:refs/heads/main");
		expect(policy?.name).toBe("mine");
		expect(policy?.allowedKeyIds).toEqual(["D8BC04E534E7706F"]);
	});

	it("returns a null key scope when no keys are pinned", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "any-key",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		const policy = await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x");
		expect(policy?.allowedKeyIds).toBeNull();
	});

	it("pins the issuer, so the same subject string on another issuer is refused", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "github-only",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		await expect(resolveOIDCSubject(env.AUDIT_DB, GITLAB, "repo:me/svc:ref:x")).resolves.toBeNull();
	});

	it("refuses another repository on the same shared issuer", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "mine",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:attacker/evil:ref:x")).resolves.toBeNull();
	});

	it("refuses an expired trust", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "expired",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: new Date(Date.now() - 1000).toISOString(),
		});

		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.toBeNull();
	});

	it("refuses a revoked trust", async () => {
		const id = await insertOIDCSubject(env.AUDIT_DB, {
			name: "revoked",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		expect(await revokeOIDCSubject(env.AUDIT_DB, id)).toBe(true);
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.toBeNull();
		// Revoking twice is not an error, it is a no-op.
		expect(await revokeOIDCSubject(env.AUDIT_DB, id)).toBe(false);
	});

	it("prefers the most specific prefix when several match", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "owner-wide",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: ["AAAAAAAAAAAAAAAA"],
			expiresAt: null,
		});
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "one-repo",
			issuer: GITHUB,
			subjectPrefix: "repo:me/svc",
			keyIds: ["BBBBBBBBBBBBBBBB"],
			expiresAt: null,
		});

		const policy = await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x");
		expect(policy?.name).toBe("one-repo");
		expect(policy?.allowedKeyIds).toEqual(["BBBBBBBBBBBBBBBB"]);
	});

	it("stamps last use, and signing still works when that write fails", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "stamped",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x");
		const [listed] = await listOIDCSubjects(env.AUDIT_DB);
		expect(listed?.lastUsedAt).not.toBeNull();

		// A failed usage stamp must not deny a legitimate signature.
		const realPrepare = env.AUDIT_DB.prepare.bind(env.AUDIT_DB);
		const spy = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			if (query.startsWith("UPDATE oidc_subjects SET last_used_at")) {
				throw new Error("stamp failed");
			}
			return realPrepare(query);
		});
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.not.toBeNull();
		spy.mockRestore();

		// Same again with a non-Error rejection, which takes the String(error) branch.
		const spyNonError = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			if (query.startsWith("UPDATE oidc_subjects SET last_used_at")) {
				throw "stamp failed";
			}
			return realPrepare(query);
		});
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.not.toBeNull();
		spyNonError.mockRestore();
	});

	it("lists subjects with their metadata", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "listed",
			issuer: GITLAB,
			subjectPrefix: "project_path:group/proj",
			keyIds: ["D8BC04E534E7706F"],
			expiresAt: null,
		});

		const subjects = await listOIDCSubjects(env.AUDIT_DB);
		expect(subjects).toHaveLength(1);
		expect(subjects[0]).toMatchObject({
			name: "listed",
			issuer: GITLAB,
			subjectPrefix: "project_path:group/proj",
			keyIds: ["D8BC04E534E7706F"],
			revokedAt: null,
		});
	});
});

async function adminRequest(path: string, options: RequestInit = {}): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request(`http://localhost${path}`, {
			...options,
			headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}`, ...options.headers },
		}),
		env,
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

describe("admin subject management", () => {
	beforeEach(async () => {
		await clearTrustedSubjects(env.AUDIT_DB);
	});

	it("trusts, lists, and revokes a subject end to end", async () => {
		const created = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				name: "ci/e2e",
				issuer: GITHUB,
				subjectPrefix: "repo:me/",
				expiresInDays: 30,
			}),
		});
		expect(created.status).toBe(201);
		const subject = (await created.json()) as { id: string; expiresAt: string | null };
		expect(subject.expiresAt).not.toBeNull();

		const listed = await adminRequest("/admin/subjects");
		expect(listed.status).toBe(200);
		const { subjects } = (await listed.json()) as { subjects: { name: string }[] };
		expect(subjects.map((entry) => entry.name)).toContain("ci/e2e");

		// Trusted until revoked.
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.not.toBeNull();

		const revoked = await adminRequest(`/admin/subjects/${subject.id}`, { method: "DELETE" });
		expect(revoked.status).toBe(200);
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.toBeNull();

		// Revoking again reports not-found rather than pretending to succeed.
		const again = await adminRequest(`/admin/subjects/${subject.id}`, { method: "DELETE" });
		expect(again.status).toBe(404);
	});

	it("refuses a second live row for the same issuer and prefix, under any name", async () => {
		const body = { issuer: GITHUB, subjectPrefix: "repo:pair/" };
		const first = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "pair-one", ...body }),
		});
		expect(first.status).toBe(201);

		const second = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "pair-two", ...body }),
		});
		expect(second.status).toBe(409);
		// The name is the one field that was fine; do not send the operator to change it.
		const error = (await second.json()) as { error: string };
		expect(error.error).toContain("already trusted");
		expect(error.error).not.toContain("pair-two");
	});

	it("allows re-trusting an identity after it has been revoked", async () => {
		// The incident path: kill a compromised trust, remediate, trust it again.
		// A unique index spanning revoked rows would make revoke a one-way door.
		const body = { issuer: GITHUB, subjectPrefix: "repo:incident/" };
		const created = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "incident-before", ...body }),
		});
		expect(created.status).toBe(201);
		const { id } = (await created.json()) as { id: string };

		expect((await adminRequest(`/admin/subjects/${id}`, { method: "DELETE" })).status).toBe(200);
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:incident/svc:ref:x")).resolves.toBeNull();

		const restored = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "incident-after", ...body }),
		});
		expect(restored.status).toBe(201);
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:incident/svc:ref:x")).resolves.not.toBeNull();
	});

	it("rejects duplicate names", async () => {
		// Distinct prefixes, so this exercises the name constraint rather than
		// the (issuer, prefix) index.
		const create = (subjectPrefix: string) =>
			adminRequest("/admin/subjects", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "ci/dup", issuer: GITHUB, subjectPrefix }),
			});
		expect((await create("repo:a/")).status).toBe(201);
		const clash = await create("repo:b/");
		expect(clash.status).toBe(409);
		expect(((await clash.json()) as { error: string }).error).toContain("name already exists");
	});

	it("rejects a malformed name, issuer, prefix or key id", async () => {
		const cases = [
			{ name: "spaces are bad", issuer: GITHUB, subjectPrefix: "repo:a/" },
			{ name: "ci/badissuer", issuer: "not-a-url", subjectPrefix: "repo:a/" },
			{ name: "ci/badprefix", issuer: GITHUB, subjectPrefix: "has spaces" },
			{ name: "ci/badkey", issuer: GITHUB, subjectPrefix: "repo:a/", keyIds: ["nope"] },
			// Empty array means "every key" once stored, so it must not be a way
			// to ask for a restriction. Omitting the field is how you say that.
			{ name: "ci/emptykeys", issuer: GITHUB, subjectPrefix: "repo:a/", keyIds: [] },
			// A bare scheme names nobody and would trust the whole host.
			{ name: "ci/bareprefix", issuer: GITHUB, subjectPrefix: "repo:" },
			{ name: "ci/schemeonly", issuer: GITHUB, subjectPrefix: "repo" },
			{ name: "ci/gitlabbare", issuer: GITHUB, subjectPrefix: "project_path:" },
			{ name: "ci/delimsonly", issuer: GITHUB, subjectPrefix: "repo:/" },
		];
		for (const body of cases) {
			const response = await adminRequest("/admin/subjects", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
			expect(response.status).toBe(400);
		}
	});

	it("refuses an issuer that is not in ALLOWED_ISSUERS", async () => {
		// Otherwise the row lists as trusted and can never match anything.
		const response = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				name: "ci/typo",
				issuer: "https://token.actions.githubusercontent.com/",
				subjectPrefix: "repo:a/",
			}),
		});
		expect(response.status).toBe(400);
		expect(((await response.json()) as { error: string }).error).toContain("ALLOWED_ISSUERS");
	});

	it("normalizes a lowercase key id to uppercase", async () => {
		// Stored keys are uppercase and the sign route compares case-sensitively,
		// so a lowercase id would list as allowed and never match anything.
		const created = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				name: "ci/lowercase-key",
				issuer: GITHUB,
				subjectPrefix: "repo:case/",
				keyIds: ["d8bc04e534e7706f"],
			}),
		});
		expect(created.status).toBe(201);
		expect(((await created.json()) as { keyIds: string[] }).keyIds).toEqual(["D8BC04E534E7706F"]);

		const policy = await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:case/svc:ref:x");
		expect(policy?.allowedKeyIds).toEqual(["D8BC04E534E7706F"]);
	});

	it("requires the admin token", async () => {
		const ctx = createExecutionContext();
		const response = await app.fetch(
			new Request("http://localhost/admin/subjects", {
				headers: { Authorization: "Bearer wrong-token" },
			}),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		// Unauthenticated, not forbidden: the caller never proved who it is.
		expect(response.status).toBe(401);
	});

	it("surfaces a create failure as a 500, not a conflict", async () => {
		const realPrepare = env.AUDIT_DB.prepare.bind(env.AUDIT_DB);
		const spy = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			if (query.includes("INSERT INTO oidc_subjects")) {
				throw new Error("DB down");
			}
			return realPrepare(query);
		});
		const response = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "ci/boom", issuer: GITHUB, subjectPrefix: "repo:a/" }),
		});
		expect(response.status).toBe(500);
		spy.mockRestore();
	});

	it("surfaces a revoke failure as a 500", async () => {
		const id = await insertOIDCSubject(env.AUDIT_DB, {
			name: "ci/revoke-boom",
			issuer: GITHUB,
			subjectPrefix: "repo:a/",
			keyIds: [],
			expiresAt: null,
		});
		const realPrepare = env.AUDIT_DB.prepare.bind(env.AUDIT_DB);
		const spy = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			if (query.startsWith("UPDATE oidc_subjects SET revoked_at")) {
				throw new Error("DB down");
			}
			return realPrepare(query);
		});
		const response = await adminRequest(`/admin/subjects/${id}`, { method: "DELETE" });
		expect(response.status).toBe(500);
		spy.mockRestore();
	});

	it("surfaces a database failure as a 500", async () => {
		const realPrepare = env.AUDIT_DB.prepare.bind(env.AUDIT_DB);
		const spy = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			if (query.includes("FROM oidc_subjects ORDER BY")) {
				throw new Error("DB down");
			}
			return realPrepare(query);
		});
		const response = await adminRequest("/admin/subjects");
		expect(response.status).toBe(500);
		spy.mockRestore();
	});
});
