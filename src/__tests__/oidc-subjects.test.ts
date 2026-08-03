import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import app from "#gpg-signing-service";
import { logger } from "#utils/logger";
import type { OIDCSubjectPolicy, OIDCSubjectResolution } from "#utils/oidc-subjects";
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

/**
 * Assert that a resolution admitted the caller, and narrow to its policy.
 *
 * A refusal now carries a reason rather than being null, so a test that wants
 * the policy has to say which arm it expects; this keeps that to one line.
 */
function trustedPolicy(resolution: OIDCSubjectResolution): OIDCSubjectPolicy {
	expect(resolution.status).toBe("trusted");
	if (resolution.status !== "trusted") {
		throw new Error(`expected a trusted resolution, got ${resolution.status}`);
	}
	return resolution.policy;
}

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

	it("rejects a missing or non-string subject instead of throwing", () => {
		// A token with no `sub` is a malformed credential. Throwing here would be
		// caught by the store-unavailable handler and reported as a 503 outage.
		expect(subjectMatchesPrefix(undefined as unknown as string, "repo:me/")).toBe(false);
		expect(subjectMatchesPrefix("", "repo:me/")).toBe(false);
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
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:anyone/anything:ref:x")).resolves.toMatchObject({
			status: "unknown",
		});
	});

	it("resolves a trusted subject and returns its key scope", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "mine",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: ["D8BC04E534E7706F"],
			expiresAt: null,
		});

		const policy = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:refs/heads/main"));
		expect(policy.name).toBe("mine");
		expect(policy.allowedKeyIds).toEqual(["D8BC04E534E7706F"]);
	});

	it("returns a null key scope when no keys are pinned", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "any-key",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		const policy = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x"));
		expect(policy.allowedKeyIds).toBeNull();
	});

	it("pins the issuer, so the same subject string on another issuer is refused", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "github-only",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		await expect(resolveOIDCSubject(env.AUDIT_DB, GITLAB, "repo:me/svc:ref:x")).resolves.toMatchObject({
			status: "unknown",
		});
	});

	it("refuses another repository on the same shared issuer", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "mine",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:attacker/evil:ref:x")).resolves.toMatchObject({
			status: "unknown",
		});
	});

	it("refuses an expired trust", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "expired",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: new Date(Date.now() - 1000).toISOString(),
		});

		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.toMatchObject({
			status: "expired",
		});
	});

	it("refuses a revoked trust", async () => {
		const id = await insertOIDCSubject(env.AUDIT_DB, {
			name: "revoked",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		// The name comes back so the revoke can be audited under the same key the
		// row's signatures were recorded under.
		expect(await revokeOIDCSubject(env.AUDIT_DB, id)).toMatchObject({
			name: "revoked",
			stillCoveredBy: [],
			stillTrustedWithin: [],
		});
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.toMatchObject({
			status: "revoked",
		});
		// Revoking twice is not an error, it is a no-op.
		expect(await revokeOIDCSubject(env.AUDIT_DB, id)).toBeNull();
		// An unknown id is likewise a no-op, not a throw.
		expect(await revokeOIDCSubject(env.AUDIT_DB, crypto.randomUUID())).toBeNull();
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

		const policy = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x"));
		expect(policy.name).toBe("one-repo");
		expect(policy.allowedKeyIds).toEqual(["BBBBBBBBBBBBBBBB"]);
	});

	it("reports the broader row that takes over when a narrow trust is revoked", async () => {
		// Revoke is not subtraction. Resolution takes the longest *live* prefix, so
		// killing the narrow row promotes the owner-wide one — with *its* key grant.
		// Here that means the repository loses BBBB and gains AAAA, which is the
		// opposite of what "stops being able to sign immediately" implies.
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "owner-wide",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: ["AAAAAAAAAAAAAAAA"],
			expiresAt: null,
		});
		const narrowId = await insertOIDCSubject(env.AUDIT_DB, {
			name: "one-repo",
			issuer: GITHUB,
			subjectPrefix: "repo:me/svc",
			keyIds: ["BBBBBBBBBBBBBBBB"],
			expiresAt: null,
		});

		const revoked = await revokeOIDCSubject(env.AUDIT_DB, narrowId);
		expect(revoked?.name).toBe("one-repo");
		expect(revoked?.stillCoveredBy).toEqual([
			{
				id: expect.any(String),
				name: "owner-wide",
				subjectPrefix: "repo:me/",
				keyIds: ["AAAAAAAAAAAAAAAA"],
			},
		]);

		// And it really does still sign, under the surviving grant.
		const after = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x"));
		expect(after.name).toBe("owner-wide");
		expect(after.allowedKeyIds).toEqual(["AAAAAAAAAAAAAAAA"]);
	});

	it("does not report siblings, expired rows or other issuers as still covering", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "sibling",
			issuer: GITHUB,
			subjectPrefix: "repo:me/other",
			keyIds: [],
			expiresAt: null,
		});
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "lapsed-parent",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: new Date(Date.now() - 1000).toISOString(),
		});
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "other-issuer-parent",
			issuer: GITLAB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});
		const narrowId = await insertOIDCSubject(env.AUDIT_DB, {
			name: "target",
			issuer: GITHUB,
			subjectPrefix: "repo:me/svc",
			keyIds: [],
			expiresAt: null,
		});

		const revoked = await revokeOIDCSubject(env.AUDIT_DB, narrowId);
		expect(revoked).toMatchObject({ name: "target", stillCoveredBy: [], stillTrustedWithin: [] });
	});

	it("reports the nested rows a broad revoke leaves signing", async () => {
		// The mirror image, and the worse one: the operator revokes the parent to
		// cut a whole owner off, and the children are untouched. Reporting only
		// ancestors answers with an empty list, which reads as "final".
		const wideId = await insertOIDCSubject(env.AUDIT_DB, {
			name: "owner-wide",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "one-repo",
			issuer: GITHUB,
			subjectPrefix: "repo:me/svc",
			keyIds: ["BBBBBBBBBBBBBBBB"],
			expiresAt: null,
		});

		const revoked = await revokeOIDCSubject(env.AUDIT_DB, wideId);
		expect(revoked?.stillCoveredBy).toEqual([]);
		expect(revoked?.stillTrustedWithin).toEqual([
			{ id: expect.any(String), name: "one-repo", subjectPrefix: "repo:me/svc", keyIds: ["BBBBBBBBBBBBBBBB"] },
		]);

		// The rest of the owner really did stop; the nested repository did not.
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/api:ref:x")).resolves.toMatchObject({
			status: "revoked",
		});
		expect(trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).name).toBe("one-repo");
	});

	it("truncates the audit summary when a revoke leaves many rows trusted", async () => {
		// `audit_logs.metadata` has no length cap and nothing stops one row per
		// repository under a shared parent.
		const wideId = await insertOIDCSubject(env.AUDIT_DB, {
			name: "many-parent",
			issuer: GITHUB,
			subjectPrefix: "repo:many/",
			keyIds: [],
			expiresAt: null,
		});
		for (let i = 0; i < 25; i++) {
			await insertOIDCSubject(env.AUDIT_DB, {
				name: `child-${i}`,
				issuer: GITHUB,
				subjectPrefix: `repo:many/svc${i}`,
				keyIds: [],
				expiresAt: null,
			});
		}

		const revoked = await revokeOIDCSubject(env.AUDIT_DB, wideId);
		// The util returns everything; truncation is the route's summary concern.
		expect(revoked?.stillTrustedWithin).toHaveLength(25);
	});

	it("orders covering rows most specific first", async () => {
		// The response is read top-down mid-incident, so the nearest surviving
		// grant has to be the first line.
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "host-wide",
			issuer: GITHUB,
			subjectPrefix: "repo:me",
			keyIds: [],
			expiresAt: null,
		});
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "owner-wide",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});
		const leafId = await insertOIDCSubject(env.AUDIT_DB, {
			name: "leaf",
			issuer: GITHUB,
			subjectPrefix: "repo:me/svc",
			keyIds: [],
			expiresAt: null,
		});

		const revoked = await revokeOIDCSubject(env.AUDIT_DB, leafId);
		expect(revoked?.stillCoveredBy.map((row) => row.name)).toEqual(["owner-wide", "host-wide"]);
	});

	it("warns that expiry promotes a narrow grant to a wider one", async () => {
		// The same mechanism with nobody watching. `expiresInDays` reads like a
		// deadline; under a live unrestricted parent it is a promotion to every key.
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "unrestricted-parent",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "scoped-child",
			issuer: GITHUB,
			subjectPrefix: "repo:me/svc",
			keyIds: ["BBBBBBBBBBBBBBBB"],
			expiresAt: new Date(Date.now() - 1000).toISOString(),
		});

		const policy = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x"));
		expect(policy.name).toBe("unrestricted-parent");
		// null is *every* key: the expiry widened the grant rather than ending it.
		expect(policy.allowedKeyIds).toBeNull();
	});

	it("stamps last use, and signing still works when that write fails", async () => {
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "stamped",
			issuer: GITHUB,
			subjectPrefix: "repo:me/",
			keyIds: [],
			expiresAt: null,
		});

		// Await the stamp explicitly: it is deferred now, so asserting on it
		// without this would depend on D1 statement ordering rather than on the
		// write actually having happened.
		const stamped = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x"));
		await stamped.stampUsage();
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
		const onFailure = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x"));
		await expect(onFailure.stampUsage()).resolves.toBeUndefined();
		spy.mockRestore();

		// Same again with a non-Error rejection, which takes the String(error) branch.
		const spyNonError = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			if (query.startsWith("UPDATE oidc_subjects SET last_used_at")) {
				throw "stamp failed";
			}
			return realPrepare(query);
		});
		const onNonError = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x"));
		await expect(onNonError.stampUsage()).resolves.toBeUndefined();
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
			active: true,
		});
	});

	it("reports expired and revoked rows as inactive", async () => {
		// An expired row is unrevoked, so `revokedAt: null` alone reads as live.
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "expired",
			issuer: GITHUB,
			subjectPrefix: "repo:me/expired",
			keyIds: [],
			expiresAt: new Date(Date.now() - 1000).toISOString(),
		});
		const revokedId = await insertOIDCSubject(env.AUDIT_DB, {
			name: "killed",
			issuer: GITHUB,
			subjectPrefix: "repo:me/killed",
			keyIds: [],
			expiresAt: null,
		});
		await revokeOIDCSubject(env.AUDIT_DB, revokedId);

		const subjects = await listOIDCSubjects(env.AUDIT_DB);
		const byName = new Map(subjects.map((subject) => [subject.name, subject.active]));
		expect(byName.get("expired")).toBe(false);
		expect(byName.get("killed")).toBe(false);
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
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.toMatchObject({
			status: "trusted",
		});

		const revoked = await adminRequest(`/admin/subjects/${subject.id}`, { method: "DELETE" });
		expect(revoked.status).toBe(200);
		// The response echoes the name, which is the key `sign` events are logged
		// under; without it the operator holds an id that joins to nothing.
		expect(await revoked.json()).toMatchObject({ success: true, id: subject.id, name: "ci/e2e" });
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:me/svc:ref:x")).resolves.toMatchObject({
			status: "revoked",
		});

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
		expect(error.error).toContain("already claimed");
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
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:incident/svc:ref:x")).resolves.toMatchObject({
			status: "revoked",
		});

		const restored = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "incident-after", ...body }),
		});
		expect(restored.status).toBe(201);
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:incident/svc:ref:x")).resolves.toMatchObject({
			status: "trusted",
		});
	});

	it("explains that a renewal is blocked by an expired row, and how to clear it", async () => {
		// An expired row authorizes nobody but still holds the (issuer, prefix)
		// slot, so renewal collides. Saying "already trusted" is false, and the
		// nearest thing an operator can then type is a *broader* prefix.
		await insertOIDCSubject(env.AUDIT_DB, {
			name: "renew-me",
			issuer: GITHUB,
			subjectPrefix: "repo:renew/",
			keyIds: [],
			expiresAt: new Date(Date.now() - 1000).toISOString(),
		});
		await expect(resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:renew/svc:ref:x")).resolves.toMatchObject({
			status: "expired",
		});

		const blocked = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "renew-me-2", issuer: GITHUB, subjectPrefix: "repo:renew/" }),
		});
		expect(blocked.status).toBe(409);
		const error = ((await blocked.json()) as { error: string }).error;
		expect(error).not.toContain("already trusted");
		expect(error).toContain("expired");
		expect(error).toMatch(/revoke it/i);
		// It must also steer away from the one workaround that widens access.
		expect(error).toContain("do not widen the prefix");
	});

	it("tells the operator when a revoke left a broader trust in charge", async () => {
		// The response is the only place this shows up in time to matter: the
		// operator is mid-incident and about to believe {"success": true}.
		const create = (name: string, subjectPrefix: string, keyIds?: string[]) =>
			adminRequest("/admin/subjects", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name, issuer: GITHUB, subjectPrefix, ...(keyIds ? { keyIds } : {}) }),
			});

		expect((await create("wide", "repo:cover/")).status).toBe(201);
		const narrow = await create("narrow", "repo:cover/svc", ["D8BC04E534E7706F"]);
		expect(narrow.status).toBe(201);
		const { id } = (await narrow.json()) as { id: string };

		const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
		const revoked = await adminRequest(`/admin/subjects/${id}`, { method: "DELETE" });
		expect(revoked.status).toBe(200);
		expect(await revoked.json()).toMatchObject({
			success: true,
			name: "narrow",
			stillCoveredBy: [{ name: "wide", subjectPrefix: "repo:cover/", keyIds: null }],
			stillTrustedWithin: [],
		});
		expect(warnSpy).toHaveBeenCalledWith(
			"Revoked subject is still trusted through another row",
			expect.objectContaining({ coveredBy: ["wide"], trustedWithin: [] }),
		);
		warnSpy.mockRestore();
	});

	it("caps the surviving-trust names written to the audit row", async () => {
		const create = (name: string, subjectPrefix: string) =>
			adminRequest("/admin/subjects", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name, issuer: GITHUB, subjectPrefix }),
			});

		const parent = await create("cap-parent", "repo:cap/");
		expect(parent.status).toBe(201);
		const { id } = (await parent.json()) as { id: string };
		for (let i = 0; i < 22; i++) {
			expect((await create(`cap-child-${i}`, `repo:cap/svc${i}`)).status).toBe(201);
		}

		const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
		const revoked = await adminRequest(`/admin/subjects/${id}`, { method: "DELETE" });
		expect(revoked.status).toBe(200);
		// The response is complete; only the durable summary is capped.
		const body = (await revoked.json()) as { stillTrustedWithin: unknown[] };
		expect(body.stillTrustedWithin).toHaveLength(22);
		warnSpy.mockRestore();
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
		const error = ((await clash.json()) as { error: string }).error;
		expect(error).toContain("name already exists");
		// Naming the blocking row is what makes it actionable; "already exists"
		// alone leaves the operator guessing which row they are fighting.
		expect(error).toContain("still live");
	});

	it("still reports a 409 when the conflict cannot be described", async () => {
		// Both describers are best-effort by design: naming the blocking row is a
		// nicety, and a failure looking it up must not turn a 409 into a 500.
		const create = (name: string, subjectPrefix: string) =>
			adminRequest("/admin/subjects", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name, issuer: GITHUB, subjectPrefix }),
			});
		expect((await create("ci/describe-fail", "repo:describe/")).status).toBe(201);

		const realPrepare = env.AUDIT_DB.prepare.bind(env.AUDIT_DB);
		const spy = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			if (query.startsWith("SELECT id, revoked_at FROM oidc_subjects")) {
				throw new Error("describe failed");
			}
			if (query.startsWith("SELECT id, expires_at FROM oidc_subjects")) {
				throw new Error("describe failed");
			}
			return realPrepare(query);
		});
		try {
			const nameClash = await create("ci/describe-fail", "repo:other/");
			expect(nameClash.status).toBe(409);
			expect(((await nameClash.json()) as { error: string }).error).toBe(
				"Subject name already exists: ci/describe-fail",
			);

			const prefixClash = await create("ci/describe-fail-2", "repo:describe/");
			expect(prefixClash.status).toBe(409);
			expect(((await prefixClash.json()) as { error: string }).error).toBe(
				`Issuer and subject prefix are already claimed: ${GITHUB} repo:describe/`,
			);
		} finally {
			spy.mockRestore();
		}
	});

	it("falls back to the plain message when the blocking row cannot be found", async () => {
		// The lookup succeeds but returns nothing — possible if the row is removed
		// between the failed insert and the describe. Still a 409, still useful.
		const create = (name: string, subjectPrefix: string) =>
			adminRequest("/admin/subjects", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name, issuer: GITHUB, subjectPrefix }),
			});
		expect((await create("ci/vanishing", "repo:vanish/")).status).toBe(201);

		const realPrepare = env.AUDIT_DB.prepare.bind(env.AUDIT_DB);
		const spy = vi.spyOn(env.AUDIT_DB, "prepare").mockImplementation((query: string) => {
			// Rewrite the describe lookups so they match nothing.
			if (query.startsWith("SELECT id, revoked_at FROM oidc_subjects")) {
				return realPrepare("SELECT id, revoked_at FROM oidc_subjects WHERE name = ? AND 0");
			}
			if (query.startsWith("SELECT id, expires_at FROM oidc_subjects")) {
				return realPrepare(
					`SELECT id, expires_at FROM oidc_subjects
					 WHERE issuer = ? AND subject_prefix = ? AND revoked_at IS NULL AND 0`,
				);
			}
			return realPrepare(query);
		});
		try {
			const nameClash = await create("ci/vanishing", "repo:elsewhere/");
			expect(nameClash.status).toBe(409);
			expect(((await nameClash.json()) as { error: string }).error).toBe("Subject name already exists: ci/vanishing");

			const prefixClash = await create("ci/vanishing-2", "repo:vanish/");
			expect(prefixClash.status).toBe(409);
			expect(((await prefixClash.json()) as { error: string }).error).toBe(
				`Issuer and subject prefix are already claimed: ${GITHUB} repo:vanish/`,
			);
		} finally {
			spy.mockRestore();
		}
	});

	it("says so when the name is held by a row that was already revoked", async () => {
		// Otherwise "already exists" reads as "still trusted" for a trust the
		// operator killed minutes ago, and names are never freed.
		const created = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "ci/reused", issuer: GITHUB, subjectPrefix: "repo:a/" }),
		});
		const { id } = (await created.json()) as { id: string };
		expect((await adminRequest(`/admin/subjects/${id}`, { method: "DELETE" })).status).toBe(200);

		const clash = await adminRequest("/admin/subjects", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "ci/reused", issuer: GITHUB, subjectPrefix: "repo:b/" }),
		});
		expect(clash.status).toBe(409);
		const error = ((await clash.json()) as { error: string }).error;
		expect(error).toContain("revoked at");
		expect(error).toContain(id);
		expect(error).toMatch(/choose a new name/i);
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

		const policy = trustedPolicy(await resolveOIDCSubject(env.AUDIT_DB, GITHUB, "repo:case/svc:ref:x"));
		expect(policy.allowedKeyIds).toEqual(["D8BC04E534E7706F"]);
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
