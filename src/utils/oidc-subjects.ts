/**
 * Trusted OIDC subjects: which verified CI identities may sign, and with which
 * keys.
 *
 * A verified OIDC token proves only "some workflow, on an issuer we accept,
 * asked for our audience". Both issuers we accept are shared —
 * token.actions.githubusercontent.com covers every repository on GitHub
 * Actions, gitlab.com every project there — and the audience is public, so
 * that proves nothing about *who* is calling. This module is the authorization
 * half: a row per trusted identity, mirroring `service-tokens.ts` so an OIDC
 * caller is revocable, expirable and key-scoped like any other credential.
 */

import { logger } from "#utils/logger";

/** A matched subject's identity and signing policy. */
export interface OIDCSubjectPolicy {
	id: string;
	name: string;
	/** Key ids this subject may sign with; null means every key. */
	allowedKeyIds: string[] | null;
	/**
	 * Writes the last-used stamp when called. A function rather than a started
	 * promise so a caller that ignores it performs no I/O at all — a dangling
	 * promise would instead be cancelled when the response returns, losing the
	 * write with nothing logged. Already error-handled; hand it to
	 * `scheduleBackgroundTask` to keep it off the request path.
	 */
	stampUsage: () => Promise<void>;
}

/** A stored subject as returned to admins. */
export interface OIDCSubjectRecord {
	id: string;
	name: string;
	issuer: string;
	subjectPrefix: string;
	keyIds: string[] | null;
	createdAt: string;
	expiresAt: string | null;
	revokedAt: string | null;
	lastUsedAt: string | null;
	/** True when the row is neither revoked nor expired, i.e. it can authorize now. */
	active: boolean;
}

interface OIDCSubjectRow {
	id: string;
	name: string;
	issuer: string;
	subject_prefix: string;
	key_ids: string;
	created_at: string;
	expires_at: string | null;
	revoked_at: string | null;
	last_used_at: string | null;
}

/** Characters that terminate a subject prefix in GitHub and GitLab subjects. */
const SUBJECT_DELIMITERS = new Set([":", "@", "/"]);

/**
 * Does `sub` fall under `prefix`?
 *
 * The prefix must end at a delimiter or at the end of the subject, so
 * `repo:me/svc` does not also admit `repo:me/svc-evil:ref:...`. A prefix that
 * already ends at a delimiter carries its own boundary, which makes
 * `repo:me/` owner-wide while still rejecting `repo:meevil/...`.
 *
 * GitHub subjects are `repo:<owner>/<repo>:<context>`, or
 * `repo:<owner>@<ownerId>/<repo>@<repoId>:<context>` when the repository has
 * immutable subject claims enabled — the two forms are matched the same way,
 * so store whichever you intend to trust.
 *
 * @param sub - The `sub` claim from a verified token
 * @param prefix - A stored subject prefix
 * @returns true when the subject falls under the prefix
 */
export function subjectMatchesPrefix(sub: string, prefix: string): boolean {
	if (!prefix) {
		return false;
	}
	if (sub === prefix) {
		return true;
	}
	if (!sub.startsWith(prefix)) {
		return false;
	}
	if (SUBJECT_DELIMITERS.has(prefix.charAt(prefix.length - 1))) {
		return true;
	}
	return SUBJECT_DELIMITERS.has(sub.charAt(prefix.length));
}

function parseKeyIds(raw: string): string[] | null {
	const keyIds = raw
		.split(",")
		.map((keyId) => keyId.trim())
		.filter((keyId) => keyId.length > 0);
	return keyIds.length > 0 ? keyIds : null;
}

/** Persist a trusted subject. Returns the stored row's id. */
export async function insertOIDCSubject(
	db: D1Database,
	input: {
		name: string;
		issuer: string;
		subjectPrefix: string;
		keyIds: string[];
		expiresAt: string | null;
		/** Stored verbatim, so the value the API echoes is the persisted one. */
		createdAt?: string;
	},
): Promise<string> {
	const id = crypto.randomUUID();
	await db
		.prepare(
			`INSERT INTO oidc_subjects (id, name, issuer, subject_prefix, key_ids, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
		)
		.bind(
			id,
			input.name,
			input.issuer,
			input.subjectPrefix,
			input.keyIds.join(","),
			input.createdAt ?? new Date().toISOString(),
			input.expiresAt,
		)
		.run();
	return id;
}

/**
 * Resolve a verified token's issuer and subject to a signing policy.
 *
 * Returns null when nothing matches, which callers must treat as a refusal:
 * an empty table denies everyone rather than admitting everyone.
 *
 * Where several prefixes match, the longest (most specific) wins, so a
 * narrow `repo:owner/repo` row can grant different keys than a broad
 * `repo:owner/` row covering the rest.
 *
 * @param db - Audit/policy database
 * @param issuer - Verified `iss` claim
 * @param sub - Verified `sub` claim
 * @returns The matching subject's policy, or null
 */
export async function resolveOIDCSubject(
	db: D1Database,
	issuer: string,
	sub: string,
): Promise<OIDCSubjectPolicy | null> {
	// Filter by issuer in SQL; the delimiter rule cannot be expressed there, so
	// candidate prefixes are matched in application code.
	const { results } = await db
		.prepare(
			`SELECT id, name, issuer, subject_prefix, key_ids, created_at, expires_at, revoked_at, last_used_at
       FROM oidc_subjects
       WHERE issuer = ? AND revoked_at IS NULL`,
		)
		.bind(issuer)
		.all<OIDCSubjectRow>();

	const now = Date.now();
	const matches = results
		.filter((row) => !row.expires_at || Date.parse(row.expires_at) >= now)
		.filter((row) => subjectMatchesPrefix(sub, row.subject_prefix))
		.sort((a, b) => b.subject_prefix.length - a.subject_prefix.length);

	const row = matches[0];
	if (!row) {
		return null;
	}

	// Best-effort usage stamp, deferred rather than awaited: this sits on the
	// critical path of every signed commit, and the caller can hand it to
	// waitUntil so the write costs nothing. Failures are swallowed here so a
	// caller that does await it still cannot be blocked by one.
	const stampUsage = async () => {
		try {
			await db
				.prepare("UPDATE oidc_subjects SET last_used_at = ? WHERE id = ?")
				.bind(new Date().toISOString(), row.id)
				.run();
		} catch (error) {
			logger.warn("Failed to stamp OIDC subject usage", {
				subjectId: row.id,
				error: error instanceof Error ? error.message : String(error),
			});
		}
	};

	return {
		id: row.id,
		name: row.name,
		allowedKeyIds: parseKeyIds(row.key_ids),
		stampUsage,
	};
}

/** List all trusted subjects, newest first. */
export async function listOIDCSubjects(db: D1Database): Promise<OIDCSubjectRecord[]> {
	const { results } = await db
		.prepare(
			`SELECT id, name, issuer, subject_prefix, key_ids, created_at, expires_at, revoked_at, last_used_at
       FROM oidc_subjects ORDER BY created_at DESC`,
		)
		.all<OIDCSubjectRow>();

	const now = Date.now();
	return results.map((row) => ({
		id: row.id,
		name: row.name,
		issuer: row.issuer,
		subjectPrefix: row.subject_prefix,
		keyIds: parseKeyIds(row.key_ids),
		createdAt: row.created_at,
		expiresAt: row.expires_at,
		revokedAt: row.revoked_at,
		lastUsedAt: row.last_used_at,
		// Same test `resolveOIDCSubject` applies, so the list cannot disagree with
		// what the sign path will actually do.
		active: !row.revoked_at && (!row.expires_at || Date.parse(row.expires_at) >= now),
	}));
}

/**
 * Revoke a subject by id.
 *
 * Returns the revoked row's name, or null when the id is unknown or already
 * revoked. The name rather than a bare boolean because `sign` events are keyed
 * by name (`metadata.subjectPolicy`) while the revoke is keyed by id: without
 * returning it here, no audit event carries both identifiers and "what did the
 * trust I just revoked sign?" needs a join against `oidc_subjects` mid-incident.
 *
 * @param db - Audit/policy database
 * @param id - Row id to revoke
 * @returns The revoked row's name, or null
 */
export async function revokeOIDCSubject(db: D1Database, id: string): Promise<string | null> {
	const row = await db
		.prepare("UPDATE oidc_subjects SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING name")
		.bind(new Date().toISOString(), id)
		.first<{ name: string }>();
	return row?.name ?? null;
}
