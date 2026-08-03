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

/**
 * Why a subject was refused, or the policy that admitted it.
 *
 * The three refusal reasons are deliberately distinct. An unknown subject is
 * noise — both issuers are shared with every repository on their platform, so
 * strangers arrive unprompted. A *revoked* row still being presented is the
 * opposite: it means a credential someone deliberately killed is still in use,
 * which is the incident the revoke button exists for. Collapsing them into one
 * null files the incident under the noise.
 */
export type OIDCSubjectResolution =
	| { status: "trusted"; policy: OIDCSubjectPolicy }
	| { status: "unknown" }
	| { status: "revoked"; id: string; name: string; revokedAt: string }
	| { status: "expired"; id: string; name: string; expiresAt: string };

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
	// A token with no `sub` is a malformed credential, not a service fault. Both
	// real issuers always set it, but ALLOWED_ISSUERS is configurable, and
	// `sub.startsWith` on undefined throws — which the caller's catch would file
	// as "authorization store unavailable", a 503 and an alert for what is a 401.
	if (typeof sub !== "string" || !sub) {
		return false;
	}
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
 * Anything but `trusted` is a refusal: an empty table denies everyone rather
 * than admitting everyone. The refusal carries *why*, because a revoked
 * credential still being presented and a stranger arriving on a shared issuer
 * warrant very different reactions.
 *
 * Where several prefixes match, the longest (most specific) wins, so a
 * narrow `repo:owner/repo` row can grant different keys than a broad
 * `repo:owner/` row covering the rest. A live row always beats a dead one, so a
 * revoked narrow row cannot shadow a live broad one that still covers the
 * subject.
 *
 * @param db - Audit/policy database
 * @param issuer - Verified `iss` claim
 * @param sub - Verified `sub` claim
 * @returns The matching subject's policy, or the reason it was refused
 */
export async function resolveOIDCSubject(db: D1Database, issuer: string, sub: string): Promise<OIDCSubjectResolution> {
	// Filter by issuer in SQL; the delimiter rule cannot be expressed there, so
	// candidate prefixes are matched in application code. Revoked and expired
	// rows are selected too — not to honour them, but so a refusal can say which
	// of the three it is.
	const { results } = await db
		.prepare(
			`SELECT id, name, issuer, subject_prefix, key_ids, created_at, expires_at, revoked_at, last_used_at
       FROM oidc_subjects
       WHERE issuer = ?`,
		)
		.bind(issuer)
		.all<OIDCSubjectRow>();

	const now = Date.now();
	const matches = results
		.filter((candidate) => subjectMatchesPrefix(sub, candidate.subject_prefix))
		.sort((a, b) => b.subject_prefix.length - a.subject_prefix.length);

	const isLive = (candidate: OIDCSubjectRow) =>
		!candidate.revoked_at && (!candidate.expires_at || Date.parse(candidate.expires_at) >= now);

	const row = matches.find(isLive);
	if (!row) {
		// No live row. Report the most specific dead match so the log names the
		// credential actually being presented, preferring a revoked row over an
		// expired one: expiry is routine, revocation was a decision.
		const revoked = matches.find((candidate) => candidate.revoked_at);
		if (revoked?.revoked_at) {
			return { status: "revoked", id: revoked.id, name: revoked.name, revokedAt: revoked.revoked_at };
		}
		const expired = matches[0];
		if (expired?.expires_at) {
			return { status: "expired", id: expired.id, name: expired.name, expiresAt: expired.expires_at };
		}
		return { status: "unknown" };
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
		status: "trusted",
		policy: {
			id: row.id,
			name: row.name,
			allowedKeyIds: parseKeyIds(row.key_ids),
			stampUsage,
		},
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

/** A row that still authorizes a subject after a narrower one was revoked. */
export interface CoveringSubject {
	id: string;
	name: string;
	subjectPrefix: string;
	/** Key ids the surviving row grants; null means every key. */
	keyIds: string[] | null;
}

/** Outcome of a revoke, including what the revoked identity can still do. */
export interface RevokedSubject {
	name: string;
	/**
	 * Live rows whose prefix *covers* the revoked one, most specific first. The
	 * whole revoked scope keeps signing, under these rows' grants.
	 */
	stillCoveredBy: CoveringSubject[];
	/**
	 * Live rows *nested under* the revoked prefix, broadest first — each is a
	 * separate hole in the scope just revoked, so the widest one matters most.
	 * Revoking a parent does not touch its children, so part of the revoked scope
	 * keeps signing. Only when both lists are empty was the revoke final.
	 */
	stillTrustedWithin: CoveringSubject[];
}

/**
 * Revoke a subject by id.
 *
 * Returns null when the id is unknown or already revoked.
 *
 * The name comes back because `sign` events are keyed by name
 * (`metadata.subjectPolicy`) while the revoke is keyed by id: without it, no
 * audit event carries both identifiers and "what did the trust I just revoked
 * sign?" needs a join against `oidc_subjects` mid-incident.
 *
 * The two coverage lists come back because revoke is not subtraction, in either
 * direction. Resolution takes the longest *live* prefix, so killing a narrow row
 * promotes the next one up — **with that row's key grant**, which may be wider
 * than the one just removed, and is unrestricted when the surviving row pins no
 * keys. Revoking `repo:me/svc` (keys: BBBB) under a live `repo:me/` (keys: none)
 * leaves that repository signing with *every* key. Killing the *broad* row is
 * the mirror image: rows nested underneath it are untouched, so part of the
 * scope the operator meant to cut keeps signing. Answering a bare success — or
 * worse, an empty list that reads as "final" — is how "revoked, still signing"
 * gets missed during an incident.
 *
 * @param db - Audit/policy database
 * @param id - Row id to revoke
 * @returns The revoked row's name and anything still trusted, or null
 */
export async function revokeOIDCSubject(db: D1Database, id: string): Promise<RevokedSubject | null> {
	const row = await db
		.prepare(
			`UPDATE oidc_subjects SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
       RETURNING name, issuer, subject_prefix`,
		)
		.bind(new Date().toISOString(), id)
		.first<{ name: string; issuer: string; subject_prefix: string }>();

	if (!row) {
		return null;
	}

	const { results } = await db
		.prepare(
			`SELECT id, name, subject_prefix, key_ids, expires_at FROM oidc_subjects
       WHERE issuer = ? AND revoked_at IS NULL AND id != ?`,
		)
		.bind(row.issuer, id)
		.all<{ id: string; name: string; subject_prefix: string; key_ids: string; expires_at: string | null }>();

	const now = Date.now();
	const live = results.filter((candidate) => !candidate.expires_at || Date.parse(candidate.expires_at) >= now);
	const bySpecificity = (a: { subject_prefix: string }, b: { subject_prefix: string }) =>
		b.subject_prefix.length - a.subject_prefix.length;
	const toCovering = (candidate: (typeof live)[number]): CoveringSubject => ({
		id: candidate.id,
		name: candidate.name,
		subjectPrefix: candidate.subject_prefix,
		keyIds: parseKeyIds(candidate.key_ids),
	});

	// Ancestors: rows whose prefix covers the revoked one, so the identity keeps
	// signing outright under their grant. `subjectMatchesPrefix` in this direction
	// finds `repo:me/` for `repo:me/svc`, and excludes siblings like
	// `repo:me/other`.
	const stillCoveredBy = live
		.filter((candidate) => subjectMatchesPrefix(row.subject_prefix, candidate.subject_prefix))
		.sort(bySpecificity)
		.map(toCovering);

	// Descendants: rows nested *under* the revoked prefix, which revoking the
	// parent does not touch. Same "revoked, still signing" state, reached by
	// killing the broad row instead of the narrow one — and reporting only
	// ancestors would answer with an empty list, which reads as "final". The two
	// lists are disjoint: the live-unique index forbids two live rows sharing a
	// prefix, so no row can be both.
	//
	// Sorted *broadest* first, the opposite of the ancestor list. These rows do
	// not compete for one resolution; each carves a piece out of the scope the
	// operator just tried to cut, so the top line should be the biggest remaining
	// hole. Longest-first would lead with a single repository and bury a
	// team-wide row under it.
	const stillTrustedWithin = live
		.filter((candidate) => subjectMatchesPrefix(candidate.subject_prefix, row.subject_prefix))
		.sort((a, b) => a.subject_prefix.length - b.subject_prefix.length)
		.map(toCovering);

	return { name: row.name, stillCoveredBy, stillTrustedWithin };
}
