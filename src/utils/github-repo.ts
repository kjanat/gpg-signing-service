/**
 * The GitHub API, reachable only for the repository an operator authorized.
 *
 * `#utils/github-app` pins the *host*. This pins the *subject*: a client is
 * constructed from a `repository`-scoped {@link WebhookAuthorization} and the
 * `owner/repo` in its path comes from that decision — which is the operator's
 * spelling out of the allowlist, never `payload.repository.full_name`. There is
 * no function here that takes a repository argument, and that absence is the
 * mechanism: a handler holding this client cannot address another repository,
 * whatever the delivery says, because there is no parameter through which to
 * say it.
 *
 * The installation id is bound the same way and for the same reason. A token is
 * minted for the installation the *allowlist* paired with this repository, so a
 * delivery cannot present repository R with installation A's id and be handed
 * A's authority over R.
 *
 * Everything else this module does is a consequence of those two bindings:
 *
 * - **The host stays pinned.** Every path goes through `githubApiUrl`, so a
 *   path that resolves off `api.github.com` throws rather than dials.
 * - **The token is a bearer credential and is treated as one.** It is passed
 *   in a header and never logged, never put in an error message, never returned.
 *   An error from here carries a method, a path shape and a status.
 * - **Responses are parsed, not cast.** What comes back decides which bytes get
 *   signed, so a field that is missing or the wrong type is an error rather than
 *   an `undefined` that reaches a commit payload.
 */

import { z } from "@hono/zod-openapi";

import type { Env, WebhookAuthorization } from "#types";
import { TIME } from "#types";
import type { ReportedVerification } from "#utils/commit-signature";
import { fetchWithTimeout } from "#utils/fetch";
import type { CommitIdentity, CommitOffsets, CommitReconstruction } from "#utils/git-commit";
import { isoWithOffset, recoverCommitObject } from "#utils/git-commit";
import { getInstallationToken, githubApiUrl } from "#utils/github-app";

/** How long any single GitHub call may take. */
const GITHUB_TIMEOUT = 10 * TIME.SECOND;

/**
 * A GitHub call that did not go the way it needed to.
 *
 * Carries a status and the operation, and never the response body. A body from
 * this API can quote back the request that produced it — which for us contains
 * an installation token — and no diagnosis worth having needs it.
 */
export class GitHubApiError extends Error {
	readonly status: number | null;

	constructor(message: string, status: number | null = null, options: { cause?: unknown } = {}) {
		super(message, options);
		this.name = "GitHubApiError";
		this.status = status;
	}
}

/** What GitHub said about one login's access, and whether it said anything. */
export interface ActorPermission {
	/** The legacy base role GitHub reports, or `none`. */
	permission: "admin" | "write" | "read" | "none";
	/**
	 * Whether GitHub answered with a permission at all.
	 *
	 * False only for a 404 on a repository this installation can still see: that
	 * login is not a collaborator here. True whenever a body came back, including
	 * one naming a role this service does not recognise — which decides the same
	 * way, and is not the same sentence in an audit row.
	 */
	collaborator: boolean;
}

/**
 * The installation can no longer see the repository it is bound to.
 *
 * Its own type because it is the one GitHub failure on this path that is not a
 * fact about the *user* being asked about. A caller that flattened it into an
 * ordinary lookup failure would still fail closed, which is why this is a
 * subclass and not a separate return channel; what it would lose is the ability
 * to say so in an audit row, and "the App was removed from this repository" and
 * "GitHub was having a bad minute" send an operator to different places.
 */
export class RepositoryNotVisibleError extends GitHubApiError {
	constructor(message: string, status: number | null = null) {
		super(message, status);
		this.name = "RepositoryNotVisibleError";
	}
}

/** A commit as the Git Data API returns it, reduced to the fields that matter. */
const IdentitySchema = z.object({
	name: z.string().min(1),
	email: z.string().min(1),
	date: z.string().min(1),
});

const CommitSchema = z.object({
	sha: z.string().min(1),
	message: z.string(),
	tree: z.object({ sha: z.string().min(1) }),
	parents: z.array(z.object({ sha: z.string().min(1) })).default([]),
	author: IdentitySchema,
	committer: IdentitySchema,
	/**
	 * Present on every commit; `signature` is null when the commit carries none.
	 *
	 * Optional here rather than required, because the field's absence and a null
	 * signature must mean the same thing to {@link RepositoryClient.getCommit}'s
	 * caller — "no signature was reported" — and a schema failure would instead
	 * turn an unsigned commit into an outage.
	 */
	verification: z.object({ signature: z.string().nullable() }).optional(),
});

const RefSchema = z.object({
	ref: z.string().min(1),
	object: z.object({ sha: z.string().min(1) }),
});

/**
 * A commit reduced to what GitHub says about its signature.
 *
 * Every field of `verification` is optional and defaulted, and the whole object
 * is too, because the absence of a field and an unsigned commit have to mean
 * the same thing here — "no signature was reported". A schema failure would
 * instead turn an unsigned commit, or a field GitHub adds later, into an outage
 * on a reporting path.
 */
const VerificationSchema = z.object({
	sha: z.string().min(1),
	verification: z
		.object({
			verified: z.boolean().default(false),
			reason: z.string().nullable().default(null),
			signature: z.string().nullable().default(null),
			payload: z.string().nullable().default(null),
		})
		.optional(),
});

/**
 * A check run, reduced to what deciding "is this one ours" needs.
 *
 * `app` is nullable in GitHub's schema, and a run with no app is not this App's
 * — so a null reads as "somebody else's" rather than as a match.
 */
const CheckRunSchema = z.object({
	id: z.number().int().positive(),
	name: z.string(),
	app: z.object({ id: z.number().int() }).nullable().optional(),
});

const CheckRunListSchema = z.object({
	check_runs: z.array(CheckRunSchema).default([]),
});

/**
 * A collaborator's permission on this repository, as GitHub states it.
 *
 * `permission` is the *legacy base role* — `admin`, `write`, `read`, `none` —
 * and that is the field to read rather than `role_name`. GitHub collapses
 * `maintain` into `write` and `triage` into `read` here, and it collapses
 * custom roles onto whichever base role they were built from, so this is a
 * closed set of four values with a defined meaning. `role_name` is open-ended:
 * an organisation may call a role anything, and a check written against it
 * would be a check against strings an org admin can invent.
 *
 * `user` is nullable in GitHub's schema and is read anyway, because the caller
 * compares the login that comes back against the one it asked about — the same
 * discipline the check reporter applies to a sha. An answer about somebody else
 * is not an answer.
 */
const CollaboratorPermissionSchema = z.object({
	permission: z.string().min(1),
	user: z
		.object({ login: z.string().min(1) })
		.nullable()
		.optional(),
});

/** A commit, as this service needs to see one. */
export interface RepositoryCommit {
	sha: string;
	/**
	 * The message the stored object holds, not the one the JSON reported.
	 *
	 * `GET /git/commits/{sha}` strips a trailing newline from the message, and
	 * `git commit` writes one on every message it makes — so for most commits in
	 * most repositories those two strings differ by a byte, and the JSON gives no
	 * way to tell which case you are in. {@link recoverCommitObject} tells, by
	 * reproducing the sha, and this is the representation that reproduced it.
	 *
	 * There is deliberately no second field holding the API's version. This is
	 * *the* message: the bytes to sign, and the bytes to hand back to
	 * create-a-commit. A caller that reached for the other one would sign a
	 * message the author did not write, and the round-trip id check could not
	 * catch it — both sides of that comparison would have started from the same
	 * stripped string.
	 *
	 * When `offsets` is null nothing was proven and this is the API's message
	 * unchanged, which is safe because a commit with null offsets is never
	 * rewritten.
	 */
	message: string;
	tree: string;
	parents: string[];
	author: CommitIdentity;
	committer: CommitIdentity;
	/**
	 * The `±HHMM` offsets the stored object carries, proven against `sha`.
	 *
	 * Null when they could not be proven — a signed commit, whose object holds a
	 * `gpgsig` this reconstruction does not model and is never rewritten anyway,
	 * or an unsigned one carrying something else unmodelled. Null is a refusal to
	 * rewrite, handled by `signableRun`; it is never read as "UTC".
	 */
	offsets: CommitOffsets | null;
	/**
	 * Whether the commit already carries *some* signature.
	 *
	 * Presence, not validity, and deliberately: a commit signed by a key this
	 * service does not hold is one it must not touch either, so "is there a
	 * signature" is the question that decides, and "is it good" is GitHub's to
	 * answer. See `signablePrefix` in `#utils/github-push`.
	 */
	signed: boolean;
}

/**
 * A completed check run, as this service publishes one.
 *
 * Only completed runs: this service reports a conclusion it has already
 * reached, so there is no in-progress state to model and no half-written run
 * left behind if a delivery dies.
 */
export interface CheckRunInput {
	/** A constant chosen by this service. Never anything a payload supplied. */
	name: string;
	/** The sha read back from the authorized repository's ref. */
	headSha: string;
	conclusion: "success" | "failure" | "neutral";
	title: string;
	summary: string;
	completedAt: string;
}

/**
 * The fields both endpoints take.
 *
 * `head_sha` is not among them, and is added only by the create path: the
 * update endpoint does not accept it, and a run's commit is not a thing that
 * can be edited. That asymmetry is the API's, and keeping it here means an
 * update cannot be the thing that moves a check onto another commit.
 */
function checkRunFields(input: CheckRunInput) {
	return {
		name: input.name,
		status: "completed",
		conclusion: input.conclusion,
		completed_at: input.completedAt,
		output: { title: input.title, summary: input.summary },
	};
}

/** What a `refs/heads/<name>` lookup found. */
export interface BranchRef {
	/** The full ref, e.g. `refs/heads/main`. */
	ref: string;
	/** The commit the branch points at right now. */
	sha: string;
}

/**
 * Encode a ref name for a URL path without destroying its slashes.
 *
 * `feature/x` is one ref whose path segment is `heads/feature/x`;
 * `encodeURIComponent` on the whole thing would send `heads/feature%2Fx`, which
 * is a different — and non-existent — ref. Each segment is encoded on its own
 * so the slashes survive and everything else is escaped.
 */
function encodeRefPath(ref: string): string {
	return ref
		.split("/")
		.map((segment) => encodeURIComponent(segment))
		.join("/");
}

/**
 * The author's `±HHMM` offset, read out of a `git format-patch` rendering.
 *
 * The patch representation is the one place GitHub still shows a commit's real
 * offset: `Date: Sun, 30 Aug 2026 21:05:00 +0200` for an object that says
 * `1788116700 +0200`, where every JSON rendering of the same commit says `Z`.
 *
 * The `From <sha>` sentinel is checked rather than assumed, and that check is
 * what makes this safe on a merge: asking for a merge commit's patch returns the
 * patches of the commits it merged, whose first line names one of *them*. A
 * mismatch answers null and the caller falls back to refusing, instead of
 * stamping some other commit's timezone onto this one.
 *
 * @param patch - The body of a `application/vnd.github.patch` response
 * @param sha - The commit that body was asked for
 */
export function patchAuthorOffset(patch: string, sha: string): string | null {
	const lines = patch.split("\n");

	if (lines[0] === undefined || !lines[0].startsWith(`From ${sha} `)) {
		return null;
	}

	for (const line of lines.slice(1)) {
		// The mail header block ends at the first blank line. Stopping there keeps
		// a `Date:` inside the diff body — a patch to a changelog, say — from being
		// read as the commit's own.
		if (line.trim() === "") {
			return null;
		}

		const match = /^Date:\s.*\s([+-]\d{4})$/.exec(line.trimEnd());
		if (match) {
			return match[1] as string;
		}
	}

	return null;
}

/**
 * An identity as create-a-commit takes it: ISO 8601 carrying the real offset.
 *
 * An identity with no recovered offset is sent exactly as it arrived, which is
 * the shape a caller that never went through {@link recoverCommitObject} has —
 * and the shape nothing in this service signs.
 */
function wireIdentity(identity: CommitIdentity): { name: string; email: string; date: string } {
	return {
		name: identity.name,
		email: identity.email,
		date: identity.offset === undefined ? identity.date : isoWithOffset(identity.date, identity.offset),
	};
}

/** The GitHub API bound to one authorized repository and one installation. */
export class RepositoryClient {
	private readonly env: Env;
	private readonly installationId: number;
	/** Percent-encoded `owner/repo`, built once from the operator's string. */
	private readonly repoPath: string;
	/** The un-encoded `owner/repo`, for messages. */
	readonly repository: string;

	private constructor(env: Env, installationId: number, repository: string) {
		this.env = env;
		this.installationId = installationId;
		this.repository = repository;

		const [owner, name] = repository.split("/");
		this.repoPath = `${encodeURIComponent(owner as string)}/${encodeURIComponent(name as string)}`;
	}

	/**
	 * A client for the repository this delivery was authorized to act on.
	 *
	 * Returns null for anything that is not a `repository`-scoped grant with both
	 * halves present. Null rather than a throw, because "this delivery may not
	 * touch a repository" is a routine answer — every `ping` gives it — and the
	 * caller has to branch on it either way.
	 */
	static forAuthorization(env: Env, authorization: WebhookAuthorization | undefined): RepositoryClient | null {
		if (
			authorization === undefined ||
			authorization.scope !== "repository" ||
			authorization.repository === null ||
			authorization.installationId === null
		) {
			return null;
		}

		return new RepositoryClient(env, authorization.installationId, authorization.repository);
	}

	/**
	 * A call to the pinned host, on this repository's path, as this installation.
	 *
	 * `accept` is the media type, defaulting to JSON. The one caller that overrides
	 * it is {@link RepositoryClient.authorOffsetFromPatch}, which needs the patch
	 * representation because it is the only one of GitHub's renderings that keeps
	 * a commit's timezone offset.
	 */
	private async call(
		method: string,
		path: string,
		body?: unknown,
		accept = "application/vnd.github+json",
	): Promise<Response> {
		const url = githubApiUrl(`/repos/${this.repoPath}${path}`);

		let token: string;
		try {
			token = (await getInstallationToken(this.env, this.installationId)).token;
		} catch (error) {
			// The cause is kept for Sentry and the message is not reused: a token
			// failure's message is written by `#utils/github-app`, which is careful
			// about what it says, and re-wrapping it here would be a second chance
			// to say something it decided not to.
			throw new GitHubApiError(`Could not obtain an installation token for ${this.repository}`, null, { cause: error });
		}

		try {
			return await fetchWithTimeout(
				url,
				{
					method,
					headers: {
						Authorization: `Bearer ${token}`,
						Accept: accept,
						"X-GitHub-Api-Version": "2022-11-28",
						"User-Agent": "gpg-signing-service",
						...(body === undefined ? {} : { "Content-Type": "application/json" }),
					},
					...(body === undefined ? {} : { body: JSON.stringify(body) }),
				},
				GITHUB_TIMEOUT,
			);
		} catch (error) {
			throw new GitHubApiError(`Could not reach GitHub for ${method} ${path}`, null, { cause: error });
		}
	}

	/** Parse a response, or explain what was wrong with it without quoting it. */
	private async read<T>(response: Response, schema: z.ZodType<T>, operation: string): Promise<T> {
		if (!response.ok) {
			throw new GitHubApiError(`GitHub refused ${operation} for ${this.repository}`, response.status);
		}

		let json: unknown;
		try {
			json = await response.json();
		} catch (error) {
			throw new GitHubApiError(`GitHub returned an unreadable body for ${operation}`, response.status, {
				cause: error,
			});
		}

		const parsed = schema.safeParse(json);
		if (!parsed.success) {
			// The issues, not the document. A GitHub response can echo request
			// content, and this path is reached precisely when the document is not
			// the shape we expected — which is the worst moment to log it whole.
			throw new GitHubApiError(
				`GitHub returned an unexpected shape for ${operation} (${parsed.error.issues.length} field(s))`,
				response.status,
			);
		}

		return parsed.data;
	}

	/** Where a branch points right now. Null when the branch does not exist. */
	async getBranch(branch: string): Promise<BranchRef | null> {
		const response = await this.call("GET", `/git/ref/heads/${encodeRefPath(branch)}`);

		if (response.status === 404) {
			return null;
		}

		const ref = await this.read(response, RefSchema, "a branch lookup");

		return { ref: ref.ref, sha: ref.object.sha };
	}

	/**
	 * One commit object, with the timezone offsets this API does not report.
	 *
	 * The JSON is the source for everything except the two offsets and the exact
	 * message bytes, both of which it renders away — the offsets to `Z`
	 * unconditionally, the message by stripping a trailing newline. Both are
	 * recovered together by reproducing the object id — see
	 * {@link recoverCommitObject} — and the patch representation is consulted only
	 * when that fails, which happens when a commit's author and committer offsets
	 * differ. So the common commit costs exactly the request it always cost, and
	 * the unusual one costs a second read rather than a wrong answer.
	 *
	 * What comes back is the reconstruction's message, never the response's. The
	 * two are the same string for a commit whose message had no trailing newline
	 * and differ by that byte for every commit `git commit` made, and the whole
	 * reason to reproduce the sha is that only the reproduction knows which.
	 *
	 * Signed commits are not reproduced at all: their object carries a `gpgsig`,
	 * so no reconstruction of ours can match their sha, and they are never
	 * rewritten. Skipping them turns what would be a guaranteed-failing search
	 * plus a wasted patch fetch into nothing.
	 */
	async getCommit(sha: string): Promise<RepositoryCommit> {
		const response = await this.call("GET", `/git/commits/${encodeURIComponent(sha)}`);
		const commit = await this.read(response, CommitSchema, "a commit lookup");

		const signed = typeof commit.verification?.signature === "string";

		const object = {
			tree: commit.tree.sha,
			parents: commit.parents.map((parent) => parent.sha),
			author: commit.author,
			committer: commit.committer,
			message: commit.message,
		};

		let reconstruction: CommitReconstruction | null = null;
		if (!signed) {
			reconstruction = await recoverCommitObject(object, commit.sha);

			if (reconstruction === null) {
				const authorOffset = await this.authorOffsetFromPatch(commit.sha);
				if (authorOffset !== null) {
					reconstruction = await recoverCommitObject(object, commit.sha, authorOffset);
				}
			}
		}

		const offsets: CommitOffsets | null = reconstruction === null ? null : reconstruction.offsets;

		return {
			sha: commit.sha,
			// The proven bytes when there are any. Falling back to the response's
			// message costs nothing, because `signableRun` refuses every commit whose
			// offsets are null before one of them is signed.
			message: reconstruction === null ? commit.message : reconstruction.message,
			tree: object.tree,
			parents: object.parents,
			author: offsets === null ? commit.author : { ...commit.author, offset: offsets.author },
			committer: offsets === null ? commit.committer : { ...commit.committer, offset: offsets.committer },
			offsets,
			signed,
		};
	}

	/**
	 * What GitHub reports about one commit's signature.
	 *
	 * Deliberately not folded into {@link RepositoryClient.getCommit}, which
	 * reconstructs an object in order to *rewrite* it and skips signed commits
	 * for exactly that reason. This asks the opposite question — what is on the
	 * commit already — so it is a separate read with a separate schema, and the
	 * signing path is unchanged by its existence.
	 *
	 * The `sha` that comes back is GitHub's own for the object, and the caller
	 * compares it against the one it asked for: an abbreviated or otherwise
	 * indirect reference must not be allowed to resolve to a different commit
	 * than the one being reported on.
	 */
	async getCommitVerification(sha: string): Promise<ReportedVerification> {
		const response = await this.call("GET", `/git/commits/${encodeURIComponent(sha)}`);
		const commit = await this.read(response, VerificationSchema, "a commit signature lookup");

		return {
			sha: commit.sha,
			signature: commit.verification?.signature ?? null,
			payload: commit.verification?.payload ?? null,
			verified: commit.verification?.verified ?? false,
			reason: commit.verification?.reason ?? null,
		};
	}

	/**
	 * This App's check runs named `name` on `sha`, oldest first.
	 *
	 * Filtered to `appId` here rather than trusted from the query: the endpoint
	 * lists every app's runs, `check_name` is not unique across apps, and a
	 * client that took the first match would try to update a run belonging to
	 * somebody else — which GitHub refuses, so the visible failure would be a
	 * 403 on a path that should have created its own run instead. `app_id` is
	 * *also* sent, so a page of somebody else's runs cannot crowd ours out of the
	 * first hundred; the local filter is what decides, the query is what narrows.
	 *
	 * `filter=all` is not optional. This endpoint defaults to `filter=latest`,
	 * which answers with the most recent run per name — which is precisely the
	 * answer that hides the older duplicate a create race can leave behind, and
	 * so the answer that makes the ordering rule below unable to do the one job
	 * it exists for.
	 *
	 * Sorted by id, which is monotonic, so "the earliest one" is a stable choice
	 * that two callers reach independently. That is what makes convergence
	 * possible without a lock: if a race ever does produce two, every later
	 * report picks the same one of them.
	 */
	async listCheckRuns(sha: string, name: string, appId: number): Promise<{ id: number }[]> {
		const response = await this.call(
			"GET",
			`/commits/${encodeURIComponent(sha)}/check-runs?check_name=${encodeURIComponent(name)}&filter=all&app_id=${appId}&per_page=100`,
		);
		const listed = await this.read(response, CheckRunListSchema, "a check run lookup");

		return listed.check_runs
			.filter((run) => run.name === name && run.app?.id === appId)
			.map((run) => ({ id: run.id }))
			.sort((left, right) => left.id - right.id);
	}

	/**
	 * Is this repository still visible to the installation bound to this client?
	 *
	 * One read of the repository itself, and the only question asked of it is
	 * which of three answers came back: a 2xx is visible, a 404 is not, and
	 * anything else is unanswerable and throws. The body is never parsed —
	 * nothing here needs a field from it, and a schema would add a way for this
	 * to fail that has nothing to do with the question.
	 *
	 * A 404 here is not ambiguous the way a 404 on the collaborator endpoint is.
	 * The installation token was minted successfully, so the installation exists;
	 * a repository it cannot see is one that was removed from the installation or
	 * dropped from its repository selection. That is an operator's problem and
	 * not a commenter's.
	 */
	private async repositoryVisible(): Promise<boolean> {
		const response = await this.call("GET", "");

		if (response.ok) {
			return true;
		}

		if (response.status === 404) {
			return false;
		}

		throw new GitHubApiError(`GitHub refused a repository visibility check for ${this.repository}`, response.status);
	}

	/**
	 * What `login` may do to this repository, as one of GitHub's four base roles.
	 *
	 * Every non-2xx other than a 404 throws, and the caller fails closed on it —
	 * an installation that has not granted the read, or an outage, must not read
	 * as "no permission and carry on", because carrying on is what this call
	 * gates.
	 *
	 * ### The 404 is two different answers and only one of them is settled
	 *
	 * `GET /collaborators/{login}/permission` answers 404 for "that user is not a
	 * collaborator here", which is the ordinary answer for everybody who has ever
	 * commented on a public repository. It answers 404 *identically* when the
	 * installation cannot see the repository at all — removed from the
	 * installation, or dropped from its repository selection. `getInstallationToken`
	 * still succeeds in that case, because the installation itself is fine, so
	 * this is the first place the difference can surface and there is nowhere
	 * later that it would.
	 *
	 * Read as one answer they are catastrophic to conflate. "Not a collaborator"
	 * is a settled fact about a person: a redelivery reaches it again, so the
	 * delivery id is spent and the audit row says the author was not trusted.
	 * "The App cannot see this repository" is a configuration failure that makes
	 * *every* comment — the owner's included — look like an untrusted author,
	 * with the delivery burned non-retryably and the audit pointing at the
	 * commenter rather than at the installation.
	 *
	 * So the status is not taken as proof on its own. A 404 is followed by an
	 * independent {@link RepositoryClient.repositoryVisible} read on the same
	 * token: a visible repository turns it into `"none"`, and an invisible or
	 * unanswerable one throws — {@link RepositoryNotVisibleError} for the former,
	 * so the caller can name it in an audit row.
	 *
	 * The cost is one extra GitHub call per comment by a non-collaborator, which
	 * is why the caller spends the dispatch budget before reaching this.
	 *
	 * The login that comes back is checked against the one asked about, case
	 * insensitively because GitHub logins are. A redirect from a renamed account,
	 * or any other answer about a different user, is refused rather than applied
	 * to the user whose comment is being authorized.
	 */
	async getActorPermission(login: string): Promise<ActorPermission> {
		const response = await this.call("GET", `/collaborators/${encodeURIComponent(login)}/permission`);

		if (response.status === 404) {
			if (await this.repositoryVisible()) {
				return { permission: "none", collaborator: false };
			}

			throw new RepositoryNotVisibleError(
				`GitHub answered a collaborator permission lookup for ${this.repository} with 404 and the installation can no longer see the repository`,
				response.status,
			);
		}

		const answer = await this.read(response, CollaboratorPermissionSchema, "a collaborator permission lookup");

		if (answer.user && answer.user.login.toLowerCase() !== login.toLowerCase()) {
			throw new GitHubApiError(
				`GitHub answered a collaborator permission lookup about a different user for ${this.repository}`,
				response.status,
			);
		}

		// Anything outside the documented four is `none`. A value this service does
		// not recognise is not a grant, and mapping it onto the *permissive* side
		// is how a new role name silently becomes write access. `collaborator` stays
		// true: GitHub answered about this person, and "a role we could not read"
		// is a different sentence from "not a collaborator" even though both refuse.
		return {
			permission:
				answer.permission === "admin" || answer.permission === "write" || answer.permission === "read"
					? answer.permission
					: "none",
			collaborator: true,
		};
	}

	/**
	 * Start a workflow run, and report which side of the ambiguity the answer
	 * landed on.
	 *
	 * Deliberately not a throw-or-succeed, because the caller's replay decision
	 * turns on a distinction a thrown error erases. There is no idempotency key
	 * on this endpoint and a repeat starts a second run, so the caller commits
	 * the delivery id *before* calling — which means the only thing worth knowing
	 * afterwards is whether GitHub definitely did nothing:
	 *
	 * - `refused` — a 4xx. A response arrived and it says no run was created: an
	 *   unknown workflow, a ref it is not on, a permission the installation never
	 *   granted. All operator-fixable, and all safely redeliverable, so this is
	 *   the one outcome that hands the delivery id back.
	 * - `unknown` — the call threw, or GitHub answered 5xx. Nothing here can tell
	 *   a request that never arrived from one that arrived and whose answer was
	 *   lost, so the delivery stays spent. That is the at-most-once direction,
	 *   and it is chosen on purpose: a lost acknowledgement costs a run that has
	 *   to be asked for again, and the other direction costs two agents editing
	 *   one branch.
	 * - `accepted` — a 2xx. GitHub used to answer 204 with no body here and now
	 *   answers 200 with the run it created, so the status is not asserted to be
	 *   either one; any 2xx is acceptance.
	 *
	 * `workflow` and `ref` are the operator's, from configuration. There is no
	 * overload of this that takes them from anywhere else.
	 */
	async dispatchWorkflow(
		workflow: string,
		ref: string,
		inputs: Record<string, string>,
	): Promise<{ outcome: "accepted" | "refused" | "unknown"; status: number | null }> {
		let response: Response;
		try {
			response = await this.call("POST", `/actions/workflows/${encodeURIComponent(workflow)}/dispatches`, {
				ref,
				inputs,
			});
		} catch (error) {
			// The message is not reused. `call` already decided what a token failure
			// and a transport failure may say, and this is not the place to widen it.
			return { outcome: "unknown", status: error instanceof GitHubApiError ? error.status : null };
		}

		if (response.ok) {
			return { outcome: "accepted", status: response.status };
		}

		return {
			outcome: response.status >= 400 && response.status < 500 ? "refused" : "unknown",
			status: response.status,
		};
	}

	/** Create a check run, returning its id. */
	async createCheckRun(input: CheckRunInput): Promise<number> {
		const response = await this.call("POST", "/check-runs", { ...checkRunFields(input), head_sha: input.headSha });
		const created = await this.read(response, CheckRunSchema, "a check run creation");

		return created.id;
	}

	/** Overwrite an existing check run of ours with the same fields. */
	async updateCheckRun(id: number, input: CheckRunInput): Promise<void> {
		const response = await this.call("PATCH", `/check-runs/${encodeURIComponent(String(id))}`, checkRunFields(input));

		if (!response.ok) {
			throw new GitHubApiError(`GitHub refused a check run update for ${this.repository}`, response.status);
		}
	}

	/**
	 * The author offset from `sha`'s patch rendering, or null.
	 *
	 * Every failure is null rather than a throw. This is a fallback consulted
	 * after a cheaper answer did not work, and its absence costs a refusal to
	 * rewrite one commit — which is already the outcome without it. Turning a 404
	 * on an unusual commit into an exception would instead turn that refusal into
	 * a delivery-wide read failure.
	 */
	private async authorOffsetFromPatch(sha: string): Promise<string | null> {
		try {
			const response = await this.call(
				"GET",
				`/commits/${encodeURIComponent(sha)}`,
				undefined,
				"application/vnd.github.patch",
			);

			if (!response.ok) {
				return null;
			}

			return patchAuthorOffset(await response.text(), sha);
		} catch {
			return null;
		}
	}

	/**
	 * Create a commit object carrying `signature`.
	 *
	 * Creating an object is not a visible change: until a ref points at it, the
	 * commit is unreachable and GitHub garbage-collects it. That is what makes
	 * this the last *recoverable* step and {@link updateBranch} the irreversible
	 * one.
	 *
	 * `message` goes out exactly as the caller holds it, trailing newline
	 * included. GitHub stores what it is given here too: a message ending `\n`
	 * produces an object ending `\n`, verified against the live API by creating a
	 * commit both ways and hashing the result. It is the *read* path that strips
	 * that byte, which is why the caller carries the reproduced message rather
	 * than the reported one.
	 *
	 * The dates go out with their recovered offsets rather than as the `Z` this
	 * API handed back, and rendering them is done *here* rather than by the
	 * caller so it cannot drift from the identity the payload was built over:
	 * both come from the same {@link CommitIdentity}, one through `gitTimestamp`
	 * and one through {@link isoWithOffset}. GitHub stores the offset it is given
	 * — an author at `+0545` and a committer at `-0330` both survive — and if it
	 * ever stopped doing so, the object id the caller checks would no longer
	 * match and nothing would be published.
	 */
	async createCommit(input: {
		message: string;
		tree: string;
		parents: string[];
		author: CommitIdentity;
		committer: CommitIdentity;
		signature: string;
	}): Promise<string> {
		const response = await this.call("POST", "/git/commits", {
			message: input.message,
			tree: input.tree,
			parents: input.parents,
			author: wireIdentity(input.author),
			committer: wireIdentity(input.committer),
			signature: input.signature,
		});
		const created = await this.read(response, CommitSchema, "a commit creation");

		return created.sha;
	}

	/**
	 * Move a branch to `sha`.
	 *
	 * `force` is required and true in practice: replacing a commit changes its
	 * id, so the rewritten head is not a descendant of the old one and the update
	 * is not a fast-forward. That is exactly why the caller re-reads the branch
	 * immediately before calling this, and why the delivery is marked
	 * non-retryable before it rather than after — the ledger write itself lands
	 * afterwards, from `webhookReplayGuard`'s `finally`. See
	 * `#utils/webhook-replay`.
	 */
	async updateBranch(branch: string, sha: string, force: boolean): Promise<void> {
		const response = await this.call("PATCH", `/git/refs/heads/${encodeRefPath(branch)}`, { sha, force });

		if (!response.ok) {
			throw new GitHubApiError(`GitHub refused a branch update for ${this.repository}`, response.status);
		}
	}
}
