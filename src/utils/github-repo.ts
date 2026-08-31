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
import { fetchWithTimeout } from "#utils/fetch";
import type { CommitIdentity, CommitOffsets } from "#utils/git-commit";
import { isoWithOffset, recoverCommitOffsets } from "#utils/git-commit";
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

/** A commit, as this service needs to see one. */
export interface RepositoryCommit {
	sha: string;
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
 * the shape a caller that never went through {@link recoverCommitOffsets} has —
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
	 * The JSON is the source for everything except the two offsets, which it
	 * renders to `Z` unconditionally. Those are recovered by reproducing the
	 * object id — see {@link recoverCommitOffsets} — and the patch representation
	 * is consulted only when that fails, which happens when a commit's author and
	 * committer offsets differ. So the common commit costs exactly the request it
	 * always cost, and the unusual one costs a second read rather than a wrong
	 * answer.
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

		let offsets: CommitOffsets | null = null;
		if (!signed) {
			offsets = await recoverCommitOffsets(object, commit.sha);

			if (offsets === null) {
				const authorOffset = await this.authorOffsetFromPatch(commit.sha);
				if (authorOffset !== null) {
					offsets = await recoverCommitOffsets(object, commit.sha, authorOffset);
				}
			}
		}

		return {
			sha: commit.sha,
			message: commit.message,
			tree: object.tree,
			parents: object.parents,
			author: offsets === null ? commit.author : { ...commit.author, offset: offsets.author },
			committer: offsets === null ? commit.committer : { ...commit.committer, offset: offsets.committer },
			offsets,
			signed,
		};
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
