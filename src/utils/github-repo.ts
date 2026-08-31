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
	author: { name: string; email: string; date: string };
	committer: { name: string; email: string; date: string };
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

	/** A call to the pinned host, on this repository's path, as this installation. */
	private async call(method: string, path: string, body?: unknown): Promise<Response> {
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
						Accept: "application/vnd.github+json",
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

	/** One commit object. */
	async getCommit(sha: string): Promise<RepositoryCommit> {
		const response = await this.call("GET", `/git/commits/${encodeURIComponent(sha)}`);
		const commit = await this.read(response, CommitSchema, "a commit lookup");

		return {
			sha: commit.sha,
			message: commit.message,
			tree: commit.tree.sha,
			parents: commit.parents.map((parent) => parent.sha),
			author: commit.author,
			committer: commit.committer,
			signed: typeof commit.verification?.signature === "string",
		};
	}

	/**
	 * Create a commit object carrying `signature`.
	 *
	 * Creating an object is not a visible change: until a ref points at it, the
	 * commit is unreachable and GitHub garbage-collects it. That is what makes
	 * this the last *recoverable* step and {@link updateBranch} the irreversible
	 * one.
	 */
	async createCommit(input: {
		message: string;
		tree: string;
		parents: string[];
		author: { name: string; email: string; date: string };
		committer: { name: string; email: string; date: string };
		signature: string;
	}): Promise<string> {
		const response = await this.call("POST", "/git/commits", input);
		const created = await this.read(response, CommitSchema, "a commit creation");

		return created.sha;
	}

	/**
	 * Move a branch to `sha`.
	 *
	 * `force` is required and true in practice: replacing a commit changes its
	 * id, so the rewritten head is not a descendant of the old one and the update
	 * is not a fast-forward. That is exactly why the caller re-reads the branch
	 * immediately before calling this, and why the delivery id is committed
	 * before it rather than after — see `#routes/github-webhook`.
	 */
	async updateBranch(branch: string, sha: string, force: boolean): Promise<void> {
		const response = await this.call("PATCH", `/git/refs/heads/${encodeRefPath(branch)}`, { sha, force });

		if (!response.ok) {
			throw new GitHubApiError(`GitHub refused a branch update for ${this.repository}`, response.status);
		}
	}
}
