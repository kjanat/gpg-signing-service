/**
 * The four GitHub calls a push-signing run makes, and nothing else.
 *
 * Every one of them is scoped by construction rather than by discipline. The
 * owner and repository come from {@link RepositoryContext}, which a caller can
 * only build from a {@link WebhookAuthorization} at `repository` scope — so the
 * repository a request touches is the one an operator wrote in
 * `GITHUB_APP_ALLOWED_REPOSITORIES`, never `payload.repository.full_name`. The
 * installation whose token is used comes from the same entry. There is no
 * function here that takes a payload, a URL, or a host.
 *
 * The destination is pinned twice over: `githubApiUrl` resolves every path
 * against `api.github.com` and asserts the resulting origin, and the path
 * itself is assembled from percent-encoded segments so a repository or branch
 * name can never introduce one. `validateUrl` is deliberately absent for the
 * reason `#utils/github-app` gives — it sifts caller-controlled URLs and
 * answers the wrong question about a constant host.
 *
 * Responses are parsed, not cast. A field this service acts on — an object
 * name, a parent list, a signature — is checked for shape before it can reach
 * the code that rewrites history with it, and a response that does not parse is
 * a refusal rather than an `undefined` two frames later.
 *
 * Nothing here logs or returns a token, and no error message quotes a response
 * body: a 401 from these endpoints describes the credential that was refused.
 */

import { z } from "zod";
import type { Env, WebhookAuthorization } from "#types";
import { TIME } from "#types";
import { fetchWithTimeout } from "#utils/fetch";
import { getInstallationToken, githubApiUrl } from "#utils/github-app";
import { isRepositoryFullName } from "#utils/github-authorization";

/** How long to wait on GitHub before giving up on one call. */
const GITHUB_TIMEOUT = 10 * TIME.SECOND;

/** Headers every call carries, apart from the credential. */
const GITHUB_HEADERS = {
	Accept: "application/vnd.github+json",
	"X-GitHub-Api-Version": "2022-11-28",
	"User-Agent": "gpg-signing-service",
} as const;

/**
 * A GitHub call that did not succeed.
 *
 * Carries the operation and the status, and never the body. `status` is null
 * when the request did not complete at all — a timeout, a reset — which is the
 * case a caller must treat as "outcome unknown" rather than as "refused".
 */
export class GitHubApiError extends Error {
	readonly status: number | null;

	constructor(operation: string, status: number | null, options: { cause?: unknown } = {}) {
		super(status === null ? `${operation} could not reach GitHub` : `${operation} failed (HTTP ${status})`, options);
		this.name = "GitHubApiError";
		this.status = status;
	}
}

/**
 * Which repository, under which installation, this run may touch.
 *
 * Built only by {@link repositoryContext}, from an authorization decision. The
 * two fields cannot be set independently, which is the point: a repository
 * under the wrong installation is not a context this type can hold.
 */
export interface RepositoryContext {
	installationId: number;
	owner: string;
	repo: string;
	/** `owner/repo`, the operator's spelling, for logs and audit rows. */
	fullName: string;
}

/**
 * The context an authorized delivery grants, or null when it grants none.
 *
 * Refuses anything below `repository` scope, and re-checks the repository's
 * shape even though `parseRepositoryAllowlist` already did: this is the last
 * point before the value becomes a URL path, and `WebhookAuthorization` crosses
 * a context boundary as a plain string.
 */
export function repositoryContext(authorization: WebhookAuthorization | undefined): RepositoryContext | null {
	if (authorization === undefined || authorization.scope !== "repository") {
		return null;
	}

	const { installationId, repository } = authorization;
	if (installationId === null || repository === null || !isRepositoryFullName(repository)) {
		return null;
	}

	const separator = repository.indexOf("/");
	return {
		installationId,
		owner: repository.slice(0, separator),
		repo: repository.slice(separator + 1),
		fullName: repository,
	};
}

/** A path under `/repos/<owner>/<repo>`, with every segment encoded. */
function repoPath(context: RepositoryContext, suffix: string): string {
	return `/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repo)}${suffix}`;
}

/**
 * A branch name split into encoded path segments.
 *
 * Branch names may contain `/`, so the separator survives and everything else
 * does not. Without this a branch called `..` or one carrying a `?` would
 * rewrite the path it was meant to be a leaf of — on a host `githubApiUrl`
 * would still be perfectly happy with.
 */
function encodeBranch(branch: string): string {
	return branch.split("/").map(encodeURIComponent).join("/");
}

/** One authenticated call, with the response left for the caller to read. */
async function call(
	env: Env,
	context: RepositoryContext,
	operation: string,
	path: string,
	init: { method: string; body?: unknown } = { method: "GET" },
): Promise<Response> {
	const { token } = await getInstallationToken(env, context.installationId);
	const url = githubApiUrl(path);

	try {
		return await fetchWithTimeout(
			url,
			{
				method: init.method,
				headers: {
					...GITHUB_HEADERS,
					Authorization: `Bearer ${token}`,
					...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
				},
				...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
			},
			GITHUB_TIMEOUT,
		);
	} catch (error) {
		// The cause is attached and the message is this service's own: the request
		// that failed carried an installation token, and whatever the runtime threw
		// about it is not something to re-raise verbatim.
		throw new GitHubApiError(operation, null, { cause: error });
	}
}

/** A JSON body, parsed against `schema`, or a `GitHubApiError`. */
async function readJson<T>(response: Response, operation: string, schema: z.ZodType<T>): Promise<T> {
	if (!response.ok) {
		throw new GitHubApiError(operation, response.status);
	}

	let body: unknown;
	try {
		body = await response.json();
	} catch (error) {
		throw new GitHubApiError(`${operation} returned unreadable JSON`, response.status, { cause: error });
	}

	const parsed = schema.safeParse(body);
	if (!parsed.success) {
		// The issues are not carried out: they quote the values that failed, and
		// those come from a response body this module has decided not to repeat.
		throw new GitHubApiError(`${operation} returned an unexpected shape`, response.status);
	}

	return parsed.data;
}

const ShaSchema = z.string().regex(/^[0-9a-f]{40}$/);

const RefSchema = z.object({ object: z.object({ sha: ShaSchema }) });

const IdentitySchema = z.object({
	name: z.string(),
	email: z.string(),
	date: z.string(),
});

/**
 * A commit as the Git Data API describes it.
 *
 * `verification` is optional because it is absent from the object `POST
 * /git/commits` echoes back on some paths, and its `signature` is null on an
 * unsigned commit. Both are states this service has to tell apart, so neither
 * is defaulted.
 */
const CommitSchema = z.object({
	sha: ShaSchema,
	tree: z.object({ sha: ShaSchema }),
	parents: z.array(z.object({ sha: ShaSchema })).default([]),
	author: IdentitySchema,
	committer: IdentitySchema,
	message: z.string(),
	verification: z
		.object({
			signature: z.string().nullable().default(null),
			payload: z.string().nullable().default(null),
		})
		.optional(),
});

/** A commit, flattened into the shape the rest of the run works in. */
export interface RepositoryCommit {
	sha: string;
	tree: string;
	parents: string[];
	author: { name: string; email: string; date: string };
	committer: { name: string; email: string; date: string };
	message: string;
	/** The armored `gpgsig`, or null when the commit carries none. */
	signature: string | null;
	/**
	 * The bytes GitHub says that signature covers, or null.
	 *
	 * Authoritative when present — it is GitHub's own reconstruction of the
	 * object without its `gpgsig` header — and so preferred over rebuilding one
	 * locally. Null on an unsigned commit, where there is nothing for it to
	 * describe.
	 */
	verificationPayload: string | null;
}

function flatten(commit: z.infer<typeof CommitSchema>): RepositoryCommit {
	return {
		sha: commit.sha,
		tree: commit.tree.sha,
		parents: commit.parents.map((parent) => parent.sha),
		author: commit.author,
		committer: commit.committer,
		message: commit.message,
		signature: commit.verification?.signature ?? null,
		verificationPayload: commit.verification?.payload ?? null,
	};
}

/** The object a branch currently points at. */
export async function getBranchHead(env: Env, context: RepositoryContext, branch: string): Promise<string> {
	const operation = "reading the branch head";
	const response = await call(env, context, operation, repoPath(context, `/git/ref/heads/${encodeBranch(branch)}`));
	return (await readJson(response, operation, RefSchema)).object.sha;
}

/** One commit object. */
export async function getCommit(env: Env, context: RepositoryContext, sha: string): Promise<RepositoryCommit> {
	const operation = "reading a commit";
	const response = await call(env, context, operation, repoPath(context, `/git/commits/${encodeURIComponent(sha)}`));
	return flatten(await readJson(response, operation, CommitSchema));
}

/** What a new commit is made of. `signature` becomes its `gpgsig` header. */
export interface NewCommit {
	message: string;
	tree: string;
	parents: string[];
	author: { name: string; email: string; date: string };
	committer: { name: string; email: string; date: string };
	signature: string;
}

/**
 * Create a commit object.
 *
 * Creating one moves nothing: the object is unreferenced until a ref points at
 * it, so this call is reversible by doing nothing at all. That is what makes it
 * safe to run before the delivery's claim is committed — see the boundary
 * argument in `#utils/push-signing`.
 */
export async function createCommit(env: Env, context: RepositoryContext, commit: NewCommit): Promise<RepositoryCommit> {
	const operation = "creating a commit";
	const response = await call(env, context, operation, repoPath(context, "/git/commits"), {
		method: "POST",
		body: commit,
	});
	return flatten(await readJson(response, operation, CommitSchema));
}

/**
 * Point a branch at `sha`, overwriting whatever it points at now.
 *
 * **This is the irreversible step.** Everything before it reads, or writes
 * objects nothing references; this changes what the repository *is*. `force` is
 * required because a signed rewrite is never a fast-forward, and the guard
 * against overwriting someone else's work is the caller re-reading the head
 * immediately before calling this — not this function, which cannot know what
 * it is replacing.
 */
export async function updateBranch(env: Env, context: RepositoryContext, branch: string, sha: string): Promise<string> {
	const operation = "updating the branch";
	const response = await call(env, context, operation, repoPath(context, `/git/refs/heads/${encodeBranch(branch)}`), {
		method: "PATCH",
		body: { sha, force: true },
	});
	return (await readJson(response, operation, RefSchema)).object.sha;
}
