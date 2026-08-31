/**
 * What a `push` delivery may cause, decided before anything is caused.
 *
 * Everything in this module is a decision and none of it is an action: it reads
 * a payload and a branch and produces a plan, so the rules below can be tested
 * against the states that matter without a repository, a key or a network.
 *
 * ### The head comes from the ref, not from the payload
 *
 * A push payload names the commit it thinks the branch now points at (`after`).
 * Nothing here reads it. {@link planPush} extracts only the *branch*, and the
 * handler then asks GitHub where that branch actually is — so the commit this
 * service rewrites is the one the repository holds, not the one a delivery
 * claims it holds, and a forged or stale `after` cannot aim the operation at
 * some other commit. The branch itself is payload-derived and unavoidably so —
 * a push event is about a branch — but it is a branch *inside the authorized
 * repository*, which is the boundary that matters.
 *
 * ### Only a trailing run of unsigned commits is ever rewritten
 *
 * Replacing a commit changes its id, which changes its children's ids, which
 * invalidates any signature those children carry. So the set this service may
 * touch is exactly the unsigned commits at the tip, walked back from the head
 * until the first one that is already signed. A signed commit stops the walk and
 * is never rewritten, and neither is anything beneath it — which is what "leave
 * already-correct signatures alone" has to mean once you notice that rewriting a
 * parent breaks a child.
 *
 * An unsigned commit *below* a signed one therefore stays unsigned. That is the
 * honest outcome and not an oversight: the alternative is destroying a signature
 * somebody else made.
 *
 * ### And that is also the loop suppression
 *
 * Moving the branch raises another `push` delivery, for a head this service just
 * signed. The walk sees a signed commit immediately, the run is empty, and the
 * plan is `nothing_to_sign`. The suppression is the *commit state* — a signature
 * on the head — rather than a guess about who pushed: `sender`, `pusher` and
 * `X-GitHub-Event` are all payload fields, and a loop that is stopped by the
 * state of the object graph stops whether or not those fields say what we
 * expected. `stops on a head this service just signed` in the suite is that
 * exact state, asserted rather than reasoned about.
 */

import type { RepositoryCommit } from "#utils/github-repo";

/**
 * How many commits one delivery may cause to be signed.
 *
 * A bound, not a tuning parameter. It caps the work a single delivery can
 * demand, and it declines to quietly rewrite a large import — a push of two
 * hundred unsigned commits is a history event that wants a person looking at it,
 * not an automatic rewrite of everything in it.
 */
export const MAX_SIGNABLE_COMMITS = 20;

/** Why a push causes nothing. */
export type PushRefusal =
	/** The ref is not `refs/heads/<branch>` — a tag, a note, or something else. */
	| "not_a_branch"
	/** The push deleted the branch. There is nothing at the tip to sign. */
	| "branch_deleted"
	/**
	 * The payload could not be shown to describe a signable push: no usable ref,
	 * or a `deleted` flag that is not the literal `false` a non-deletion carries.
	 */
	| "malformed"
	/** The head already carries a signature, so the run is empty. */
	| "nothing_to_sign"
	/** The branch named by the delivery does not exist any more. */
	| "branch_missing"
	/** More unsigned commits at the tip than one delivery may rewrite. */
	| "too_many_unsigned";

/** A push this service will act on, and the branch it will act on. */
export type PushPlan = { act: true; branch: string } | { act: false; reason: PushRefusal };

/** Branch names this service is willing to put in a URL path and move. */
const BRANCH_PATTERN = /^(?!\/)(?!.*\/\/)(?!.*\.\.)(?!.*@\{)[\x21-\x7e]{1,255}$/;

/**
 * The branch a `refs/heads/...` ref names, or null.
 *
 * Refuses the shapes Git itself refuses (`..`, `@{`, an empty or doubled
 * segment) and everything outside printable ASCII, because this value is
 * interpolated into an API path and then used to move a ref. A branch name this
 * rejects is not signed rather than signed somewhere unexpected.
 */
export function branchFromRef(ref: unknown): string | null {
	if (typeof ref !== "string" || !ref.startsWith("refs/heads/")) {
		return null;
	}

	const branch = ref.slice("refs/heads/".length);

	if (!BRANCH_PATTERN.test(branch) || branch.endsWith("/") || branch.endsWith(".lock")) {
		return null;
	}

	return branch;
}

/** Is `value` a JSON object rather than an array, a null, or a scalar? */
function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Decide whether this `push` payload describes something to sign.
 *
 * The `deleted` flag is read as a proof obligation rather than as a filter: a
 * delivery acts only if it carries exactly `false`, the literal boolean GitHub
 * sends on every non-deletion push. Exactly `true` is the deletion it names.
 * Every other shape — a missing flag, a `null`, the string `"false"`, a `0`, an
 * object — is `malformed` and causes nothing.
 *
 * The asymmetry is the point. Refusing only `=== true` would mean a payload
 * that is silent about whether it is a deletion is treated as a non-deletion,
 * so the one field that says "this branch is gone" could be removed to make it
 * act; requiring `=== false` means a payload that cannot *prove* it is a
 * non-deletion is refused. Acting on a deletion means recreating a branch
 * somebody deleted, which is the direction that has to be closed.
 *
 * Checked before the ref, so a payload whose `deleted` cannot be believed is
 * refused without its `ref` ever being read, let alone put in a URL.
 */
export function planPush(payload: unknown): PushPlan {
	if (!isObject(payload)) {
		return { act: false, reason: "malformed" };
	}

	if (payload.deleted === true) {
		return { act: false, reason: "branch_deleted" };
	}

	if (payload.deleted !== false) {
		return { act: false, reason: "malformed" };
	}

	const branch = branchFromRef(payload.ref);
	if (branch === null) {
		return { act: false, reason: payload.ref === undefined ? "malformed" : "not_a_branch" };
	}

	return { act: true, branch };
}

/** The commits a delivery may rewrite, oldest first, or why it may rewrite none. */
export type SignableRun = { act: true; commits: RepositoryCommit[] } | { act: false; reason: PushRefusal };

/**
 * Walk back from `head` collecting the unsigned commits at the tip.
 *
 * Stops at the first commit that carries a signature, at a root commit, and at
 * {@link MAX_SIGNABLE_COMMITS}. Follows first parents only: a merge commit's
 * other parents are not at the tip, are not being rewritten, and keep whatever
 * signatures they have.
 *
 * The returned order is oldest first, which is the order they must be created
 * in — each rewritten commit's parent is the previous one's new id.
 *
 * @param head - The sha the branch actually points at, read from the ref
 * @param fetchCommit - How to read one commit; the repository-scoped client's
 *   `getCommit`, so every read is inside the authorized repository
 */
export async function signableRun(
	head: string,
	fetchCommit: (sha: string) => Promise<RepositoryCommit>,
): Promise<SignableRun> {
	const collected: RepositoryCommit[] = [];
	let sha: string | undefined = head;

	while (sha !== undefined) {
		const commit: RepositoryCommit = await fetchCommit(sha);

		if (commit.signed) {
			break;
		}

		collected.push(commit);

		if (collected.length > MAX_SIGNABLE_COMMITS) {
			return { act: false, reason: "too_many_unsigned" };
		}

		sha = commit.parents[0];
	}

	if (collected.length === 0) {
		return { act: false, reason: "nothing_to_sign" };
	}

	return { act: true, commits: collected.reverse() };
}
