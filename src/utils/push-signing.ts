/**
 * Signing the commits a push left unsigned, and where the point of no return is.
 *
 * This is the first thing in the service that a webhook can *cause*. Everything
 * before it — the HMAC, the allowlist, the key binding, the delivery ledger —
 * exists so that by the time control arrives here the two questions that matter
 * are already answered: which repository, and which key. Neither is asked again
 * here, and neither can be: the client is bound to one repository and the key
 * arrives as material, not as an id to look up.
 *
 * ### The irreversible boundary
 *
 * The operation has four steps and only the last one can be observed by anyone
 * else:
 *
 * 1. **Read** the branch and the commits at its tip. Changes nothing.
 * 2. **Sign** each commit payload. Produces bytes that exist only in memory.
 * 3. **Create** each commit object. Creates objects no ref points at — GitHub
 *    collects them, and until a ref moves nobody can reach them or know they
 *    were made.
 * 4. **Move the branch.** This is the one a person sees, the one that cannot be
 *    taken back, and the one the delivery id is committed in front of.
 *
 * So a failure anywhere in 1–3 leaves the world exactly as it was, and the
 * delivery is released for a genuine retry. From 4 onward the delivery is spent,
 * whatever the outcome — including an ambiguous one, where the request was sent
 * and the answer was lost, which is the case that makes "commit before, not
 * after" the only safe order.
 *
 * {@link PushSigningHooks.beforePublish} is that boundary, made explicit rather
 * than left as a comment about statement order. The caller supplies what to do
 * at it; this module guarantees where it happens.
 *
 * ### The branch is re-read before it is moved
 *
 * Rewriting a commit changes its id, so the new head is not a descendant of the
 * old one and the update cannot be a fast-forward — it is a force update, which
 * is the one kind that can discard somebody else's work. Immediately before
 * publishing, the branch is read again and required to still point where it did
 * when the run was planned. That does not close the window entirely, and nothing
 * available over this API does; it closes the window that is actually open in
 * practice, which is the seconds this operation takes.
 */

import type { AnyStoredKey, StoredKey } from "#schemas/keys";
import { isX509Key } from "#schemas/keys";
import { commitObjectId, commitPayload, signedCommitObject } from "#utils/git-commit";
import type { PushRefusal } from "#utils/github-push";
import { signableRun } from "#utils/github-push";
import type { RepositoryClient } from "#utils/github-repo";
import { signCommitData } from "#utils/signing";

/** What the caller must provide around the two moments this module cannot decide. */
export interface PushSigningHooks {
	/**
	 * Spend budget for `commits` signatures, or refuse.
	 *
	 * Consulted once the run is known and before anything is signed, so a refusal
	 * costs a read and nothing else. Counted per commit rather than per delivery,
	 * because a signature is the unit of work being bounded — one delivery
	 * carrying twenty commits is twenty signatures.
	 */
	reserveBudget(commits: number): Promise<"ok" | "limited" | "unavailable">;
	/**
	 * Called once, immediately before the branch is moved.
	 *
	 * Everything up to this call is reversible; nothing after it is. The caller
	 * uses it to commit the delivery id.
	 */
	beforePublish(): Promise<void>;
}

/** How a push-signing attempt ended. */
export type PushSigningResult =
	/** The branch was moved. `published` is implied and unconditional. */
	| { outcome: "signed"; branch: string; previousHead: string; head: string; commits: number }
	/** There was nothing to do, and nothing was done. */
	| { outcome: "skipped"; reason: PushRefusal | "branch_moved" | "unsupported_key" }
	/** The budget refused. Nothing was done. */
	| { outcome: "refused"; reason: "rate_limited" | "limiter_unavailable" }
	/**
	 * Something went wrong.
	 *
	 * `published` says which side of the irreversible boundary it went wrong on,
	 * and it is the field the caller's replay decision turns on: false means the
	 * repository is untouched and a redelivery is a real retry.
	 */
	| { outcome: "failed"; reason: string; published: boolean };

/**
 * Sign the unsigned commits at the tip of `branch`, and move it to them.
 *
 * @param client - Bound to the authorized repository and installation
 * @param branch - A branch name from {@link branchFromRef}, inside that repository
 * @param key - The stored key the operator bound to this repository
 * @param passphrase - For decrypting `key`
 * @param hooks - Budget, and the irreversible boundary
 */
export async function signPushedCommits(
	client: RepositoryClient,
	branch: string,
	key: AnyStoredKey,
	passphrase: string,
	hooks: PushSigningHooks,
): Promise<PushSigningResult> {
	// X.509 keys sign S/MIME, which is a different `gpgsig` dialect and not what
	// GitHub's create-a-commit `signature` field takes. Refused rather than
	// attempted: a signature GitHub stores and cannot verify is worse than no
	// signature, because it looks like one.
	if (isX509Key(key)) {
		return { outcome: "skipped", reason: "unsupported_key" };
	}

	// The reads, together, because a failure in any of them means the same thing:
	// GitHub could not be asked, so nothing is known and nothing was done. Left
	// uncaught they would escape to the route, which cannot tell a read failure
	// from a publish failure and therefore has to assume the worse of the two —
	// turning a transient token or API error into a delivery that can never be
	// redelivered.
	let start: Awaited<ReturnType<RepositoryClient["getBranch"]>>;
	let run: Awaited<ReturnType<typeof signableRun>>;
	try {
		start = await client.getBranch(branch);
		if (start === null) {
			return { outcome: "skipped", reason: "branch_missing" };
		}

		run = await signableRun(start.sha, (sha) => client.getCommit(sha));
	} catch (error) {
		return {
			outcome: "failed",
			reason: error instanceof Error ? error.message : "Could not read the repository",
			published: false,
		};
	}

	if (!run.act) {
		return { outcome: "skipped", reason: run.reason };
	}

	const budget = await hooks.reserveBudget(run.commits.length);
	if (budget === "limited") {
		return { outcome: "refused", reason: "rate_limited" };
	}
	if (budget === "unavailable") {
		return { outcome: "refused", reason: "limiter_unavailable" };
	}

	// The id the previous iteration produced. Seeded with the run's base so the
	// first commit is a no-op case rather than a special one.
	let rewritten: string | null = null;

	for (const commit of run.commits) {
		// The oldest commit in the run keeps its parents exactly as they are: what
		// is beneath the run is not being rewritten. Every later one takes the id
		// the previous iteration produced, in the first-parent slot only — a
		// merge's other parents are untouched commits with untouched ids, and
		// copying them through unchanged is what keeps the merge a merge.
		const parents = rewritten === null ? commit.parents : [rewritten, ...commit.parents.slice(1)];

		const payload = commitPayload({
			tree: commit.tree,
			parents,
			author: commit.author,
			committer: commit.committer,
			message: commit.message,
		});

		let signature: string;
		try {
			signature = (await signCommitData(payload, key as StoredKey, passphrase)).signature;
		} catch (error) {
			return {
				outcome: "failed",
				reason: `Signing failed: ${error instanceof Error ? error.message : "unknown error"}`,
				published: false,
			};
		}

		const expected = await commitObjectId(signedCommitObject(payload, signature));

		let created: string;
		try {
			created = await client.createCommit({
				message: commit.message,
				tree: commit.tree,
				parents,
				author: commit.author,
				committer: commit.committer,
				signature,
			});
		} catch (error) {
			return {
				outcome: "failed",
				reason: error instanceof Error ? error.message : "Commit creation failed",
				published: false,
			};
		}

		// The whole-payload check. If GitHub assembled the object even one byte
		// differently from us — a date normalised, a header we did not model — the
		// ids differ, and the signature it stored is over something other than the
		// object that now exists. Nothing in the response says so; this does. The
		// created object is unreachable and gets collected, so refusing here costs
		// nothing but the call.
		if (created !== expected) {
			return {
				outcome: "failed",
				reason: "GitHub assembled a different commit object than the one signed",
				published: false,
			};
		}

		rewritten = created;
	}

	// Re-read, and require the branch to be where the plan assumed. A push that
	// landed while this was working would otherwise be discarded by the force
	// update below, silently, and the only trace would be the reflog.
	let current: Awaited<ReturnType<RepositoryClient["getBranch"]>>;
	try {
		current = await client.getBranch(branch);
	} catch (error) {
		// Still before the boundary: a re-read that fails means the branch was not
		// confirmed, so it is not moved.
		return {
			outcome: "failed",
			reason: error instanceof Error ? error.message : "Could not re-read the branch",
			published: false,
		};
	}

	if (current === null || current.sha !== start.sha) {
		return { outcome: "skipped", reason: "branch_moved" };
	}

	// Non-null here: the loop ran at least once, because `signableRun` answers
	// `nothing_to_sign` rather than handing back an empty list.
	const head = rewritten as string;

	await hooks.beforePublish();

	try {
		await client.updateBranch(branch, head, true);
	} catch (error) {
		// Past the boundary. The delivery is already committed, so this is reported
		// and not retried: the update may have landed and the answer been lost, and
		// repeating a force update on that assumption is how a branch gets moved
		// twice.
		return {
			outcome: "failed",
			reason: error instanceof Error ? error.message : "Branch update failed",
			published: true,
		};
	}

	return {
		outcome: "signed",
		branch,
		previousHead: start.sha,
		head,
		commits: run.commits.length,
	};
}
