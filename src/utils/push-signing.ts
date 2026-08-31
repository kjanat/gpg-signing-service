/**
 * Signing the commits a `push` delivered, and where this run is allowed to stop.
 *
 * This is the first thing in the service that a webhook can *cause*. Everything
 * the earlier slices built — the HMAC, the `<installation, repository>`
 * allowlist, the key bound to that pair, the delivery ledger — exists so that
 * this module can be written without asking any of those questions again. It
 * takes a {@link RepositoryContext} that can only be built from an
 * authorization decision, and a key that can only come from
 * {@link loadSigningKey}. **No function here reads the payload for anything but
 * the ref and the two object names**, and both of those are re-checked against
 * GitHub's own state before anything is written.
 *
 * ### The irreversible boundary
 *
 * There is exactly one: `PATCH /git/refs/heads/<branch>`. Reading commits
 * changes nothing, and creating a commit object changes nothing either — an
 * object no ref points at is unreferenced and collectable, invisible to every
 * clone. So the whole run up to `updateBranch` is a dry run that happens to
 * leave objects lying around, and a failure anywhere in it can be retried by
 * simply doing it again.
 *
 * That is what makes the two-phase delivery ledger in `#utils/webhook-replay`
 * work. A refusal from this module says whether it happened before the
 * boundary; the middleware releases the delivery id when it did, so the
 * operator's **Redeliver** is a real retry rather than
 * `200 {"duplicate": true}`. The one case that is *not* answerable is a ref
 * update that did not complete — a timeout, a reset — where the outcome is
 * genuinely unknown; that is reported not-retryable and the reservation is left
 * to expire, which is the only honest answer.
 *
 * ### Why retrying is safe at all
 *
 * Because a run is a fixpoint. A commit is rewritten only when it carries no
 * signature that verifies under the bound key, and every signature this service
 * produces is verified under that same key *before* the commit object is
 * created. So the push this service makes carries commits it will refuse to
 * touch, and the delivery that push provokes finds nothing to sign and stops.
 * That is also the whole of the loop prevention: it is a property of the
 * commits, not a guess about who sent the event, so it holds for a redelivery,
 * a replay, and a manual push of the same objects alike.
 *
 * ### What it will not do
 *
 * Refuses, rather than acting, on: a branch being created or deleted, a merge
 * or root commit, a commit already carrying somebody else's signature, a commit
 * whose committer the key does not name, a commit whose bytes cannot be
 * reproduced, a range longer than {@link MAX_PUSH_COMMITS}, and a branch whose
 * head moved while the run was working. Each of those is a case where the
 * "helpful" behaviour destroys something: a signature, an authorship claim, or
 * somebody else's push.
 */

import type { StoredKey } from "#schemas/keys";
import { isX509Key } from "#schemas/keys";
import type { Env, KeyId, WebhookAuthorization } from "#types";
import { createIdentity, HTTP } from "#types";
import { fetchRateLimiter } from "#utils/durable-objects";
import type { CommitContents, MessageTermination } from "#utils/git-commit";
import {
	commitObjectSha,
	commitPayload,
	commitWithSignature,
	isObjectSha,
	NULL_SHA,
	reproduceCommit,
} from "#utils/git-commit";
import { GitHubAppError } from "#utils/github-app";
import type { RepositoryCommit, RepositoryContext } from "#utils/github-repo";
import {
	createCommit,
	GitHubApiError,
	getBranchHead,
	getCommit,
	repositoryContext,
	updateBranch,
} from "#utils/github-repo";
import { loadSigningKey } from "#utils/github-signing-key";
import { extractPublicKey, keyIdentityEmails, signCommitData, verifyDetachedSignature } from "#utils/signing";

/**
 * How many commits one push may have this service rewrite.
 *
 * GitHub's own `push` payload caps its `commits` array at 20, so a range longer
 * than this is already one where the event does not describe itself — and every
 * commit costs a GitHub round trip, a signature and another round trip. A
 * larger range is a job for the `sign-commits` workflow, which has a checkout
 * and no request deadline.
 */
export const MAX_PUSH_COMMITS = 20;

/**
 * Rate-limiter namespace for signatures a webhook causes.
 *
 * Disjoint from `webhook` — which meters *deliveries* by source address and is
 * not a signing budget — and from the `<iss>:<sub>` buckets `POST /sign`
 * consumes. A webhook that signs cannot exhaust an OIDC caller's budget, and a
 * burst of deliveries from GitHub's addresses cannot exhaust this one.
 */
const PUSH_SIGN_METER = "github-app-sign";

/**
 * The bucket one grant's signatures are counted against.
 *
 * The whole grant — installation, repository *and* key — because that is the
 * unit an operator wrote. One repository cannot spend another's budget, the
 * same repository under two installations is two budgets, and re-pointing a
 * repository at a different key starts a fresh one rather than inheriting the
 * old key's spending.
 */
export function signingBudgetIdentity(installationId: number, repository: string, keyId: string) {
	return createIdentity(PUSH_SIGN_METER, `${installationId}:${repository}=${keyId}`);
}

/** Why a run did not sign anything. */
export type PushRefusal =
	/** The delivery is not a `push`. */
	| "not_a_push"
	/** No `<installation, repository>` grant, so nothing may be touched. */
	| "not_repository_scope"
	/** The grant binds no signing key. */
	| "no_key_bound"
	/** The bound key is not in storage. */
	| "key_missing"
	/** Key storage could not be reached. */
	| "key_storage_unavailable"
	/** The bound key is an X.509 key; git's `gpgsig` header carries OpenPGP. */
	| "key_type_unsupported"
	/** The key carries no user ID with an address, so it names no committer. */
	| "key_without_identity"
	/** `ref` is not `refs/heads/<branch>`, or the branch name is unusable. */
	| "unsupported_ref"
	/** The push deleted the branch. */
	| "branch_deleted"
	/** The push created the branch, so there is no base to stop the walk at. */
	| "branch_created"
	/** `before`/`after` are missing or are not object names. */
	| "unreadable_range"
	/** More than {@link MAX_PUSH_COMMITS} commits would have to be rewritten. */
	| "range_too_long"
	/** A commit in the range is a merge or a root commit. */
	| "unsupported_commit_shape"
	/** A commit in the range carries a signature this key did not make. */
	| "foreign_signature"
	/** A commit in the range was committed by an identity the key does not carry. */
	| "foreign_committer"
	/** A commit's bytes could not be rebuilt from GitHub's JSON. */
	| "commit_not_reproducible"
	/** The signing budget for this grant is exhausted. */
	| "rate_limited"
	/** The limiter could not be consulted. */
	| "rate_limiter_unavailable"
	/** A signature this service produced did not verify under its own key. */
	| "signature_unverifiable"
	/** The commit GitHub created is not the commit that was signed. */
	| "created_commit_mismatch"
	/** The branch moved between the delivery and the update. */
	| "head_moved"
	/** GitHub refused or could not be reached. */
	| "github_unavailable"
	/** The App identity is missing or unusable, so no installation token can be minted. */
	| "app_misconfigured"
	/** The ref update did not complete, so whether it took effect is unknown. */
	| "ref_update_indeterminate"
	/** Signing itself failed. */
	| "signing_failed";

/** Nothing needed doing: every commit in the range already verifies. */
export type PushSigningOutcome =
	| { acted: true; branch: string; from: string; head: string; signed: number }
	| { acted: false; retryable: boolean; reason: PushRefusal; detail?: string };

/**
 * Refusals a redelivery could plausibly get past.
 *
 * Everything reached *before* the ref update is technically retryable, so this
 * is narrower than that on purpose: it names the refusals where retrying could
 * produce a different answer. Re-running a merge commit or a foreign signature
 * through the same code gets the same refusal, and a delivery released for one
 * of those would simply be refused again — with the operator having been told
 * to press a button that cannot work.
 */
const RETRYABLE: ReadonlySet<PushRefusal> = new Set<PushRefusal>([
	"no_key_bound",
	"key_missing",
	"key_storage_unavailable",
	"rate_limited",
	"rate_limiter_unavailable",
	"github_unavailable",
	"head_moved",
	"signing_failed",
	// An operator can fix the App credentials and redeliver, which is the only
	// way this delivery is ever handled — GitHub does not retry on its own.
	"app_misconfigured",
]);

function refuse(reason: PushRefusal, detail?: string): PushSigningOutcome {
	return { acted: false, retryable: RETRYABLE.has(reason), reason, ...(detail === undefined ? {} : { detail }) };
}

/** What a `push` payload says about itself, before any of it is believed. */
interface PushSubject {
	branch: string | null;
	before: string | null;
	after: string | null;
	deleted: boolean;
}

/** Is `value` a JSON object (and not null, and not an array)? */
function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A branch name safe to put in a URL path and to hand to git.
 *
 * git's own rules, minus the ones that cannot occur inside `refs/heads/`. No
 * empty segment, no `.` or `..` segment, no `.lock` suffix, none of the
 * characters git reserves, and no control characters. Applied even though the
 * value reaches `encodeBranch` — a name that percent-encodes cleanly can still
 * be a traversal once GitHub decodes it, and this service should not be the one
 * that finds out.
 */
export function isBranchName(value: string): boolean {
	if (value.length === 0 || value.length > 255) {
		return false;
	}
	// Written as a code-point scan rather than a character class, because the
	// class would have to contain control characters literally — which is both a
	// lint error and unreadable. The characters git itself reserves are refused
	// by name, and everything at or below space, plus DEL, as a group.
	for (const character of value) {
		const code = character.codePointAt(0) as number;
		if (code <= 0x20 || code === 0x7f || "~^:?*[\\".includes(character)) {
			return false;
		}
	}

	if (value.includes("..") || value.includes("@{")) {
		return false;
	}
	if (value.startsWith("/") || value.endsWith("/") || value.endsWith(".")) {
		return false;
	}

	return value
		.split("/")
		.every((segment) => segment.length > 0 && !segment.startsWith(".") && !segment.endsWith(".lock"));
}

/**
 * The ref and range a `push` claims, read defensively.
 *
 * Three fields out of a document with dozens, and none of them is trusted on
 * its own: the branch is re-read from GitHub before the update, and `after` has
 * to match what GitHub says the branch points at. What the payload actually
 * decides is only *which* branch of the already-authorized repository this run
 * is about.
 */
export function pushSubject(payload: unknown): PushSubject {
	if (!isObject(payload)) {
		return { branch: null, before: null, after: null, deleted: false };
	}

	const ref = typeof payload.ref === "string" ? payload.ref : "";
	const branch = ref.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : "";

	return {
		branch: isBranchName(branch) ? branch : null,
		before: isObjectSha(payload.before) ? payload.before : null,
		after: isObjectSha(payload.after) ? payload.after : null,
		deleted: payload.deleted === true,
	};
}

/**
 * The three payload fields worth recording, read without trusting any of them.
 *
 * Separate from {@link pushSubject}, which returns only values it was willing
 * to *believe*. An audit row wants what the delivery said even when that was
 * unusable — an unrenderable ref is exactly the case where an operator needs
 * the ref — so this one validates nothing and only bounds the length, because
 * these strings end up in a D1 column.
 */
export function pushDiagnostics(payload: unknown): {
	branch: string | null;
	before: string | null;
	after: string | null;
} {
	const record = isObject(payload) ? payload : {};
	const value = (key: string) => (typeof record[key] === "string" ? (record[key] as string).slice(0, 128) : null);

	return { branch: value("ref"), before: value("before"), after: value("after") };
}

/** One commit the run intends to rewrite, with its bytes already proven. */
interface PlannedCommit {
	commit: RepositoryCommit;
	payload: string;
	termination: MessageTermination;
}

/** The key material a run signs with, and what it is allowed to sign. */
interface SigningMaterial {
	keyId: KeyId;
	key: StoredKey;
	publicKey: string;
	/** Lowercase committer addresses this key may sign for. */
	identities: Set<string>;
}

/**
 * The key this delivery may use, loaded and made ready to verify against.
 *
 * `loadSigningKey` answers "which key, and is it there". This adds the two
 * things a *commit* signing run needs and the signing API does not: the public
 * half, so a signature can be checked against the key that made it, and the
 * addresses the key names, so a commit belonging to somebody else is refused
 * rather than re-attributed.
 */
async function signingMaterial(
	env: Env,
	authorization: WebhookAuthorization | undefined,
): Promise<SigningMaterial | PushSigningOutcome> {
	const load = await loadSigningKey(env, authorization);
	if (!load.allowed) {
		return refuse(load.reason === "not_repository_scope" ? "not_repository_scope" : load.reason);
	}

	if (isX509Key(load.key)) {
		// git's `gpgsig` header carries an OpenPGP signature unless the repository
		// is configured for `gpg.format=x509`, which is a repository-side setting
		// this service cannot see. Refused rather than guessed at.
		return refuse("key_type_unsupported", load.keyId);
	}

	const publicKey = await extractPublicKey(load.key.armoredPrivateKey);
	const identities = await keyIdentityEmails(load.key.armoredPrivateKey);
	if (identities.size === 0) {
		return refuse("key_without_identity", load.keyId);
	}

	return { keyId: load.keyId, key: load.key, publicKey, identities };
}

/**
 * Which commits in `before..after` need this key's signature.
 *
 * Walks parents from the pushed head and stops at the first commit that is
 * already the base — either `before` itself, or a commit carrying a signature
 * that verifies under this key. Everything collected on the way is checked
 * before it is collected, so the plan either describes a rewrite this service
 * is willing to make in full or it is a refusal.
 */
async function planCommits(
	env: Env,
	context: RepositoryContext,
	material: SigningMaterial,
	subject: { before: string; after: string },
): Promise<PlannedCommit[] | PushSigningOutcome> {
	const planned: PlannedCommit[] = [];
	let sha = subject.after;

	while (sha !== subject.before) {
		if (planned.length >= MAX_PUSH_COMMITS) {
			return refuse("range_too_long", `more than ${MAX_PUSH_COMMITS} commits`);
		}

		const commit = await getCommit(env, context, sha);

		if (commit.signature !== null) {
			// GitHub's own reconstruction of the signed bytes when it offers one,
			// and a local rebuild when it does not. Either way the payload is proven
			// against this commit's name before it decides anything: a payload that
			// hashes to a different object would make an unrelated valid signature
			// look like this commit's.
			const signed =
				commit.verificationPayload !== null &&
				(await commitObjectSha(commitWithSignature(commit.verificationPayload, commit.signature))) === sha
					? commit.verificationPayload
					: ((await reproduceCommit(commitContents(commit), sha, commit.signature))?.payload ?? null);

			if (signed !== null && (await verifyDetachedSignature(signed, commit.signature, material.publicKey))) {
				// The base: this commit and everything under it already carry a
				// signature this key made. Reached on every delivery provoked by this
				// service's own push, which is what makes the run terminate.
				break;
			}

			// Somebody else's signature — a different key, an SSH signature, a
			// signature that no longer verifies. Rewriting the commit strips it and
			// nothing replaces it, so the run stops instead. `sign-commits.py` calls
			// this out with the same emphasis and hides it behind `allow_resign`;
			// there is no such switch on a webhook.
			return refuse("foreign_signature", sha);
		}

		if (commit.parents.length !== 1) {
			// A merge has two histories to re-parent and a root commit has none.
			// Neither is what a service that signs a linear push is for.
			return refuse("unsupported_commit_shape", sha);
		}

		if (!material.identities.has(commit.committer.email.toLowerCase())) {
			return refuse("foreign_committer", sha);
		}

		const reproduced = await reproduceCommit(commitContents(commit), sha);
		if (reproduced === null) {
			return refuse("commit_not_reproducible", sha);
		}

		planned.push({ commit, payload: reproduced.payload, termination: reproduced.termination });
		sha = commit.parents[0] as string;
	}

	// Oldest first: a rewritten parent has to exist before its child names it.
	return planned.reverse();
}

/** A commit's contents, optionally re-parented. */
function commitContents(commit: RepositoryCommit, parents: string[] = commit.parents): CommitContents {
	return {
		tree: commit.tree,
		parents,
		author: commit.author,
		committer: commit.committer,
		message: commit.message,
	};
}

/**
 * Spend one token per signature this run is about to make.
 *
 * Consumed **before** anything is signed, all of it, so a run either has the
 * budget for the whole rewrite or makes no signature at all. A run that spent
 * its way halfway through a range and then stopped would leave the branch
 * needing exactly the work it just refused to finish.
 *
 * Keyed by the grant — installation, repository *and* key — because that is the
 * unit an operator wrote, so one repository cannot spend another's budget and
 * re-pointing a repository at a different key does not inherit the old one's.
 * Fails closed, like every other limiter on this path.
 */
async function consumeSigningBudget(
	env: Env,
	context: RepositoryContext,
	keyId: KeyId,
	signatures: number,
): Promise<PushSigningOutcome | null> {
	const identity = signingBudgetIdentity(context.installationId, context.fullName, keyId);

	for (let spent = 0; spent < signatures; spent += 1) {
		let response: Response;
		try {
			response = await fetchRateLimiter(env, identity);
		} catch (error) {
			return refuse("rate_limiter_unavailable", error instanceof Error ? error.message : String(error));
		}

		// A 429 carries the verdict, not a failure — reading `!ok` alone reports
		// every denial as an outage. Same note as `adminRateLimit`.
		if (!response.ok && response.status !== HTTP.TooManyRequests) {
			return refuse("rate_limiter_unavailable", `limiter returned ${response.status}`);
		}

		const verdict = (await response.json()) as { allowed?: boolean };
		if (verdict.allowed !== true) {
			return refuse("rate_limited", `after ${spent} of ${signatures}`);
		}
	}

	return null;
}

/**
 * Sign one commit and have GitHub create it, or refuse.
 *
 * Two checks stand between the signature and the returned object, and both are
 * before anything is referenced:
 *
 * 1. **The signature verifies under the key that made it**, checked here rather
 *    than trusted. This is what makes the run a fixpoint — see the module
 *    comment — and a signature that failed silently would produce a commit this
 *    service rewrites again on the very next delivery.
 * 2. **The object GitHub created is the object that was signed.** Its name is
 *    recomputed from the payload plus the `gpgsig` that was sent, and its
 *    fields are compared one by one. The two together mean a ref is never moved
 *    to a commit whose contents were decided anywhere but here.
 */
async function signAndCreate(
	env: Env,
	context: RepositoryContext,
	material: SigningMaterial,
	planned: PlannedCommit,
	parents: string[],
): Promise<{ sha: string } | PushSigningOutcome> {
	const contents = commitContents(planned.commit, parents);

	let payload: string;
	try {
		payload = commitPayload(contents, planned.termination);
	} catch (error) {
		return refuse("commit_not_reproducible", error instanceof Error ? error.message : String(error));
	}

	let signature: string;
	try {
		signature = (await signCommitData(payload, material.key, env.KEY_PASSPHRASE)).signature;
	} catch {
		// The detail is this commit's name and nothing from the thrown value. A
		// failure inside openpgp can quote the key it choked on, and this one is
		// decrypted.
		return refuse("signing_failed", planned.commit.sha);
	}

	if (!(await verifyDetachedSignature(payload, signature, material.publicKey))) {
		return refuse("signature_unverifiable", planned.commit.sha);
	}

	const created = await createCommit(env, context, {
		message: planned.commit.message,
		tree: contents.tree,
		parents,
		author: contents.author,
		committer: contents.committer,
		signature,
	});

	const expected = await commitObjectSha(commitWithSignature(payload, signature));
	const sameFields =
		created.tree === contents.tree &&
		created.parents.length === parents.length &&
		created.parents.every((parent, index) => parent === parents[index]) &&
		created.message === planned.commit.message;

	if (!sameFields || created.sha !== expected) {
		return refuse("created_commit_mismatch", `${planned.commit.sha} -> ${created.sha}`);
	}

	return { sha: created.sha };
}

/** Did this outcome come back from one of the helpers as a refusal? */
function isOutcome(value: unknown): value is PushSigningOutcome {
	return isObject(value) && typeof value.acted === "boolean";
}

/**
 * Sign the commits a `push` delivered, or say why not.
 *
 * @param env - Deployment bindings
 * @param authorization - The decision `githubWebhookAuthorize` reached. The
 *   repository and the key both come from here and from nowhere else
 * @param payload - The verified delivery payload, consulted for the ref and the
 *   two object names only
 */
export async function signPushedCommits(
	env: Env,
	authorization: WebhookAuthorization | undefined,
	payload: unknown,
): Promise<PushSigningOutcome> {
	const context = repositoryContext(authorization);
	if (context === null) {
		return refuse("not_repository_scope");
	}

	const subject = pushSubject(payload);
	if (subject.branch === null) {
		return refuse("unsupported_ref");
	}
	if (subject.deleted || subject.after === NULL_SHA) {
		return refuse("branch_deleted");
	}
	if (subject.before === NULL_SHA) {
		// A created branch has no base to walk down to, so the range is "every
		// commit reachable from the tip" — which is not a webhook's job. The
		// `sign-commits` workflow exists for that.
		return refuse("branch_created");
	}
	if (subject.before === null || subject.after === null) {
		return refuse("unreadable_range");
	}

	const range = { before: subject.before, after: subject.after };

	try {
		const material = await signingMaterial(env, authorization);
		if (isOutcome(material)) {
			return material;
		}

		const planned = await planCommits(env, context, material, range);
		if (isOutcome(planned)) {
			return planned;
		}

		if (planned.length === 0) {
			// Every commit in the range already carries a signature this key made.
			// This is the outcome on every delivery caused by this service's own
			// push, and it is a success rather than a refusal: the branch is in the
			// state the run exists to put it in.
			return { acted: true, branch: subject.branch, from: range.after, head: range.after, signed: 0 };
		}

		const denied = await consumeSigningBudget(env, context, material.keyId, planned.length);
		if (denied !== null) {
			return denied;
		}

		const rewritten = new Map<string, string>();
		for (const commit of planned) {
			const parents = commit.commit.parents.map((parent) => rewritten.get(parent) ?? parent);
			const created = await signAndCreate(env, context, material, commit, parents);
			if (isOutcome(created)) {
				return created;
			}
			rewritten.set(commit.commit.sha, created.sha);
		}

		const head = rewritten.get(range.after);
		if (head === undefined) {
			// Unreachable: the walk starts at `after`, so it is in the map unless the
			// plan was empty, which returned above. Present so a future change to the
			// walk cannot silently move a ref to the wrong object.
			return refuse("created_commit_mismatch", "the pushed head was not rewritten");
		}

		// The last read before the only write. A branch that moved since the
		// delivery is somebody else's push, and forcing over it is the one mistake
		// this run could make that destroys work rather than merely failing.
		// It leaves a window — GitHub has no compare-and-set on a ref — but it
		// closes the hours-long one an unchecked force would leave open.
		if ((await getBranchHead(env, context, subject.branch)) !== range.after) {
			return refuse("head_moved", subject.branch);
		}

		try {
			await updateBranch(env, context, subject.branch, head);
		} catch (error) {
			if (error instanceof GitHubApiError && error.status === null) {
				// The request did not complete. Whether the ref moved is unknown, and
				// "unknown" must not be reported as "safe to retry": the caller uses
				// that answer to decide whether to hand the delivery id back.
				return refuse("ref_update_indeterminate", subject.branch);
			}
			throw error;
		}

		return { acted: true, branch: subject.branch, from: range.after, head, signed: planned.length };
	} catch (error) {
		if (error instanceof GitHubApiError) {
			return refuse("github_unavailable", error.message);
		}
		// A deployment that serves the webhook without usable App credentials is a
		// configuration fault, and it is *this* handler's fault to report rather
		// than an exception to let escape: an escaping throw settles the delivery
		// neither way and leaves it to a lease, when what actually happened is
		// precisely nothing, and the operator's redelivery after fixing the
		// credentials is the whole recovery path. The message names settings, never
		// their values — see `requireAppConfig`.
		if (error instanceof GitHubAppError) {
			return refuse("app_misconfigured", error.message);
		}
		throw error;
	}
}
