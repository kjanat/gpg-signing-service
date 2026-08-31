/**
 * Turning an `@claude` comment into a workflow run, and the four things that
 * stand between those two facts.
 *
 * The entrypoint this replaces is a native Actions trigger: GitHub raises
 * `issue_comment`, Actions matches the workflow's `if:`, a runner boots. That
 * path has one gate, the `if:` expression, and it is evaluated by GitHub inside
 * a file this repository's own automation cannot push. Moving the entrypoint
 * here moves the gate here with it, and a gate that used to be one line of YAML
 * has to become something worth reading, because what is on the other side of
 * it is a job holding `contents: write`, `id-token: write`, every repository
 * secret and unrestricted Bash.
 *
 * ### A valid signature is not permission to spend somebody's budget
 *
 * By the time anything here runs, the delivery has proved it came from GitHub
 * (`githubWebhookAuth`) and that it is about a repository an operator paired
 * with an installation (`githubWebhookAuthorize`). Neither says anything about
 * *who wrote the comment*. Comments on a public repository are written by
 * anyone at all, and they arrive under the same installation, about the same
 * allowlisted repository, with the same valid HMAC as the owner's. An allowlist
 * entry authorizes the repository; it does not authorize its readers.
 *
 * So the author is authorized separately, and against GitHub rather than
 * against anything in the payload: {@link authorizeActor} asks what that login
 * may actually do to the repository and requires `write` or `admin`. Every
 * other answer, and every failure to get one, refuses. `author_association` is
 * *not* the check — it reports `COLLABORATOR` for a read-only collaborator,
 * which is precisely the account this has to exclude.
 *
 * One status is not allowed to answer two questions. A 404 from the collaborator
 * endpoint means "not a collaborator" *and* "this installation can no longer see
 * the repository", and only the first is a settled fact about a person. They are
 * separated by asking a second, independent question — is the repository still
 * visible on this token — rather than by reading the first answer harder. See
 * {@link RepositoryClient.getActorPermission}.
 *
 * ### Dispatching cannot be taken back
 *
 * There is no idempotency key on the workflow-dispatch endpoint, and a second
 * call starts a second run. Two agent sessions on one request is not a
 * duplicate log line — it is two sessions pushing to one branch. So the delivery
 * id is written to the ledger *before* the call rather than after it, through
 * {@link CommentDispatchHooks.beforeDispatch}, and the ambiguous outcome — the
 * request left, the answer did not come back — resolves as at-most-once.
 *
 * Written, and not merely decided. A flag on the request context would still
 * have to be turned into a ledger write by something that runs afterwards, and
 * "afterwards" is exactly what an evicted isolate does not have; the hold is
 * durable when the POST leaves, so a process that never runs again still leaves
 * the id spent. A hold that does not land refuses the dispatch outright.
 *
 * The one exception is a definite refusal. A 4xx is GitHub saying it created
 * nothing: an unknown workflow, a ref the workflow is not on, a permission the
 * installation never granted. Those are operator-fixable, so the hold is
 * released and a redelivery is a real retry. See
 * {@link RepositoryClient.dispatchWorkflow}.
 *
 * ### Nothing here may become a loop
 *
 * The session this starts finishes by writing a comment. That comment is on the
 * same issue, arrives as the same event, and may perfectly reasonably contain
 * the phrase — quoting the request it answered is the obvious thing for it to
 * do. So a comment that was not written by a human is refused, and refused on
 * the identity GitHub attaches rather than on anything the text says: bots have
 * `type: "Bot"`, and a comment posted through an App carries
 * `performed_via_github_app`. Both are facts about the actor; a body that
 * merely promises not to be a loop is not.
 *
 * ### What this deliberately does not do
 *
 * It leaves no reaction and posts no acknowledgement. A reaction is a write to
 * the repository under the installation token to tell somebody something they
 * find out anyway when the run starts, and the App's own comment would be one
 * more thing that has to be excluded from the loop check above. The workflow
 * reports; this starts it.
 */

import type { Env } from "#types";
import { GitHubAppError } from "#utils/github-app";
import { LOGIN_PATTERN } from "#utils/github-authorization";
import type { ActorPermission, RepositoryClient } from "#utils/github-repo";
import { GitHubApiError, RepositoryNotVisibleError } from "#utils/github-repo";

/**
 * The phrase a comment must contain, matched case-insensitively.
 *
 * The same string and the same case rule the workflow's own `if:` used, because
 * the two have to agree about what a request is: GitHub expression `contains()`
 * folds case for strings, and `.github/scripts/claude-agent-harness.sh` greps
 * with `-i`. A dispatch path that were stricter would silently drop requests
 * the old entrypoint accepted, which is the failure nobody reports because it
 * looks like the service being down.
 *
 * A constant rather than a var. It is the trigger for one workflow this
 * repository owns, and a configurable trigger phrase is a way for a
 * misconfiguration to make every comment a request.
 */
export const TRIGGER_PHRASE = "@claude";

/**
 * Dispatch attempts per minute, per authorized `<installation, repository>`.
 *
 * Not the same thing as the webhook meter in front of the whole route, which
 * counts requests per source address and would be exhausted by GitHub's own
 * delivery traffic long before it bounded anything about this. This bounds
 * *comments that reach the actor check*, which is the first thing an arbitrary
 * commenter can cause to cost a GitHub API call — one lookup each, on a
 * repository where anybody may comment.
 *
 * Ten a minute is far more than a person asks for and far less than a loop
 * produces. Tune it against real traffic rather than treating the number as
 * load-bearing.
 */
export const DISPATCH_LIMIT = 10;

/** Is comment dispatch switched on for this deployment? */
export function commentDispatchEnabled(env: Pick<Env, "GITHUB_APP_COMMENT_DISPATCH">): boolean {
	// A literal `"true"`, the third flag to use this rule and for the reason
	// `githubAppEnabled` states: a near-miss must read as off.
	return env.GITHUB_APP_COMMENT_DISPATCH === "true";
}

/**
 * A workflow file name, and nothing that could be a path.
 *
 * The value is interpolated into `/actions/workflows/<here>/dispatches`. It is
 * percent-encoded at that point, so a `/` could not escape the segment — but a
 * setting whose *documented* meaning is "a file under `.github/workflows/`"
 * should not silently accept something that is not one, because the failure
 * would be a 404 from GitHub rather than a sentence naming the mistake.
 */
const WORKFLOW_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.ya?ml$/;

/**
 * A ref this service will name to GitHub.
 *
 * Deliberately narrower than git allows. It is operator configuration, it names
 * the version of a privileged workflow, and every name a real deployment uses
 * passes: `master`, `main`, `release/2026-08`, `v1.2.3`.
 *
 * The leading-character rule is doing more work than it looks like: quoting
 * stops a value becoming a second word but not a second *option*, and requiring
 * the first character to be alphanumeric is what makes a `--upload-pack=`-shaped
 * value un-option-like. `..` is excluded separately, because the character class
 * admits `.` and a ref may not contain the sequence.
 */
const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/;

/** Which workflow, on which ref. Operator configuration, never payload. */
export interface DispatchTarget {
	workflow: string;
	ref: string;
}

/**
 * The configured dispatch target, or a `misconfigured` throw naming what is
 * missing.
 *
 * Both halves are checked together, the way {@link requireAppConfig} checks the
 * App credentials, so an operator who set one is told about the other in the
 * same breath. Neither has a default: a default workflow would be this service
 * picking which of somebody's workflows a comment may start, and a default ref
 * would be it picking which version of that workflow — which is to say, which
 * prompt, which tool allowlist and which permissions.
 */
export function requireDispatchTarget(
	env: Pick<Env, "GITHUB_APP_DISPATCH_WORKFLOW" | "GITHUB_APP_DISPATCH_REF">,
): DispatchTarget {
	const workflow = env.GITHUB_APP_DISPATCH_WORKFLOW?.trim();
	const ref = env.GITHUB_APP_DISPATCH_REF?.trim();

	const missing: string[] = [];
	if (!workflow) {
		missing.push("GITHUB_APP_DISPATCH_WORKFLOW");
	}
	if (!ref) {
		missing.push("GITHUB_APP_DISPATCH_REF");
	}

	if (!workflow || !ref) {
		throw new GitHubAppError(`GITHUB_APP_COMMENT_DISPATCH is true but ${missing.join(" and ")} is not set`, {
			misconfigured: true,
		});
	}

	if (!WORKFLOW_PATTERN.test(workflow)) {
		throw new GitHubAppError(
			`GITHUB_APP_DISPATCH_WORKFLOW must be a workflow file name under .github/workflows/, such as claude.yml`,
			{ misconfigured: true },
		);
	}

	if (!REF_PATTERN.test(ref) || ref.includes("..")) {
		throw new GitHubAppError(`GITHUB_APP_DISPATCH_REF is not a ref name this service will hand to GitHub`, {
			misconfigured: true,
		});
	}

	return { workflow, ref };
}

/** Why a comment started nothing. Logged and audited; never sent in this detail. */
export type CommentDispatchRefusal =
	/** `GITHUB_APP_COMMENT_DISPATCH` is not `"true"`. No GitHub call was made. */
	| "disabled"
	/** The delivery is an `edited` or `deleted` comment, not a new one. */
	| "not_created"
	/** The comment does not contain the trigger phrase. */
	| "no_trigger_phrase"
	/** The payload has no usable issue number, comment id or body. */
	| "unreadable_comment"
	/** No usable author login, or a sender that disagrees with the comment's author. */
	| "unreadable_actor"
	/** The comment was written by a bot, or posted through a GitHub App. */
	| "actor_is_not_human"
	/** The author holds `read` or no access to the authorized repository. */
	| "actor_not_permitted"
	/** GitHub could not be asked what the author may do. Fails closed. */
	| "permission_lookup_failed"
	/** The per-repository dispatch budget refused this comment. */
	| "rate_limited"
	/** The budget could not be consulted. Fails closed. */
	| "budget_unavailable"
	/** The delivery id could not be durably held before dispatching. Fails closed. */
	| "ledger_unavailable";

/** What a dispatchable comment is, once the payload has been read defensively. */
export interface CommentDispatchPlan {
	/** The issue or pull request the comment is on. */
	issueNumber: number;
	/** The comment itself, which is how the workflow fetches the instruction. */
	commentId: number;
	/** The author, already shaped like a GitHub login. Not yet authorized. */
	actor: string;
	/** Whether the entity is a pull request. Reported, never used to authorize. */
	isPullRequest: boolean;
}

/** Reading the payload found a request, or it did not. */
export type CommentPlan = { act: true; plan: CommentDispatchPlan } | { act: false; reason: CommentDispatchRefusal };

/** Is `value` a JSON object (and not null, and not an array)? */
function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A positive integer as GitHub numbers its issues and comments. */
function positiveId(value: unknown): number | null {
	return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null;
}

/**
 * Read an actor object, insisting it is a human's.
 *
 * Returns the login only when the object says `type: "User"`. `type` is
 * GitHub's own classification and it is the field that separates a person from
 * an App's bot account — which is what the completion comment of the very
 * session this dispatches is posted by.
 */
function humanLogin(value: unknown): string | null {
	if (!isObject(value)) {
		return null;
	}

	const login = value.login;
	if (typeof login !== "string" || !LOGIN_PATTERN.test(login)) {
		return null;
	}

	// Absent `type` is refused rather than assumed to be a user. Every real
	// payload carries it, so the only thing an assumption would buy is accepting
	// a payload shape GitHub does not send.
	return value.type === "User" ? login : null;
}

/**
 * What this delivery is asking for, read from the verified payload.
 *
 * Pure: no bindings, no clock, no network. The order is the policy, and the
 * cheap refusals come first so an arbitrary comment on a busy repository is
 * dropped before anything costs a GitHub call.
 *
 * The one check worth pointing at: `action` must be `created`. An `edited`
 * delivery is a comment somebody changed, and accepting it would mean a
 * year-old comment could be edited into a fresh request — and edited again, and
 * again, each edit a new delivery id that the replay ledger has no reason to
 * refuse.
 */
export function planCommentDispatch(payload: unknown): CommentPlan {
	if (!isObject(payload)) {
		return { act: false, reason: "unreadable_comment" };
	}

	if (payload.action !== "created") {
		return { act: false, reason: "not_created" };
	}

	const comment = payload.comment;
	const issue = payload.issue;
	if (!isObject(comment) || !isObject(issue)) {
		return { act: false, reason: "unreadable_comment" };
	}

	const body = comment.body;
	if (typeof body !== "string") {
		return { act: false, reason: "unreadable_comment" };
	}

	// Case-insensitively, matching the entrypoint this replaces. A comment that
	// merely quotes an earlier request does trigger, exactly as it did before —
	// changing that is a change to what a request *is*, and it belongs with the
	// workflow that reads the comment rather than with the transport that
	// forwards it.
	if (!body.toLowerCase().includes(TRIGGER_PHRASE)) {
		return { act: false, reason: "no_trigger_phrase" };
	}

	const issueNumber = positiveId(issue.number);
	const commentId = positiveId(comment.id);
	if (issueNumber === null || commentId === null) {
		return { act: false, reason: "unreadable_comment" };
	}

	const author = humanLogin(comment.user);
	const sender = humanLogin(payload.sender);

	if (author === null || sender === null) {
		// Either identity being unreadable is the same refusal as either being a
		// bot, and they are one reason rather than two on purpose: an attacker
		// choosing between "omit the field" and "set type to Bot" learns nothing
		// from the answer, and neither shape is one this service acts on.
		return {
			act: false,
			reason: isObject(comment.user) || isObject(payload.sender) ? "actor_is_not_human" : "unreadable_actor",
		};
	}

	// On `issue_comment.created` these are always the same account. Requiring it
	// costs nothing on a real delivery and means the one identity that gets
	// authorized is unambiguously the one that wrote the instruction.
	if (author.toLowerCase() !== sender.toLowerCase()) {
		return { act: false, reason: "unreadable_actor" };
	}

	// A comment posted through an App, by an App. Refused even though `type` said
	// `User`, because that combination is an integration acting under somebody's
	// name — including this repository's own automation using `gh`. The cost is
	// stated rather than hidden: a maintainer whose client posts through an App
	// is refused too, and comments again from the web UI. Erring the other way
	// costs a session that starts sessions.
	if (comment.performed_via_github_app !== undefined && comment.performed_via_github_app !== null) {
		return { act: false, reason: "actor_is_not_human" };
	}

	return {
		act: true,
		plan: {
			issueNumber,
			commentId,
			actor: author,
			// `issue.pull_request` is the only thing separating a pull request
			// comment from an issue comment: both arrive as `issue_comment`.
			isPullRequest: issue.pull_request !== undefined && issue.pull_request !== null,
		},
	};
}

/** The roles that may start a privileged run. */
const PERMITTED = new Set(["admin", "write"]);

/**
 * What a refused lookup was refused *for*, in one word, for the audit row.
 *
 * `reason` already carries the decision — whether the delivery is spent and
 * whether it may be redelivered — and this carries the diagnosis. They are
 * separate fields because they answer to different readers: the first is the
 * service deciding what to do, the second is an operator at three in the
 * morning working out whether the problem is a person or the installation.
 */
export type ActorLookupDetail =
	/** GitHub answered, and the role it named is not enough. */
	| "insufficient_permission"
	/** GitHub 404'd the lookup and the repository is still visible: an outsider. */
	| "not_a_collaborator"
	/** The installation can no longer see the repository. An operator's problem. */
	| "repository_not_visible"
	/** Anything else: a 403, a 5xx, a timeout, an unreadable answer. */
	| "lookup_failed";

/** How the actor question was answered, or why it could not be. */
export type ActorAuthorization =
	| { allowed: true; permission: string }
	| {
			allowed: false;
			reason: CommentDispatchRefusal;
			status: number | null;
			detail: ActorLookupDetail;
	  };

/**
 * May this login cause a workflow run on the authorized repository?
 *
 * Asked of GitHub, about the repository the *allowlist* named — the client
 * carries that binding and takes no repository argument — so a comment cannot
 * present an author's access to one repository as authority over another.
 *
 * `write` covers `maintain`, which GitHub folds into it in this field's legacy
 * base-role vocabulary. `read` covers `triage`, and neither is enough: the job
 * on the other side of this writes to the repository.
 *
 * Fails closed on anything it cannot establish. A lookup that 500s, times out,
 * or comes back in a shape this service does not recognise is not a grant.
 *
 * **A repository the installation cannot see is one of those things.** It
 * arrives as a 404 from the collaborator endpoint, which is the same status an
 * ordinary outsider produces, and {@link RepositoryClient.getActorPermission}
 * is what tells them apart — by asking a second, independent question rather
 * than by reading the first answer harder. Only the outsider is settled; the
 * invisible repository is a configuration failure that must stay retryable, or
 * an operator who removed the App from a repository by accident would find
 * every comment burned and audited as an untrusted author.
 */
export async function authorizeActor(client: RepositoryClient, login: string): Promise<ActorAuthorization> {
	let answer: ActorPermission;
	try {
		answer = await client.getActorPermission(login);
	} catch (error) {
		// The status travels, the message does not. A GitHub error body from this
		// endpoint can quote the request back, and the request carried an
		// installation token; the status is enough to tell "the installation never
		// granted this read" from "GitHub was having a bad minute".
		//
		// Both branches refuse and both stay retryable — the difference is only
		// what the audit row says, and it is worth saying because the two send an
		// operator to different pages of the App's settings.
		return {
			allowed: false,
			reason: "permission_lookup_failed",
			status: error instanceof GitHubApiError ? error.status : null,
			detail: error instanceof RepositoryNotVisibleError ? "repository_not_visible" : "lookup_failed",
		};
	}

	if (!PERMITTED.has(answer.permission)) {
		return {
			allowed: false,
			reason: "actor_not_permitted",
			status: null,
			// Both are settled and both refuse; they differ only in what an operator
			// reads. `not_a_collaborator` is only ever reached through a *visible*
			// repository — the invisible case threw above and never gets this far —
			// so it says "an outsider asked", not "we could not tell".
			detail: answer.collaborator ? "insufficient_permission" : "not_a_collaborator",
		};
	}

	return { allowed: true, permission: answer.permission };
}

/** The point of no return, and the budget, supplied by the caller. */
export interface CommentDispatchHooks {
	/**
	 * Spend one unit of the per-repository budget.
	 *
	 * Called before the actor lookup, because the lookup is the first GitHub call
	 * an arbitrary commenter can cause.
	 */
	reserveBudget: () => Promise<"ok" | "limited" | "unavailable">;
	/**
	 * Record durably, before the dispatch request leaves, that it left.
	 *
	 * This is the irreversible boundary. Everything above it has caused nothing
	 * observable — a permission lookup is a read — so every refusal before this
	 * line is a real retry, and everything at or after it is at-most-once.
	 *
	 * It returns rather than throwing, and the caller refuses when it does not
	 * answer `"held"`, because the write has to have *landed* for the guarantee
	 * to mean anything. A hook that only set a flag on a request context would
	 * leave the guarantee resting on this isolate living long enough to write it
	 * afterwards — and an isolate evicted between the dispatch and that write is
	 * precisely the case at-most-once exists for.
	 */
	beforeDispatch: () => Promise<"held" | "unavailable">;
}

/**
 * How a dispatch attempt ended.
 *
 * `retryable` is on every variant rather than derived by the caller, because it
 * is the only field with a security consequence and deriving it means writing
 * the derivation down somewhere it can drift from the outcome it describes.
 * True means nothing left this service and a redelivery is a real retry; false
 * means either something did, or nothing ever will.
 */
export type CommentDispatchResult =
	| { outcome: "dispatched"; plan: CommentDispatchPlan; workflow: string; ref: string; retryable: false }
	| {
			outcome: "skipped";
			reason: CommentDispatchRefusal;
			retryable: boolean;
			/** Which shape of refusal, for the audit row. Null when there is nothing to add. */
			detail: ActorLookupDetail | null;
	  }
	| {
			outcome: "failed";
			reason: CommentDispatchRefusal | "dispatch_refused" | "dispatch_unknown";
			retryable: boolean;
			/** GitHub's status, when GitHub answered. Logged, never sent. */
			status: number | null;
			/** Which shape of refusal, for the audit row. Null when there is nothing to add. */
			detail: ActorLookupDetail | null;
	  };

/**
 * Authorize the comment's author and start the configured workflow.
 *
 * The inputs are ids and one login, and no comment text: the run fetches the
 * instruction itself with the id it is given. That is not a size precaution —
 * it is that a comment body arriving as a workflow input is a comment body one
 * `${{ }}` away from a command line, and the safest place for untrusted text is
 * a place it was never interpolated into.
 *
 * @param client - Bound to the authorized `<installation, repository>` pair
 * @param target - The operator's workflow and ref
 * @param deliveryId - Carried through so a run can be traced to its delivery
 */
export async function dispatchCommentRequest(
	client: RepositoryClient,
	target: DispatchTarget,
	plan: CommentDispatchPlan,
	deliveryId: string,
	hooks: CommentDispatchHooks,
): Promise<CommentDispatchResult> {
	const budget = await hooks.reserveBudget();
	if (budget !== "ok") {
		// Both are transient by nature: a refused budget recovers on its own and an
		// unreachable limiter is an outage. Nothing was asked of GitHub either way.
		return {
			outcome: "failed",
			reason: budget === "limited" ? "rate_limited" : "budget_unavailable",
			retryable: true,
			status: null,
			detail: null,
		};
	}

	const actor = await authorizeActor(client, plan.actor);
	if (!actor.allowed) {
		if (actor.reason === "actor_not_permitted") {
			// A settled answer about who this person is — and settled is exactly what
			// the visibility check above establishes, because the same 404 with the
			// repository gone would not be. A redelivery would reach the same
			// answer, so the id stays spent; granting them access and redelivering is
			// not a workflow anybody wants and asking again is one comment.
			return { outcome: "skipped", reason: actor.reason, retryable: false, detail: actor.detail };
		}

		// Could not be established. Fails closed *and* stays retryable — the two
		// are not in tension: nothing started, so an operator who fixes the
		// installation's permissions, or puts the repository back on it, can
		// redeliver into the fix.
		return { outcome: "failed", reason: actor.reason, retryable: true, status: actor.status, detail: actor.detail };
	}

	// The last recoverable instant. After this the delivery is spent whatever
	// happens, because a request that left and a request whose answer was lost
	// are the same thing from here — so the record of it is durable before the
	// request rather than after the answer.
	if ((await hooks.beforeDispatch()) !== "held") {
		// The hold did not land, so nothing may be sent: dispatching now would be
		// dispatching with no durable record that it happened, which is the one
		// state that lets a redelivery start a second session. Nothing has left,
		// so this is a real retry.
		return { outcome: "failed", reason: "ledger_unavailable", retryable: true, status: null, detail: null };
	}

	const dispatched = await client.dispatchWorkflow(target.workflow, target.ref, {
		issue_number: String(plan.issueNumber),
		comment_id: String(plan.commentId),
		requested_by: plan.actor,
		delivery_id: deliveryId,
	});

	if (dispatched.outcome === "accepted") {
		return { outcome: "dispatched", plan, workflow: target.workflow, ref: target.ref, retryable: false };
	}

	return {
		outcome: "failed",
		reason: dispatched.outcome === "refused" ? "dispatch_refused" : "dispatch_unknown",
		// A 4xx is GitHub stating it created nothing, so the delivery goes back —
		// which is a *release* of the hold taken above, not merely a decision not to
		// commit it. Anything else leaves it spent — see the module comment.
		retryable: dispatched.outcome === "refused",
		status: dispatched.status,
		detail: null,
	};
}
