/**
 * `POST /github/webhook` — the endpoint a GitHub App delivers events to.
 *
 * Two events are acted on and everything else is acknowledged and dropped.
 *
 * `push` signs the unsigned commits at the tip of the pushed branch with the key
 * the operator bound to that repository, moves the branch to them, and — when an
 * operator has switched that on separately — publishes a check run saying what
 * the resulting head's signature turned out to be.
 *
 * `issue_comment` starts the configured Claude workflow when a comment invokes
 * it, replacing the native Actions trigger that used to do so. It is behind its
 * own flag as well, and for a sharper reason than the check runs are: this is
 * the one handler whose effect is entirely outside the service — an Actions run
 * holding repository secrets — so the author of the comment is authorized
 * against GitHub before anything starts. See `#utils/comment-dispatch`.
 *
 * `push` is the only subscribed event the *check* needs, and that is worth
 * saying because a "signature check on pull requests" sounds like it wants
 * `pull_request`. It does not: a PR's head branch lives in a repository, pushes
 * to it raise `push` there, and a check run is attached to a *commit* — which is
 * what a PR displays. `issue_comment` covers pull request conversation comments
 * too, for the same reason: GitHub raises it for both.
 *
 * By the time an event reaches this file, four gates have already run and this
 * handler re-derives none of what they decided:
 *
 * - `githubWebhookAuth` — the HMAC over the raw bytes.
 * - `githubWebhookAuthorize` — an operator-written allowlist of
 *   `<installation, repository>` pairs. **The repository a handler acts on
 *   comes from here**, never from `payload.repository.full_name`.
 * - `requireSigningKey` — the key that same allowlist entry binds. There is no
 *   default and no fall back to `KEY_ID`; a repository with no `=<keyId>`
 *   suffix receives its events and signs nothing.
 * - `webhookReplayGuard` — a delivery id reserved before this runs, and
 *   committed or released after it, so a duplicate cannot double-act and a
 *   failure that changed nothing stays redeliverable. This handler sets
 *   `webhookRetryable`; the guard is what writes the ledger. The one exception
 *   is comment dispatch, which has no idempotence of its own for a redelivery
 *   to meet and so writes a durable *hold* on the id itself, before its request
 *   leaves; the guard's settle then commits or releases that hold.
 *
 * ### What this handler owes the pipeline
 *
 * `loadSigningKey` shares `POST /sign`'s *storage fetch*, not its security
 * boundary — rate limiting and audit are the acting caller's to provide, and
 * they are provided here: a per-key, per-authorized-subject signing budget in
 * front of any signature, and one `push_sign` audit row per attempt that got
 * far enough to try.
 *
 * ### Why this is not in the OpenAPI document
 *
 * Registered with `app.post` rather than through the OpenAPI router, for the
 * reason `/e/:code` is registered with `app.get`: the document exists to
 * generate clients, and the only caller of this route is GitHub, which does not
 * read it. Declaring it would put a `PostGithubWebhook` method on the Go client
 * and on every other generated one, for a caller that will never invoke it, and
 * would require this repository to publish a schema for a payload it does not
 * model. The endpoint is documented for humans in `docs/github-app.md`.
 */

import { createOpenAPIApp } from "#lib/openapi";
import type { AnyStoredKey } from "#schemas/keys";
import type { AppContext, RateLimitResult, WebhookAuthorization, WebhookDelivery } from "#types";
import { createIdentity, HTTP } from "#types";
import { logAuditEvent } from "#utils/audit";
import type { CheckReportResult } from "#utils/check-report";
import { reportSignatureCheck } from "#utils/check-report";
import type { CommentDispatchResult, DispatchTarget } from "#utils/comment-dispatch";
import {
	commentDispatchEnabled,
	DISPATCH_LIMIT,
	dispatchCommentRequest,
	planCommentDispatch,
	requireDispatchTarget,
} from "#utils/comment-dispatch";
import { fetchRateLimiter } from "#utils/durable-objects";
import { scheduleBackgroundTask } from "#utils/execution";
import { planPush } from "#utils/github-push";
import { RepositoryClient } from "#utils/github-repo";
import { loadSigningKey, requireSigningKey } from "#utils/github-signing-key";
import { acknowledgement } from "#utils/github-webhook";
import { logger } from "#utils/logger";
import type { PushSigningResult } from "#utils/push-signing";
import { signPushedCommits } from "#utils/push-signing";
import { holdDelivery } from "#utils/webhook-replay";

const app = createOpenAPIApp();

/**
 * Rate-limiter namespace for the push-signing budget.
 *
 * Not an issuer, so it cannot collide with the `<iss>:<sub>` buckets a signing
 * caller is metered on, nor with the `webhook` meter in front of the whole
 * route — which counts *requests per IP* and is not a signing budget. This one
 * counts signatures, per authorized subject, per key.
 */
const PUSH_SIGNING_METER = "github-push";

/**
 * Signatures per minute per `<installation, repository, key>`.
 *
 * A push may carry up to `MAX_SIGNABLE_COMMITS` signatures, so this is several
 * full pushes a minute for one repository and one key — high enough that no
 * ordinary branch ever meets it, low enough that a delivery loop or a replayed
 * flood cannot turn one grant into unbounded signing. Tune against real traffic
 * rather than treating the number as load-bearing.
 */
const PUSH_SIGNING_LIMIT = 120;

/**
 * The bucket this repository's signatures are counted in.
 *
 * Every component comes from the authorization decision — the operator's
 * installation id, the operator's spelling of the repository, the key that
 * entry bound — so a delivery cannot move itself into a fresh bucket by
 * varying a payload field. That is the failure `/sign`'s second tier exists to
 * stop, arriving here by a different route.
 *
 * The key id is in there even though today it cannot vary independently: one
 * pair may appear on the allowlist once, so a fixed pair has a fixed key, and no
 * request can distinguish a bucket that includes it from one that does not. It
 * is in there because the requirement is a *per-key, per-subject* budget, and
 * the moment a pair can bind more than one key a bucket keyed only on the pair
 * silently becomes a shared one. Exported so that property can be asserted
 * directly rather than inferred from behaviour that does not yet depend on it.
 */
export function signingBudgetIdentity(authorization: WebhookAuthorization, keyId: string): string {
	return createIdentity(PUSH_SIGNING_METER, `${authorization.installationId}:${authorization.repository}:${keyId}`);
}

/**
 * Rate-limiter namespace for the comment-dispatch budget.
 *
 * A third namespace, disjoint from `github-push` and from the `webhook` meter
 * in front of the route, because it bounds a different thing: the `webhook`
 * meter counts requests per source address and GitHub's delivery addresses are
 * a small shared set, so it is exhausted by traffic rather than by abuse.
 * This counts *comments that would cost a GitHub call*, per repository.
 */
const DISPATCH_METER = "github-dispatch";

/**
 * The bucket a repository's dispatch attempts are counted in.
 *
 * Both components come from the authorization decision — the operator's
 * installation id and the operator's spelling of the repository — so a comment
 * cannot move itself into a fresh bucket by varying a payload field. No key id,
 * unlike {@link signingBudgetIdentity}: dispatching starts a workflow and
 * touches no key, so a per-key bucket here would be keyed on something the act
 * does not involve.
 */
export function dispatchBudgetIdentity(authorization: WebhookAuthorization): string {
	return createIdentity(DISPATCH_METER, `${authorization.installationId}:${authorization.repository}`);
}

/**
 * Spend `units` tokens from `identity`'s bucket, stopping at the first refusal.
 *
 * One function for both budgets rather than one each, because the part worth
 * getting right is the same for both and is easy to get wrong the same way: a
 * denied consume arrives as a 429 carrying the verdict, so `!response.ok` alone
 * reads the one answer this is asking for as an outage. The *limits* differ and
 * are the caller's; the reading of the answer does not.
 */
async function spendBudget(
	c: AppContext,
	identity: string,
	limit: number,
	units: number,
): Promise<"ok" | "limited" | "unavailable"> {
	for (let spent = 0; spent < units; spent += 1) {
		let response: Response;
		try {
			response = await fetchRateLimiter(c.env, identity, limit);
		} catch (error) {
			logger.error("Webhook rate limiter unreachable", error, { identity, requestId: c.get("requestId") });
			return "unavailable";
		}

		// A denied consume is a *verdict* and arrives as a 429 with the verdict in
		// the body, so `!ok` alone would read the one answer this is asking for as
		// an outage — the bug `/sign`'s `resolveRateLimit` carries a comment about.
		if (!response.ok && response.status !== HTTP.TooManyRequests) {
			logger.error("Webhook rate limiter failed", { identity, status: response.status, requestId: c.get("requestId") });
			return "unavailable";
		}

		const verdict = (await response.json()) as RateLimitResult;
		if (!verdict.allowed) {
			return "limited";
		}
	}

	return "ok";
}

/** Mark this delivery as having caused nothing, so a redelivery is a real retry. */
function retryable(c: AppContext): void {
	c.set("webhookRetryable", true);
}

/**
 * The audit row for one push-signing attempt.
 *
 * `issuer` names the mechanism and `subject` the *authorized* repository, so
 * filtering `audit_logs` by subject answers "what has this service done to this
 * repository" without a join. Both are operator-controlled strings, as is
 * `keyId`; nothing in the row comes from the payload.
 *
 * The metadata carries shas, a branch, a count and a reason — public facts about
 * a repository the App is installed on. It carries no signature, no token, no
 * key material and no GitHub response body.
 */
function auditPush(
	c: AppContext,
	authorization: WebhookAuthorization,
	keyId: string,
	success: boolean,
	metadata: Record<string, unknown>,
): Promise<void> {
	return scheduleBackgroundTask(
		c,
		c.get("requestId"),
		logAuditEvent(c.env.AUDIT_DB, {
			requestId: c.get("requestId"),
			action: "push_sign",
			issuer: "github-app",
			subject: authorization?.repository ?? "unknown",
			keyId,
			success,
			...(success ? {} : { errorCode: "SIGN_ERROR" as const }),
			metadata: JSON.stringify(metadata),
		}),
	);
}

/**
 * Publish the check run for the head of `branch`, and never fail the delivery
 * over it.
 *
 * **This runs off the response path.** {@link scheduleCheckReport} hands it to
 * `waitUntil`, so the acknowledgement GitHub is waiting for is not behind four
 * authenticated calls — a ref read, a commit read, a check-run lookup and a
 * write, each with its own ten-second ceiling — for a result that by
 * construction cannot change the response. GitHub gives a webhook receiver ten
 * seconds in total; a best-effort observational write does not get to spend
 * them. The cost is that the acknowledgement can no longer name the state it
 * published, which is a nicety, and the delivery no longer waits on the Checks
 * API, which is not.
 *
 * Two things this deliberately does not do. It does not touch
 * `webhookRetryable`: a check run is idempotent, so a redelivery that publishes
 * it again converges on the same run rather than causing a second effect, and
 * handing the delivery id back would instead make a signing push repeatable
 * because a *report* failed. That is now doubly true — by the time this runs
 * the response has been sent and the ledger written, so there is nothing left
 * for it to change even if it tried. And it does not raise: a reporting failure
 * is a thing to record, not a thing to turn a completed signing into a 500 over.
 *
 * The audit row is `check_report`, separate from `push_sign`, because it
 * records a different act — a verdict published about somebody's commit — and
 * because one delivery can do it without signing anything, which is what an
 * already-signed tip does. Its metadata is shas, a state from a closed set, a
 * check run id and a branch. No signature, no token, no key material, no GitHub
 * response body.
 */
async function reportCheck(
	c: AppContext,
	client: RepositoryClient,
	authorization: WebhookAuthorization,
	keyId: string,
	key: AnyStoredKey,
	branch: string,
): Promise<CheckReportResult> {
	const requestId = c.get("requestId");
	// The client is the caller's — the one already bound to the authorized
	// `<installation, repository>` pair — rather than rebuilt here. Rebuilding it
	// would be a second place that decides which repository this delivery may
	// address, and two such places are one too many.
	const report = await reportSignatureCheck(c.env, client, branch, key, keyId);

	if (report.outcome === "published") {
		logger.info("Published a commit signature check", {
			requestId,
			repository: authorization.repository,
			keyId,
			branch,
			sha: report.sha,
			state: report.state,
			conclusion: report.conclusion,
			checkRunId: report.checkRunId,
			action: report.action,
		});
		await auditCheck(c, authorization, keyId, true, {
			branch,
			sha: report.sha,
			state: report.state,
			detail: report.finding.detail,
			conclusion: report.conclusion,
			checkRunId: report.checkRunId,
			action: report.action,
		});
		return report;
	}

	if (report.outcome === "failed") {
		// At error and audited: an installation that has not granted
		// `checks: write` lands here on every delivery, and the operator needs to
		// be able to see that without reading the App's own delivery log.
		logger.error("Could not publish a commit signature check", {
			requestId,
			repository: authorization.repository,
			branch,
			reason: report.reason,
		});
		await auditCheck(c, authorization, keyId, false, { branch, reason: report.reason });
		return report;
	}

	// Skipped. `disabled` is every deployment that has not opted in, so it is
	// debug rather than info — the rest are states an operator may want to see
	// and are rare enough to log.
	if (report.reason === "disabled") {
		return report;
	}

	logger.info("Published no commit signature check", {
		requestId,
		repository: authorization.repository,
		branch,
		reason: report.reason,
	});

	return report;
}

/**
 * The audit row for one check-run report. See {@link reportCheck}.
 *
 * Written directly rather than through `scheduleBackgroundTask`, which is the
 * one difference from {@link auditPush}: its caller is *already* a background
 * task, so scheduling from here would be asking `waitUntil` to adopt a promise
 * from inside a `waitUntil` callback. Awaiting it keeps the row inside the task
 * the runtime is already keeping alive, and inside the same failure handler.
 */
function auditCheck(
	c: AppContext,
	authorization: WebhookAuthorization,
	keyId: string,
	success: boolean,
	metadata: Record<string, unknown>,
): Promise<void> {
	return logAuditEvent(c.env.AUDIT_DB, {
		requestId: c.get("requestId"),
		action: "check_report",
		issuer: "github-app",
		subject: authorization.repository ?? "unknown",
		keyId,
		success,
		...(success ? {} : { errorCode: "INTERNAL_ERROR" as const }),
		metadata: JSON.stringify(metadata),
	});
}

/**
 * Hand {@link reportCheck} to the runtime and return, without waiting for it.
 *
 * The whole reason reporting is safe to move here is the reason it was safe to
 * put after the outcome branches in the first place: it decides nothing. It
 * cannot change the status, it cannot change the body, and it cannot change
 * `webhookRetryable` — so the only thing awaiting it ever bought was latency on
 * a response GitHub times out in ten seconds.
 *
 * `scheduleBackgroundTask` awaits the task when there is no `executionCtx` to
 * hand it to, which is the documented fallback for environments that do not
 * provide one. That is the one case where this still costs the response, and it
 * is not a case any deployment is in.
 */
function scheduleCheckReport(
	c: AppContext,
	client: RepositoryClient,
	authorization: WebhookAuthorization,
	keyId: string,
	key: AnyStoredKey,
	branch: string,
): Promise<void> {
	return scheduleBackgroundTask(c, c.get("requestId"), reportCheck(c, client, authorization, keyId, key, branch));
}

/**
 * Sign what a push left unsigned.
 *
 * Every exit either publishes something or marks the delivery retryable, and
 * the two are mutually exclusive by construction: `retryable` is called only on
 * paths that have provably not reached `signPushedCommits`'s publish boundary,
 * and `PushSigningResult.published` is what reports which side of that boundary
 * a failure landed on.
 */
async function handlePush(
	c: AppContext,
	delivery: WebhookDelivery,
	authorization: WebhookAuthorization | undefined,
): Promise<Response> {
	const requestId = c.get("requestId");

	const plan = planPush(c.get("webhookPayload"));
	if (!plan.act) {
		// A tag, a deletion, a payload with no ref. Deterministic no-ops: a
		// redelivery would reach the same answer, so the id stays committed rather
		// than being handed back for a replay that cannot accomplish anything.
		logger.info("Push delivery causes no signing", { requestId, delivery: delivery.id, reason: plan.reason });
		return c.json(
			{ ...acknowledgement(delivery, authorization, { duplicate: false }), skipped: plan.reason },
			HTTP.Accepted,
		);
	}

	const decision = requireSigningKey(authorization);
	// Built here rather than after the key checks, so "no key" and "no repository
	// to address" are one refusal instead of two — the second of which would
	// otherwise be an unreachable branch nothing could test. Both mean the same
	// thing to a delivery: it may not act.
	const client = RepositoryClient.forAuthorization(c.env, authorization);

	if (!decision.allowed || client === null) {
		const reason = decision.allowed ? "not_repository_scope" : decision.reason;
		// `no_key_bound` is a configuration state an operator fixes and then
		// redelivers, so the id goes back. `not_repository_scope` cannot be fixed by
		// anything — a push that is not about an allowlisted pair was refused
		// upstream — so it does not.
		if (reason === "no_key_bound") {
			retryable(c);
		}
		logger.warn("Push delivery has no signing key", { requestId, delivery: delivery.id, reason });
		return c.json(
			{ ...acknowledgement(delivery, authorization, { duplicate: false }), skipped: reason },
			HTTP.Accepted,
		);
	}

	// Non-null: `requireSigningKey` only allows at `repository` scope, which is
	// the scope that carries both halves of the pair.
	const grant = authorization as WebhookAuthorization;

	const loaded = await loadSigningKey(c.env, grant);
	if (!loaded.allowed) {
		// The key named by the allowlist is gone, or storage did not answer.
		// Neither changed anything, and both are states an operator resolves and
		// then redelivers into.
		retryable(c);
		logger.error("Push delivery could not load its signing key", {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
			keyId: decision.keyId,
			reason: loaded.reason,
		});
		await auditPush(c, grant, decision.keyId, false, { branch: plan.branch, reason: loaded.reason });
		return c.json(
			{ ...acknowledgement(delivery, authorization, { duplicate: false }), skipped: loaded.reason },
			HTTP.ServiceUnavailable,
		);
	}

	const identity = signingBudgetIdentity(grant, decision.keyId);

	let result: PushSigningResult;
	try {
		result = await signPushedCommits(client, plan.branch, loaded.key, c.env.KEY_PASSPHRASE, {
			reserveBudget: (commits) => spendBudget(c, identity, PUSH_SIGNING_LIMIT, commits),
			// The irreversible boundary. Deciding *before* the branch moves that this
			// delivery is no longer retryable is what makes an ambiguous outcome —
			// request sent, answer lost — a non-repeat: a redelivery finds the id
			// spent instead of force-updating the branch a second time.
			//
			// The decision is all that happens here. `webhookReplayGuard` performs
			// the ledger write from its `finally`, after this handler has returned,
			// and the reservation it took covers the whole request in the meantime.
			beforePublish: async () => {
				c.set("webhookRetryable", false);
			},
		});
	} catch (error) {
		// Anything `signPushedCommits` did not turn into a result. It reports its
		// own failures with a `published` flag, so reaching here means something
		// unmodelled went wrong; the delivery is left committed, which is the
		// direction that cannot sign twice.
		logger.error("Push signing failed unexpectedly", error, {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
		});
		await auditPush(c, grant, decision.keyId, false, { branch: plan.branch, reason: "unexpected_error" });
		return c.json({ error: "Internal server error", code: "INTERNAL_ERROR" }, HTTP.InternalServerError);
	}

	if (result.outcome === "refused") {
		// The budget said no. Nothing was signed and nothing was published, so the
		// delivery goes back: this is exactly the case where an operator waits and
		// redelivers.
		//
		// **Answered before the report is scheduled, and that ordering is the
		// point.** The budget is a bound on this service acting on a repository
		// under one `<installation, repository, key>` grant, and a check run is
		// this service acting on that repository: a ref read, a commit read, a
		// check-run lookup and a write, all under the installation token. Publish
		// after a refusal and the budget stops bounding GitHub API usage at the
		// moment it is being enforced — a delivery loop that the budget refuses
		// every time would still spend four calls per delivery, and would still
		// have this service posting a verdict about a commit it had just declined
		// to touch. The report is not lost: a refusal is redeliverable, and the
		// redelivery that eventually signs reports then.
		retryable(c);
		logger.warn("Push signing refused by its budget", {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
			reason: result.reason,
		});
		await auditPush(c, grant, decision.keyId, false, { branch: plan.branch, reason: result.reason });
		return c.json(
			{ error: "Push signing is over budget", code: "RATE_LIMITED", retryAfter: 60 },
			result.reason === "rate_limited" ? HTTP.TooManyRequests : HTTP.ServiceUnavailable,
		);
	}

	// The head as it stands *after* whatever the signing path did or declined to
	// do, reported as a check run. Deliberately outside every outcome branch
	// below: the useful thing to publish is the state of the commit the branch
	// actually points at, and that is worth saying whether this delivery signed
	// it, found it already signed, or failed part way.
	//
	// Scheduled rather than awaited, so none of the responses below wait on the
	// Checks API — see {@link scheduleCheckReport}. It cannot change any of those
	// outcomes either: `reportCheck` swallows its own failures into an audit row,
	// and nothing in it touches `webhookRetryable`, so the replay decisions
	// `signPushedCommits` drove are exactly the ones that stand — see
	// `#utils/check-report` for why an idempotent write does not want the
	// ledger's protection in the first place.
	//
	// The one outcome above it: a budget refusal, which returned already.
	await scheduleCheckReport(c, client, grant, decision.keyId, loaded.key, plan.branch);

	if (result.outcome === "signed") {
		logger.info("Signed pushed commits", {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
			keyId: decision.keyId,
			branch: result.branch,
			commits: result.commits,
			previousHead: result.previousHead,
			head: result.head,
		});
		await auditPush(c, grant, decision.keyId, true, {
			branch: result.branch,
			commits: result.commits,
			previousHead: result.previousHead,
			head: result.head,
		});
		return c.json(
			{
				...acknowledgement(delivery, authorization, { duplicate: false }),
				handled: true,
				signed: result.commits,
			},
			HTTP.OK,
		);
	}

	if (result.outcome === "skipped") {
		// Nothing was published. Most of these would reach the same answer on a
		// repeat — the head is already signed, the branch is gone, the run is too
		// long, or somebody else's push won the race and will raise its own
		// delivery — so the id stays committed.
		//
		// `unsupported_key` is the exception, and it is the same shape as
		// `no_key_bound` above: an operator bound an X.509 key to this repository,
		// nothing was signed, and the fix is to bind a PGP one and redeliver. A
		// committed id would answer that redelivery `duplicate: true`, which is
		// exactly the lost-event failure the two-phase ledger exists to prevent.
		if (result.reason === "unsupported_key") {
			retryable(c);
		}
		logger.info("Push signing did nothing", {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
			branch: plan.branch,
			reason: result.reason,
		});
		return c.json(
			{ ...acknowledgement(delivery, authorization, { duplicate: false }), skipped: result.reason },
			HTTP.Accepted,
		);
	}

	// Failed. `published` decides whether the delivery may be retried, and it is
	// the only thing that decides it: a failure before the ref moved left the
	// repository untouched.
	if (!result.published) {
		retryable(c);
	}

	logger.error("Push signing failed", {
		requestId,
		delivery: delivery.id,
		repository: grant.repository,
		branch: plan.branch,
		published: result.published,
		reason: result.reason,
	});
	await auditPush(c, grant, decision.keyId, false, {
		branch: plan.branch,
		reason: result.reason,
		published: result.published,
	});

	return c.json({ error: "Push signing failed", code: "SIGN_ERROR" }, HTTP.InternalServerError);
}

/**
 * The audit row for one comment-dispatch decision.
 *
 * Written for refusals as well as for runs that started, which is the point: a
 * comment declined for want of write access is exactly the row an operator
 * wants to be able to find, and it is the row that does not exist anywhere else
 * — the Actions run list shows what ran and never what was turned away.
 *
 * `keyId` is `"none"` rather than `"unknown"`. The column cannot be null, and
 * the two sentinels say different things: `unknown` is admin's "a key was
 * involved and we could not name it", whereas dispatching a workflow involves
 * no key at all. Reusing `unknown` here would make a `WHERE key_id = 'unknown'`
 * over the table mean two things at once.
 *
 * The metadata carries an issue number, a comment id, an actor login and a
 * reason — public facts about a repository the App is installed on, all of them
 * visible to anyone who can read the comment. It carries no token, no key
 * material, and no GitHub response body.
 */
function auditDispatch(
	c: AppContext,
	authorization: WebhookAuthorization | undefined,
	success: boolean,
	errorCode: "AUTH_SUBJECT_UNTRUSTED" | "RATE_LIMITED" | "INTERNAL_ERROR" | null,
	metadata: Record<string, unknown>,
): Promise<void> {
	return scheduleBackgroundTask(
		c,
		c.get("requestId"),
		logAuditEvent(c.env.AUDIT_DB, {
			requestId: c.get("requestId"),
			action: "comment_dispatch",
			issuer: "github-app",
			subject: authorization?.repository ?? "unknown",
			keyId: "none",
			success,
			...(errorCode === null ? {} : { errorCode }),
			metadata: JSON.stringify(metadata),
		}),
	);
}

/**
 * Start the configured workflow for an `@claude` comment, or explain why not.
 *
 * The order is the policy and it is chosen so that the cheapest refusals come
 * first: the flag, then the payload, then the budget, then GitHub. An arbitrary
 * comment on a busy repository is dropped before it costs an API call, and the
 * first thing that *can* cost one — the actor's permission lookup — is behind a
 * per-repository budget.
 *
 * Every exit before {@link CommentDispatchHooks.beforeDispatch} leaves the
 * delivery retryable, and everything from there on does not. See
 * `#utils/comment-dispatch` for why the ambiguous case resolves that way.
 */
async function handleIssueComment(
	c: AppContext,
	delivery: WebhookDelivery,
	authorization: WebhookAuthorization | undefined,
): Promise<Response> {
	const requestId = c.get("requestId");

	const acknowledged = (reason: string) =>
		c.json({ ...acknowledgement(delivery, authorization, { duplicate: false }), skipped: reason }, HTTP.Accepted);

	if (!commentDispatchEnabled(c.env)) {
		// Not merely "did not dispatch": no GitHub call is made at all, which is
		// what makes an upgraded deployment that has not granted `Actions: write`
		// behave exactly as it did before. Deliberately *before* the payload is
		// read, so a deployment with the feature off does no work per comment.
		return acknowledged("dispatch_disabled");
	}

	const plan = planCommentDispatch(c.get("webhookPayload"));
	if (!plan.act) {
		// Deterministic no-ops, every one of them: an edit rather than a new
		// comment, no trigger phrase, a bot, an unreadable payload. A redelivery
		// reaches the same answer, so the id stays spent. At debug for the two that
		// are the overwhelming majority of deliveries on a busy repository — a
		// comment with no phrase in it is not an event, it is the weather.
		const routine = plan.reason === "no_trigger_phrase" || plan.reason === "not_created";
		const line = { requestId, delivery: delivery.id, reason: plan.reason, repository: authorization?.repository };
		if (routine) {
			logger.debug("Comment delivery is not a request", line);
		} else {
			logger.info("Comment delivery will not be dispatched", line);
		}

		// Two of these earn a row, and the volume argument is what decides which.
		// `actor_is_not_human` only fires on a comment that *does* invoke the
		// phrase — which is the App recognising its own completion comment, or an
		// integration posting under somebody's name — and `unreadable_actor` is a
		// `sender` disagreeing with `comment.user`, which a real
		// `issue_comment.created` never produces. Both are rare by construction and
		// both are the security-significant ones. The rest are weather: a comment
		// with no phrase in it is not an event, and a row per one of those would be
		// a D1 write per comment on the repository.
		if (plan.reason === "actor_is_not_human" || plan.reason === "unreadable_actor") {
			await auditDispatch(c, authorization, false, "AUTH_SUBJECT_UNTRUSTED", { reason: plan.reason });
		}

		return acknowledged(plan.reason);
	}

	const client = RepositoryClient.forAuthorization(c.env, authorization);
	if (client === null) {
		// An `issue_comment` always names a repository, so reaching this means the
		// grant was not a repository-scoped one — refused upstream — and there is
		// nothing an operator can redeliver into.
		logger.warn("Comment delivery has no repository to act on", { requestId, delivery: delivery.id });
		return acknowledged("not_repository_scope");
	}

	// Non-null: `forAuthorization` returns a client only at `repository` scope.
	const grant = authorization as WebhookAuthorization;

	let target: DispatchTarget;
	try {
		target = requireDispatchTarget(c.env);
	} catch (error) {
		// An operator switched the flag on and did not say what to dispatch. Named
		// in the log and never in the body, the same posture as the webhook secret
		// guard; retryable, because setting the two vars and redelivering is
		// exactly the recovery.
		retryable(c);
		logger.error("Comment dispatch is enabled but not configured", error, { requestId, delivery: delivery.id });
		await auditDispatch(c, grant, false, "INTERNAL_ERROR", { reason: "misconfigured" });
		return c.json({ error: "Service is misconfigured", code: "SERVICE_MISCONFIGURED" }, HTTP.InternalServerError);
	}

	const identity = dispatchBudgetIdentity(grant);

	const deliveryId = delivery.id;

	let result: CommentDispatchResult;
	try {
		result = await dispatchCommentRequest(client, target, plan.plan, deliveryId ?? "unknown", {
			reserveBudget: () => spendBudget(c, identity, DISPATCH_LIMIT, 1),
			// The irreversible boundary, and it is a *durable write* rather than a
			// decision to write later. There is no idempotency key on the dispatch
			// endpoint, so an isolate that died between the POST and the replay
			// guard's `finally` would leave a reservation that lapses in five
			// minutes and a redelivery that starts a second agent session. Holding
			// the id here closes that window: the ledger has the delivery for the
			// full retention window from the moment the request leaves.
			//
			// The context flag is set as well, and it is set *after* the write. It
			// is what the guard reads to decide commit-or-release, and a flag set
			// before a write that did not happen would say the delivery was spent
			// when nothing had recorded it.
			beforeDispatch: async () => {
				if (deliveryId === null) {
					// Unreachable behind `webhookReplayGuard`, which refuses a delivery
					// with no usable id before any handler runs. Present so that a
					// change to the mounting cannot dispatch onto a ledger key that
					// every id-less delivery would share.
					logger.error("Comment dispatch reached the irreversible boundary with no delivery id", { requestId });
					return "unavailable";
				}

				try {
					await holdDelivery(c.env, deliveryId);
				} catch (error) {
					// Fail closed, and nothing has left: the dispatch is refused and the
					// delivery stays retryable, which is the same posture the guard
					// itself takes when the ledger cannot be reached.
					logger.error("Delivery ledger could not hold a delivery before dispatching", error, {
						requestId,
						delivery: deliveryId,
						repository: grant.repository,
					});
					return "unavailable";
				}

				c.set("webhookRetryable", false);
				return "held";
			},
		});
	} catch (error) {
		// Anything `dispatchCommentRequest` did not model. It reports its own
		// failures with a `retryable` flag, so reaching here means something
		// unexpected went wrong at an unknown point; the delivery is left
		// committed, which is the direction that cannot start two runs.
		logger.error("Comment dispatch failed unexpectedly", error, {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
		});
		await auditDispatch(c, grant, false, "INTERNAL_ERROR", { reason: "unexpected_error" });
		return c.json({ error: "Internal server error", code: "INTERNAL_ERROR" }, HTTP.InternalServerError);
	}

	if (result.outcome === "dispatched") {
		logger.info("Dispatched a workflow for a comment", {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
			workflow: result.workflow,
			ref: result.ref,
			issue: result.plan.issueNumber,
			comment: result.plan.commentId,
			actor: result.plan.actor,
		});
		await auditDispatch(c, grant, true, null, {
			workflow: result.workflow,
			ref: result.ref,
			issue: result.plan.issueNumber,
			comment: result.plan.commentId,
			actor: result.plan.actor,
			pullRequest: result.plan.isPullRequest,
		});
		return c.json(
			{ ...acknowledgement(delivery, authorization, { duplicate: false }), handled: true, dispatched: true },
			HTTP.OK,
		);
	}

	if (result.outcome === "skipped") {
		// `actor_not_permitted`, and today only that. Audited as a failure with
		// `AUTH_SUBJECT_UNTRUSTED` rather than logged and forgotten: somebody who
		// may read this repository asked it to run something, and that is the
		// record worth keeping. The reply says nothing about *why*, which would
		// otherwise be a way to probe who holds write access here.
		if (result.retryable) {
			retryable(c);
		}
		logger.warn("Comment delivery was not authorized to dispatch", {
			requestId,
			delivery: delivery.id,
			repository: grant.repository,
			reason: result.reason,
			detail: result.detail,
			actor: plan.plan.actor,
		});
		await auditDispatch(c, grant, false, "AUTH_SUBJECT_UNTRUSTED", {
			reason: result.reason,
			// Which shape of refusal. `not_a_collaborator` is an outsider on a
			// repository the App can still see; `insufficient_permission` is somebody
			// with read or triage. Neither is `repository_not_visible`, which never
			// reaches this branch because it is not a settled answer.
			detail: result.detail,
			actor: plan.plan.actor,
			issue: plan.plan.issueNumber,
			comment: plan.plan.commentId,
		});
		return acknowledged(result.reason);
	}

	// Failed. `retryable` is the only thing that decides whether the delivery
	// goes back, and it is decided where the knowledge is — see
	// `#utils/comment-dispatch`.
	if (result.retryable) {
		retryable(c);
	}

	logger.error("Comment dispatch failed", {
		requestId,
		delivery: delivery.id,
		repository: grant.repository,
		reason: result.reason,
		detail: result.detail,
		status: result.status,
		retryable: result.retryable,
		actor: plan.plan.actor,
	});
	await auditDispatch(c, grant, false, result.reason === "rate_limited" ? "RATE_LIMITED" : "INTERNAL_ERROR", {
		reason: result.reason,
		// `repository_not_visible` lands here, and it is the row that says the
		// problem is the installation rather than the commenter — the distinction
		// a bare 404 on the collaborator endpoint cannot express.
		detail: result.detail,
		status: result.status,
		retryable: result.retryable,
		actor: plan.plan.actor,
		issue: plan.plan.issueNumber,
		comment: plan.plan.commentId,
	});

	if (result.reason === "rate_limited") {
		return c.json(
			{ error: "Comment dispatch is over budget", code: "RATE_LIMITED", retryAfter: 60 },
			HTTP.TooManyRequests,
		);
	}

	return c.json({ error: "Comment dispatch failed", code: "INTERNAL_ERROR" }, HTTP.InternalServerError);
}

/**
 * Handle a verified, authorized, first-time delivery.
 *
 * Everything interesting about *trust* has already happened by the time this
 * runs. The HMAC verified, an operator's allowlist granted the scope, and the
 * delivery id was reserved — so a repeat never arrives here at all, it is
 * answered by `webhookReplayGuard`.
 *
 * A `push` is handled. Anything else is acknowledged with 202: "received, not
 * acted upon", which is exactly true of it. A push that signs answers 200,
 * because for that one there is nothing outstanding.
 *
 * The body names the delivery back to the sender. That is not a disclosure —
 * every field is a value GitHub itself just sent or a decision made about it,
 * and reaching this line required a valid HMAC — and it is what makes the
 * "Recent Deliveries" tab useful: a redelivery shows the same id and comes back
 * `duplicate: true`, so an operator can tell a retry from a fresh event without
 * a log.
 */
app.post("/webhook", async (c) => {
	// Set by `githubWebhookAuth`, which is mounted in front of this route in
	// `src/index.ts`. Absent is impossible on a request that got here; the
	// fallback exists so this handler cannot be the thing that 500s if the
	// mounting is ever changed.
	const delivery = c.get("webhookDelivery");

	if (!delivery) {
		logger.error("Webhook handler reached without a verified delivery on the context");
		return c.json({ error: "Internal server error", code: "INTERNAL_ERROR" }, HTTP.InternalServerError);
	}

	const authorization = c.get("webhookAuthorization");

	if (delivery.event === "push") {
		return await handlePush(c as AppContext, delivery, authorization);
	}

	if (delivery.event === "issue_comment") {
		return await handleIssueComment(c as AppContext, delivery, authorization);
	}

	// At info, not debug: for an event nothing acts on, this is the only record
	// the delivery leaves. Deliberately not an `audit_logs` row — that table
	// records operations on keys and credentials, and a row per
	// acknowledged-and-discarded event would be a D1 write per delivery for
	// something nothing acted on. The *action* is what earns an audit record, and
	// `push_sign` above is the first one that exists.
	//
	// The authorized repository is logged rather than the payload's, for the same
	// reason a handler must act on the authorized one: it is the operator's
	// string, so a log line cannot be made to say a repository nobody granted.
	// The bound key id is logged with it and is the same kind of value. A key id
	// is not a secret — `/public-key` serves the key it names — and it is the
	// field that makes a binding diagnosable without an operator having to read
	// `wrangler.toml` next to a delivery log.
	const signingKey = requireSigningKey(authorization);
	logger.info("GitHub webhook delivery accepted", {
		requestId: c.get("requestId"),
		event: delivery.event,
		delivery: delivery.id,
		installationId: delivery.installationId,
		scope: authorization?.scope,
		repository: authorization?.repository,
		keyId: signingKey.allowed ? signingKey.keyId : null,
		// Why no key, when there is none. `not_repository_scope` is routine — a
		// ping has no repository — and `no_key_bound` is the one an operator wants
		// to see, because it means an allowlisted repository is missing the
		// `=<keyId>` suffix and would be refused the moment a handler tried to
		// sign for it.
		signingKeyRefusal: signingKey.allowed ? null : signingKey.reason,
	});

	return c.json(acknowledgement(delivery, authorization, { duplicate: false }), HTTP.Accepted);
});

export default app;
