/**
 * `POST /github/webhook` — the endpoint a GitHub App delivers events to.
 *
 * One event is acted on: `push`, which signs the unsigned commits at the tip of
 * the pushed branch with the key the operator bound to that repository, and
 * moves the branch to them. Everything else is acknowledged and dropped, as the
 * whole route used to be. Publishing a check run and dispatching `@claude` are
 * still named in issue #26 and still absent.
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
 *   `webhookRetryable`; the guard is what writes the ledger.
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
import type { AppContext, RateLimitResult, WebhookAuthorization, WebhookDelivery } from "#types";
import { createIdentity, HTTP } from "#types";
import { logAuditEvent } from "#utils/audit";
import { fetchRateLimiter } from "#utils/durable-objects";
import { scheduleBackgroundTask } from "#utils/execution";
import { planPush } from "#utils/github-push";
import { RepositoryClient } from "#utils/github-repo";
import { loadSigningKey, requireSigningKey } from "#utils/github-signing-key";
import { acknowledgement } from "#utils/github-webhook";
import { logger } from "#utils/logger";
import type { PushSigningResult } from "#utils/push-signing";
import { signPushedCommits } from "#utils/push-signing";

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

/** Spend one token per commit, stopping at the first refusal. */
async function spendSigningBudget(
	c: AppContext,
	identity: string,
	commits: number,
): Promise<"ok" | "limited" | "unavailable"> {
	for (let spent = 0; spent < commits; spent += 1) {
		let response: Response;
		try {
			response = await fetchRateLimiter(c.env, identity, PUSH_SIGNING_LIMIT);
		} catch (error) {
			logger.error("Push-signing rate limiter unreachable", error, { requestId: c.get("requestId") });
			return "unavailable";
		}

		// A denied consume is a *verdict* and arrives as a 429 with the verdict in
		// the body, so `!ok` alone would read the one answer this is asking for as
		// an outage — the bug `/sign`'s `resolveRateLimit` carries a comment about.
		if (!response.ok && response.status !== HTTP.TooManyRequests) {
			logger.error("Push-signing rate limiter failed", { status: response.status, requestId: c.get("requestId") });
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
			subject: authorization.repository ?? "unknown",
			keyId,
			success,
			...(success ? {} : { errorCode: "SIGN_ERROR" as const }),
			metadata: JSON.stringify(metadata),
		}),
	);
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
			reserveBudget: (commits) => spendSigningBudget(c, identity, commits),
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
			{ ...acknowledgement(delivery, authorization, { duplicate: false }), handled: true, signed: result.commits },
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

	if (result.outcome === "refused") {
		// The budget said no. Nothing was signed and nothing was published, so the
		// delivery goes back: this is exactly the case where an operator waits and
		// redelivers.
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
