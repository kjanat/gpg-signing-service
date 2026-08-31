/**
 * `POST /github/webhook` — the endpoint a GitHub App delivers events to.
 *
 * **One event is acted upon: `push`.** A push to an allowlisted
 * `<installation, repository>` pair has its unsigned commits signed with the
 * key that pair binds, and the branch moved to the rewritten range. Everything
 * else — the Checks API status, `@claude` dispatch, the rest of issue #26 — is
 * still absent, and every other event is acknowledged and dropped exactly as
 * before.
 *
 * What stands in front of that one action is the work of the three slices
 * before this one: the HMAC over the raw bytes, an operator-written allowlist
 * of pairs, the key bound to the matched pair, and a delivery ledger that makes
 * a repeat a no-op. This module adds no checks of its own — it dispatches, and
 * it records.
 *
 * ### Why the reservation is settled here and not decided here
 *
 * `webhookReplayGuard` reserves the delivery id on the way in and settles it on
 * the way out, and what it settles on is `webhookOutcome.retryable` — an
 * assertion this handler makes and no middleware could. Only the code that ran
 * the operation knows whether it stopped before the irreversible step, and that
 * is the only question the ledger has. Saying nothing commits the id, so a
 * handler that forgets is treated as one that acted.
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
import type { ErrorCode } from "#schemas/errors";
import type { AppContext, WebhookAuthorization, WebhookDelivery } from "#types";
import { HTTP } from "#types";
import { logAuditEvent } from "#utils/audit";
import { scheduleBackgroundTask } from "#utils/execution";
import { requireSigningKey } from "#utils/github-signing-key";
import { acknowledgement } from "#utils/github-webhook";
import { logger } from "#utils/logger";
import type { PushRefusal, PushSigningOutcome } from "#utils/push-signing";
import { pushDiagnostics, signPushedCommits } from "#utils/push-signing";

const app = createOpenAPIApp();

/** The issuer every webhook-caused audit row is written under. */
const AUDIT_ISSUER = "github-app";

/**
 * The `key_id` column's value when no key was resolved.
 *
 * The column is `NOT NULL`, and a refusal that happened *because* nothing was
 * bound still has to be recordable — that is precisely the row an operator goes
 * looking for. `admin.ts` writes `"unknown"` for the same reason on a failed
 * upload; this one says which kind of absence it is.
 */
const NO_KEY = "unbound";

/**
 * Which error code an audit row carries for each refusal.
 *
 * Existing codes only. A refusal here is one of three things an operator
 * already has vocabulary for — the key is not usable, the budget is spent, or a
 * dependency did not answer — and everything else is a signing failure. The
 * *specific* reason is not lost: it is the `reason` field of the metadata, which
 * is where a value this closed-enum has no room for belongs.
 */
function auditCode(reason: PushRefusal): ErrorCode {
	switch (reason) {
		case "no_key_bound":
			return "KEY_NOT_ALLOWED";
		case "key_missing":
			return "KEY_NOT_FOUND";
		case "key_storage_unavailable":
		case "github_unavailable":
		case "rate_limiter_unavailable":
			return "SERVICE_DEGRADED";
		case "app_misconfigured":
			return "SERVICE_MISCONFIGURED";
		case "rate_limited":
			return "RATE_LIMITED";
		default:
			return "SIGN_ERROR";
	}
}

/**
 * The status a refusal answers with.
 *
 * A retryable refusal must be a **non-2xx**, and that is not cosmetic: GitHub
 * marks any non-2xx as a failed delivery and shows it red in "Recent
 * Deliveries", which is the affordance an operator uses to find and redeliver
 * it. A retryable failure answered 200 is one nobody will ever be told about.
 *
 * A refusal nothing can be done about answers 200 for the mirror-image reason:
 * a red row inviting a redelivery that will be refused identically is worse than
 * no row at all.
 */
function refusalStatus(outcome: Extract<PushSigningOutcome, { acted: false }>) {
	if (!outcome.retryable) {
		return HTTP.OK;
	}
	return outcome.reason === "rate_limited" ? HTTP.TooManyRequests : HTTP.ServiceUnavailable;
}

/**
 * Record an attempt, with enough to reconstruct it and nothing that is a secret.
 *
 * Every field here is an object name, a branch name, a repository an operator
 * wrote, a key id `/public-key` already serves, or a decision this service made.
 * Absent by construction: the private key, the passphrase, the installation
 * token, the webhook secret, and any body GitHub or key storage sent back — the
 * modules those come from do not carry them out, so there is nothing here to
 * filter.
 */
function auditAttempt(
	c: AppContext,
	authorization: WebhookAuthorization,
	delivery: WebhookDelivery,
	outcome: PushSigningOutcome,
	subject: { branch: string | null; before: string | null; after: string | null },
) {
	const key = requireSigningKey(authorization);
	const requestId = c.get("requestId");

	return scheduleBackgroundTask(
		c,
		requestId,
		logAuditEvent(c.env.AUDIT_DB, {
			requestId,
			action: "webhook_sign",
			issuer: AUDIT_ISSUER,
			// The operator's spelling of the repository, under the installation the
			// same entry named. Never `payload.repository.full_name`, which is what
			// makes this row a record of what was *authorized* rather than of what
			// was claimed.
			subject: `${authorization.installationId}:${authorization.repository}`,
			keyId: key.allowed ? key.keyId : NO_KEY,
			success: outcome.acted,
			...(outcome.acted ? {} : { errorCode: auditCode(outcome.reason) }),
			metadata: JSON.stringify({
				delivery: delivery.id,
				branch: subject.branch,
				before: subject.before,
				after: subject.after,
				...(outcome.acted
					? { signed: outcome.signed, head: outcome.head }
					: { reason: outcome.reason, detail: outcome.detail ?? null, retryable: outcome.retryable }),
			}),
		}),
	);
}

/**
 * Handle a delivery: sign a `push`, acknowledge anything else.
 *
 * Answers 202 for an event with no handler, and the distinction from 200 is
 * real rather than decorative: 202 is "received, not yet acted upon", which is
 * exactly true of an event this service records and does nothing with. A `push`
 * that was handled answers 200, because for that one there is nothing
 * outstanding.
 */
app.post("/webhook", async (c) => {
	// Set by `githubWebhookAuth`, which is mounted in front of this route in
	// `src/index.ts`. Absent is impossible on a request that got here; the
	// fallback exists so this handler cannot be the thing that 500s if the
	// mounting is ever changed.
	const delivery = c.get("webhookDelivery");

	if (!delivery) {
		logger.error("Webhook handler reached without a verified delivery on the context");
		return c.json(
			{ error: "Internal server error", code: "INTERNAL_ERROR" as const satisfies ErrorCode },
			HTTP.InternalServerError,
		);
	}

	const authorization = c.get("webhookAuthorization");
	const signingKey = requireSigningKey(authorization);

	// At info, and for every delivery: this is the only record an event with no
	// handler leaves. It is deliberately not an `audit_logs` row — that table
	// records operations on keys and credentials, and a row per
	// acknowledged-and-discarded event would be a D1 write per delivery for an
	// event nothing acted on. A `push` at repository scope earns one below,
	// because it is an operation.
	//
	// The authorized repository is logged rather than the payload's, for the same
	// reason a handler must act on the authorized one: it is the operator's
	// string, so a log line cannot be made to say a repository nobody granted.
	// The bound key id rides with it and is the same kind of value — it comes
	// from the matched allowlist entry, and a key id is not a secret, since
	// `/public-key` serves the key it names. Read through `requireSigningKey`
	// rather than off the field, so a line saying a key is the same thing a
	// handler would be given.
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

	if (delivery.event !== "push") {
		return c.json(acknowledgement(delivery, authorization, { duplicate: false }), HTTP.Accepted);
	}

	return await handlePush(c, delivery, authorization);
});

/** The one acting path. */
async function handlePush(c: AppContext, delivery: WebhookDelivery, authorization: WebhookAuthorization | undefined) {
	const outcome = await signPushedCommits(c.env, authorization, c.get("webhookPayload"));

	// The assertion the replay guard settles on, set before anything else can go
	// wrong: a `return` that skipped it would commit a delivery the run never
	// acted on. Never set to true for a run that acted — `signPushedCommits` only
	// reports retryable for refusals it reached before the ref update.
	c.set("webhookOutcome", { retryable: !outcome.acted && outcome.retryable });

	// A delivery refused before there was any grant to record against is not an
	// attempt at anything: there is no repository to name in the row and no key
	// to name it under. It is logged, like every other unhandled delivery.
	if (authorization === undefined || authorization.scope !== "repository" || authorization.repository === null) {
		logger.info("Push delivery carried no repository grant", {
			requestId: c.get("requestId"),
			delivery: delivery.id,
			scope: authorization?.scope,
		});
		return c.json(
			acknowledgement(delivery, authorization, { duplicate: false, outcome: "not_repository_scope" }),
			HTTP.Accepted,
		);
	}

	// Read here rather than passed down from `signPushedCommits`, so the row
	// records what the delivery *said* even for the refusals that never got as
	// far as reading it — an unusable ref is exactly the case an operator wants
	// the ref for.
	const subject = pushDiagnostics(c.get("webhookPayload"));

	await auditAttempt(c, authorization, delivery, outcome, subject);

	if (outcome.acted) {
		logger.info("Signed a pushed range", {
			requestId: c.get("requestId"),
			delivery: delivery.id,
			repository: authorization.repository,
			branch: outcome.branch,
			signed: outcome.signed,
			from: outcome.from,
			head: outcome.head,
		});

		return c.json(
			acknowledgement(delivery, authorization, {
				duplicate: false,
				handled: true,
				outcome: outcome.signed === 0 ? "already_signed" : "signed",
			}),
			HTTP.OK,
		);
	}

	// At warn when a retry could change the answer, at info when it could not.
	// The difference is the one an operator acts on: a red delivery they should
	// redeliver, against a decision this service made on purpose.
	const log = outcome.retryable ? logger.warn.bind(logger) : logger.info.bind(logger);
	log("Push delivery was not signed", {
		requestId: c.get("requestId"),
		delivery: delivery.id,
		repository: authorization.repository,
		reason: outcome.reason,
		detail: outcome.detail,
		retryable: outcome.retryable,
	});

	return c.json(
		acknowledgement(delivery, authorization, { duplicate: false, outcome: outcome.reason }),
		refusalStatus(outcome),
	);
}

export default app;
