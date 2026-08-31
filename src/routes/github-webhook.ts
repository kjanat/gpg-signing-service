/**
 * `POST /github/webhook` — the endpoint a GitHub App delivers events to.
 *
 * **This is a scaffold and it acts on nothing.** Every verified delivery is
 * acknowledged and dropped. Auto-signing pushed commits, publishing a check
 * run, and dispatching `@claude` are all named in issue #26 and none of them
 * are here. What is here is the part that has to be right before any of them
 * can be written — the trust boundary, the credential exchange behind it, and
 * the three checks that stand between "this delivery is genuine" and "this
 * delivery may cause something": an operator-written allowlist of
 * `<installation, repository>` pairs, a delivery-id ledger that makes a
 * replayed delivery a no-op, and the signing key that same allowlist entry
 * binds — which is how a handler learns *which* key it may cause to sign,
 * rather than deciding for itself inside a webhook handler.
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
import { HTTP } from "#types";
import { requireSigningKey } from "#utils/github-signing-key";
import { acknowledgement } from "#utils/github-webhook";
import { logger } from "#utils/logger";

const app = createOpenAPIApp();

/**
 * Acknowledge a verified, authorized, first-time delivery.
 *
 * Everything interesting has already happened by the time this runs. The HMAC
 * verified, an operator's allowlist granted the scope, and the delivery id was
 * claimed — so a repeat never arrives here at all, it is answered by
 * `webhookReplayGuard`. What is left is to say so.
 *
 * Answers 202 rather than 200, and the distinction is real rather than
 * decorative: 202 is "received, not yet acted upon", which is exactly true of
 * every event that reaches here. A duplicate gets 200 from the guard, because
 * for that one there is nothing outstanding. When a handler does start doing
 * work, the events it handles can move to 200 and the ones it still only
 * records stay here, so the status keeps meaning something.
 *
 * The body names the delivery back to the sender. That is not a disclosure —
 * every field is a value GitHub itself just sent or a decision made about it,
 * and reaching this line required a valid HMAC — and it is what makes the
 * "Recent Deliveries" tab useful: a redelivery shows the same id and comes back
 * `duplicate: true`, so an operator can tell a retry from a fresh event without
 * a log.
 */
app.post("/webhook", (c) => {
	// Set by `githubWebhookAuth`, which is mounted in front of this route in
	// `src/index.ts`. Absent is impossible on a request that got here; the
	// fallback exists so this handler cannot be the thing that 500s if the
	// mounting is ever changed.
	const delivery = c.get("webhookDelivery");

	if (!delivery) {
		logger.error("Webhook handler reached without a verified delivery on the context");
		return c.json({ error: "Internal server error", code: "INTERNAL_ERROR" }, HTTP.InternalServerError);
	}

	// At info, not debug: this is the only record a delivery leaves. It is
	// deliberately not an `audit_logs` row — that table records operations on
	// keys and credentials, and a row per acknowledged-and-discarded event would
	// be a D1 write per delivery for an event nothing acted on. When a handler
	// starts acting, the *action* is what earns an audit record.
	//
	// The authorized repository is logged rather than the payload's, for the same
	// reason a handler must act on the authorized one: it is the operator's
	// string, so a log line cannot be made to say a repository nobody granted.
	//
	// The bound key id is logged with it, and it is the same kind of value: it
	// comes from the matched allowlist entry, so this line cannot be made to name
	// a key nobody granted either. A key id is not a secret — `/public-key`
	// serves the key it names — and it is the field that makes a binding
	// diagnosable without an operator having to read `wrangler.toml` next to a
	// delivery log. Read through `requireSigningKey` rather than off the field,
	// so a line saying a key is the same thing a handler would be given.
	const authorization = c.get("webhookAuthorization");
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
