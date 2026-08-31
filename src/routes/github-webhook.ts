/**
 * `POST /github/webhook` — the endpoint a GitHub App delivers events to.
 *
 * **This is a scaffold and it acts on nothing.** Every verified delivery is
 * acknowledged and dropped. Auto-signing pushed commits, publishing a check
 * run, and dispatching `@claude` are all named in issue #26 and none of them
 * are here: they need an authorization model deciding *which* installation may
 * cause *which* key to sign, and inventing that inside a webhook handler is how
 * a signing service acquires a second, weaker front door. What is here is the
 * part that has to be right before any of that can be written — the trust
 * boundary, and the credential exchange behind it.
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
import { logger } from "#utils/logger";

const app = createOpenAPIApp();

/**
 * Acknowledge a verified delivery.
 *
 * Answers 202 rather than 200, and the distinction is real rather than
 * decorative: 202 is "received, not yet acted upon", which is exactly true of
 * every event that reaches here. When a handler does start doing work, the
 * events it handles can move to 200 and the ones it still only records stay
 * here, so the status keeps meaning something.
 *
 * The body names the delivery back to the sender. That is not a disclosure —
 * `event` and `delivery` are values GitHub itself just sent, and reaching this
 * line at all required a valid HMAC — and it is what makes the "Recent
 * Deliveries" tab on the App's settings page useful: a redelivery shows the
 * same id, so an operator can tell a retry from a fresh event without a log.
 *
 * `installationId` is echoed as a boolean rather than as the id. Whether an
 * event carries an installation is what an operator is checking; the id itself
 * adds nothing they did not send and would put an account identifier into a
 * response body for no reader.
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
	logger.info("GitHub webhook delivery accepted", {
		requestId: c.get("requestId"),
		event: delivery.event,
		delivery: delivery.id,
		installationId: delivery.installationId,
	});

	return c.json(
		{
			received: true,
			event: delivery.event,
			delivery: delivery.id,
			/** Whether a token could be minted for this event, not whether one was. */
			installation: delivery.installationId !== null,
			/** Always false while this is a scaffold. See the module comment. */
			handled: false,
		},
		HTTP.Accepted,
	);
});

export default app;
