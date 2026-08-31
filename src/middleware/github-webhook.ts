/**
 * The three gates in front of `POST /github/webhook`, in the order they run.
 *
 * They are separate middlewares rather than one because the ordering between
 * them is itself a property worth being able to state and test:
 *
 * 1. `githubWebhookGate` — is the feature on, and is it completely configured?
 *    First, so a deployment that has not opted in spends nothing on a request
 *    to a route it does not serve. Putting the rate limiter ahead of this would
 *    mean a Durable Object round trip per probe on every deployment in the
 *    world that has this code and not this feature.
 * 2. `webhookRateLimit` — before the HMAC, for the same reason `adminRateLimit`
 *    sits before `adminAuth`: the expensive, attacker-triggerable work is the
 *    verification, and a limiter behind it is a limiter that has already paid.
 * 3. `githubWebhookAuth` — the HMAC over the raw bytes. Nothing downstream sees
 *    a body that did not pass this.
 */

import type { MiddlewareHandler } from "hono";
import type { ErrorCode } from "#schemas/errors";
import type { Env, RateLimitResult, Variables } from "#types";
import { HEADERS, HTTP, TIME } from "#types";
import { serviceMisconfigured, unauthorized } from "#utils/errors";
import { githubAppEnabled } from "#utils/github-app";
import {
	DELIVERY_HEADER,
	EVENT_HEADER,
	installationIdOf,
	SIGNATURE_HEADER,
	verifyWebhookSignature,
} from "#utils/github-webhook";
import { logger } from "#utils/logger";
import { rateLimitExceeded, retryAfterSeconds } from "#utils/rate-limit";

/**
 * Rate-limiter namespace for webhook deliveries.
 *
 * Disjoint from `admin` and from the `<iss>:<sub>` buckets the signing path
 * consumes, so a burst of deliveries cannot exhaust an operator's ability to
 * reach `/admin` and vice versa.
 */
const WEBHOOK_METER = "webhook";

/**
 * The shape every middleware here is written against.
 *
 * `webhookDelivery` and `webhookPayload` live on the shared `Variables`, beside
 * the sign path's `allowedKeyIds` and `subjectPolicyId`, because that is where
 * this codebase already keeps a contract between one route's middleware and its
 * handler. The contract is the same as the service-token path's in
 * `caller-auth.ts`: the middleware that authenticated the request is the only
 * thing that writes them, so a handler that finds them may assume the signature
 * check passed.
 */
type WebhookMiddleware = MiddlewareHandler<{ Bindings: Env; Variables: Variables }>;

/**
 * The 404 an unrouted path gets, built here on purpose.
 *
 * A disabled feature must be *indistinguishable* from one that was never
 * deployed. Anything else — a distinct code, a different message, even a
 * different key order — turns this route into a way to enumerate which
 * deployments have the integration and which have merely shipped the code, and
 * that is a question an unauthenticated caller has no business getting an
 * answer to. The body is byte-identical to `app.notFound`'s, and a test asserts
 * that against a genuinely unrouted path rather than against this literal.
 *
 * Written out rather than delegating to `c.notFound()`: this sub-app is mounted
 * with `app.route`, so which app's not-found handler a middleware would reach
 * is a Hono composition detail, and the guarantee is too load-bearing to rest
 * on one.
 */
function notFound(c: Parameters<WebhookMiddleware>[0]) {
	return c.json({ error: "Not found", code: "NOT_FOUND" as const satisfies ErrorCode }, HTTP.NotFound);
}

/**
 * Refuse unless the integration is switched on *and* every setting it needs is
 * present.
 *
 * The two halves answer differently, and the difference is the point. Off is a
 * 404: nothing is wrong, this deployment simply does not serve the route. On
 * but half-configured is a 500 `SERVICE_MISCONFIGURED`: an operator did opt in,
 * the deployment cannot honour it, and no retry and no better-formed request
 * will change that. Answering 404 there too would hide a broken deployment
 * behind a page that looks deliberate — which is exactly how a webhook
 * integration ends up silently receiving nothing for a week.
 *
 * `GITHUB_WEBHOOK_SECRET` is the one checked here rather than the App
 * credentials, because it is the one this route cannot run without. An App id
 * and private key are needed to *act* on a delivery, which the scaffold does
 * not yet do; `requireAppConfig` refuses at that point instead.
 */
export const githubWebhookGate: WebhookMiddleware = async (c, next) => {
	if (!githubAppEnabled(c.env)) {
		return notFound(c);
	}

	if (!c.env.GITHUB_WEBHOOK_SECRET) {
		// Named in the log, absent from the body: the response goes to whoever
		// sent the request, and "this deployment enabled a webhook without a
		// secret" is the most useful sentence an attacker could be handed. Same
		// posture as the two `adminAuth` configuration guards.
		logger.error(
			"GITHUB_APP_ENABLED is true but GITHUB_WEBHOOK_SECRET is not set; refusing every delivery. Put one with `wrangler secret put GITHUB_WEBHOOK_SECRET` and set the same value on the App.",
		);
		return serviceMisconfigured(c, "GitHub webhook delivery is not configured");
	}

	return next();
};

/**
 * Token-bucket limit on deliveries, keyed by source address.
 *
 * By IP rather than by installation, because the installation id is inside a
 * body that has not been verified yet — trusting it here would let an unsigned
 * request choose which bucket it is metered against, including one nobody else
 * uses. GitHub's delivery addresses are a small published set, so real traffic
 * shares a handful of buckets; that is the right shape for a limit whose job is
 * to bound *unverified* work.
 *
 * Fails closed, like every other limiter here, and that costs more here than it
 * does on `/admin`: GitHub does not automatically redeliver a failed delivery.
 * A refusal or a 503 from this path loses the event until an operator
 * redelivers it by hand from the App's "Advanced" tab, or through
 * `POST /app/hook/deliveries/{id}/attempts`. Failing closed is still the right
 * trade while the handler acts on nothing — an accepted delivery with no limit
 * in front of the HMAC is unbounded verification work for an anonymous caller —
 * but the budget this limiter sets is a dropped-event budget, not only a work
 * budget, and the first handler that acts on an event has to weigh it as one.
 */
export const webhookRateLimit: WebhookMiddleware = async (c, next) => {
	const clientIp =
		c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For")?.split(",")[0]?.trim() || "unknown";
	const identity = `webhook:${clientIp}`;

	try {
		const rateLimiterId = c.env.RATE_LIMITER.idFromName(WEBHOOK_METER);
		const rateLimiter = c.env.RATE_LIMITER.get(rateLimiterId);

		const rateLimitResponse = await rateLimiter.fetch(
			new Request(`http://internal/consume?identity=${encodeURIComponent(identity)}`),
		);

		// A 429 from the object is a verdict, not an outage. Reading `!ok` alone
		// would report every denial as a failure of the limiter itself — see the
		// same note in `adminRateLimit`.
		if (!rateLimitResponse.ok && rateLimitResponse.status !== HTTP.TooManyRequests) {
			throw new Error(`Rate limiter returned ${rateLimitResponse.status}`);
		}

		const rateLimit = (await rateLimitResponse.json()) as RateLimitResult;

		if (!rateLimit.allowed) {
			return rateLimitExceeded(c, retryAfterSeconds(rateLimit.resetAt));
		}

		c.header(HEADERS.RATE_LIMIT_REMAINING, String(rateLimit.remaining));
		c.header(HEADERS.RATE_LIMIT_RESET, String(Math.ceil(rateLimit.resetAt / TIME.SECOND)));

		return next();
	} catch (error) {
		logger.error("Webhook rate limiter failed", {
			error: error instanceof Error ? error.message : String(error),
			clientIp,
		});
		return c.json(
			{
				error: "Service temporarily unavailable",
				code: "RATE_LIMIT_ERROR" as const satisfies ErrorCode,
			},
			HTTP.ServiceUnavailable,
		);
	}
};

/**
 * Verify `X-Hub-Signature-256` over the raw request bytes.
 *
 * The body is read here, once, as an `ArrayBuffer`, and parsed here after the
 * verdict. Downstream reads `webhookPayload` off the context rather than
 * calling `c.req.json()`, so there is exactly one place in the service where
 * webhook bytes are turned into a document, and it is on the far side of the
 * signature check. That also removes any dependence on Hono's body cache
 * handing back the same bytes to a second reader.
 *
 * The codes match the rest of the service, and mean here what they mean
 * everywhere else: `AUTH_MISSING` when no credential was presented at all,
 * `AUTH_INVALID` when one was and it was refused. The distinction is drawn on
 * whether the header is present, never on how far verification got.
 */
export const githubWebhookAuth: WebhookMiddleware = async (c, next) => {
	const signature = c.req.header(SIGNATURE_HEADER);

	if (signature === undefined) {
		return unauthorized(c, "Missing webhook signature", "AUTH_MISSING", {
			hint: `Deliveries must carry ${SIGNATURE_HEADER}. GitHub sends it whenever the App has a webhook secret configured; an App with no secret set sends nothing and cannot be accepted.`,
		});
	}

	// `c.req.arrayBuffer()` and not `c.req.json()`: GitHub signs the octets it
	// sent, and a re-serialised document is a different sequence of octets for
	// the same JSON. See the module comment in `#utils/github-webhook`.
	const raw = await c.req.arrayBuffer();

	if (!(await verifyWebhookSignature(c.env.GITHUB_WEBHOOK_SECRET ?? "", raw, signature))) {
		// No detail about *why*. A caller learning that its digest was well-formed
		// but wrong, as against malformed, is being told where to spend its next
		// attempt.
		return unauthorized(c, "Invalid webhook signature", "AUTH_INVALID", {
			hint: "The delivery did not verify against this deployment's GITHUB_WEBHOOK_SECRET. The same value must be set on the GitHub App and here.",
		});
	}

	let payload: unknown;
	try {
		payload = JSON.parse(new TextDecoder().decode(raw));
	} catch {
		// Signed and unparseable. That is not an authentication failure — the
		// sender proved it holds the secret — so it is a 400, and it is worth a
		// log line because it means GitHub sent something this service cannot
		// read.
		logger.warn("Verified webhook delivery did not contain JSON", {
			event: c.req.header(EVENT_HEADER),
			delivery: c.req.header(DELIVERY_HEADER),
		});
		return c.json(
			{
				error: "Webhook payload is not valid JSON",
				code: "INVALID_REQUEST" as const satisfies ErrorCode,
			},
			HTTP.BadRequest,
		);
	}

	c.set("webhookPayload", payload);
	c.set("webhookDelivery", {
		event: c.req.header(EVENT_HEADER) ?? "unknown",
		id: c.req.header(DELIVERY_HEADER) ?? "unknown",
		installationId: installationIdOf(payload),
	});

	return next();
};
