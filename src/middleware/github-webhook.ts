/**
 * The six gates in front of `POST /github/webhook`, in the order they run.
 *
 * They are separate middlewares rather than one because the ordering between
 * them is itself a property worth being able to state and test:
 *
 * 1. `githubWebhookGate` — is the feature on, and is it completely configured?
 *    First, so a deployment that has not opted in spends nothing on a request
 *    to a route it does not serve. Putting anything ahead of this would mean
 *    work per probe on every deployment in the world that has this code and not
 *    this feature.
 * 2. `webhookBodyLimit` — does the request already say it is too big? One
 *    header read and no body read, so it is strictly cheaper than the Durable
 *    Object round trip that would otherwise precede it, and a request that
 *    announces a body no route here will read should not consume a bucket that
 *    GitHub's real delivery addresses share.
 * 3. `webhookRateLimit` — before the HMAC, for the same reason `adminRateLimit`
 *    sits before `adminAuth`: the expensive, attacker-triggerable work is the
 *    verification, and a limiter behind it is a limiter that has already paid.
 * 4. `githubWebhookAuth` — reads the body under the same ceiling, counting the
 *    octets that actually arrive rather than trusting the ones step 2 was told
 *    about, and then the HMAC over exactly those bytes. Nothing downstream sees
 *    a body that did not pass this.
 * 5. `githubWebhookAuthorize` — the delivery is genuine; is it *about something
 *    this deployment granted*? One App has one webhook secret and many
 *    installations, so a valid signature says who sent it and nothing about
 *    what it may cause. Separate from step 4 because authentication and
 *    authorization are separate questions, and a service whose purpose is to
 *    sign things cannot afford to answer them with one check.
 * 6. `webhookReplayGuard` — has this delivery id been acted on already? **Last,
 *    and that position is the security property**, not an ordering convenience.
 *    Claiming an id is one-way: whoever claims it first makes every later
 *    arrival of that id a no-op. Put this ahead of step 4 or step 5 and an
 *    unauthenticated stranger — or an authenticated one with no grant — could
 *    burn the id of a delivery it is not allowed to cause, and so suppress the
 *    real one. Nothing consumes an id until the delivery has proved both that
 *    it came from GitHub and that it is allowed to be about what it says.
 *
 * Steps 2 and 4 are the same limit enforced twice on purpose, and neither is
 * redundant. The header is a claim by the party whose body is in question, so
 * it can only ever be used to refuse early, never to accept; the count during
 * the read is the one that holds, and it costs at most one chunk beyond the
 * ceiling. Enforcing only the header would be a guard any sender can step
 * around by declaring a smaller number, and enforcing only the read would spend
 * a Durable Object round trip on requests that already told us the answer.
 */

import type { MiddlewareHandler } from "hono";
import type { ErrorCode } from "#schemas/errors";
import type { Env, RateLimitResult, Variables } from "#types";
import { HEADERS, HTTP, TIME } from "#types";
import { serviceDegraded, serviceMisconfigured, unauthorized } from "#utils/errors";
import { githubAppEnabled } from "#utils/github-app";
import { ALLOWLIST_VAR, authorizeDelivery, parseRepositoryAllowlist } from "#utils/github-authorization";
import {
	acknowledgement,
	DELIVERY_HEADER,
	declaredBodyLength,
	EVENT_HEADER,
	installationIdOf,
	MAX_WEBHOOK_BODY_BYTES,
	readBodyWithin,
	SIGNATURE_HEADER,
	verifyWebhookSignature,
} from "#utils/github-webhook";
import { logger } from "#utils/logger";
import { rateLimitExceeded, retryAfterSeconds } from "#utils/rate-limit";
import { claimDelivery, isDeliveryId } from "#utils/webhook-replay";

/**
 * Rate-limiter namespace for webhook deliveries.
 *
 * Disjoint from `admin` and from the `<iss>:<sub>` buckets the signing path
 * consumes, so a burst of deliveries cannot exhaust an operator's ability to
 * reach `/admin` and vice versa.
 */
const WEBHOOK_METER = "webhook";

/**
 * What a delivery refused by an unreachable ledger is told to wait.
 *
 * The only caller that acts on it is a human redelivering from the App's
 * Advanced tab or through the API — GitHub itself never retries — so this is an
 * interval for a person, not a backoff schedule. Thirty seconds: long enough
 * that an immediate second attempt does not land in the same outage, short
 * enough that nobody walks away.
 */
const LEDGER_RETRY_AFTER_SECONDS = 30;

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
 * The one refusal here that is not about who sent the request.
 *
 * Written once and used from both ends of the ceiling — the declared length and
 * the counted one — so a request that lies about its size and one that is
 * honest about it are answered identically. A sender that could tell those
 * apart would have learnt that this deployment reads the header, which is the
 * one fact needed to choose the cheaper of the two attacks.
 *
 * The hint names the number rather than describing it. An operator reading this
 * in a delivery log needs to know whether their payload is near a limit, and
 * "too large" without a figure sends them to the source to find out.
 */
function tooLarge(c: Parameters<WebhookMiddleware>[0]) {
	return c.json(
		{
			error: "Webhook payload too large",
			code: "PAYLOAD_TOO_LARGE" as const satisfies ErrorCode,
			hint: `Deliveries are limited to ${MAX_WEBHOOK_BODY_BYTES} bytes, GitHub's own payload cap. A delivery larger than that is not sent by GitHub at all.`,
		},
		HTTP.ContentTooLarge,
	);
}

/**
 * Refuse a request that has already declared a body over the ceiling.
 *
 * Nothing but a header read: the body is never touched, so this costs the same
 * whether the sender goes on to upload 25 MiB or hangs up. That is why it sits
 * ahead of the rate limiter rather than behind it — the limiter is a
 * cross-region Durable Object round trip, and spending one to decide a question
 * already answered by a header the request arrived with would make the meter
 * more expensive than the thing it meters.
 *
 * It is only ever a refusal. A declared length under the ceiling means nothing
 * has been established — the header is the sender's own account of a body that
 * has not arrived — so passing this gate buys no trust downstream, and
 * `githubWebhookAuth` counts the octets again as it reads them.
 */
export const webhookBodyLimit: WebhookMiddleware = async (c, next) => {
	const declared = declaredBodyLength(c.req.header("Content-Length"));

	if (declared !== null && declared > MAX_WEBHOOK_BODY_BYTES) {
		// At info: an oversize declaration is this gate working, and the volume is
		// the caller's to choose, not ours to page on.
		logger.info("Webhook delivery declared a body over the ceiling", {
			requestId: c.get("requestId"),
			declared,
			limit: MAX_WEBHOOK_BODY_BYTES,
		});
		return tooLarge(c);
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

	// The raw octets, and not `c.req.json()`: GitHub signs the bytes it sent, and
	// a re-serialised document is a different sequence of octets for the same
	// JSON. See the module comment in `#utils/github-webhook`.
	//
	// `readBodyWithin` rather than `c.req.arrayBuffer()`, which buffers whatever
	// arrives: this counts as it reads and stops at the first chunk past the
	// ceiling, so the most an anonymous delivery can cost is the limit plus one
	// chunk. `webhookBodyLimit` has already refused the ones that *declared* more
	// than that; this is what catches a sender that declared less, or nothing at
	// all, which is one line of client code away.
	const raw = await readBodyWithin(c.req.raw, MAX_WEBHOOK_BODY_BYTES);

	if (raw === null) {
		// Answered before the signature is examined, and that is the point rather
		// than an accident of ordering: a body over GitHub's own cap did not come
		// from GitHub, so there is no signature worth the CPU to check. It also
		// keeps the refusal identical to the declared-length one — see `tooLarge`.
		logger.info("Webhook delivery exceeded the ceiling while being read", {
			requestId: c.get("requestId"),
			limit: MAX_WEBHOOK_BODY_BYTES,
			declared: declaredBodyLength(c.req.header("Content-Length")),
		});
		return tooLarge(c);
	}

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

	const deliveryId = c.req.header(DELIVERY_HEADER);

	c.set("webhookPayload", payload);
	c.set("webhookDelivery", {
		event: c.req.header(EVENT_HEADER) ?? "unknown",
		// Null rather than a placeholder, and that is a correctness choice rather
		// than tidiness. A default like `"unknown"` is a *shared* name: two
		// deliveries that both arrived without an id would dedupe against each
		// other, so the first id-less delivery to be claimed would silently
		// suppress every later one — and an attacker who can send one signed
		// request with no id gets to do that on purpose.
		id: isDeliveryId(deliveryId) ? deliveryId : null,
		installationId: installationIdOf(payload),
	});

	return next();
};

/**
 * Decide what this delivery is allowed to be about.
 *
 * The check `githubWebhookAuth` does not do, and cannot: one App has one
 * webhook secret and as many installations as accept it, so a signature proves
 * the sender and says nothing about the subject. A delivery for a repository
 * this deployment has no business touching carries exactly the same valid HMAC
 * as one for the repository it was configured for.
 *
 * Refused with `AUTH_SUBJECT_UNTRUSTED`, the same code and the same 401 the
 * OIDC path uses for a verified credential whose identity holds no trust —
 * because that is the identical situation. The fix is to the allowlist, never
 * to the credential, and a caller that reads this as `AUTH_INVALID` goes and
 * rotates a webhook secret that is working exactly as provisioned.
 *
 * The *reason* is logged and never sent. The refusal body says which variable
 * governs the decision, which an operator needs, and does not say which half of
 * the pair was wrong — that is the one fact that would turn a refusal into a
 * way to enumerate the allowlist.
 */
export const githubWebhookAuthorize: WebhookMiddleware = async (c, next) => {
	const delivery = c.get("webhookDelivery");

	if (!delivery) {
		// Unreachable behind `githubWebhookAuth`. Present so a change to the
		// mounting fails closed rather than authorizing an unverified payload.
		logger.error("Webhook authorization reached without a verified delivery on the context");
		return serviceMisconfigured(c, "Webhook authorization is not correctly mounted");
	}

	let allowlist: ReturnType<typeof parseRepositoryAllowlist>;
	try {
		allowlist = parseRepositoryAllowlist(c.env.GITHUB_APP_ALLOWED_REPOSITORIES);
	} catch (error) {
		// A malformed allowlist refuses every delivery rather than applying the
		// entries that happened to parse. A typo must not silently drop a grant,
		// and must certainly not silently widen one — so the whole list is refused
		// and an operator is told which entry, by name, in the log.
		logger.error("GITHUB_APP_ALLOWED_REPOSITORIES could not be parsed; refusing every delivery", {
			error: error instanceof Error ? error.message : String(error),
		});
		return serviceMisconfigured(c, "GitHub webhook authorization is not configured");
	}

	const decision = authorizeDelivery(allowlist, c.get("webhookPayload"));

	if (!decision.allowed) {
		// At warn with the reason and the subject the delivery claimed: all three
		// are values the sender chose, and together they are what an operator needs
		// to tell "I forgot to allowlist this repo" from "something is delivering
		// events I never installed".
		logger.warn("GitHub webhook delivery is not authorized", {
			requestId: c.get("requestId"),
			event: delivery.event,
			reason: decision.reason,
			installationId: delivery.installationId,
		});

		return unauthorized(c, "Webhook delivery is not authorized for this deployment", "AUTH_SUBJECT_UNTRUSTED", {
			hint: `The installation and repository this delivery names are not paired in ${ALLOWLIST_VAR}. Entries are comma-separated \`<installationId>:<owner>/<repo>\`.`,
		});
	}

	c.set("webhookAuthorization", decision.authorization);

	return next();
};

/**
 * Refuse a delivery id that has already been acted upon.
 *
 * A webhook signature covers the body and nothing else — no timestamp, no nonce
 * — so a delivery that verified once verifies forever, and the only thing
 * separating a repeat from a fresh event is `X-GitHub-Delivery`. See
 * `#utils/webhook-replay` for what this can and cannot promise.
 *
 * Three decisions worth naming:
 *
 * **A repeat is answered here, not by the handler.** The guard short-circuits,
 * so a duplicate never reaches a route. "Do not act twice" is then a property of
 * the pipeline rather than a rule every future handler has to remember, and the
 * one that forgets is the one that signs something twice.
 *
 * **A repeat gets 200, not an error.** GitHub marks any non-2xx as a failed
 * delivery, and a redelivery an operator triggers on purpose is not a failure —
 * the event was already handled, which is the outcome they wanted. The body says
 * `duplicate: true` so the answer is still distinguishable from a first
 * arrival.
 *
 * **An unreachable ledger refuses the delivery.** Fail closed, like every other
 * dependency on this path: a claim that did not happen is not a claim, and
 * treating an unreachable ledger as "not seen before" removes the protection at
 * exactly the moment nothing can check it. That costs a dropped event, because
 * GitHub does not redeliver on its own — the same trade `webhookRateLimit`
 * documents, and answered 503 with a `Retry-After` so the one caller that
 * *does* retry, an operator with the API, is told when.
 */
export const webhookReplayGuard: WebhookMiddleware = async (c, next) => {
	const delivery = c.get("webhookDelivery");

	if (!delivery) {
		logger.error("Webhook replay guard reached without a verified delivery on the context");
		return serviceMisconfigured(c, "Webhook replay protection is not correctly mounted");
	}

	if (delivery.id === null) {
		// Signed, and unusable. Not an authentication failure — the sender proved
		// it holds the secret — but there is no id to dedupe on, so this delivery
		// cannot be protected from being repeated, and accepting it would mean
		// accepting the one shape a replay attack would choose.
		logger.warn("Verified webhook delivery carried no usable delivery id", {
			requestId: c.get("requestId"),
			event: delivery.event,
		});
		return c.json(
			{
				error: "Webhook delivery has no usable delivery id",
				code: "INVALID_REQUEST" as const satisfies ErrorCode,
				hint: `Deliveries must carry a ${DELIVERY_HEADER} of 8 to 200 characters from [A-Za-z0-9._-]. GitHub sends a GUID; a delivery without one cannot be protected against replay and is refused.`,
			},
			HTTP.BadRequest,
		);
	}

	let claim: Awaited<ReturnType<typeof claimDelivery>>;
	try {
		claim = await claimDelivery(c.env, delivery.id);
	} catch (error) {
		logger.error("Delivery ledger failed", {
			requestId: c.get("requestId"),
			error: error instanceof Error ? error.message : String(error),
		});
		return serviceDegraded(c, "Webhook replay protection is unavailable", {
			retryAfter: LEDGER_RETRY_AFTER_SECONDS,
			hint: "The delivery was not accepted, because it could not be checked against ones already handled. Redeliver it from the App's Advanced tab.",
		});
	}

	if (!claim.claimed) {
		logger.info("GitHub webhook delivery is a repeat", {
			requestId: c.get("requestId"),
			event: delivery.event,
			delivery: delivery.id,
			firstSeen: new Date(claim.firstSeen).toISOString(),
		});

		return c.json(acknowledgement(delivery, c.get("webhookAuthorization"), { duplicate: true }), HTTP.OK);
	}

	c.set("webhookReplay", { firstSeen: claim.firstSeen });

	return next();
};
