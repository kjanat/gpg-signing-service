/**
 * Environment bindings and context types
 */

import type { Context } from "hono";
import type { Identity } from "#types/branded";
import type { WebhookAuthorization, WebhookDelivery, WebhookReplay } from "#types/github";
import type { ValidatedOIDCClaims } from "#types/oidc";

/** Context variables (for c.set/c.get) */
export interface Variables {
	/** Validated OIDC claims */
	oidcClaims: ValidatedOIDCClaims;
	/** Validated identity */
	identity: Identity;
	/** Request ID */
	requestId: string;
	/** Service-token key allowlist; null/absent means every key */
	allowedKeyIds?: string[] | null;
	/**
	 * Name of the trusted-subject row that authorized an OIDC caller, so the
	 * audit trail records *which trust* signed rather than only the JWT subject.
	 * Absent on the service-token path, where the row's name is already the
	 * synthetic `sub`.
	 */
	subjectPolicyName?: string;
	/**
	 * Id of the trusted-subject row that authorized an OIDC caller. Server-side
	 * and stable, unlike `sub`, which the caller varies per ref — so this is what
	 * the per-row signing ceiling is metered on. Absent on the service-token path,
	 * which is already metered per credential.
	 */
	subjectPolicyId?: string;
	/**
	 * A GitHub webhook delivery whose `X-Hub-Signature-256` verified.
	 *
	 * Written only by `githubWebhookAuth`, so a handler that finds it may assume
	 * the HMAC passed. Absent on every other route, like `allowedKeyIds` above.
	 */
	webhookDelivery?: WebhookDelivery;
	/**
	 * The verified webhook payload, parsed once.
	 *
	 * `unknown` rather than a modelled type: see `#types/github`. Published on
	 * the context rather than re-read with `c.req.json()` so that the bytes the
	 * signature covered are the only bytes anything downstream ever sees.
	 */
	webhookPayload?: unknown;
	/**
	 * What the verified delivery is authorized to be about.
	 *
	 * Written only by `githubWebhookAuthorize`, which refuses the request rather
	 * than setting anything when the delivery names a subject this deployment has
	 * not granted. A handler that finds it may assume both that the HMAC passed
	 * and that the scope below was granted by an operator — and must take the
	 * repository from *here*, never from `webhookPayload`.
	 */
	webhookAuthorization?: WebhookAuthorization;
	/**
	 * Proof that this delivery id had not been seen before.
	 *
	 * Written only by `webhookReplayGuard`, and only when the reservation
	 * succeeded — a repeat is answered by the guard and never reaches a handler.
	 * So a handler that finds it is running for the first time on this event.
	 */
	webhookReplay?: WebhookReplay;
	/**
	 * A handler's statement that this delivery caused nothing irreversible.
	 *
	 * Read by `webhookReplayGuard` after the handler returns, to decide whether
	 * to commit the delivery id for the retention window or release it so a
	 * redelivery is a genuine retry.
	 *
	 * **Absent means committed.** The default is deliberately the safe direction
	 * rather than the convenient one: a handler that acts and forgets to say so
	 * is not repeatable, whereas a handler that acts and is treated as repeatable
	 * signs the same commits twice. Only a handler that *knows* it published
	 * nothing sets this, and it sets it at the point it knows.
	 */
	webhookRetryable?: boolean;
}

/** Cloudflare Workers environment bindings */
export interface Env {
	/** Durable Object namespace for key storage */
	KEY_STORAGE: DurableObjectNamespace;
	/** Durable Object namespace for rate limiting */
	RATE_LIMITER: DurableObjectNamespace;
	/**
	 * Durable Object namespace for the webhook delivery ledger.
	 *
	 * Not optional even though the feature it serves is: a binding that might be
	 * absent is one whose absence has to be handled, and the handling for "the
	 * ledger is missing" would be either "act twice" or "refuse everything". It
	 * is declared in every environment and costs nothing until a delivery is
	 * claimed.
	 */
	WEBHOOK_DELIVERIES: DurableObjectNamespace;

	/** D1 Database */
	AUDIT_DB: D1Database;

	/** KV Namespace */
	JWKS_CACHE: KVNamespace;

	/** Environment variables */
	/** Comma-separated list of allowed issuers */
	ALLOWED_ISSUERS: string;
	/** GPG Key identifier */
	KEY_ID: string;
	/** Optional: comma-separated list of allowed CORS origins */
	ALLOWED_ORIGINS?: string;
	/** Optional: expected JWT audience (defaults to "gpg-signing-service") */
	EXPECTED_AUDIENCE?: string;
	/**
	 * Optional: public origin to build the `docs` links on error responses from.
	 * Defaults to the origin the request arrived on, which is right everywhere
	 * except behind a proxy that rewrites the host.
	 */
	SERVICE_BASE_URL?: string;
	/**
	 * Optional: document that `GET /e/:code` redirects into. Defaults to the
	 * error reference in this repository.
	 */
	ERROR_DOCS_URL?: string;
	/**
	 * Optional: set to "true" to name the trusted subject prefixes in an
	 * untrusted-subject 401. Off by default — the issuers this service accepts
	 * are shared with every repository on their platform, so that list would be
	 * readable by anyone who can run a workflow. See `RefusalContext`.
	 */
	DISCLOSE_TRUST_PATTERNS?: string;

	/**
	 * Optional: this deployment's environment label, e.g. `staging`. Set from
	 * `[env.<name>.vars]` and absent on the top-level one. It is what keeps two
	 * deployments' alert mail — otherwise identical — telling apart.
	 */
	ENVIRONMENT?: string;

	/** Key-expiry monitor */
	/**
	 * Optional: days ahead of expiry the scheduled monitor starts reporting a
	 * key. Defaults to 60. Plain decimal digits naming a positive whole number —
	 * `1e3` and `0x3C` are refused rather than read as 1000 and 60 — and
	 * anything else fails the run rather than silently reverting to the
	 * default.
	 */
	KEY_EXPIRY_WARN_DAYS?: string;
	/**
	 * Cloudflare Email Service send binding the monitor alerts through.
	 *
	 * Optional in the type because a deployment can genuinely lack it — the test
	 * environment does — and `mailConfig` is what turns that absence into a loud
	 * failure on the next scheduled run rather than a silent one.
	 */
	KEY_EXPIRY_ALERTS?: SendEmail;
	/**
	 * Optional: address the monitor's alerts are sent from. Must belong to a
	 * domain onboarded to Email Service; the binding's own
	 * `allowed_sender_addresses` is what enforces that.
	 */
	KEY_EXPIRY_ALERT_FROM?: string;
	/**
	 * Optional: address the monitor's alerts are sent to. Must be a verified
	 * destination address; the binding's own `destination_address` is what
	 * enforces that.
	 *
	 * A plain var rather than a secret on purpose: an address is not a
	 * credential, and hiding it would mean the repository could not show an
	 * operator where their own monitor reports to.
	 */
	KEY_EXPIRY_ALERT_TO?: string;

	/** GitHub App integration */
	/**
	 * Optional: set to the literal `"true"` to serve `POST /github/webhook`.
	 *
	 * Anything else — unset, `"false"`, `"1"`, `"TRUE"` — leaves the route
	 * answering exactly what an unrouted path answers, so a deployment that has
	 * not opted in does not advertise that the feature exists. See
	 * `githubAppEnabled` in `src/utils/github-app.ts` for why only one spelling
	 * is accepted.
	 */
	GITHUB_APP_ENABLED?: string;
	/**
	 * Optional: the App's numeric id, from its settings page. A plain var, not a
	 * secret: it is printed in the App's own public URL and proves nothing on its
	 * own.
	 */
	GITHUB_APP_ID?: string;
	/**
	 * Optional: which `<installation, repository>` pairs a delivery may be about,
	 * and which signing key each of them may cause to sign with.
	 *
	 * Comma-separated `<installationId>:<owner>/<repo>[=<keyId>]` entries, e.g.
	 * `12345678:kjanat/gpg-signing-service=62E75E54497815DD`. Unset authorizes no
	 * installation and no repository — the App-level `ping`, which names neither,
	 * still answers so an operator can check the endpoint before writing this.
	 *
	 * The `=<keyId>` suffix is optional and there is **no default**: a pair
	 * written without one has its deliveries received, authorized and logged, and
	 * may cause nothing to sign. `KEY_ID` is the default for `POST /sign`, where
	 * the caller's own key grant has already been checked, and it is deliberately
	 * not inherited here. See `src/utils/github-signing-key.ts`.
	 *
	 * A plain var rather than a secret: it is a policy an operator should be able
	 * to read back from `wrangler.toml` and diff, and it grants nothing on its
	 * own — reaching the check at all requires the webhook secret. A key id is
	 * not a secret either; `/public-key` serves the key it names.
	 *
	 * Pairs rather than two independent lists, because two lists authorize every
	 * combination of their members, and the key rides inside the entry for the
	 * same reason. A pair may appear at most once — a repeat refuses the whole
	 * list rather than resolving to whichever entry came first. See
	 * `src/utils/github-authorization.ts`.
	 */
	GITHUB_APP_ALLOWED_REPOSITORIES?: string;

	/** Error tracking */
	/**
	 * Optional: Sentry DSN. Unset — or set to whitespace — disables Sentry
	 * entirely: no events, no traces, no breadcrumbs, and none of the SDK's
	 * integrations are installed, so `console.log` reaches Workers Logs and
	 * `audit_logs` is written exactly as it is without this binding. Set via
	 * `wrangler secret put SENTRY_DSN`; a DSN is not a credential that grants
	 * read access, but it does authorize writes into a project, so it is kept
	 * out of tracked config.
	 */
	SENTRY_DSN?: string;
	/**
	 * Optional: fraction of requests traced, `0`..`1`. Defaults to 0.1 when a
	 * DSN is configured, and is forced to 0 when one is not. Anything
	 * unparseable or out of range falls back to the default rather than failing
	 * the request — the cost of getting it wrong is a different amount of
	 * telemetry, not a wrong answer.
	 */
	SENTRY_TRACES_SAMPLE_RATE?: string;
	/**
	 * Not read here, and deliberately not declared: the SDK fills `spotlight`,
	 * `tunnel` and `debug` from `SENTRY_SPOTLIGHT`, `SENTRY_TUNNEL` and
	 * `SENTRY_DEBUG` for any option `buildSentryOptions` leaves unset. The first
	 * two change where events are sent; all three are pinned in
	 * `src/utils/sentry.ts` so the configured DSN is the only thing that decides
	 * whether, and where, anything is forwarded.
	 */

	/** Secrets */
	/** Passphrase for private key */
	KEY_PASSPHRASE: string;
	/** Admin token for authentication */
	ADMIN_TOKEN: string;
	/**
	 * Optional: a second admin bearer that may only read.
	 *
	 * Presented the same way as `ADMIN_TOKEN`, and accepted on `GET`/`HEAD`
	 * admin routes only; every state-changing admin route answers 403
	 * `AUTH_SCOPE_INSUFFICIENT` for it. Unset means the credential does not
	 * exist on this deployment and no bearer can obtain the read-only scope.
	 *
	 * Must differ from `ADMIN_TOKEN`. Setting them equal is refused rather than
	 * tolerated: the two would be indistinguishable at the comparison, so the
	 * "read-only" holder would silently be a full administrator, which is the
	 * one outcome this binding exists to prevent.
	 */
	ADMIN_READONLY_TOKEN?: string;

	/**
	 * Optional: the GitHub App's RSA private key, PEM-encoded.
	 *
	 * Accepted in either PKCS#1 (`BEGIN RSA PRIVATE KEY`, which is what GitHub's
	 * download button produces) or PKCS#8 (`BEGIN PRIVATE KEY`) form;
	 * `toPkcs8Pem` converts the first into the second, because WebCrypto imports
	 * only the second. Holding it *is* being the App, so it is a secret in the
	 * strongest sense: it mints credentials for every installation.
	 */
	GITHUB_APP_PRIVATE_KEY?: string;
	/**
	 * Optional: the webhook secret configured on the App.
	 *
	 * The sole control on `POST /github/webhook` — the URL is public by
	 * construction — so an enabled integration with this unset refuses every
	 * delivery rather than accepting unauthenticated ones.
	 */
	GITHUB_WEBHOOK_SECRET?: string;
}

/** Hono context with env bindings and variables */
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;
