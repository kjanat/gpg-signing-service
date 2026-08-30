/**
 * Environment bindings and context types
 */

import type { Context } from "hono";
import type { Identity } from "#types/branded";
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
}

/** Cloudflare Workers environment bindings */
export interface Env {
	/** Durable Object namespace for key storage */
	KEY_STORAGE: DurableObjectNamespace;
	/** Durable Object namespace for rate limiting */
	RATE_LIMITER: DurableObjectNamespace;

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
}

/** Hono context with env bindings and variables */
export type AppContext = Context<{ Bindings: Env; Variables: Variables }>;
