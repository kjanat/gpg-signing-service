import type { Context, MiddlewareHandler } from "hono";
import { createLocalJWKSet, jwtVerify } from "jose";
import { INSUFFICIENT_SCOPE_MESSAGE } from "#lib/openapi";
import { getRequestId } from "#middleware/request-id";
import type { Env, LegacyJWKSResponse, OIDCClaims, RateLimitResult, Variables } from "#types";
import { createIdentity, HEADERS, HTTP, markClaimsAsValidated, TIME } from "#types";
import { logAuditEvent } from "#utils/audit";
import { CACHE_TTL } from "#utils/constants";
import { fetchRateLimiter } from "#utils/durable-objects";
import { insufficientScope, serviceDegraded, serviceMisconfigured, unauthorized } from "#utils/errors";
import { scheduleBackgroundTask } from "#utils/execution";
import { fetchWithTimeout } from "#utils/fetch";
import { logger } from "#utils/logger";
import type { OIDCSubjectResolution, RefusalContext } from "#utils/oidc-subjects";
import { resolveOIDCSubject } from "#utils/oidc-subjects";
import { validateUrl } from "#utils/url-validation";

/**
 * Rate-limiter namespace for revoked-trust reuse, kept disjoint from the
 * `<iss>:<sub>` buckets the signing path consumes.
 *
 * Not because `ALLOWED_ISSUERS` is validated — it is a bare string, split on
 * commas and checked nowhere; `SubjectCreateSchema.issuer` constrains stored
 * *rows*, and the bucket name is built from `payload.iss`. The real guarantee is
 * that a non-URL issuer cannot authenticate at all: `getJWKS` fetches
 * `${issuer}/.well-known/openid-configuration` through `validateUrl`, which
 * requires an absolute `https:` URL. So this string can never appear as an `iss`
 * that reached the point of naming a bucket.
 */
const REVOKED_REUSE_METER = "oidc-revoked-reuse";

/**
 * This deployment could not reach the issuer, as distinct from the issuer
 * refusing the token.
 *
 * `validateOIDCToken` throws a plain Error for every way a *credential* can be
 * wrong, and `oidcAuth` echoes those as 401 `AUTH_INVALID`. Five of the things
 * it could throw were never credential faults at all: a discovery or JWKS fetch
 * that failed or timed out, and a URL this deployment refuses to fetch. They
 * arrived at the caller wearing a code whose reference section is a table of
 * seven token faults, none of which they had — and whose whole meaning to the
 * Go client is "do not retry this", when a JWKS blip is the one auth failure a
 * retry does fix.
 *
 * Carrying its own type is what lets the catch tell them apart, since both
 * kinds surface from the same call.
 *
 * `transient` separates the two ways this happens. A timeout or a 5xx from the
 * issuer clears on its own and is worth another attempt; a URL blocked by SSRF
 * validation is this deployment's `ALLOWED_ISSUERS` pointing somewhere it will
 * never fetch from, which no amount of waiting resolves. Neither is the
 * caller's to fix, and they are answered differently all the way down: the
 * transient one is `SERVICE_DEGRADED`, 503, with a `Retry-After`; the permanent
 * one is `SERVICE_MISCONFIGURED`, 500, with none. Telling a caller to try again
 * for a fault that is permanent until an operator edits a variable is just a
 * slower failure.
 *
 * The code is what carries that, and the missing `Retry-After` deliberately is
 * not: a header's absence is not a channel any client reads as "stop", so
 * expressing it that way left the permanent fault being attempted four times.
 * The status is not the channel either — `shouldRetry` reads `>= 500` — but it
 * is read by every proxy in between, and 503 is the one they retry.
 */
export class IssuerUnavailableError extends Error {
	constructor(
		message: string,
		readonly transient: boolean,
		options?: { cause?: unknown },
	) {
		super(message, options);
		this.name = "IssuerUnavailableError";
	}
}

/**
 * What a caller is asked to wait when the issuer could not be reached.
 *
 * Shorter than the JWKS cache's five minutes on purpose: nothing was cached, so
 * this is a guess at how long an upstream blip lasts, and the cost of guessing
 * low is one more request against a dependency that is already answering again
 * by then.
 */
const ISSUER_RETRY_AFTER_SECONDS = 30;

/**
 * Write a durable record of a revoked trust being presented, if the caller is
 * within its rate-limit budget.
 *
 * Metered because it is a D1 write on a refusal path: without the check, the
 * holder of a revoked credential could flood `audit_logs`, which shares a
 * database with the authorization table every request reads. Best-effort in
 * every direction — a limiter outage or a failed write must not change the 401.
 *
 * Metered on the *revoked row's id*, not on `<iss>:<sub>` like the signing path.
 * A row is a prefix, and one prefix covers unboundedly many subjects: GitHub
 * puts the ref in `sub`, so anyone who can push a branch under the revoked scope
 * mints a fresh subject — and a per-subject bucket hands them a fresh budget
 * with it, which makes the cap no cap at all. Keying on the id bounds the whole
 * revoked trust to one bucket however many subjects it presents, the same shape
 * as the service-token path, which meters on `policy.name` rather than on
 * anything the caller picks.
 *
 * The signing path applies the same argument as a second tier: a per-caller
 * bucket for fairness, plus a per-row ceiling keyed the same way this is.
 *
 * @param c - Request context
 * @param requestId - This request's id, shared with the rest of the pipeline
 * @param payload - The verified (but unauthorized) claims
 * @param resolution - The revoked row that matched
 */
async function recordRevokedReuse(
	c: Context<{ Bindings: Env; Variables: Variables }>,
	requestId: string,
	payload: OIDCClaims,
	resolution: Extract<OIDCSubjectResolution, { status: "revoked" }>,
): Promise<void> {
	try {
		const limit = await fetchRateLimiter(c.env, createIdentity(REVOKED_REUSE_METER, resolution.id));
		if (!limit.ok) {
			return;
		}
		const { allowed } = (await limit.json()) as RateLimitResult;
		if (!allowed) {
			return;
		}
	} catch (error) {
		logger.warn("Could not meter a revoked-trust reuse, so it was not recorded", {
			requestId,
			error: error instanceof Error ? error.message : String(error),
		});
		return;
	}

	await scheduleBackgroundTask(
		c,
		requestId,
		logAuditEvent(c.env.AUDIT_DB, {
			requestId,
			action: "sign",
			issuer: payload.iss,
			subject: payload.sub,
			keyId: "*",
			success: false,
			errorCode: "AUTH_SUBJECT_UNTRUSTED",
			metadata: JSON.stringify({
				reason: "revoked_trust_presented",
				subjectId: resolution.id,
				subjectPolicy: resolution.name,
				revokedAt: resolution.revokedAt,
			}),
		}),
	);
}

/**
 * What to change when the *credential* was refused.
 *
 * `validateOIDCToken` throws a curated string per failure, and each one has a
 * different fix — a stale token, a workflow that asked for the wrong audience,
 * an issuer this deployment does not accept. The message names the fault; this
 * names the action, because the two are not the same sentence and a caller
 * reading "Invalid token audience" in a CI log has no way to guess which knob
 * produces it.
 *
 * Returns undefined for the faults where the message already is the action, or
 * where anything more specific would describe our JWKS handling to a stranger.
 * The `docs` link covers those.
 *
 * @param message - The message `validateOIDCToken` threw
 * @param env - Deployment bindings, for naming the values actually configured
 */
function tokenHint(message: string, env: Env): string | undefined {
	if (message === "Token expired" || message === "Token not yet valid") {
		return "The token's lifetime does not cover this request. Mint a fresh OIDC token immediately before calling /sign rather than reusing one from earlier in the job, and check the runner's clock.";
	}
	if (message === "Invalid token audience") {
		return `Request the token with audience "${env.EXPECTED_AUDIENCE || "gpg-signing-service"}" — for GitHub Actions, core.getIDToken(audience) or the audience input of the OIDC step.`;
	}
	if (message.startsWith("Issuer not allowed")) {
		// The list is behind the same flag the trusted prefixes are, and for a
		// stronger reason. This check runs before the timing check, the audience
		// check and the JWKS fetch, so an unsigned JWT assembled by hand reaches
		// it — no credential is presented, and none is ever verified. Naming every
		// issuer this deployment accepts to that caller hands a self-hoster's
		// internal Keycloak hostname to anyone who can reach the worker. The
		// message already names the issuer that was refused, which is the caller's
		// half; the knob is the operator's half, and it is the same sentence
		// whether or not the values are printed.
		const base =
			"The `iss` in this token is not one this deployment accepts. The operator sets that list in `ALLOWED_ISSUERS`.";
		if (env.DISCLOSE_TRUST_PATTERNS !== "true") {
			return base;
		}
		const issuers = env.ALLOWED_ISSUERS.split(",")
			.map((issuer) => issuer.trim())
			.filter(Boolean);
		return issuers.length > 0 ? `${base} It currently accepts: ${issuers.join(", ")}.` : base;
	}
	if (message === "Invalid token format" || message === "Invalid token encoding") {
		return "The Authorization header did not carry a JWT. A common cause is an unset variable expanding to an empty string, so the header reads `Bearer ` with nothing after it.";
	}
	if (message.startsWith("Algorithm not allowed")) {
		// Named because the reference's table is the caller's only account of what
		// AUTH_INVALID means, and a fault missing from it reads as a fault the
		// documentation does not know about.
		return "The token's `alg` header is not one this service verifies. It accepts RS256, RS384, RS512, ES256 and ES384 — an `alg` of `none`, or a symmetric one, is refused before any key is fetched.";
	}
	if (message === "Key not intended for signatures") {
		return "The issuer's JWKS names this key with `use` set to something other than `sig`, so it is not a signing key. This is the issuer's metadata, not the token's — if it persists, it is one for the issuer's operator.";
	}
	return undefined;
}

/**
 * What to check when the *deployment* could not reach the issuer.
 *
 * Split by `transient` because the two have opposite audiences. A timeout is
 * the caller's to wait out and nobody's to fix; a blocked URL is an operator's
 * to correct and waiting will not help. Saying "retry" for the second is how a
 * pipeline burns its retry budget on a variable that is simply wrong — so the
 * second one says outright that the answer will not change, which is the part
 * a human reading a CI log acts on. The `code` says the same to a client.
 *
 * @param error - The failure to reach the issuer
 */
function issuerUnavailableHint(error: IssuerUnavailableError): string {
	if (error.transient) {
		return "This deployment could not reach the issuer to verify the token, so it could not decide the request either way. Nothing about the token is wrong and nothing in the workflow needs changing — wait the interval in `Retry-After` and call again. If it persists, check the issuer's status and this deployment's egress.";
	}
	return "This deployment refuses to fetch from the URL that issuer's discovery points at, so no token from it can ever be verified here. Retrying will get this same answer every time. That is a deployment fault, not a credential one: the operator should check the entry in `ALLOWED_ISSUERS` resolves to a public host.";
}

/**
 * What to change when the credential verified but the identity is not trusted.
 *
 * Deliberately identical for all three refusal statuses. Reaching `revoked` or
 * `expired` means the presented `sub` matched a stored prefix, and saying so
 * confirms to whoever holds that token that the row exists — the same
 * disclosure the single shared message has always avoided. The operator still
 * gets the three apart, in the logs.
 *
 * What it does add is the one distinction a caller can act on: whether this
 * service has *any* rules for the issuer. Nought means nobody was ever
 * authorized here; several means this particular subject is not among them,
 * which points at the ref or repository part of the claim.
 *
 * @param issuer - The verified `iss`
 * @param context - Counts gathered while resolving
 * @param env - Deployment bindings, for the disclosure opt-in
 */
function untrustedSubjectHint(issuer: string, context: RefusalContext, env: Env): string {
	if (context.issuerRuleCount === 0) {
		return `No trust rules are configured for issuer ${issuer}. Authorize this subject with POST /admin/subjects before signing.`;
	}

	const active = context.activePrefixes.length;
	// No figures in the default hint. The branch above already carried the whole
	// actionable half — *is this deployment configured for my issuer at all* —
	// and by the time a reader is on this line they have their answer. Whether
	// the number is 4 or 40 changes nothing they can do, which puts the exact
	// counts in the same category as the prefixes themselves: not actionable, and
	// not free. This 401 is answered before the identity is set and before any
	// limiter is consulted, and the `unknown` arm deliberately writes no audit
	// row, so a live count here is an unmetered, unrecorded oracle on the trust
	// table for anyone who can mint a token on a shared issuer — poll it and the
	// delta is an add/revoke/expire feed.
	// Says which rules failed to apply, not why this particular one did. The
	// three arms share this string, so it has to be true of all three, and
	// "none of them covers this subject" is not: `revoked` and `expired` are
	// reachable only when a stored prefix *did* cover the subject and the row
	// was not live. An operator who followed that sentence to GET /admin/subjects
	// would find a rule matching the subject exactly and conclude the prefix
	// matcher was broken, when the answer was in `revoked_at` or `expires_at` on
	// the row in front of them. Naming both ways a rule misses keeps the string
	// identical on every arm — so it still discloses nothing about which one this
	// was — while sending the reader at the two columns that actually decide it.
	let hint =
		`No active trust rule matches this subject. Trust rules exist for this issuer, but none of them both ` +
		`covers this subject and is currently active. A rule misses either way: its prefix must cover the subject ` +
		`and end at a ":", "@" or "/" boundary, so a rule for one ref does not cover another; and a rule that has ` +
		`been revoked or has expired stops applying while still being listed. Compare the subject above with ` +
		`GET /admin/subjects, checking "active" as well as the prefix, then add or renew a rule with ` +
		`POST /admin/subjects.`;

	// Off by default; see RefusalContext for why the trust list is not free to
	// hand out. `=== "true"` rather than truthiness so an operator who sets it to
	// "false" gets what they asked for.
	if (env.DISCLOSE_TRUST_PATTERNS === "true") {
		hint += ` ${context.issuerRuleCount} rule(s) exist for issuer ${issuer}, ${active} of them active.`;
		if (active > 0) {
			hint += ` Active prefixes: ${context.activePrefixes.join(", ")}.`;
		}
	}
	return hint;
}

/**
 * OIDC validation middleware.
 *
 * The identity published here is `<iss>:<sub>` and becomes the sign route's
 * per-caller rate-limit bucket. GitHub puts the ref in `sub`, so that bucket
 * alone does not bound a trusted *row* — a caller who can push branches mints a
 * fresh budget per branch. `subjectPolicyId` is published alongside it for the
 * route's second-tier ceiling, which is keyed on the row and closes that gap;
 * see `SUBJECT_ROW_LIMIT` in `routes/sign.ts`.
 *
 * Every distinct `sub` still writes its own `bucket:` key in the limiter Durable
 * Object; the row ceiling bounds the signing *rate*, not that growth. The
 * limiter's reaper is what bounds it, by deleting buckets that have refilled to
 * capacity — see `alarm` in `durable-objects/rate-limiter.ts`.
 */
export const oidcAuth: MiddlewareHandler<{
	Bindings: Env;
	Variables: Variables;
}> = async (c, next) => {
	// One id for the whole request. The global request-id middleware already
	// derived it and captured that value for the `X-Request-ID` it echoes on the
	// way out, so re-deriving here mints a *different* UUID when the caller sent
	// no header — stranding every row this request writes under an id the caller
	// never sees. The fallback covers direct invocation in tests.
	const requestId = c.get("requestId") ?? getRequestId(c.req.header(HEADERS.REQUEST_ID));
	c.set("requestId", requestId);

	const authHeader = c.req.header("Authorization");

	if (!authHeader?.startsWith("Bearer ")) {
		return unauthorized(c, "Missing authorization header", "AUTH_MISSING", {
			hint: "Send `Authorization: Bearer <token>` with an OIDC token minted for this service's audience.",
		});
	}

	const token = authHeader.split(" ")[1];
	if (!token) {
		// `code` is not decoration: the document now declares this 401 as an
		// ErrorResponse, and every client that reads the envelope branches on the
		// code rather than the prose. A bare `Bearer ` is the same fault as no
		// header at all, so it carries the same code.
		return unauthorized(c, "Missing token", "AUTH_MISSING", {
			hint: "The Authorization header was `Bearer ` with nothing after it, which is what an unset variable expands to.",
		});
	}

	// Deliberately narrow: this catch echoes the thrown message to the caller,
	// which is only safe for validateOIDCToken's curated auth strings. A database
	// read or anything downstream must not be in here — see below.
	let payload: OIDCClaims;
	try {
		payload = await validateOIDCToken(token, c.env);
	} catch (error) {
		// Not every throw from there is a bad credential. A discovery or JWKS
		// fetch that failed is this deployment failing to reach the issuer, and
		// answering it 401 told the caller to go and mend a token that was fine —
		// while handing the Go client the one code its retry policy refuses to
		// retry, for the one auth failure a retry actually fixes.
		if (error instanceof IssuerUnavailableError) {
			// The two halves of `transient` get two codes, not one code and a
			// missing header. Retryability is the only thing a caller does with a
			// 5xx, and no client reads the absence of `Retry-After` as "stop" — the
			// Go retrier attempts any 5xx — so expressing "permanent" that way had
			// the SSRF fault tried four times and only cost it the interval.
			if (!error.transient) {
				return serviceMisconfigured(c, error.message, { hint: issuerUnavailableHint(error) });
			}
			return serviceDegraded(c, error.message, {
				hint: issuerUnavailableHint(error),
				retryAfter: ISSUER_RETRY_AFTER_SECONDS,
			});
		}
		const message = error instanceof Error ? error.message : "Invalid token";
		return unauthorized(c, message, "AUTH_INVALID", { hint: tokenHint(message, c.env) });
	}

	// Authentication is not authorization. A verified token only proves that some
	// workflow on an accepted issuer asked for our audience — and both issuers are
	// shared by every repository on GitHub Actions and every project on
	// gitlab.com. The subject must be one we trust.
	//
	// A policy we cannot read is not a bad credential. Reporting it as 401 would
	// point the operator at credentials on the day the real cause is a migration
	// that has not run yet, and would hand our schema to every caller.
	let resolution: OIDCSubjectResolution;
	try {
		resolution = await resolveOIDCSubject(c.env.AUDIT_DB, payload.iss, payload.sub);
	} catch (error) {
		// Same three arguments as the service-token branch in `caller-auth.ts`,
		// for the same outage: the caught value in the error slot the logger
		// unpacks, and `requestId` in context. This was the one line in this
		// function's failure block without the id — the three `logger.warn` calls
		// below all carry it, for the reason stated there, and the caller holding
		// the 503's id had no entry to match it against on the one arm whose
		// answer is "wait" rather than "fix your credential".
		logger.error("OIDC subject lookup failed", error, {
			requestId,
			issuer: payload.iss,
		});
		// SERVICE_DEGRADED rather than INTERNAL_ERROR. The status was always 503,
		// but the code said "internal fault" — whose reference section is about
		// migrations and unhandled exceptions — for what is usually D1 being
		// briefly unavailable. The caller's move is to wait, and only a code that
		// says so gets them there.
		return serviceDegraded(c, "Authorization store unavailable", {
			hint: "The trusted-subject lookup failed, so this request could not be authorized either way. Nothing about the token is wrong. Retry after the interval in Retry-After; if it persists, the operator should check D1 and that `task db:migrate` has been applied.",
			retryAfter: ISSUER_RETRY_AFTER_SECONDS,
		});
	}

	if (resolution.status !== "trusted") {
		// Three different events, one response. The caller learns nothing extra —
		// telling a stranger that their subject matches a revoked row would confirm
		// the row exists — but the operator gets to tell them apart. Reuse of a
		// revoked credential is an incident; an unknown subject on a shared issuer
		// is background traffic.
		//
		// `requestId` on all three: the 401 hands the caller an id and the response
		// deliberately does not say which of the three it was, so the id is the
		// operator's only route from a pasted CI log to the reason. Without it here
		// that route dead-ended — the id reached `audit_logs` on the revoked path
		// alone, and the two arms that write no row were unfindable by it.
		if (resolution.status === "revoked") {
			logger.warn("Revoked OIDC trust presented", {
				requestId,
				issuer: payload.iss,
				subject: payload.sub,
				subjectId: resolution.id,
				subjectPolicy: resolution.name,
				revokedAt: resolution.revokedAt,
			});
		} else if (resolution.status === "expired") {
			logger.warn("Expired OIDC trust presented", {
				requestId,
				issuer: payload.iss,
				subject: payload.sub,
				subjectId: resolution.id,
				subjectPolicy: resolution.name,
				expiresAt: resolution.expiresAt,
			});
		} else {
			// Counted, not listed. This is the arm no limiter guards and no audit
			// row records, so anyone who can mint a token on a shared issuer can
			// reach it as often as they like — and while it logged the array, the
			// size of each record it produced was a function of how many orgs sign
			// here. That is trust-table-size amplification into the log store,
			// paid for by the operator and chosen by the caller.
			//
			// The counts keep the diagnosis whole: `issuerRuleCount` is zero when
			// the deployment was never configured for the issuer, and the active
			// count separates "configured and all dead" from "configured, live,
			// and this subject is not among them" — the three states an operator
			// acts on differently. Which prefixes those are is the same question
			// `DISCLOSE_TRUST_PATTERNS` gates in the response, and the authorized
			// answer to it is GET /admin/subjects. `requestId`, `issuer` and
			// `subject` stay so the pasted CI log still joins to this line.
			logger.warn("Rejected untrusted OIDC subject", {
				requestId,
				issuer: payload.iss,
				subject: payload.sub,
				issuerRuleCount: resolution.issuerRuleCount,
				activePrefixCount: resolution.activePrefixes.length,
			});
		}
		// `unknown` gets no audit_logs row: that arm is reachable by anyone holding
		// any token the issuer will mint, so a write there would be unmetered — the
		// same problem the key-scope denial had.
		//
		// `revoked` is not that. Reaching it requires the token's `sub` to match a
		// stored prefix, and GitHub binds `sub` to the caller's actual repository,
		// so the population that can trigger it is the org that used to hold the
		// trust. That is the same bounded, already-vetted caller whose scope denial
		// this service records durably — and a killed credential still in use is
		// the stronger signal of the two. It gets a row, metered the same way, so
		// it survives past the log store's retention window.
		//
		// `expired` is bounded the same way but stays log-only: a lapsed trust is
		// routine maintenance, not evidence of anything, and it is the row owner's
		// problem rather than an operator's. Recording it would mostly add volume.
		if (resolution.status === "revoked") {
			await recordRevokedReuse(c, requestId, payload, resolution);
		}

		// Its own code, not AUTH_INVALID. The token is fine; the identity it proves
		// is not authorized, and those two take opposite fixes — regenerate the
		// credential versus edit the trust list. One code for both is what sends a
		// caller round the first loop for a problem only the second one solves.
		//
		// `subject` is echoed because it is the fact the caller needs and the one
		// thing here that discloses nothing: it arrived in a token they hold and
		// already signed. Withholding it only meant re-running the workflow with a
		// debug step to print the claim the refusal was about.
		return unauthorized(c, "Subject is not trusted for signing", "AUTH_SUBJECT_UNTRUSTED", {
			subject: payload.sub,
			hint: untrustedSubjectHint(payload.iss, resolution, c.env),
		});
	}

	const policy = resolution.policy;

	// Store validated claims in context for downstream use
	c.set("oidcClaims", markClaimsAsValidated(payload));
	c.set("identity", createIdentity(payload.iss, payload.sub));
	// Key scoping now applies to OIDC callers too, not just service tokens.
	c.set("allowedKeyIds", policy.allowedKeyIds);
	// Which trust authorized this call. Without it the audit trail records only
	// the JWT subject, so "what did the row I just revoked sign?" means re-running
	// prefix matching over the whole history. The service-token path gets this
	// for free by putting the policy name in its synthetic `sub`.
	c.set("subjectPolicyName", policy.name);
	// Metering handle for the sign route's per-row ceiling; see the note above.
	c.set("subjectPolicyId", policy.id);

	// The last-used stamp is bookkeeping; do not make every signature wait on a
	// D1 write for it.
	await scheduleBackgroundTask(c, requestId, policy.stampUsage());

	// Outside the try on purpose: an error from the sign handler is a 500, not a
	// 401 carrying an internal message.
	return next();
};

/**
 * The methods the read-only admin credential may use.
 *
 * This set, and not a list of paths, is the whole authorization boundary — for
 * one reason worth stating plainly: the router already sorts admin routes into
 * reads and writes, and every read is a `GET` while every write is a `POST` or
 * a `DELETE`. A path allowlist would be a second copy of that split, and copies
 * drift. Worse, they drift in the unsafe direction: a new mutation route is
 * denied here by construction, whereas an allowlist only denies it if whoever
 * added the route remembered this file existed.
 *
 * The converse is equally true and is the cost of choosing it: a new *read*
 * route is **granted** to the monitoring credential by construction. Add
 * `GET /admin/keys/{keyId}/export` and `ADMIN_READONLY_TOKEN` reaches it at
 * runtime without anyone deciding that it should. Nothing in this file stops
 * that; what stops it is `admin-scope.test.ts`, which pins the read set
 * literally and diffs it against the generated OpenAPI document, so widening
 * the read side fails CI until somebody edits that list on purpose. That is a
 * review gate rather than a runtime one, and it is where the trade lands:
 * mutations are closed by code, reads are opened by code and closed by CI. The
 * posture that makes it acceptable is documented rather than enforced — this
 * credential is narrower in authority, not in disclosure, and already reads
 * every key id, trust rule, token name and audit row.
 *
 * `HEAD` rides along because Workers answers it from the `GET` handler, so
 * excluding it would refuse a request that returns nothing but headers for a
 * body the credential may read in full.
 *
 * `OPTIONS` is deliberately absent even though RFC 9110 calls it safe. CORS
 * preflight is answered upstream by `productionCors` and never arrives here; an
 * `OPTIONS` that does reach this point is not a read, and failing it closed
 * costs a caller nothing.
 */
const READ_ONLY_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD"]);

/**
 * Admin auth for management endpoints, and the scope boundary between the two
 * admin credentials.
 *
 * Two bearers reach this: `ADMIN_TOKEN`, which may do anything, and the
 * optional `ADMIN_READONLY_TOKEN`, which may only read. The second exists
 * because a scheduled key-expiry monitor needs four `GET`s and nothing else,
 * and holding `ADMIN_TOKEN` to get them means a repository secret that can also
 * delete a signing key, mint a service token and rewrite the trust list. The
 * monitor was already least-privileged at the Actions permission layer; this is
 * the same claim at the service layer.
 *
 * Typed with `Variables` so the refusals can read `requestId` off the context
 * the global middleware populated — the same id `X-Request-ID` echoes and
 * `audit_logs.request_id` stores.
 */
export const adminAuth: MiddlewareHandler<{
	Bindings: Env;
	Variables: Variables;
}> = async (c, next) => {
	// An unset or empty ADMIN_TOKEN is a deployment fault, not a credential
	// fault, and it is not a harmless one: timingSafeEqual("", "") compares two
	// zero-length arrays of matching length and returns true, so without this
	// guard a bare `Authorization: Bearer ` would authorize every admin route on
	// a Worker whose secret was never put. `Env` types ADMIN_TOKEN as `string`,
	// which is a compile-time promise about a value wrangler supplies at runtime
	// — nothing checks it. Answer 500, because the caller's credential is not
	// what is wrong and no amount of retrying with a better one will help.
	if (!c.env.ADMIN_TOKEN) {
		logger.error("ADMIN_TOKEN is not configured; refusing every admin request");
		return c.json(
			{ error: "Admin authentication is not configured", code: "INTERNAL_ERROR" },
			HTTP.InternalServerError,
		);
	}

	// Empty is "not provisioned", by the same argument as above: an unset
	// wrangler secret and a `""` are the same thing to a caller, and the compare
	// below would hand the read-only scope to a bare `Bearer `.
	const readOnlyToken = c.env.ADMIN_READONLY_TOKEN || undefined;

	// Two identical secrets are a silent privilege escalation, not a typo to
	// tolerate: the comparison cannot tell them apart, so whichever matches
	// first wins and the credential labelled read-only is a full administrator.
	// That is precisely the outcome the second secret exists to prevent, and it
	// is invisible from the outside — the monitor's calls all succeed. Refuse
	// the whole admin surface instead. A plain `===` is right here: both values
	// are this deployment's own, neither is attacker-supplied, and there is no
	// secret to leak by timing.
	//
	// The diagnosis goes to the operator log and not into the body. This guard
	// runs before the `Authorization` header is even read, so anything put in
	// the response is handed to unauthenticated callers — and it would be the
	// most specific configuration statement the service makes, naming both
	// secrets and describing the exact defect. The `!ADMIN_TOKEN` guard above
	// already answers its own deployment fault with no hint for that reason;
	// this one is the same class and gets the same posture. `requestId` ties the
	// caller's 500 to the log line that says what to fix.
	if (readOnlyToken !== undefined && readOnlyToken === c.env.ADMIN_TOKEN) {
		logger.error(
			"ADMIN_READONLY_TOKEN is set to the same value as ADMIN_TOKEN, which would make the read-only credential a full administrator; refusing every admin request until they differ. Put a distinct value with `wrangler secret put ADMIN_READONLY_TOKEN`.",
		);
		return serviceMisconfigured(c, "Admin authentication is misconfigured");
	}

	const authHeader = c.req.header("Authorization");

	if (!authHeader?.startsWith("Bearer ")) {
		return unauthorized(c, "Missing authorization header", "AUTH_MISSING", {
			hint: "Admin routes take `Authorization: Bearer <ADMIN_TOKEN>`.",
		});
	}

	const token = authHeader.slice(7);
	// Answered before the compare so a bare `Bearer ` gets the same code here as
	// it does on the OIDC path. The premise of declaring `code` is that clients
	// branch on it rather than on the prose, which is worth nothing if one
	// malformed header maps to two codes depending on which route received it.
	// An empty token is not a credential the service refused; it is no
	// credential at all.
	if (!token) {
		return unauthorized(c, "Missing token", "AUTH_MISSING", {
			hint: "The Authorization header was `Bearer ` with nothing after it, which is what an unset variable expands to.",
		});
	}

	// Both comparisons run, and both are awaited before either is read, so which
	// of the two secrets a valid bearer matched is not observable as one extra
	// constant-time compare.
	//
	// Whether a read-only credential is provisioned at all is *not* hidden: with
	// `ADMIN_READONLY_TOKEN` unset the second compare is skipped outright rather
	// than run against a placeholder nothing can present. That is deliberate, and
	// the reason is that the bit is not a secret — a deployment's own docs say
	// whether it provisioned the credential. The value is what this compare
	// protects, and that stays constant-time either way.
	const [isFullAdmin, isReadOnly] = await Promise.all([
		timingSafeEqual(token, c.env.ADMIN_TOKEN),
		readOnlyToken === undefined ? Promise.resolve(false) : timingSafeEqual(token, readOnlyToken),
	]);

	if (!isFullAdmin && !isReadOnly) {
		return unauthorized(c, "Invalid admin token", "AUTH_INVALID", {
			hint: "The bearer did not match this deployment's ADMIN_TOKEN secret, or its ADMIN_READONLY_TOKEN if one is set. Rotate with `wrangler secret put ADMIN_TOKEN` if it has been lost.",
		});
	}

	// `isFullAdmin` wins a tie it can no longer have — the equality guard above
	// already refused the only way both could match — but reading it this way
	// keeps the safe outcome if that guard is ever weakened.
	if (!isFullAdmin && !READ_ONLY_METHODS.has(c.req.method)) {
		return insufficientScope(c, INSUFFICIENT_SCOPE_MESSAGE, {
			hint: `ADMIN_READONLY_TOKEN is accepted on ${[...READ_ONLY_METHODS].join(" and ")} admin routes only. ${c.req.method} ${c.req.path} changes state and needs ADMIN_TOKEN.`,
		});
	}

	return next();
};

// Constant-time string comparison to prevent timing attacks
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
	const encoder = new TextEncoder();
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);

	// Pad shorter value to match longer length for constant-time comparison
	const maxLen = Math.max(aBytes.length, bBytes.length);
	const aPadded = new Uint8Array(maxLen);
	const bPadded = new Uint8Array(maxLen);
	aPadded.set(aBytes);
	bPadded.set(bBytes);

	// Now compare same-length arrays, then check if original lengths matched
	const bytesEqual = crypto.subtle.timingSafeEqual(aPadded, bPadded);
	const lengthsEqual = aBytes.length === bBytes.length;

	return bytesEqual && lengthsEqual;
}

// Allowed JWT signing algorithms
const ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384"];

async function validateOIDCToken(token: string, env: Env): Promise<OIDCClaims> {
	// Decode JWT header and payload (without verification first)
	const parts = token.split(".");
	if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
		throw new Error("Invalid token format");
	}

	// Parse header and payload with explicit error handling
	let header: { kid: string; alg: string };
	let payload: OIDCClaims;
	try {
		header = JSON.parse(atob(parts[0])) as { kid: string; alg: string };
		payload = JSON.parse(atob(parts[1])) as OIDCClaims;
	} catch {
		throw new Error("Invalid token encoding");
	}

	// Validate algorithm against whitelist
	if (!ALLOWED_ALGORITHMS.includes(header.alg)) {
		throw new Error(`Algorithm not allowed: ${header.alg}`);
	}

	// Validate issuer. Trim to match how /admin/subjects reads the same variable:
	// if only one side trimmed, whitespace after a comma would let an issuer be
	// trusted at create time and refused here, producing exactly the silently
	// dead row that check exists to prevent.
	const allowedIssuers = env.ALLOWED_ISSUERS.split(",").map((issuer) => issuer.trim());
	if (!allowedIssuers.includes(payload.iss)) {
		throw new Error(`Issuer not allowed: ${payload.iss}`);
	}

	// Check timing claims with 60-second clock skew tolerance
	const now = Math.floor(Date.now() / 1000);
	const CLOCK_SKEW_SECONDS = 60;

	// Check not-before (nbf) with skew tolerance
	if (payload.nbf && payload.nbf > now + CLOCK_SKEW_SECONDS) {
		throw new Error("Token not yet valid");
	}

	// Check expiration with skew tolerance
	if (payload.exp < now - CLOCK_SKEW_SECONDS) {
		throw new Error("Token expired");
	}

	// Validate audience (configurable via env, defaults to service name)
	const expectedAudience = env.EXPECTED_AUDIENCE || "gpg-signing-service";
	const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (!audiences.includes(expectedAudience)) {
		throw new Error("Invalid token audience");
	}

	// Fetch JWKS and verify signature. If the cached JWKS doesn't have the
	// required key id, getJWKS will refresh from the network.
	const jwks = await getJWKS(payload.iss, env, header.kid);

	// Pre-flight: make sure a matching key exists and is intended for signatures.
	// This check prevents jose's internal JWKSNoMatchingKey error from escaping
	// as an unhandled rejection (jose's createLocalJWKSet throws synchronously
	// inside its promise chain when no matching key is found).
	const matchingKey = jwks.keys.find((key) => key.kid === header.kid);
	if (!matchingKey) {
		throw new Error("Key not found");
	}
	if (matchingKey.use && matchingKey.use !== "sig") {
		throw new Error("Key not intended for signatures");
	}

	// The `jose.jwtVerify` function handles finding the correct key from the JWKS
	// based on the `kid` in the token header, so manual key lookup is not needed.
	const JWKS = createLocalJWKSet(jwks);

	// Verify JWT signature using jose library
	// Note: jose's createLocalJWKSet can emit unhandled rejections during key lookup
	// when no matching key is found. The error is still caught here and mapped to
	// a user-friendly message, but the internal rejection may escape in test environments.
	try {
		const { payload: verifiedPayload } = await jwtVerify(token, JWKS, {
			issuer: allowedIssuers,
			algorithms: ALLOWED_ALGORITHMS,
			clockTolerance: "60s",
		});
		return verifiedPayload as OIDCClaims;
	} catch (e) {
		const err = e as Error & { code?: string };
		if (err.code === "ERR_JWKS_NO_MATCHING_KEY") {
			throw new Error("Key not found", { cause: e });
		}
		if (err.message?.includes("signature verification failed")) {
			throw new Error("Invalid token signature", { cause: e });
		}
		throw err;
	}
}

// Exported for targeted testing of error mapping logic
export function mapJoseError(err: Error & { code?: string }): never {
	// Map jose error codes/messages to user-friendly, test-specific messages.
	if (err.code === "ERR_JWKS_NO_MATCHING_KEY") {
		throw new Error("Key not found");
	}
	if (err.message?.includes("signature verification failed")) {
		throw new Error("Invalid token signature");
	}
	throw err;
}

async function getJWKS(issuer: string, env: Env, expectedKid?: string): Promise<LegacyJWKSResponse> {
	const cacheKey = `jwks:${issuer}`;

	// Check cache first
	const cached = await env.JWKS_CACHE.get(cacheKey, "json");
	if (cached) {
		const cachedJWKS = cached as LegacyJWKSResponse;
		// If an expected kid is provided and it's not in the cached JWKS, refresh
		// from the origin to pick up key rotations.
		if (expectedKid && !cachedJWKS.keys?.some((k: { kid?: string }) => k.kid === expectedKid)) {
			// fall through to network fetch below
		} else {
			return cachedJWKS;
		}
	}

	// Fetch JWKS from issuer with timeout
	const wellKnownUrl = `${issuer}/.well-known/openid-configuration`;

	// SSRF Protection: Validate wellKnown URL before fetching
	try {
		await validateUrl(wellKnownUrl);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Invalid URL";
		logger.warn("SSRF protection blocked OIDC config URL", {
			issuer,
			url: wellKnownUrl,
			error: message,
		});
		// Not transient, and not the caller's: an issuer in ALLOWED_ISSUERS whose
		// discovery URL this deployment refuses to fetch is a deployment that was
		// configured wrong, and it will answer identically forever.
		throw new IssuerUnavailableError(`SSRF protection: ${message}`, false, { cause: error });
	}

	// Everything from here to the parsed JWKS is "can this deployment reach the
	// issuer", and every way it fails is a 503 rather than a refused credential.
	let configResponse: Response;
	try {
		configResponse = await fetchWithTimeout(wellKnownUrl, {}, 10000);
	} catch (error) {
		// fetchWithTimeout throws on the timeout and on a dead socket alike.
		throw new IssuerUnavailableError(
			`Could not reach the OIDC configuration at ${wellKnownUrl}: ${error instanceof Error ? error.message : String(error)}`,
			true,
			{ cause: error },
		);
	}

	if (!configResponse.ok) {
		throw new IssuerUnavailableError(
			`Failed to fetch OIDC config from ${wellKnownUrl} (status ${configResponse.status})`,
			true,
		);
	}

	let config: { jwks_uri: string };
	try {
		config = (await configResponse.json()) as { jwks_uri: string };
	} catch (error) {
		// A 200 whose body is not the document the issuer is supposed to serve —
		// a captive portal, a proxy's error page under a 200. Still "we could not
		// read the issuer", not "your token is bad".
		throw new IssuerUnavailableError(`OIDC configuration at ${wellKnownUrl} was not readable JSON`, true, {
			cause: error,
		});
	}

	// SSRF Protection: Validate JWKS URI before fetching
	try {
		await validateUrl(config.jwks_uri);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Invalid URL";
		logger.warn("SSRF protection blocked JWKS URI", {
			issuer,
			jwks_uri: config.jwks_uri,
			error: message,
		});
		throw new IssuerUnavailableError(`SSRF protection: ${message}`, false, { cause: error });
	}

	let jwksResponse: Response;
	try {
		jwksResponse = await fetchWithTimeout(config.jwks_uri, {}, 10000);
	} catch (error) {
		throw new IssuerUnavailableError(
			`Could not reach the JWKS at ${config.jwks_uri}: ${error instanceof Error ? error.message : String(error)}`,
			true,
			{ cause: error },
		);
	}

	if (!jwksResponse.ok) {
		throw new IssuerUnavailableError(
			`Failed to fetch JWKS from ${config.jwks_uri} (status ${jwksResponse.status})`,
			true,
		);
	}

	let jwks: LegacyJWKSResponse;
	try {
		jwks = (await jwksResponse.json()) as LegacyJWKSResponse;
	} catch (error) {
		throw new IssuerUnavailableError(`JWKS at ${config.jwks_uri} was not readable JSON`, true, { cause: error });
	}

	// Cache for 5 minutes (non-critical, don't fail on cache errors)
	try {
		await env.JWKS_CACHE.put(cacheKey, JSON.stringify(jwks), {
			expirationTtl: CACHE_TTL.JWKS / TIME.SECOND,
		});
	} catch (error) {
		logger.warn("Failed to cache JWKS", {
			error: error instanceof Error ? error.message : String(error),
			issuer,
		});
		// Continue - caching is optimization, not critical path
	}

	return jwks;
}
