/**
 * The outbound half of the GitHub App integration.
 *
 * Two things happen here and nothing else: this deployment proves it *is* the
 * registered App by signing a short JWT with the App's private key, and it
 * trades that proof for an installation token — a credential scoped to one
 * installation and to the permissions that installation granted.
 *
 * Nothing in this module is reachable from the request path yet. The webhook
 * route acknowledges deliveries and acts on none of them, so the only caller is
 * the suite. That is deliberate: the credential exchange is the part that is
 * hard to get right and easy to get wrong quietly, so it lands with tests and
 * without a caller that could act on a webhook before the authorization model
 * for doing so exists.
 *
 * Three properties this module is responsible for:
 *
 * **The destination is pinned.** Every request goes to `api.github.com` and
 * there is no code path that reaches anywhere else. `validateUrl` — the SSRF
 * guard the OIDC path uses — is deliberately *not* called: it exists to sift
 * caller-controlled URLs, and it answers the wrong question here. It would pass
 * `https://api.github.com.evil.example`, pass any public host at all, and its
 * verdict would say nothing about whether the URL under it is the one we meant.
 * `githubApiUrl` asserts the origin instead, which is the property that actually
 * matters when the hostname is a constant.
 *
 * **Secrets do not escape.** The private key, the App JWT and the installation
 * token are never logged, never put in an error message, and never returned in
 * a response body. Errors from here carry an installation id and a status code.
 *
 * **The cache cannot outlive the credential.** GitHub stamps every installation
 * token with an `expires_at`; the KV entry is given a TTL derived from *that*
 * value with a safety margin subtracted, so a cached token is always still valid
 * when it comes back out.
 */

import { signJwt } from "micro509/jose";
import { type ImportRsaKeyInput, importPkcs1Pem, importPkcs8Pem } from "micro509/keys";
import { z } from "zod";
import type { Env } from "#types";
import { TIME } from "#types";
import { PKCS8_PRIVATE_BEGIN, RSA_PRIVATE_BEGIN } from "#utils/armor";
import { fetchWithTimeout } from "#utils/fetch";
import { logger } from "#utils/logger";

/**
 * The only origin this module talks to.
 *
 * A constant rather than a binding: making it configurable would turn a pinned
 * destination back into a caller-influenced one, and GitHub Enterprise Server
 * support is not in scope for a scaffold. When it is, it belongs behind its own
 * validated setting rather than by relaxing this.
 */
export const GITHUB_API_ORIGIN = "https://api.github.com";

/**
 * How long an App JWT is valid.
 *
 * GitHub rejects anything over 10 minutes outright. Nine leaves a minute of
 * headroom so a clock that is slightly fast does not turn every request into a
 * 401 that looks like a bad key.
 */
const APP_JWT_TTL = 9 * TIME.MINUTE;

/**
 * How far `iat` is backdated.
 *
 * GitHub's own guidance, and for a concrete reason: the JWT is validated on
 * their clock, not ours, and a Worker whose clock is a few seconds ahead issues
 * a token that is "not yet valid" on arrival. Costs nothing — `exp` is measured
 * from now, not from `iat`.
 */
const CLOCK_SKEW = 60 * TIME.SECOND;

/**
 * Subtracted from a cached installation token's remaining life.
 *
 * A token that expires while in flight is indistinguishable from a revoked App,
 * and the retry lands on the same cached value. Handing back only tokens with a
 * comfortable margin left means the caller never has to tell those apart.
 */
const INSTALLATION_TOKEN_MARGIN = 5 * TIME.MINUTE;

/**
 * KV's floor for `expirationTtl`. Below it, `put` throws.
 *
 * Reached when a token arrives with under six minutes of life once the margin
 * is taken off, which GitHub does not do today. The token is still returned; it
 * is simply not cached.
 */
const KV_MIN_TTL_SECONDS = 60;

/** How long to wait on GitHub before giving up. */
const GITHUB_TIMEOUT = 10 * TIME.SECOND;

/**
 * A fault in the App integration, distinguishable from a fault in the caller.
 *
 * `misconfigured` separates "this deployment is not set up" — which no retry and
 * no different caller will fix — from "GitHub said no this time". The webhook
 * path maps the first onto `SERVICE_MISCONFIGURED` and answers 500; see the
 * code's own note in `src/schemas/errors.ts` for why that is not a 503.
 */
export class GitHubAppError extends Error {
	readonly misconfigured: boolean;

	constructor(message: string, options: { misconfigured?: boolean; cause?: unknown } = {}) {
		super(message, options.cause === undefined ? undefined : { cause: options.cause });
		this.name = "GitHubAppError";
		this.misconfigured = options.misconfigured ?? false;
	}
}

/** The App identity, once it is known to be completely configured. */
interface AppConfig {
	appId: string;
	privateKey: string;
}

/**
 * Is the GitHub App integration switched on for this deployment?
 *
 * A literal `"true"` and nothing else. Worker vars are strings, so the
 * alternative is deciding what `"1"`, `"yes"` and `"TRUE"` mean — and a flag
 * that gates an inbound webhook is the wrong place to be generous, because
 * every near-miss reads as "off" until it does not. `wrangler.toml` ships the
 * value spelled out.
 */
export function githubAppEnabled(env: Pick<Env, "GITHUB_APP_ENABLED">): boolean {
	return env.GITHUB_APP_ENABLED === "true";
}

/**
 * The App identity, or a `misconfigured` error naming what is missing.
 *
 * Both halves are checked together so an operator who set one of the two gets
 * told about the other in the same breath rather than one deploy later. The
 * message names the *setting*, never any part of its value.
 */
export function requireAppConfig(env: Pick<Env, "GITHUB_APP_ID" | "GITHUB_APP_PRIVATE_KEY">): AppConfig {
	const missing: string[] = [];
	// Empty and unset are the same thing to a Worker: an unset `wrangler secret`
	// and one put with an empty value both arrive as something falsy, and
	// treating `""` as configured would mean signing with a zero-length key.
	const appId = env.GITHUB_APP_ID?.trim();
	const privateKey = env.GITHUB_APP_PRIVATE_KEY?.trim();

	if (!appId) {
		missing.push("GITHUB_APP_ID");
	}
	if (!privateKey) {
		missing.push("GITHUB_APP_PRIVATE_KEY");
	}

	if (!appId || !privateKey) {
		throw new GitHubAppError(`GitHub App integration is enabled but ${missing.join(" and ")} is not set`, {
			misconfigured: true,
		});
	}

	return { appId, privateKey };
}

/**
 * A URL under `api.github.com`, or a throw.
 *
 * The check is on the resulting origin rather than on the input, because the
 * inputs that get this wrong do not look wrong. `//evil.example/x` is a valid
 * relative reference that `new URL` resolves to a different host entirely, and
 * an absolute URL passed here would silently replace the base. Asserting the
 * origin *after* resolution catches both without having to enumerate them.
 *
 * @param path - Absolute path beginning with `/`
 */
export function githubApiUrl(path: string): URL {
	if (!path.startsWith("/") || path.startsWith("//")) {
		throw new GitHubAppError("GitHub API path must be an absolute path on api.github.com");
	}

	const url = new URL(path, GITHUB_API_ORIGIN);

	if (url.origin !== GITHUB_API_ORIGIN) {
		throw new GitHubAppError("GitHub API path resolved off api.github.com");
	}

	return url;
}

/** RS256: RSASSA-PKCS1-v1_5 with SHA-256, the only App JWT algorithm GitHub accepts. */
const RS256_KEY: ImportRsaKeyInput = { kind: "rsa", scheme: "pkcs1-v1_5", hash: "SHA-256" };

/**
 * The App private key as a signing `CryptoKey`, whichever form the operator
 * pasted in.
 *
 * GitHub's "Generate a private key" button downloads a PKCS#1 `BEGIN RSA PRIVATE
 * KEY` PEM; an operator who ran `openssl pkcs8 -topk8 -nocrypt` has PKCS#8.
 * Both import directly. Anything else is named as a misconfiguration, and a
 * failed import never quotes the key back.
 */
async function importAppPrivateKey(pem: string): Promise<CryptoKey> {
	const imported = pem.includes(PKCS8_PRIVATE_BEGIN)
		? await importPkcs8Pem(pem, RS256_KEY)
		: pem.includes(RSA_PRIVATE_BEGIN)
			? await importPkcs1Pem(pem, RS256_KEY)
			: null;

	if (imported === null) {
		throw new GitHubAppError(
			"GITHUB_APP_PRIVATE_KEY is not a PEM private key; expected a `BEGIN RSA PRIVATE KEY` block as downloaded from GitHub, or a `BEGIN PRIVATE KEY` block",
			{ misconfigured: true },
		);
	}
	if (!imported.ok) {
		throw new GitHubAppError("GITHUB_APP_PRIVATE_KEY could not be imported as an RSA private key", {
			misconfigured: true,
			cause: imported.code,
		});
	}

	return imported.value;
}

/**
 * A JWT that proves this deployment holds the App's private key.
 *
 * Exported for the suite, which needs to assert what the claims are without a
 * network. Nothing else should call it: an App JWT authenticates the *App* and
 * can enumerate installations, whereas `getInstallationToken` below hands back
 * the narrower credential that is right for acting on one of them.
 */
export async function mintAppJwt(env: Pick<Env, "GITHUB_APP_ID" | "GITHUB_APP_PRIVATE_KEY">): Promise<string> {
	const { appId, privateKey } = requireAppConfig(env);

	const key = await importAppPrivateKey(privateKey);
	const nowSeconds = Math.floor(Date.now() / TIME.SECOND);

	return signJwt({
		privateKey: key,
		algorithm: "RS256",
		claims: {
			iss: appId,
			iat: nowSeconds - CLOCK_SKEW / TIME.SECOND,
			exp: nowSeconds + APP_JWT_TTL / TIME.SECOND,
		},
	});
}

/**
 * The fields of GitHub's access-token response this service relies on.
 *
 * Parsed rather than cast, because `expires_at` is what the cache TTL is
 * computed from: a response that omitted it, or gave it as something other than
 * a timestamp, would otherwise produce a `NaN` TTL and a `put` that fails at
 * runtime for a reason nowhere near the cause. Unlisted fields — `permissions`,
 * `repository_selection` — are dropped on purpose; nothing reads them yet, and
 * a token response is not somewhere to carry unexamined data around.
 */
const AccessTokenResponseSchema = z.object({
	token: z.string().min(1),
	expires_at: z.iso.datetime({ offset: true }),
});

/** An installation token and when it stops working. */
export interface InstallationToken {
	/** The credential. Never log this. */
	token: string;
	/** ISO 8601, as GitHub stated it. */
	expiresAt: string;
}

/**
 * Where one installation's token is cached.
 *
 * Namespaced under `gh-app:` so it cannot collide with the `jwks:` entries
 * sharing this KV namespace, and keyed by App id as well as installation id so
 * that re-registering the App — which is how an operator responds to a leaked
 * private key — does not serve tokens minted by the App that leaked.
 */
export function installationTokenCacheKey(appId: string, installationId: number): string {
	return `gh-app:${appId}:installation:${installationId}`;
}

/**
 * An installation token, from cache when one is still comfortably valid.
 *
 * @param env - Deployment bindings
 * @param installationId - `installation.id` from a webhook delivery
 * @throws {GitHubAppError} when the App is not configured, the id is not one,
 *   or GitHub refuses. Never carries a token or a key in its message.
 */
export async function getInstallationToken(env: Env, installationId: number): Promise<InstallationToken> {
	// Checked rather than trusted: the id reaches here from a webhook payload,
	// and it is about to be interpolated into a URL path. `githubApiUrl` would
	// catch an origin change but not a `1/../../orgs/x` that stays on the host.
	if (!Number.isSafeInteger(installationId) || installationId <= 0) {
		throw new GitHubAppError("Installation id must be a positive integer");
	}

	const { appId } = requireAppConfig(env);
	const cacheKey = installationTokenCacheKey(appId, installationId);

	const cached = await readCachedToken(env, cacheKey);
	if (cached) {
		return cached;
	}

	const url = githubApiUrl(`/app/installations/${installationId}/access_tokens`);
	const jwt = await mintAppJwt(env);

	let response: Response;
	try {
		response = await fetchWithTimeout(
			url,
			{
				method: "POST",
				headers: {
					Authorization: `Bearer ${jwt}`,
					Accept: "application/vnd.github+json",
					"X-GitHub-Api-Version": "2022-11-28",
					"User-Agent": "gpg-signing-service",
				},
			},
			GITHUB_TIMEOUT,
		);
	} catch (error) {
		// `fetchWithTimeout` puts the URL in its timeout message, which is a
		// constant here, but the cause may be anything the runtime threw. Neither
		// is re-raised verbatim: the JWT was in the request that failed.
		throw new GitHubAppError(`Could not reach GitHub to mint a token for installation ${installationId}`, {
			cause: error,
		});
	}

	if (!response.ok) {
		// The status and nothing else. A 401 body from this endpoint describes the
		// *App credential* that was refused, which is the one thing that must not
		// be quoted back into a log line or an error.
		throw new GitHubAppError(
			`GitHub refused an installation token for installation ${installationId} (HTTP ${response.status})`,
		);
	}

	const parsed = AccessTokenResponseSchema.safeParse(await response.json());
	if (!parsed.success) {
		throw new GitHubAppError(`GitHub returned an unreadable access-token response for installation ${installationId}`);
	}

	const issued: InstallationToken = { token: parsed.data.token, expiresAt: parsed.data.expires_at };
	await cacheToken(env, cacheKey, issued, installationId);

	return issued;
}

/** The cached token for `cacheKey`, if one is stored and still usable. */
async function readCachedToken(env: Env, cacheKey: string): Promise<InstallationToken | null> {
	let cached: unknown;
	try {
		cached = await env.JWKS_CACHE.get(cacheKey, "json");
	} catch (error) {
		// A cache that cannot be read is a slow path, not a failure: fall through
		// and mint. Logged without the key, which names an installation.
		logger.warn("Could not read the installation-token cache", {
			error: error instanceof Error ? error.message : String(error),
		});
		return null;
	}

	if (!cached) {
		return null;
	}

	const parsed = AccessTokenResponseSchema.safeParse(cached);
	if (!parsed.success) {
		return null;
	}

	// KV expiry is the primary control; this is the belt to its braces. An entry
	// written by an older release, or one KV is still serving inside its
	// eventual-consistency window, is discarded rather than used.
	if (Date.parse(parsed.data.expires_at) - Date.now() <= INSTALLATION_TOKEN_MARGIN) {
		return null;
	}

	return { token: parsed.data.token, expiresAt: parsed.data.expires_at };
}

/**
 * Store a token for the remainder of its life, less the safety margin.
 *
 * Failing to cache is not failing: the token in hand is good, and the next call
 * simply mints another. The alternative — propagating a KV error — would turn a
 * degraded cache into a broken integration.
 */
async function cacheToken(
	env: Env,
	cacheKey: string,
	issued: InstallationToken,
	installationId: number,
): Promise<void> {
	const usableMs = Date.parse(issued.expiresAt) - Date.now() - INSTALLATION_TOKEN_MARGIN;
	const ttlSeconds = Math.floor(usableMs / TIME.SECOND);

	if (ttlSeconds < KV_MIN_TTL_SECONDS) {
		return;
	}

	try {
		await env.JWKS_CACHE.put(cacheKey, JSON.stringify({ token: issued.token, expires_at: issued.expiresAt }), {
			expirationTtl: ttlSeconds,
		});
	} catch (error) {
		logger.warn("Could not cache an installation token", {
			installationId,
			error: error instanceof Error ? error.message : String(error),
		});
	}
}
