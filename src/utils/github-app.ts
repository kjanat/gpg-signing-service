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

import { importPKCS8, SignJWT } from "jose";
import { z } from "zod";
import type { Env } from "#types";
import { TIME } from "#types";
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

/** PEM label GitHub's downloaded App key carries. */
const PKCS1_LABEL = "RSA PRIVATE KEY";
/** PEM label WebCrypto — and therefore `jose` — can import. */
const PKCS8_LABEL = "PRIVATE KEY";

/**
 * DER for `AlgorithmIdentifier { rsaEncryption, NULL }`, RFC 8017 A.1.
 *
 * `SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }`. Fixed bytes because there is
 * exactly one algorithm a GitHub App key can be: the App registration page
 * issues RSA and nothing else.
 */
const RSA_ENCRYPTION_ALGORITHM_ID = Uint8Array.from([
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
]);

/** DER `INTEGER 0` — `PrivateKeyInfo.version` is always v1. */
const PKCS8_VERSION_ZERO = Uint8Array.from([0x02, 0x01, 0x00]);

/**
 * DER definite-length bytes for `length`.
 *
 * Short form under 128, long form above. A GitHub App key is 2048 bits, so the
 * real inputs land in the two- and three-byte long forms; the short form is
 * here because a length encoder that only handles its expected inputs is how a
 * later reuse produces silently malformed DER.
 */
function derLength(length: number): Uint8Array {
	if (length < 0x80) {
		return Uint8Array.from([length]);
	}

	const bytes: number[] = [];
	for (let remaining = length; remaining > 0; remaining >>>= 8) {
		bytes.unshift(remaining & 0xff);
	}

	return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

/** A DER TLV with the given tag wrapped around `contents`. */
function derWrap(tag: number, contents: Uint8Array): Uint8Array {
	const length = derLength(contents.length);
	const out = new Uint8Array(1 + length.length + contents.length);
	out[0] = tag;
	out.set(length, 1);
	out.set(contents, 1 + length.length);
	return out;
}

/** The base64 body of a PEM block, or null when the label is not present. */
function pemBody(pem: string, label: string): string | null {
	const match = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`).exec(pem);
	return match?.[1]?.replace(/\s+/g, "") ?? null;
}

/** A PEM block, wrapped at 64 columns the way every other producer writes them. */
function toPem(label: string, der: Uint8Array): string {
	let base64 = "";
	for (const byte of der) {
		base64 += String.fromCharCode(byte);
	}
	const body = btoa(base64).replace(/(.{64})/g, "$1\n");
	return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/**
 * The App private key as PKCS#8, whichever form the operator pasted in.
 *
 * This exists because of a mismatch nobody chooses: **GitHub hands you a PKCS#1
 * key** — the "Generate a private key" button downloads a `BEGIN RSA PRIVATE
 * KEY` PEM — and **WebCrypto imports only PKCS#8**. So the obvious thing, which
 * is to `wrangler secret put` the file GitHub gave you, fails at the import with
 * an error that names neither of those facts.
 *
 * The conversion is pure structure: PKCS#1 is the bare `RSAPrivateKey`, and
 * PKCS#8 is that same blob inside a `PrivateKeyInfo` that also names the
 * algorithm. So the key material is copied through untouched and only a header
 * is added; nothing here parses, validates or reads the key, and a corrupt input
 * stays corrupt and fails at the import where it should.
 *
 * An operator who has already run `openssl pkcs8 -topk8 -nocrypt` gets the
 * PKCS#8 branch and none of this runs.
 */
export function toPkcs8Pem(pem: string): string {
	if (pemBody(pem, PKCS8_LABEL) !== null) {
		return pem;
	}

	const pkcs1 = pemBody(pem, PKCS1_LABEL);
	if (pkcs1 === null) {
		throw new GitHubAppError(
			"GITHUB_APP_PRIVATE_KEY is not a PEM private key; expected a `BEGIN RSA PRIVATE KEY` block as downloaded from GitHub, or a `BEGIN PRIVATE KEY` block",
			{ misconfigured: true },
		);
	}

	let der: Uint8Array;
	try {
		const binary = atob(pkcs1);
		der = Uint8Array.from(binary, (character) => character.charCodeAt(0));
	} catch (error) {
		throw new GitHubAppError("GITHUB_APP_PRIVATE_KEY has a PEM header but its body is not valid base64", {
			misconfigured: true,
			cause: error,
		});
	}

	// PrivateKeyInfo ::= SEQUENCE { version, privateKeyAlgorithm, privateKey }
	const info = new Uint8Array([
		...PKCS8_VERSION_ZERO,
		...RSA_ENCRYPTION_ALGORITHM_ID,
		...derWrap(0x04, der), // OCTET STRING wrapping the PKCS#1 body
	]);

	return toPem(PKCS8_LABEL, derWrap(0x30, info));
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

	let key: CryptoKey;
	try {
		key = await importPKCS8(toPkcs8Pem(privateKey), "RS256");
	} catch (error) {
		if (error instanceof GitHubAppError) {
			throw error;
		}
		// The cause is attached for the tail; the message is not, because a failing
		// key import is the one place a library is most likely to quote the input
		// it choked on back at us.
		throw new GitHubAppError("GITHUB_APP_PRIVATE_KEY could not be imported as an RSA private key", {
			misconfigured: true,
			cause: error,
		});
	}

	const nowSeconds = Math.floor(Date.now() / TIME.SECOND);

	return new SignJWT({})
		.setProtectedHeader({ alg: "RS256" })
		.setIssuer(appId)
		.setIssuedAt(nowSeconds - CLOCK_SKEW / TIME.SECOND)
		.setExpirationTime(nowSeconds + APP_JWT_TTL / TIME.SECOND)
		.sign(key);
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
