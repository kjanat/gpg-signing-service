/**
 * The one door between an authorized delivery and a private key.
 *
 * `githubWebhookAuthorize` decides *what a delivery is about*. This module
 * decides the question after it — **what may this delivery make the service
 * sign with** — and it is a separate question because the answer to the first
 * one is not "yes" or "no" but a scope, and only one of those scopes can reach
 * a key at all.
 *
 * ### Why there is a door rather than a field
 *
 * {@link WebhookAuthorization.keyId} is right there on the context, and a
 * handler could read it. The reason to route through {@link requireSigningKey}
 * instead is that the field is nullable in three different situations that a
 * handler would otherwise have to remember to tell apart — a `none`-scope ping,
 * an `installation`-scope event, and a `repository`-scope pair the operator
 * bound no key to — and the tempting shorthand for all three is
 * `authorization.keyId ?? env.KEY_ID`. That single `??` is the whole failure:
 * it turns "this repository was never granted a key" into "this repository
 * signs with the service's default key", silently, for every repository on the
 * allowlist. So the nullable field is not the interface. A function that
 * returns either a key id or a reason is.
 *
 * ### No default, in any direction
 *
 * There is no fall back to `KEY_ID`, no first-key-in-storage, no
 * single-key-so-it-must-be-that-one. `KEY_ID` is the default for the *signing
 * API*, where the caller has already been authenticated by OIDC or a service
 * token and had its own key grant checked; a webhook delivery is a different
 * caller with a different grant, and inheriting the API's default would mean
 * every allowlisted repository silently acquired signing authority the moment it
 * was allowlisted.
 *
 * ### Nothing here reads the payload
 *
 * Not one field. The key comes from the allowlist entry that authorized the
 * delivery, which is a string an operator typed — so a delivery cannot ask for
 * a key, cannot name one, and cannot widen the one it was given by carrying
 * extra JSON. That property is worth stating because it is invisible: the
 * absence of a `payload` parameter on every function below is the mechanism.
 *
 * ### Where key *existence* is established
 *
 * Not here, and not at configuration time. See {@link loadSigningKey}.
 */

import type { AnyStoredKey } from "#schemas/keys";
import { AnyStoredKeySchema } from "#schemas/keys";
import type { Env, KeyId, WebhookAuthorization } from "#types";
import { createKeyId, HTTP, isKeyIdShaped } from "#types";
import { fetchKeyStorage } from "#utils/durable-objects";

/**
 * Why a delivery may not reach a key.
 *
 * Distinct values rather than one null, because they are distinct operator
 * problems and the fix for each is different: a scope refusal means the event
 * was never repository-shaped, an unbound key means the allowlist entry is
 * missing its `=<keyId>` suffix, and a missing key means the entry names a key
 * this deployment does not hold.
 */
export type SigningKeyRefusal =
	/** The delivery is not `repository`-scoped, so there is no pair to bind a key to. */
	| "not_repository_scope"
	/** The pair is allowlisted, and the operator bound no key to it. */
	| "no_key_bound"
	/** The entry binds a key id this deployment does not hold. */
	| "key_missing"
	/** Key storage could not be reached, so nothing is known either way. */
	| "key_storage_unavailable";

/** The key this delivery may use, or the reason it may use none. */
export type SigningKeyDecision = { allowed: true; keyId: KeyId } | { allowed: false; reason: SigningKeyRefusal };

/**
 * Which key may this authorized delivery cause to sign?
 *
 * Pure: no bindings, no network, no payload. Everything it consults came from
 * an allowlist entry an operator wrote, which is the property that makes the
 * answer impossible for a delivery to widen.
 *
 * @param authorization - The decision `githubWebhookAuthorize` reached, or
 *   undefined on a request that never passed it — which is refused rather than
 *   treated as unscoped, so a change to the mounting fails closed
 */
export function requireSigningKey(authorization: WebhookAuthorization | undefined): SigningKeyDecision {
	// `installation` and `none` are refused by the same branch as "no
	// authorization at all", and deliberately: all three mean the delivery names
	// no allowlisted pair, and a pair is the only thing a key is ever bound to.
	if (authorization === undefined || authorization.scope !== "repository") {
		return { allowed: false, reason: "not_repository_scope" };
	}

	if (authorization.keyId === null) {
		return { allowed: false, reason: "no_key_bound" };
	}

	// Re-checked, having already been validated at parse time. Not defensive
	// clutter: `WebhookAuthorization.keyId` is a plain `string | null` on a type
	// that crosses a context boundary, so this is the last point at which the
	// value is provably the one `parseRepositoryAllowlist` produced. It costs a
	// regex on a 16-character string and it is what lets the return type be a
	// branded `KeyId` rather than a cast.
	if (!isKeyIdShaped(authorization.keyId)) {
		return { allowed: false, reason: "no_key_bound" };
	}

	return { allowed: true, keyId: createKeyId(authorization.keyId) };
}

/** The key material this delivery may sign with, or the reason it gets none. */
export type SigningKeyLoad =
	| { allowed: true; keyId: KeyId; key: AnyStoredKey }
	| { allowed: false; reason: SigningKeyRefusal };

/**
 * The stored key this authorized delivery may sign with.
 *
 * ### Why existence is established here and nowhere earlier
 *
 * A key id in the allowlist is a claim about this deployment's storage, and
 * there are three places that claim could be checked. Two of them are wrong:
 *
 * - **At configuration parse time**, on every delivery. The allowlist is parsed
 *   per request, so this would put a `KeyStorage` round trip in front of every
 *   webhook — including the ones that will never sign anything, which today is
 *   all of them — to answer a question that goes stale the moment a key is
 *   deleted. The obvious repair is a cache, and a cache of "this key exists" is
 *   a cache whose stale entries point at a key that is gone.
 * - **As a pre-check before use.** A separate "does it exist" fetch followed by
 *   a "give me the key" fetch is two round trips and a window between them: the
 *   key can be deleted after the check and before the use, so the check
 *   establishes nothing the use does not, and the code that acts on it has to
 *   handle the missing key *again* anyway.
 *
 * So existence is established by **the fetch the signing action has to perform
 * regardless**. There is no separate check, therefore no cache, no staleness
 * and no window: the key either comes back and is signed with, or it does not
 * and the delivery is refused. That is the cleanest safe boundary, and it is
 * the same one `POST /sign` already uses.
 *
 * ### Not called from the request path
 *
 * Nothing on `/github/webhook` calls this, because nothing on that route signs
 * yet — the same reason `getInstallationToken` has no caller there. It is the
 * function the first acting handler calls, and it exists now so that handler
 * inherits the refusals rather than inventing them.
 *
 * The key material is returned and never logged. A refusal carries the key id,
 * which is public — `/public-key` serves the key it names — and nothing else.
 *
 * @param env - Worker bindings, for `KEY_STORAGE`
 * @param authorization - The decision `githubWebhookAuthorize` reached
 */
export async function loadSigningKey(
	env: Env,
	authorization: WebhookAuthorization | undefined,
): Promise<SigningKeyLoad> {
	const decision = requireSigningKey(authorization);
	if (!decision.allowed) {
		return decision;
	}

	let response: Response;
	try {
		response = await fetchKeyStorage(env, `/get-key?keyId=${encodeURIComponent(decision.keyId)}`);
	} catch {
		// Unreachable storage is not a missing key, and the two must not collapse:
		// "the key is gone" is a configuration error an operator fixes, and "the
		// object did not answer" is an outage they wait out. A caller that reads
		// an outage as a missing key sends someone to edit an allowlist that is
		// correct. The thrown value is deliberately not carried out of here — it
		// comes from the object that holds private keys, and the caller has a
		// reason and a key id, which is what it can act on.
		return { allowed: false, reason: "key_storage_unavailable" };
	}

	if (response.status === HTTP.NotFound) {
		return { allowed: false, reason: "key_missing" };
	}

	if (!response.ok) {
		return { allowed: false, reason: "key_storage_unavailable" };
	}

	let key: AnyStoredKey;
	try {
		key = AnyStoredKeySchema.parse(await response.json());
	} catch {
		// Present and unreadable. Reported as unavailable rather than missing for
		// the reason above: the entry names a key that is there, so the allowlist
		// is not what is wrong.
		return { allowed: false, reason: "key_storage_unavailable" };
	}

	return { allowed: true, keyId: decision.keyId, key };
}
