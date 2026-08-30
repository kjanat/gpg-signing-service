/**
 * Signing-key expiry inspection
 *
 * Two questions, kept apart on purpose.
 *
 * **Which keys count?** Not "every key in storage" — an operator may retain a
 * superseded key deliberately, and warning about that is a false alarm that
 * teaches people to mute the monitor. Not "the `KEY_ID` binding" either — that
 * variable is only the *default* when a caller names no key, and
 * `routes/sign.ts` lets any caller sign with any key its grant permits. The set
 * this module computes is therefore the set the sign path would actually
 * accept: the deployment's own `KEY_ID`, plus every key a **live** grant (a
 * trusted OIDC subject row or a service token) permits, intersected with what
 * the deployment holds. See {@link resolveActiveKeys}.
 *
 * **When does a key lapse?** That is a property of the key material, not a fact
 * anyone should be retyping into a config file: a hand-maintained date is a
 * claim about a key that drifts the moment the key is extended or rotated.
 * Expiry is therefore parsed out of the key itself — the armored PGP key or the
 * X.509 certificate the `KeyStorage` Durable Object holds.
 *
 * This module is deliberately free of I/O. It takes key material, grant rows
 * and an explicit `now`, and returns plain data, so `key-expiry-monitor.ts`
 * owns the bindings and the tests stay deterministic.
 */

import { parseCertificatePemOrThrow } from "micro509";
import * as openpgp from "openpgp";
import { TIME } from "#types/time";

/** Days before expiry at which a key starts being reported, absent an override */
export const DEFAULT_WARN_DAYS = 60;

/** Worker variable that overrides {@link DEFAULT_WARN_DAYS} */
export const WARN_DAYS_VAR = "KEY_EXPIRY_WARN_DAYS";

/**
 * Rotation procedure the report links to.
 *
 * Absolute rather than repo-relative: the report is rendered into an email,
 * where a relative path resolves against nothing at all.
 */
export const KEY_ROTATION_DOCS_URL =
	"https://github.com/kjanat/gpg-signing-service/blob/master/docs/self-hosting.md#key-rotation";

/**
 * Parse the warning threshold.
 *
 * Rejects anything that is not a positive whole number rather than silently
 * falling back to the default: a typo'd threshold that quietly becomes 60 is a
 * check that lies about what it enforced.
 *
 * Deliberately narrower than `Number`, which reads `1e3` as 1000 and `0x3C` as
 * 60. Both are integers and both would pass, so an operator who typed either
 * would get a threshold they did not write — the same silent reinterpretation
 * the explicit rejection exists to prevent. Plain decimal digits only, with
 * surrounding whitespace still tolerated because a `.toml` value can carry it.
 */
export function parseWarnDays(raw: string | undefined): number {
	if (raw === undefined || raw.trim() === "") return DEFAULT_WARN_DAYS;

	const trimmed = raw.trim();
	const value = /^\d+$/.test(trimmed) ? Number(trimmed) : Number.NaN;
	// `isSafeInteger` and not `isInteger`: a digit string past 2^53 parses to a
	// number that is an integer but is no longer the one that was written.
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error(
			`${WARN_DAYS_VAR} must be a positive whole number of days in plain decimal digits, got ${JSON.stringify(raw)}`,
		);
	}

	return value;
}

/** Whole days from `now` until `expiresAt`, floored, negative once lapsed */
export function daysUntil(expiresAt: Date, now: Date): number {
	return Math.floor((expiresAt.getTime() - now.getTime()) / TIME.DAY);
}

// ---------------------------------------------------------------------------
// The deployment's default key
// ---------------------------------------------------------------------------

/**
 * What this deployment signs with when a caller names no key.
 *
 * Read straight off the running Worker's own bindings rather than out of
 * `wrangler.toml`. The file in the repository is what the last deploy *meant*;
 * the binding is what this deployment actually has, and a monitor that reports
 * on a configuration the running service does not share is worse than none.
 */
export interface DeclaredDefaultKey {
	/** The deployment's environment label, or `null` for the top-level one */
	env: string | null;
	/** `KEY_ID`, uppercased, or `null` when this deployment declares none */
	keyId: string | null;
}

// ---------------------------------------------------------------------------
// The grants that decide which keys are reachable
// ---------------------------------------------------------------------------

/** Which credential table a grant came from */
export type GrantKind = "oidc-subject" | "service-token";

/**
 * A credential's signing policy, as the subject and token tables hold it.
 *
 * `keyIds: null` is the load-bearing case: both auth paths read it as *every*
 * key, so one such live grant makes storage the activation boundary after all.
 */
export interface KeyGrant {
	kind: GrantKind;
	name: string;
	/** Key ids this credential may sign with; `null` means every stored key */
	keyIds: string[] | null;
	expiresAt: string | null;
	revokedAt: string | null;
}

/**
 * Can this grant authorize a signature right now?
 *
 * Mirrors the server's own test rather than re-deriving one, so the monitored
 * set cannot claim a key the sign path would refuse — or drop one it would
 * still sign with. Both paths agree on a revoked row and on the boundary
 * instant (`expiresAt === now` is still live), and they are written the same
 * way up to that point.
 *
 * They part on an `expiresAt` that does not parse, so the rule is applied per
 * grant kind rather than picked. `verifyServiceToken` refuses only on
 * `Date.parse(expires_at) < Date.now()`, and `NaN < now` is false, so it
 * honours the row. `resolveOIDCSubject` requires `Date.parse(expires_at) >=
 * now`, and `NaN >= now` is *also* false, so it refuses the row. One condition
 * cannot mirror both: reading the service-token rule for a subject would put a
 * key in the report that nothing can sign with, and reading the subject rule
 * for a token would drop one that still signs.
 *
 * Defensive either way — `expires_at` is written server-side from
 * `expiresInDays`, so a row that does not parse is a corrupted one — but the
 * whole premise of this module is that it does not guess at the sign path.
 */
export function isGrantLive(grant: KeyGrant, now: Date): boolean {
	if (grant.revokedAt) return false;
	if (!grant.expiresAt) return true;

	const expiresAt = Date.parse(grant.expiresAt);
	return grant.kind === "oidc-subject" ? expiresAt >= now.getTime() : !(expiresAt < now.getTime());
}

/** Why a key is in the monitored set */
export type ActivationReason =
	/** It is this deployment's `KEY_ID` */
	| "default"
	/** A live grant names it explicitly */
	| "grant"
	/** A live grant pins no key ids, so it reaches every stored key */
	| "unrestricted-grant";

/** One key this deployment can currently sign with */
export interface ActiveKey {
	keyId: string;
	/** Sorted, deduplicated reasons this key counts as active */
	reasons: ActivationReason[];
	/** Live credentials that reach it, `kind:name`, sorted */
	grants: string[];
	/**
	 * The subset of {@link grants} that pins no key ids, so reaches this key
	 * only because it reaches every stored key.
	 *
	 * Kept apart from the scoped ones because the report has to tell them
	 * apart per row: a grant is scoped or unscoped as a property of the grant,
	 * not of the key, so the same credential can be the reason one key is
	 * narrowly reachable and another is reachable at all.
	 */
	anyKeyGrants: string[];
	/** Whether the deployment actually holds it */
	stored: boolean;
}

/** The monitored set, with everything needed to justify it in the report */
export interface ActiveKeySet {
	/** Keys to check, sorted by key id */
	keys: ActiveKey[];
	/** Stored keys no live grant reaches: retained, unreachable, not monitored */
	retainedInactive: string[];
	/** Live grants that pin no key ids, `kind:name`, sorted */
	unrestrictedGrants: string[];
	/** How many grants were live at `now`, of any scope */
	liveGrantCount: number;
	/** How many grants were read in total, live or not */
	totalGrantCount: number;
	/** This deployment's declared default, echoed for the report */
	defaultKey: DeclaredDefaultKey;
}

/** Uppercase a key id so grants, storage and config compare as one namespace */
function normalizeKeyId(keyId: string): string {
	return keyId.trim().toUpperCase();
}

/**
 * Compute the keys this deployment can sign with right now.
 *
 * The rule, in the order the sign path applies it:
 *
 * 1. A caller may name any key (`?keyId=`), defaulting to the deployment's
 *    `KEY_ID` — so the default is always in the set, and is reported `missing`
 *    when the deployment does not hold it.
 * 2. A grant with an explicit allowlist admits exactly those key ids. One that
 *    names a key the deployment lacks is a broken grant, and is reported the
 *    same way.
 * 3. A grant with no allowlist admits every *stored* key. This is the only case
 *    in which storage is the activation boundary, and it is detected rather
 *    than assumed.
 * 4. Everything else in storage is retained but unreachable, and is left out of
 *    the report entirely rather than warned about.
 *
 * Dead grants are excluded by {@link isGrantLive}, so revoking or expiring the
 * last credential that reached a key drops it from the monitored set on the
 * next run, with no second list to remember to prune.
 */
export function resolveActiveKeys(input: {
	storedKeyIds: readonly string[];
	defaultKey: DeclaredDefaultKey;
	grants: readonly KeyGrant[];
	now: Date;
}): ActiveKeySet {
	const stored = new Set(input.storedKeyIds.map(normalizeKeyId));
	const live = input.grants.filter((grant) => isGrantLive(grant, input.now));
	const unrestricted = live.filter((grant) => grant.keyIds === null);

	const active = new Map<string, { reasons: Set<ActivationReason>; grants: Set<string>; anyKeyGrants: Set<string> }>();
	const entryFor = (keyId: string) => {
		let entry = active.get(keyId);
		if (!entry) {
			entry = { reasons: new Set(), grants: new Set(), anyKeyGrants: new Set() };
			active.set(keyId, entry);
		}
		return entry;
	};
	const label = (grant: KeyGrant) => `${grant.kind}:${grant.name}`;

	// An unrestricted grant reaches every key the deployment *holds* — and only
	// those, since `?keyId=` on a key that was never uploaded is a 404, not a
	// signature. So this widens over storage, never over the grant lists.
	for (const grant of unrestricted) {
		for (const keyId of stored) {
			const entry = entryFor(keyId);
			entry.reasons.add("unrestricted-grant");
			entry.grants.add(label(grant));
			entry.anyKeyGrants.add(label(grant));
		}
	}

	for (const grant of live) {
		for (const keyId of grant.keyIds ?? []) {
			const entry = entryFor(normalizeKeyId(keyId));
			entry.reasons.add("grant");
			entry.grants.add(label(grant));
		}
	}

	// Last, so the default is in the set even on a deployment that has no live
	// grant at all: it is what this deployment is configured to sign with, and
	// its lapsing is news the moment anyone is trusted again.
	if (input.defaultKey.keyId) {
		entryFor(input.defaultKey.keyId).reasons.add("default");
	}

	const keys = [...active.entries()]
		.map(([keyId, entry]) => ({
			keyId,
			reasons: [...entry.reasons].sort(),
			grants: [...entry.grants].sort(),
			anyKeyGrants: [...entry.anyKeyGrants].sort(),
			stored: stored.has(keyId),
		}))
		.sort((a, b) => a.keyId.localeCompare(b.keyId));

	return {
		keys,
		retainedInactive: [...stored].filter((keyId) => !active.has(keyId)).sort(),
		unrestrictedGrants: unrestricted.map(label).sort(),
		liveGrantCount: live.length,
		totalGrantCount: input.grants.length,
		defaultKey: input.defaultKey,
	};
}

// ---------------------------------------------------------------------------
// Expiry, read out of the key material
// ---------------------------------------------------------------------------

/**
 * Outcome of inspecting one key.
 *
 * `missing` is not an expiry state as such — it marks a key this deployment is
 * configured or authorized to sign with but does not hold, which is the same
 * kind of "signing is about to break" news as an expiry and belongs in the same
 * report.
 */
export type KeyExpiryState = "ok" | "warning" | "expired" | "revoked" | "no-expiry" | "unknown" | "missing";

/** States that mean a human has to do something */
const ACTIONABLE_STATES: ReadonlySet<KeyExpiryState> = new Set<KeyExpiryState>([
	"warning",
	"expired",
	"revoked",
	"unknown",
	"missing",
]);

/** Expiry as read out of key material */
export type KeyExpiry =
	| { kind: "date"; expiresAt: Date }
	/** The key carries no expiration date and never lapses */
	| { kind: "never" }
	/**
	 * The key is revoked, or every subkey it could sign with is. Revocation is
	 * not expiry, but it stops verifiers accepting the signature just as
	 * completely, and an unexpired revoked key would otherwise be reported as
	 * healthy. `detail` names the revoked subkeys when the primary key itself is
	 * intact, because those two need different fixes.
	 */
	| { kind: "revoked"; detail?: string }
	/** The key material parsed but its expiry could not be established */
	| { kind: "unknown"; reason: string };

/** One row of the expiry report */
export interface KeyExpiryRow {
	keyId: string;
	state: KeyExpiryState;
	/** ISO-8601 expiry, or `null` when there is no date to show */
	expiresAt: string | null;
	/** Whole days from `now` until expiry; negative once lapsed */
	daysRemaining: number | null;
	/** Why the state is `unknown` or `missing`, for the report */
	detail?: string;
}

/**
 * Effective expiry of an armored PGP key.
 *
 * A commit is signed by the key's signing subkey, not by its primary key, so
 * the question this answers is about the subkeys — with the primary key's own
 * lifetime as a cap, since nothing outlives the key that certifies it.
 *
 * Asking openpgp for `getSigningKey()` and reading that one key's expiry is not
 * enough, and the failure is silent in the worst direction. That call returns
 * the *first acceptable* key: it skips a revoked subkey and falls back to the
 * next one, or to the primary key, which openpgp's own generator always marks
 * signing-capable. A deployment whose only signing subkey has been revoked
 * therefore reports its primary key's distant expiry and reads as `ok`, which
 * is precisely the state a revocation monitor exists to catch (#90).
 *
 * So the signing-capable subkeys are enumerated explicitly and reduced by
 * {@link signingSubkeyExpiry}. Every check runs with `date: null` to switch off
 * openpgp's validity filtering — an already-expired signing subkey still has to
 * reach the report, and the default lookup would refuse to return it.
 */
export async function pgpKeyExpiry(armoredKey: string): Promise<KeyExpiry> {
	let key: openpgp.Key;
	try {
		key = await openpgp.readKey({ armoredKey });
	} catch (error) {
		return { kind: "unknown", reason: `could not read PGP key: ${String(error)}` };
	}

	// `getExpirationTime()` reads the self-signature's expiration subpacket and
	// says nothing about revocation, so a revoked key that has not yet reached
	// its expiry date would otherwise be reported as `ok`. Checked first: a
	// revoked primary key takes every subkey down with it, so which subkey would
	// have signed stops mattering.
	if (await key.isRevoked()) return { kind: "revoked" };

	return signingSubkeyExpiry(
		await key.getExpirationTime(),
		await collectSigningSubkeys(key),
		await canSign(key, key.getKeyID()),
	);
}

/** What openpgp's `getExpirationTime()` can hand back */
export type OpenPgpExpiration = Date | typeof Infinity | null;

/**
 * One signing-capable subkey, reduced to what the verdict depends on.
 *
 * `revoked` and `usable` are separate because they need different words in the
 * report: a revoked subkey is a decision someone made, while a subkey openpgp
 * declines for any other reason — a broken binding, a missing embedded
 * cross-signature — is material that never worked. `revoked` implies `!usable`.
 */
export interface SigningSubkey {
	/** Long key id, lowercase hex, so the report can name the subkey at fault */
	keyId: string;
	/** A verified revocation signature covers this subkey */
	revoked: boolean;
	/** openpgp would select it for signing, with date checks switched off */
	usable: boolean;
	/** Its own expiration, before the primary key's lifetime caps it */
	expiresAt: OpenPgpExpiration;
}

/**
 * Reduce a primary key and its signing subkeys to one verdict.
 *
 * The rule is about the *usable* set, not about history. Revoking a subkey is
 * routine key hygiene — it is what rotation looks like — so "some signing
 * subkey was once revoked" is not news and a monitor that says it is gets
 * muted. What is news is that nothing is left to sign with:
 *
 * 1. **No signing subkey at all.** Either the primary key signs directly — the
 *    shape openpgp's generator produces unless a signing subkey is asked for,
 *    and then its own expiry is the whole answer — or it does not, and nothing
 *    on this key can sign. The standard offline layout is a certify-only
 *    primary, so `primarySigns` is not a formality: reading the primary's
 *    expiry there reports a comfortable date for a key that cannot produce a
 *    signature at all.
 * 2. **At least one usable signing subkey.** Signing works, and keeps working
 *    until the last of them lapses — so the *latest* usable expiry is the date
 *    signing breaks, capped by the primary key's. Taking the earliest instead
 *    would warn about an outage that a valid replacement subkey already
 *    prevents, which is the false positive that trains people to ignore this.
 * 3. **None usable.** Signing is already broken. Reported as revoked when a
 *    revocation is why, and as unknown when the subkeys are unusable for some
 *    other reason, because those two need opposite fixes.
 *
 * Note what case 3 deliberately does *not* do: fall back to the primary key.
 * openpgp would, whenever the primary carries the sign flag, and the resulting
 * signature is made by different key material than the operator configured —
 * a change worth hearing about, not one worth laundering into an `ok` row.
 *
 * Split out as a pure function for the same reason as {@link effectiveExpiry}:
 * the sets that matter here are awkward to conjure out of real key material,
 * and a rule this consequential should be assertable directly.
 */
export function signingSubkeyExpiry(
	primary: OpenPgpExpiration,
	signingSubkeys: readonly SigningSubkey[],
	primarySigns: boolean,
): KeyExpiry {
	if (primary === null) {
		return { kind: "unknown", reason: "PGP primary key has no valid self-certification (malformed)" };
	}

	if (signingSubkeys.length === 0) {
		if (!primarySigns) {
			return {
				kind: "unknown",
				reason: "no signing key: no signing subkey is bound and the primary key may not sign data",
			};
		}
		return effectiveExpiry(primary, primary);
	}

	const usable = signingSubkeys.filter((subkey) => subkey.usable);
	if (usable.length === 0) return noUsableSigningSubkey(signingSubkeys);

	// A subkey whose binding yields no verdict (`null`) is treated as lasting as
	// long as the primary key: openpgp accepted it for signing, so the report
	// should not invent an outage the key material does not claim.
	let latest = usable[0]?.expiresAt ?? primary;
	for (const subkey of usable.slice(1)) latest = later(latest, subkey.expiresAt ?? primary);

	return effectiveExpiry(primary, latest);
}

/** Verdict for a key whose every signing subkey is unusable */
function noUsableSigningSubkey(signingSubkeys: readonly SigningSubkey[]): KeyExpiry {
	const revoked = signingSubkeys.filter((subkey) => subkey.revoked).map((subkey) => subkey.keyId);
	const listed = (keyIds: readonly string[]) => keyIds.join(", ");

	// Revocation wins the wording even when other subkeys failed for other
	// reasons: it is the one cause that names a decision someone can undo or
	// replace, and it is what the operator needs to read first.
	if (revoked.length > 0) {
		return {
			kind: "revoked",
			detail: `no usable signing subkey — ${plural(revoked.length, "signing subkey")} revoked (${listed(revoked)})`,
		};
	}

	return {
		kind: "unknown",
		reason: `no usable signing subkey: openpgp will not sign with ${listed(signingSubkeys.map((s) => s.keyId))}`,
	};
}

/**
 * openpgp's key flag for "may sign data", which is what makes a subkey part of
 * the signing set rather than an encryption or authentication subkey.
 */
const SIGN_DATA_FLAG = openpgp.enums.keyFlags.signData;

/**
 * openpgp's typings accept `date: null` — "ignore dates" — only on
 * `getSigningKey`, but the implementation honours it on `Subkey` too, and this
 * module depends on that: an expired signing subkey has to stay visible instead
 * of vanishing from the set it is supposed to be reported in. Narrowed once
 * here rather than cast at each call site.
 */
interface DatelessSubkey {
	isRevoked(signature?: undefined, key?: undefined, date?: Date | null): Promise<boolean>;
	getExpirationTime(date?: Date | null): Promise<OpenPgpExpiration>;
}

/** Enumerate the signing-capable subkeys and how the sign path sees each one */
async function collectSigningSubkeys(key: openpgp.Key): Promise<SigningSubkey[]> {
	const signingSubkeys: SigningSubkey[] = [];

	for (const subkey of key.getSubkeys()) {
		const dateless = subkey as unknown as DatelessSubkey;
		const revoked = await dateless.isRevoked(undefined, undefined, null).catch(() => false);
		// openpgp's own selection rules decide usability, pinned to this one subkey
		// so the answer cannot come from a different key: pinning stops the
		// fallback that made a revoked subkey invisible in the first place.
		//
		// The `!revoked` guard is belt-and-braces rather than load-bearing —
		// `getSigningKey` pinned to a revoked subkey refuses it on its own, and
		// mutating this line to drop the guard kills no test. It is kept because
		// the guard is free and the alternative is depending on openpgp keeping
		// that behaviour, which is the dependency #90 was caused by.
		const usable = !revoked && (await canSign(key, subkey.getKeyID()));

		// Membership is the union of "openpgp will sign with it" and "its binding
		// says it may sign", and the first half is not redundant: a subkey openpgp
		// selects is in the signing set by definition, whatever this module would
		// have concluded on its own. Only the subkeys openpgp refuses need a
		// verdict derived here, and dropping one of those is what turns a broken
		// signing path back into a healthy-looking primary-key date.
		if (!usable && !(await bindsSigningCapability(key, subkey))) continue;

		signingSubkeys.push({
			keyId: subkey.getKeyID().toHex(),
			revoked,
			usable,
			expiresAt: await dateless.getExpirationTime(null),
		});
	}

	return signingSubkeys;
}

/** Would openpgp sign with exactly this (sub)key, dates aside? */
async function canSign(key: openpgp.Key, keyId: openpgp.KeyID): Promise<boolean> {
	try {
		await key.getSigningKey(keyId, null);
		return true;
	} catch {
		return false;
	}
}

/**
 * Algorithms openpgp will accept a data signature from.
 *
 * An allow-list rather than a deny-list of the encryption algorithms, mirroring
 * `isValidSigningKeyPacket`'s own `switch`: openpgp returns `false` for every
 * algorithm it does not name, so an ECDH or X25519 subkey is outside the
 * signing set no matter what its binding claims. Without this, a binding that
 * carries no key flags at all — which the rule below reads as "unrestricted" —
 * would sweep every encryption subkey into the report as broken signing
 * material.
 */
const SIGNATURE_CAPABLE_ALGORITHMS: ReadonlySet<string> = new Set([
	"rsaEncryptSign",
	"rsaSign",
	"dsa",
	"ecdsa",
	"eddsaLegacy",
	"ed25519",
	"ed448",
]);

/**
 * Does this subkey's binding say it may sign?
 *
 * Two rules, both openpgp's rather than this module's, because getting either
 * wrong moves a subkey into or out of the set whose emptiness decides whether
 * the primary key's expiry is reported instead.
 *
 * **The binding must verify.** `readKey` does not check binding signatures — it
 * appends every `subkeyBinding` packet it parses to `Subkey.bindingSignatures`
 * and leaves verification to whoever asks a question later. So the newest entry
 * in that array is not a statement the key's owner made: anyone can append a
 * packet to an armored key, and a merge with an unrelated key leaves one behind
 * without anybody trying. Reading key flags off the newest *raw* entry let a
 * spliced binding carrying `keyFlags [12]` drop a live signing subkey out of the
 * set entirely — and with it the revocation check this module exists for. Only
 * bindings that verify against this primary key are considered, which is what
 * `getLatestValidSignature` does before openpgp reads the same field.
 *
 * **The newest verified binding decides, not any of them.** A subkey re-bound
 * without the sign flag has left the signing set, and reading every binding
 * would keep it there forever — and keep its revocation raising alarms about a
 * signing path that no longer exists.
 *
 * A verified binding with no key flags at all counts as signing-capable, again
 * matching `isValidSigningKeyPacket`: absent flags are unrestricted. openpgp
 * still declines to sign with it unless `allowMissingKeyFlags` is set, so such a
 * subkey lands in the report as unusable — which is the honest answer, since
 * signing through it does not work.
 */
async function bindsSigningCapability(key: openpgp.Key, subkey: openpgp.Subkey): Promise<boolean> {
	if (!SIGNATURE_CAPABLE_ALGORITHMS.has(subkey.getAlgorithmInfo().algorithm)) return false;

	const binding = await newestVerifiedBinding(key, subkey);
	if (binding === undefined) return false;

	return !binding.keyFlags || ((binding.keyFlags[0] ?? 0) & SIGN_DATA_FLAG) !== 0;
}

/**
 * openpgp's typings date `SignaturePacket.verify` with a `Date`, but the
 * implementation runs its creation-time and expiry checks through
 * `util.normalizeDate`, which maps `null` to "no date to compare against" and
 * skips both — leaving the issuer and cryptographic checks, which is exactly
 * the question here. `getSigningKey(…, null)` reaches the same call the same
 * way, so this is the documented `date: null` contract, not a new dependency.
 */
interface DatelessSignature {
	verify(
		key: openpgp.PublicKey["keyPacket"],
		signatureType: openpgp.enums.signature,
		data: { key: openpgp.PublicKey["keyPacket"]; bind: openpgp.Subkey["keyPacket"] },
		date?: Date | null,
	): Promise<boolean>;
}

/**
 * Newest subkey binding signature that actually verifies against the primary
 * key, mirroring openpgp's `getLatestValidSignature`.
 *
 * A binding that fails to verify is not weaker evidence, it is none: it was not
 * issued by this primary key (`SignaturePacket.verify` checks the issuer key id
 * first), or it does not hash to its own signature. Such a packet is discarded
 * rather than allowed to outrank a real one by having a later `created`.
 */
async function newestVerifiedBinding(
	key: openpgp.Key,
	subkey: openpgp.Subkey,
): Promise<openpgp.SignaturePacket | undefined> {
	const primaryKeyPacket = key.keyPacket;
	const dataToVerify = { key: primaryKeyPacket, bind: subkey.keyPacket };
	const createdAt = (signature: openpgp.SignaturePacket) => signature.created?.getTime() ?? 0;

	let newest: openpgp.SignaturePacket | undefined;
	for (const binding of subkey.bindingSignatures) {
		if (newest !== undefined && createdAt(binding) < createdAt(newest)) continue;

		try {
			await (binding as unknown as DatelessSignature).verify(
				primaryKeyPacket,
				openpgp.enums.signature.subkeyBinding,
				dataToVerify,
				null,
			);
			newest = binding;
		} catch {
			// Unverifiable, so it says nothing about this subkey either way.
		}
	}

	return newest;
}

/**
 * Reduce a primary key's and its signing key's expirations to one verdict.
 *
 * Split out from {@link signingSubkeyExpiry} because openpgp's `null` — no
 * valid self-certification, so the key is malformed — cannot be produced by any
 * key it will also read back, and a rule this consequential should be asserted
 * directly rather than left to a case no fixture can reach. Revocation is
 * handled before this point, by {@link pgpKeyExpiry} and
 * {@link signingSubkeyExpiry}.
 */
export function effectiveExpiry(primary: OpenPgpExpiration, signing: OpenPgpExpiration): KeyExpiry {
	if (primary === null) {
		return { kind: "unknown", reason: "PGP primary key has no valid self-certification (malformed)" };
	}

	const effective = earlier(primary, signing ?? primary);

	return neverExpires(effective) ? { kind: "never" } : { kind: "date", expiresAt: effective };
}

/** Expiry of a PEM X.509 certificate, taken from its `notAfter` */
export function x509CertificateExpiry(certificatePem: string): KeyExpiry {
	try {
		return { kind: "date", expiresAt: parseCertificatePemOrThrow(certificatePem).notAfter };
	} catch (error) {
		return { kind: "unknown", reason: `could not parse X.509 certificate: ${String(error)}` };
	}
}

/**
 * Read the expiry out of whatever key material storage holds.
 *
 * The `KeyStorage` Durable Object holds armored PGP private keys for PGP keys
 * and a PEM certificate for X.509 ones, so the material is dispatched on its
 * armor header rather than on a caller-supplied type. Public PGP blocks are
 * accepted too: everything read here — expirations, revocations, binding
 * signatures — lives in the public half, so either armor answers the question,
 * and accepting both keeps this usable against a key served by `/public-key`.
 */
export function keyMaterialExpiry(material: string): Promise<KeyExpiry> | KeyExpiry {
	if (
		material.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----") ||
		material.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")
	) {
		return pgpKeyExpiry(material);
	}
	if (material.includes("-----BEGIN CERTIFICATE-----")) {
		return x509CertificateExpiry(material);
	}

	return { kind: "unknown", reason: "key material was neither a PGP key block nor a PEM certificate" };
}

/** Turn an expiry into a report row, relative to `now` and the threshold */
export function classifyExpiry(keyId: string, expiry: KeyExpiry, now: Date, warnDays: number): KeyExpiryRow {
	if (expiry.kind === "never") {
		return { keyId, state: "no-expiry", expiresAt: null, daysRemaining: null };
	}
	if (expiry.kind === "revoked") {
		return { keyId, state: "revoked", expiresAt: null, daysRemaining: null, detail: expiry.detail ?? "key is revoked" };
	}
	if (expiry.kind === "unknown") {
		return { keyId, state: "unknown", expiresAt: null, daysRemaining: null, detail: expiry.reason };
	}

	const expiresAt = expiry.expiresAt.toISOString();
	const daysRemaining = daysUntil(expiry.expiresAt, now);

	if (expiry.expiresAt.getTime() <= now.getTime()) {
		return { keyId, state: "expired", expiresAt, daysRemaining };
	}

	// Inclusive: a key exactly `warnDays` out is already inside the window.
	return { keyId, state: daysRemaining <= warnDays ? "warning" : "ok", expiresAt, daysRemaining };
}

/**
 * A key this deployment would sign with but does not hold.
 *
 * The detail names *why* it was expected, because the two causes need opposite
 * fixes: a `KEY_ID` pointing at nothing is a deployment that never received its
 * key, while a grant naming nothing is a credential that outlived the key it
 * was scoped to.
 */
export function missingKeyRow(key: ActiveKey): KeyExpiryRow {
	const causes: string[] = [];
	if (key.reasons.includes("default")) causes.push("this deployment's KEY_ID");
	if (key.reasons.includes("grant")) causes.push(`granted to ${key.grants.join(", ")}`);

	return {
		keyId: key.keyId,
		state: "missing",
		expiresAt: null,
		daysRemaining: null,
		detail: `${causes.join("; ") || "expected"}, but the deployment does not hold it`,
	};
}

/** Rows that need a human: anything expiring soon, lapsed, unreadable or absent */
export function actionableRows(rows: readonly KeyExpiryRow[]): KeyExpiryRow[] {
	return rows.filter((row) => ACTIONABLE_STATES.has(row.state));
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const STATE_LABELS: Record<KeyExpiryState, string> = {
	ok: "ok",
	warning: "EXPIRING",
	expired: "EXPIRED",
	revoked: "REVOKED",
	"no-expiry": "no expiry",
	unknown: "UNKNOWN",
	missing: "MISSING",
};

/** `n` with a unit, pluralised, so no report ever reads `1 days` */
function plural(count: number, unit: string): string {
	return `${count} ${unit}${count === 1 ? "" : "s"}`;
}

/** Human-readable one-liner for a row's remaining lifetime */
function describeRemaining(row: KeyExpiryRow): string {
	if (row.daysRemaining === null) return "—";
	if (row.daysRemaining < 0) return `${plural(Math.abs(row.daysRemaining), "day")} ago`;
	return plural(row.daysRemaining, "day");
}

/** At most two names, then a count, so one broad grant cannot flood the table */
function summarizeGrants(grants: readonly string[]): string {
	const shown = grants.slice(0, 2);
	const rest = grants.length - shown.length;
	return rest > 0 ? `${shown.join(", ")} +${rest} more` : shown.join(", ");
}

/**
 * Why this key is being watched, for the report's own column.
 *
 * Stated per key rather than once at the top because the answer differs per
 * key, and it is the difference that is actionable: a key held only by an
 * unrestricted grant is one scoped grant away from leaving the report.
 *
 * The two kinds of grant are rendered separately, and both are rendered when a
 * key has both. Collapsing them the other way — showing only the scoped list
 * once any scoped grant exists — printed an any-key grant's name under
 * "granted to", so the same credential was described as scoped on one row and
 * unscoped on the next, and the column stopped answering the question it
 * exists to answer.
 */
export function describeActivation(key: ActiveKey): string {
	const parts: string[] = [];
	if (key.reasons.includes("default")) parts.push("KEY_ID default");

	const scoped = key.grants.filter((grant) => !key.anyKeyGrants.includes(grant));
	if (scoped.length > 0) parts.push(`granted to ${summarizeGrants(scoped)}`);
	if (key.anyKeyGrants.length > 0) parts.push(`any-key grant ${summarizeGrants(key.anyKeyGrants)}`);

	return parts.join("; ") || "—";
}

/** Report context, kept explicit so the rendered report is reproducible */
export interface ReportContext {
	warnDays: number;
	now: Date;
	/** Which deployment this is, for a reader holding two identical emails */
	service: string;
	/** The resolved monitored set, which the report has to be able to justify */
	scope: ActiveKeySet;
}

/**
 * One piece of the report, before it is committed to a wire format.
 *
 * The report is read as plain text by whoever's mail client refuses HTML and as
 * HTML by everyone else, and both have to say the same thing. Building the
 * structure once and rendering it twice is how that stays true — writing the
 * paragraphs out in two formats is how the two quietly drift, and a monitor
 * whose two bodies disagree is a monitor nobody can quote.
 *
 * Cells and items are plain text: no inline markup crosses this boundary, so
 * each renderer owns its own escaping and emphasis and neither has to parse the
 * other's.
 */
export type ReportBlock =
	| { kind: "heading"; text: string }
	| { kind: "paragraph"; text: string }
	| { kind: "table"; headers: readonly string[]; rows: readonly (readonly string[])[] }
	| { kind: "list"; items: readonly string[] }
	| { kind: "link"; text: string; href: string };

/** A rendered report, ready to hand to the mail boundary */
export interface ReportDocument {
	/** Subject line: the whole verdict, for someone who reads only the inbox */
	subject: string;
	/** `text/plain` body */
	text: string;
	/** `text/html` body */
	html: string;
}

/**
 * Subject line for a run.
 *
 * Names the single affected key when there is exactly one, because that is the
 * common case and it makes the inbox row self-contained: an operator who sees
 * "62E75E54497815DD expires in 42 days" does not have to open anything to know
 * whether it is the production key.
 */
export function reportSubject(rows: readonly KeyExpiryRow[], context: ReportContext): string {
	const actionable = actionableRows([...rows].sort(compareBySeverity));
	const prefix = `[${context.service}]`;

	if (actionable.length === 0) {
		return rows.length === 0
			? `${prefix} No signing key was checked`
			: `${prefix} ${plural(rows.length, "signing key")} healthy`;
	}

	const worst = actionable[0];
	if (actionable.length === 1 && worst) {
		const remaining = worst.state === "warning" ? ` in ${describeRemaining(worst)}` : "";
		return `${prefix} Signing key ${worst.keyId} ${STATE_LABELS[worst.state].toLowerCase()}${remaining}`;
	}

	return `${prefix} ${plural(actionable.length, "signing key")} need attention`;
}

/** Build the report's blocks, in reading order, worst news first */
export function reportBlocks(rows: readonly KeyExpiryRow[], context: ReportContext): ReportBlock[] {
	const sorted = [...rows].sort(compareBySeverity);
	const actionable = actionableRows(sorted);
	const activations = new Map(context.scope.keys.map((key) => [key.keyId, describeActivation(key)]));

	const blocks: ReportBlock[] = [
		{ kind: "heading", text: "Signing key expiry" },
		{
			kind: "paragraph",
			text:
				`Monitored ${plural(sorted.length, "active signing key")} on ${context.service} ` +
				`at ${context.now.toISOString()}, warning ${plural(context.warnDays, "day")} ahead of expiry.`,
		},
	];

	if (sorted.length > 0) {
		blocks.push({
			kind: "table",
			headers: ["Key ID", "Status", "Expires", "Remaining", "Active because"],
			rows: sorted.map((row) => [
				row.keyId,
				STATE_LABELS[row.state],
				row.expiresAt ?? "—",
				describeRemaining(row),
				activations.get(row.keyId) ?? "—",
			]),
		});
	}

	if (sorted.length === 0) {
		// "Nothing expiring" and "nothing checked" are opposite pieces of news and
		// must not render the same. A run that resolved no active key at all has
		// verified nothing, so saying every key is clear would be a green light
		// earned by an empty set.
		blocks.push({
			kind: "paragraph",
			text:
				"No key was checked. This deployment resolved no active signing key, so nothing about " +
				"expiry was verified — see the scope note below for why the set came out empty. Until " +
				"that is fixed this monitor reports on nothing: set KEY_ID on the deployment, or grant a " +
				"stored key to a live trusted subject or service token.",
		});
	} else if (actionable.length === 0) {
		blocks.push({
			kind: "paragraph",
			text: `No active signing key expires within ${plural(context.warnDays, "day")}.`,
		});
	} else {
		blocks.push(
			{ kind: "heading", text: "Action required" },
			{
				kind: "list",
				items: actionable.map(
					(row) =>
						`${row.keyId}: ${STATE_LABELS[row.state]} (${describeRemaining(row)})${row.detail ? ` — ${row.detail}` : ""}`,
				),
			},
			{ kind: "paragraph", text: "Rotate or extend the affected keys." },
			{ kind: "link", text: "Key rotation procedure", href: KEY_ROTATION_DOCS_URL },
		);
	}

	blocks.push(...scopeBlocks(context.scope));

	return blocks;
}

/**
 * Render the report both ways at once.
 *
 * Both bodies come from one {@link reportBlocks} call rather than two, so the
 * plain-text and HTML halves of a single email cannot describe different runs.
 */
export function renderReport(rows: readonly KeyExpiryRow[], context: ReportContext): ReportDocument {
	const blocks = reportBlocks(rows, context);

	return {
		subject: reportSubject(rows, context),
		text: renderText(blocks),
		html: renderHtml(blocks),
	};
}

/**
 * Spell out how the monitored set was chosen, and where it is imprecise.
 *
 * In the report rather than only in the docs because the report is what gets
 * read — in an inbox, months later, by whoever is on call. A set this derived
 * is worth nothing if its reader cannot tell what it excluded.
 */
function scopeBlocks(scope: ActiveKeySet): ReportBlock[] {
	const blocks: ReportBlock[] = [
		{ kind: "heading", text: "Which keys count as active" },
		{
			kind: "paragraph",
			text:
				"A key is monitored when this deployment could sign with it right now: its KEY_ID " +
				"default, plus every key a live grant — a trusted OIDC subject or a service token — " +
				"permits. Grants that are revoked or expired are ignored, and stored keys no live grant " +
				"reaches are deliberately left out, so retaining a superseded key raises nothing.",
		},
		{
			kind: "paragraph",
			text: `Read ${plural(scope.totalGrantCount, "grant")}, of which ${scope.liveGrantCount} live.`,
		},
	];

	if (scope.defaultKey.keyId === null) {
		blocks.push({
			kind: "paragraph",
			text:
				`Warning: the ${scope.defaultKey.env ?? "top-level"} deployment declares no KEY_ID, so callers that ` +
				"name no key cannot sign at all. Only granted keys are monitored.",
		});
	}

	if (scope.unrestrictedGrants.length > 0) {
		blocks.push({
			kind: "paragraph",
			text:
				`Warning: ${plural(scope.unrestrictedGrants.length, "live grant")} ` +
				`${scope.unrestrictedGrants.length === 1 ? "pins" : "pin"} no key ids, so every stored key is ` +
				`signable and storage is the activation boundary: ${summarizeGrants(scope.unrestrictedGrants)}. ` +
				"Scope those grants to key ids to narrow this report.",
		});
	}

	if (scope.retainedInactive.length > 0) {
		blocks.push({
			kind: "paragraph",
			text:
				`Not monitored — stored but no live grant reaches ${scope.retainedInactive.length === 1 ? "it" : "them"}: ` +
				`${scope.retainedInactive.join(", ")}.`,
		});
	}

	blocks.push({
		kind: "paragraph",
		text:
			"Known limits: the set is a snapshot, so a grant added after this run is not covered until " +
			"the next one, and a grant is trusted to mean what it says, so a key id it names that no " +
			"longer exists is reported missing rather than dropped.",
	});

	return blocks;
}

/** Worst-first ordering: actionable rows above healthy ones, soonest expiry first */
function compareBySeverity(a: KeyExpiryRow, b: KeyExpiryRow): number {
	const rank = (row: KeyExpiryRow) => (ACTIONABLE_STATES.has(row.state) ? 0 : 1);
	if (rank(a) !== rank(b)) return rank(a) - rank(b);

	if (a.daysRemaining !== null && b.daysRemaining !== null) return a.daysRemaining - b.daysRemaining;
	if (a.daysRemaining !== null) return -1;
	if (b.daysRemaining !== null) return 1;

	return a.keyId.localeCompare(b.keyId);
}

// ---------------------------------------------------------------------------
// The two renderers
// ---------------------------------------------------------------------------

/**
 * Plain-text rendering, with the table's columns padded to line up.
 *
 * Padded rather than left as pipe-separated Markdown because this body is read
 * as-is, in a monospace mail window, by whoever's client strips HTML — and an
 * unaligned five-column table is exactly as unreadable there as it looks.
 */
function renderText(blocks: readonly ReportBlock[]): string {
	const lines: string[] = [];

	for (const block of blocks) {
		if (lines.length > 0) lines.push("");

		switch (block.kind) {
			case "heading":
				lines.push(block.text, "=".repeat(block.text.length));
				break;
			case "paragraph":
				lines.push(block.text);
				break;
			case "table":
				lines.push(...textTable(block.headers, block.rows));
				break;
			case "list":
				lines.push(...block.items.map((item) => `- ${item}`));
				break;
			case "link":
				lines.push(`${block.text}: ${block.href}`);
				break;
		}
	}

	return `${lines.join("\n")}\n`;
}

/** Column-aligned table, sized to its widest cell */
function textTable(headers: readonly string[], rows: readonly (readonly string[])[]): string[] {
	const widths = headers.map((header, column) =>
		Math.max(header.length, ...rows.map((row) => (row[column] ?? "").length)),
	);
	const line = (cells: readonly string[]) =>
		cells
			.map((cell, column) => cell.padEnd(widths[column] ?? 0))
			.join("  ")
			.trimEnd();

	return [line(headers), widths.map((width) => "-".repeat(width)).join("  "), ...rows.map(line)];
}

/** Characters that would otherwise close a tag or open an entity */
const HTML_ESCAPES: Record<string, string> = {
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	'"': "&quot;",
};

/**
 * Escape text for an HTML body.
 *
 * Every string that reaches the HTML renderer goes through here. Most of them
 * are key ids and status words, but grant *names* are operator-supplied and
 * reach the report unaltered, so the mail is one unescaped interpolation away
 * from letting whoever names a service token write markup into an operator's
 * inbox.
 */
function escapeHtml(text: string): string {
	return text.replaceAll(/[&<>"]/g, (character) => HTML_ESCAPES[character] ?? character);
}

/** HTML rendering, inline-styled because mail clients drop `<style>` blocks */
function renderHtml(blocks: readonly ReportBlock[]): string {
	const parts: string[] = [];

	for (const block of blocks) {
		switch (block.kind) {
			case "heading":
				parts.push(`<h2>${escapeHtml(block.text)}</h2>`);
				break;
			case "paragraph":
				parts.push(`<p>${escapeHtml(block.text)}</p>`);
				break;
			case "table":
				parts.push(htmlTable(block.headers, block.rows));
				break;
			case "list":
				parts.push(`<ul>${block.items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`);
				break;
			case "link":
				parts.push(`<p><a href="${escapeHtml(block.href)}">${escapeHtml(block.text)}</a></p>`);
				break;
		}
	}

	return `<html><body style="font-family:system-ui,sans-serif">${parts.join("")}</body></html>`;
}

/** Table with borders inlined, since a mail client will not read a stylesheet */
function htmlTable(headers: readonly string[], rows: readonly (readonly string[])[]): string {
	const cell = (tag: "th" | "td", text: string) =>
		`<${tag} style="border:1px solid #ccc;padding:4px 8px;text-align:left">${escapeHtml(text)}</${tag}>`;

	const head = `<tr>${headers.map((header) => cell("th", header)).join("")}</tr>`;
	const body = rows.map((row) => `<tr>${row.map((text) => cell("td", text)).join("")}</tr>`).join("");

	return `<table style="border-collapse:collapse">${head}${body}</table>`;
}

/**
 * openpgp signals "this never expires" with the number `Infinity` rather than a
 * `Date`, and `typeof Infinity` is plain `number`, so narrowing needs a guard.
 */
function neverExpires(value: Date | typeof Infinity): value is typeof Infinity {
	return value === Infinity;
}

/** Earlier of two openpgp expiry values, where `Infinity` means "never" */
function earlier(a: Date | typeof Infinity, b: Date | typeof Infinity): Date | typeof Infinity {
	if (neverExpires(a)) return b;
	if (neverExpires(b)) return a;
	return a.getTime() <= b.getTime() ? a : b;
}

/** Later of two openpgp expiry values, where `Infinity` outlasts every date */
function later(a: Date | typeof Infinity, b: Date | typeof Infinity): Date | typeof Infinity {
	if (neverExpires(a) || neverExpires(b)) return Infinity;
	return a.getTime() >= b.getTime() ? a : b;
}
