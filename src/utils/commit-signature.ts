/**
 * What a commit's signature does and does not prove, decided here and nowhere
 * else.
 *
 * This is the reporting counterpart to `#utils/push-signing`: that module makes
 * signatures, this one reads them back and says what they establish. Everything
 * in it is a decision over values, with no network and no bindings, so the
 * states below can be tested against the shapes that matter without a
 * repository.
 *
 * ### The claim has to be narrower than it is tempting to make
 *
 * A check that says "verified" is a statement other people act on, so each
 * state is exactly as strong as what was actually shown:
 *
 * - {@link SignatureState.service_key_valid} is the only state that asserts
 *   anything about *this* service. It requires an OpenPGP signature that names
 *   the operator-bound key and verifies under that key's public half — checked
 *   here, by this service, not read out of GitHub's answer.
 * - `other_signer` says the commit carries a signature that is not ours. It
 *   deliberately makes **no** claim about whether that signature is good:
 *   verifying it would need the signer's public key, which this deployment has
 *   no reason to hold. GitHub's own verdict travels alongside as GitHub's, and
 *   is labelled as such wherever it is shown.
 * - `invalid_signature` is the one alarming state, and it is reserved for a
 *   signature that *claims our key* and does not verify under it. Reporting a
 *   stranger's unverifiable signature under this state would turn "we cannot
 *   check that" into "that is forged", which is a different and much louder
 *   sentence.
 * - `unverifiable` is the honest answer whenever the inputs could not be tied
 *   to the commit at all. It is not a failure and not a pass.
 *
 * ### Why the payload is bound to the object id first
 *
 * GitHub reports a commit's `verification.payload` and `verification.signature`
 * — the bytes that were signed and the signature over them. Verifying the
 * second against the first proves only that *some* payload was signed. It does
 * not prove the payload is this commit, and a service that reported it as
 * though it did would be relaying GitHub's rendering as its own finding.
 *
 * So the two are folded back into a commit object and hashed, and the result
 * must equal the sha the ref actually points at — see
 * {@link signedCommitObject} and {@link commitObjectId}. Git computed that sha
 * over the bytes the repository holds, so an equal id means the payload and the
 * signature are the commit's own, byte for byte. It is the same total check the
 * signing path makes before it publishes, pointed in the opposite direction.
 *
 * A commit whose object carries a header this service does not model — a
 * `mergetag`, most realistically — will not fold back, and is reported
 * `unverifiable` rather than judged. That is a real and deliberate cost: a
 * perfectly good signature can land in the state that claims nothing. It is
 * the right direction to be wrong in.
 */

import * as openpgp from "openpgp";

import { commitObjectId, signedCommitObject } from "#utils/git-commit";

/** The armor header a PGP signature begins with, and nothing else does. */
const PGP_ARMOR = "-----BEGIN PGP SIGNATURE-----";

/** What this service is willing to say about a commit's signature. */
export type SignatureState =
	/** The commit carries no signature at all. */
	| "unsigned"
	/** A signature naming the bound key, verified here under that key. */
	| "service_key_valid"
	/** A signature by somebody else. No claim is made about whether it is good. */
	| "other_signer"
	/** A signature naming the bound key that does not verify under it. */
	| "invalid_signature"
	/** The signature could not be tied to this commit, so nothing was shown. */
	| "unverifiable";

/**
 * Why the state is the state, from a closed set.
 *
 * A closed set rather than a message, because these strings reach an audit row
 * and a check-run summary. Anything assembled from a GitHub response could
 * carry a GitHub response into both.
 */
export type SignatureDetail =
	/** `verification.signature` was null or empty. */
	| "no_signature"
	/** A signature was reported and no payload came with it. */
	| "no_payload"
	/** The payload and signature do not fold back into the commit's own object id. */
	| "object_binding_failed"
	/** The armor is not an OpenPGP signature — an SSH or S/MIME one, say. */
	| "non_pgp_signature"
	/** An OpenPGP armor block this service could not parse. */
	| "unreadable_signature"
	/** A well-formed OpenPGP signature naming some key other than the bound one. */
	| "different_key"
	/** It names the bound key and does not verify under it. */
	| "verification_failed"
	/** It names the bound key and verifies under it. */
	| "verified"
	/** The bound key's own material could not be read, so nothing can be attributed. */
	| "unreadable_service_key";

/**
 * The `reason` values GitHub's verification object is documented to carry.
 *
 * A closed set, because this value is echoed into a check-run summary and an
 * audit row, and it arrives in a response body. Anything outside the set is
 * reported as `unknown` rather than passed through — the alternative is letting
 * a remote API choose text that this service publishes under its own name.
 */
const GITHUB_REASONS = new Set([
	"expired_key",
	"not_signing_key",
	"gpgverify_error",
	"gpgverify_unavailable",
	"unsigned",
	"unknown_signature_type",
	"no_user",
	"unverified_email",
	"bad_email",
	"unknown_key",
	"malformed_signature",
	"invalid",
	"valid",
	"bad_cert",
	"ocsp_pending",
	"ocsp_error",
	"ocsp_revoked",
]);

/** GitHub's own verdict on the same commit, kept separate from ours. */
export interface GitHubVerdict {
	/** GitHub's `verification.verified`, which answers a different question than we do. */
	verified: boolean;
	/** GitHub's `verification.reason`, or `unknown` when it is not one we know. */
	reason: string;
}

/** What this service concluded about one commit's signature. */
export interface SignatureFinding {
	state: SignatureState;
	detail: SignatureDetail;
	/** Labelled as GitHub's throughout, because it is not our finding. */
	github: GitHubVerdict;
}

/** GitHub's verdict, reduced to the two fields worth repeating. */
export function githubVerdict(verified: unknown, reason: unknown): GitHubVerdict {
	return {
		verified: verified === true,
		reason: typeof reason === "string" && GITHUB_REASONS.has(reason) ? reason : "unknown",
	};
}

/** What GitHub reported about one commit, before any of it is believed. */
export interface ReportedVerification {
	/** The sha read back from the authorized repository, never a payload's claim. */
	sha: string;
	/** `verification.signature`: the armored signature, or null when unsigned. */
	signature: string | null;
	/** `verification.payload`: the bytes it covers, or null when none came. */
	payload: string | null;
	/** `verification.verified`. */
	verified: boolean;
	/** `verification.reason`. */
	reason: string | null;
}

/**
 * Did the bound key sign this commit?
 *
 * @param reported - What GitHub said, read back for a sha from the ref
 * @param armoredPublicKey - The public half of the key the operator bound to
 *   this repository
 */
export async function inspectCommitSignature(
	reported: ReportedVerification,
	armoredPublicKey: string,
): Promise<SignatureFinding> {
	const github = githubVerdict(reported.verified, reported.reason);

	const signature = reported.signature?.trim();
	if (signature === undefined || signature === "") {
		return { state: "unsigned", detail: "no_signature", github };
	}

	if (reported.payload === null) {
		// Signed, with nothing to check the signature against. Not a judgement on
		// the signature — we were not given the bytes it covers.
		return { state: "unverifiable", detail: "no_payload", github };
	}

	// The binding, before anything is parsed. Everything after this point is a
	// statement about *this commit*, and this is what makes it one.
	if (!(await bindsToCommit(reported.payload, signature, reported.sha))) {
		return { state: "unverifiable", detail: "object_binding_failed", github };
	}

	if (!signature.startsWith(PGP_ARMOR)) {
		// An SSH or S/MIME signature. Somebody else's, and not one this service
		// has any means of checking — which is `other_signer`, not `invalid`.
		return { state: "other_signer", detail: "non_pgp_signature", github };
	}

	let key: openpgp.Key;
	try {
		key = await openpgp.readKey({ armoredKey: armoredPublicKey });
	} catch {
		// The bound key's own material would not parse. Nothing can be attributed
		// to a key that cannot be read, and that is a fact about this deployment
		// rather than about the commit — so it is `unverifiable`, not a verdict.
		return { state: "unverifiable", detail: "unreadable_service_key", github };
	}

	let parsed: openpgp.Signature;
	try {
		parsed = await openpgp.readSignature({ armoredSignature: signature });
	} catch {
		// PGP armor that is not a PGP signature. Nothing names a key, so nothing
		// attributes it to anybody — but it is a broken OpenPGP signature on a
		// commit, which is a finding rather than a shrug.
		return { state: "invalid_signature", detail: "unreadable_signature", github };
	}

	// Compared against **the key's own ids**, primary and subkeys alike, rather
	// than against the id string the allowlist entry carries. Two reasons, and
	// the second is the one that would have been a bug: a configured id is a
	// label on a storage slot and the key inside it could have been rotated, and
	// — more to the point — an OpenPGP key signs with its *signing subkey*, whose
	// id is not the primary's. GnuPG-generated keys almost always have one. So
	// asking "does this signature name the key we hold" has to ask the key.
	const ours = new Set(key.getKeys().map((each) => each.getKeyID().toHex().toUpperCase()));
	const signedBy = parsed.getSigningKeyIDs().map((id) => id.toHex().toUpperCase());

	if (!signedBy.some((id) => ours.has(id))) {
		// Somebody else's key. Verifying it would need their public half, which
		// this deployment has no reason to hold, so no claim is made either way.
		return { state: "other_signer", detail: "different_key", github };
	}

	const verifies = await verifiesUnder(parsed, reported.payload, key);

	return {
		state: verifies ? "service_key_valid" : "invalid_signature",
		detail: verifies ? "verified" : "verification_failed",
		github,
	};
}

/**
 * Do these bytes reassemble into the commit the ref points at?
 *
 * Any failure is false rather than a throw: a payload with no header boundary,
 * an armor block that folds oddly, a sha that simply does not match. All of
 * them mean the same thing to the caller — the reported bytes were not shown to
 * be this commit's — and none of them is worth a distinct state.
 */
async function bindsToCommit(payload: string, signature: string, sha: string): Promise<boolean> {
	try {
		return (await commitObjectId(signedCommitObject(payload, signature))) === sha;
	} catch {
		return false;
	}
}

/**
 * Does `signature` verify over `payload` under `armoredPublicKey`?
 *
 * The message is built from **binary** bytes, matching `signCommitData`: a text
 * message would make openpgp.js hash the payload with every line ending
 * rewritten, which is a different question than the one Git asks and would
 * quietly accept two distinct commit objects under one signature.
 *
 * No `date` is passed, and that is a decision rather than an omission. It was
 * tempting to verify "as of when the signature was made", so that a key which
 * has since expired would not turn every commit it ever signed into a claim of
 * forgery. It turns out openpgp.js does not gate *verification* on key expiry at
 * all — it looks the key up by id regardless — so passing a past date would have
 * bought nothing except the one thing it does affect: a signature claiming a
 * creation time in the future would start verifying, which is the opposite of
 * what anyone wants. Both behaviours are pinned by tests, so a change in
 * openpgp.js's semantics is a failing test rather than a silent change of
 * verdict.
 */
async function verifiesUnder(signature: openpgp.Signature, payload: string, key: openpgp.Key): Promise<boolean> {
	try {
		const message = await openpgp.createMessage({ binary: new TextEncoder().encode(payload) });

		const result = await openpgp.verify({
			message,
			signature,
			verificationKeys: key,
			format: "binary",
		});

		// `verified` rejects rather than resolving false, which is why these are
		// awaited inside the try rather than returned out of it. The length is
		// checked *after* awaiting rather than before: `Promise.all` over an empty
		// list resolves happily, so a result carrying no signature at all would
		// otherwise come back as a pass.
		const verdicts = await Promise.all(result.signatures.map((each) => each.verified));

		return verdicts.length > 0;
	} catch {
		return false;
	}
}
