/**
 * The inbound half of the GitHub App integration: deciding whether a delivery
 * really came from GitHub.
 *
 * A webhook URL is public by construction — it is typed into a settings form
 * and then reachable by anyone who guesses it — so the HMAC is not one of
 * several controls on this route. It is the only one. Everything downstream is
 * written on the assumption that a payload reaching it was signed with a secret
 * only GitHub and this deployment hold.
 *
 * Two properties carry that weight, and both are easy to lose by accident:
 *
 * **The bytes verified are the bytes that arrived.** GitHub signs the body
 * octet by octet. `JSON.parse` followed by `JSON.stringify` produces a different
 * string for the same document — key order, escaping, whitespace, number
 * formatting — so a verifier that re-serialises is not checking the signature it
 * was given, and it fails *closed* on honest traffic, which is the failure mode
 * that gets a check quietly removed. Everything here works on an `ArrayBuffer`
 * and the parse happens strictly after the verdict.
 *
 * **The comparison does not leak.** An attacker with the ability to send
 * unlimited candidate signatures and time the answers can walk a byte-at-a-time
 * comparison to a forgery. `crypto.subtle.timingSafeEqual` is what stops that,
 * and it only helps if it is reached — hence the fixed-width parse below, which
 * makes every well-formed candidate take the same path.
 */

/** The header GitHub puts the HMAC in. */
export const SIGNATURE_HEADER = "X-Hub-Signature-256";

/** The header carrying GitHub's unique id for a delivery. */
export const DELIVERY_HEADER = "X-GitHub-Delivery";

/** The header naming the event type. */
export const EVENT_HEADER = "X-GitHub-Event";

/** How GitHub prefixes the hex digest. */
export const SIGNATURE_PREFIX = "sha256=";

/** Hex characters in a SHA-256 digest. */
const DIGEST_HEX_LENGTH = 64;

/** Exactly 64 hex characters, either case. */
const DIGEST_PATTERN = /^[0-9a-fA-F]{64}$/;

/**
 * `hex` as bytes, or null when it is not a full-width SHA-256 digest.
 *
 * Deliberately strict, and deliberately not constant-time. Whether a *candidate
 * is well-formed* is not a secret — the attacker wrote it — and rejecting a
 * short or non-hex value early is what guarantees the real comparison always
 * runs on two equal-length 32-byte arrays, which is the precondition
 * `crypto.subtle.timingSafeEqual` requires and throws without.
 */
function hexToBytes(hex: string): Uint8Array | null {
	if (hex.length !== DIGEST_HEX_LENGTH || !DIGEST_PATTERN.test(hex)) {
		return null;
	}

	const bytes = new Uint8Array(DIGEST_HEX_LENGTH / 2);
	for (let index = 0; index < bytes.length; index++) {
		bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
	}

	return bytes;
}

/**
 * Does `signature` prove that `body` was sent by a holder of `secret`?
 *
 * Returns a boolean rather than throwing, because every negative answer means
 * the same thing to the caller — refuse — and distinguishing "no header" from
 * "wrong header" in the response is how a prober learns which half to work on.
 * The middleware does draw that distinction, and draws it on the *presence* of
 * the header rather than on anything this function saw.
 *
 * @param secret - `GITHUB_WEBHOOK_SECRET`; an empty value always fails
 * @param body - The raw request bytes, exactly as received
 * @param signature - The `X-Hub-Signature-256` value, or undefined
 */
export async function verifyWebhookSignature(
	secret: string,
	body: ArrayBuffer,
	signature: string | undefined,
): Promise<boolean> {
	// An unset secret verifies nothing, and says so rather than throwing.
	// `importKey` refuses a zero-length HMAC key with a `DataError`, so without
	// this the misconfiguration would surface as an unhandled fault and a 500
	// instead of a refusal — a difference that matters, because a 500 is what a
	// caller retries. The middleware refuses an unset secret before reaching
	// here; this is the second of two independent guards, so a future caller
	// cannot acquire the first one's mistake.
	if (!secret || signature === undefined) {
		return false;
	}

	if (!signature.startsWith(SIGNATURE_PREFIX)) {
		return false;
	}

	const presented = hexToBytes(signature.slice(SIGNATURE_PREFIX.length));
	if (presented === null) {
		return false;
	}

	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);

	const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, body));

	return crypto.subtle.timingSafeEqual(expected, presented);
}

/**
 * The `installation.id` in a verified payload, or null.
 *
 * Narrow on purpose. The payload is JSON of GitHub's choosing and this is the
 * one field the scaffold reads, so it is read defensively rather than by
 * declaring a type for a document nothing else inspects. A non-integer or
 * out-of-range value reads as absent, which is the same answer as an event that
 * has no installation — and both mean "no token can be minted for this".
 */
export function installationIdOf(payload: unknown): number | null {
	if (typeof payload !== "object" || payload === null) {
		return null;
	}

	const installation = (payload as { installation?: unknown }).installation;
	if (typeof installation !== "object" || installation === null) {
		return null;
	}

	const id = (installation as { id?: unknown }).id;

	return typeof id === "number" && Number.isSafeInteger(id) && id > 0 ? id : null;
}
