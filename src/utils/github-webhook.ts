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
 * Three properties carry that weight, and each is easy to lose by accident:
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
 *
 * **The verification is bounded.** The MAC covers the whole body, so the body
 * has to be in memory before anything is known about the sender. The ceiling
 * below — GitHub's own — is what turns "buffer whatever arrives" into a fixed
 * cost, and it is enforced on the octets received rather than on the sender's
 * account of how many it is about to send.
 */

import type { WebhookAuthorization, WebhookDelivery } from "#types";
import { requireSigningKey } from "#utils/github-signing-key";

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

/**
 * GitHub's own ceiling on a webhook payload, in bytes.
 *
 * 25 MiB, [documented on the events-and-payloads
 * page](https://docs.github.com/en/webhooks/webhook-events-and-payloads#payload-cap):
 * a delivery larger than this is not truncated, it is *not sent*. So this is
 * not a policy invented here that honest traffic could grow into — it is the
 * number above which a request cannot have come from GitHub, whatever its
 * signature says.
 *
 * The ceiling exists because the HMAC runs over the whole body, and the body is
 * read before anything is known about the sender. Workers accept up to 100 MB
 * against a 128 MB isolate memory limit, and the rate limiter in front bounds
 * request *count*, not bytes — so without this, one metered request per second
 * is still an unbounded amount of buffering, and the failure mode is an
 * "Exceeded memory limit" isolate kill that takes the other in-flight requests
 * on that isolate with it.
 */
export const MAX_WEBHOOK_BODY_BYTES = 25 * 1024 * 1024;

/**
 * `Content-Length` as a byte count, or null when there is no usable one.
 *
 * Strict digits, because everything else about this header is attacker-chosen.
 * `Number("")` is `0` and `Number(" 25 ")` is `25`, so a lenient parse would
 * read an empty or padded value as a small declared body and wave it through
 * the check below — which is fine only because nothing here *trusts* the
 * answer: an unparseable value reads as "not declared", and an undeclared body
 * is metered by {@link readBodyWithin} as it arrives.
 */
export function declaredBodyLength(value: string | null | undefined): number | null {
	if (value === undefined || value === null || !/^\d+$/.test(value)) {
		return null;
	}

	const length = Number(value);

	return Number.isSafeInteger(length) ? length : null;
}

/**
 * The request body, or null when it is larger than `limit` bytes.
 *
 * **Deliberately does not read `Content-Length`.** A guard that did would be
 * satisfied by a sender that simply declares a smaller number than it sends,
 * which is one line of client code — the header is a claim by the same party
 * whose body is under suspicion. This counts the octets it actually receives
 * and stops reading at the first chunk that crosses the ceiling, so the most
 * memory a single delivery can cost is the limit plus one chunk. The header
 * check that exists in the middleware is an optimisation on top of this, not
 * the protection: it declines a request that has already told us it is too big
 * before spending anything at all, and this is what catches the ones that lie.
 *
 * Returns null rather than throwing so the caller answers with a status rather
 * than a fault: a body over the ceiling is a refusal, not a bug.
 *
 * @param request - The request whose body to read; its stream is consumed
 * @param limit - Largest acceptable body, in bytes, inclusive
 */
export async function readBodyWithin(request: Request, limit: number): Promise<ArrayBuffer | null> {
	const stream = request.body;

	if (stream === null) {
		// No stream to meter, which for a `Request` means no octets: `body` is null
		// exactly when there is no body, and `arrayBuffer()` on one of those
		// resolves empty. So there is nothing to count and nothing to buffer. The
		// branch exists because a `GET` reaching this code must not throw — a fault
		// here would be a 500 on a path whose whole design is to answer 401s and
		// 404s — rather than because a bodyless request could be over a ceiling.
		return request.arrayBuffer();
	}

	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;

	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) {
				break;
			}

			total += value.byteLength;
			if (total > limit) {
				// Stop pulling. Cancelling propagates back to the sender rather than
				// draining the rest of the upload into a buffer nobody will read.
				await reader.cancel();
				return null;
			}

			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}

	// Concatenated by hand rather than through `new Blob(chunks).arrayBuffer()`:
	// the exact octets are what the HMAC is computed over, and this keeps the
	// copy visible and single.
	const body = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}

	return body.buffer;
}

/**
 * The body every accepted delivery is answered with.
 *
 * One function, called from both the replay guard and the route, because a
 * duplicate and a first arrival must be told apart by exactly one field. Two
 * hand-written object literals would drift, and the way they drift is that the
 * two answers become distinguishable by something other than `duplicate` —
 * which is the field an operator reading "Recent Deliveries" is looking at.
 *
 * Everything here is either a value GitHub just sent or a decision made about
 * it, and reaching this point at all required a valid HMAC, so nothing is
 * disclosed. `installationId` is reported as a boolean rather than as the id:
 * whether an event carries an installation is what an operator is checking, and
 * the id itself adds nothing they did not send.
 *
 * @param delivery - The verified delivery
 * @param authorization - What it was authorized to be about, when that has been
 *   decided; `scope` and `signingKey` are omitted otherwise rather than guessed
 *   at
 * @param options - `duplicate` marks a delivery id already claimed
 */
export function acknowledgement(
	delivery: WebhookDelivery,
	authorization: WebhookAuthorization | undefined,
	options: { duplicate: boolean; handled?: boolean; outcome?: string },
) {
	return {
		received: true,
		event: delivery.event,
		delivery: delivery.id,
		/** Whether a token could be minted for this event, not whether one was. */
		installation: delivery.installationId !== null,
		/** How much authority the allowlist granted this delivery. */
		...(authorization === undefined
			? {}
			: {
					scope: authorization.scope,
					/**
					 * Whether the grant binds a signing key, not which one.
					 *
					 * Read through `requireSigningKey` rather than off the field, so
					 * this cannot claim a key for a state that function refuses — the
					 * answer an operator reads here is the answer a handler would get.
					 */
					signingKey: requireSigningKey(authorization).allowed,
				}),
		/** True when this delivery id was already held — by a settled run or one still going. */
		duplicate: options.duplicate,
		/**
		 * Whether this delivery caused the service to do something.
		 *
		 * False for every event with no handler, and false for a `push` that was
		 * refused. True for a `push` the signing handler completed, *including* one
		 * that found nothing to sign: the run reached its conclusion, and the
		 * conclusion was that the branch is already in the state it should be in.
		 */
		handled: options.handled ?? false,
		/**
		 * One word for what happened, echoed so a "Recent Deliveries" row is
		 * readable without a log. Every value is a decision this service made about
		 * a delivery the caller already authenticated for a repository the operator
		 * granted it, so it discloses nothing the caller did not supply or is not
		 * entitled to know.
		 */
		...(options.outcome === undefined ? {} : { outcome: options.outcome }),
	};
}
