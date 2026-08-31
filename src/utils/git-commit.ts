/**
 * Git commit objects, as bytes.
 *
 * Signing a commit is not an operation on a repository — it is an operation on
 * a byte string. A commit object is
 *
 * ```text
 * tree <sha>\n
 * parent <sha>\n          (zero or more)
 * author <ident>\n
 * committer <ident>\n
 * [gpgsig <armor>\n]      (continuation lines are prefixed with one space)
 * \n
 * <message>
 * ```
 *
 * and its name is `sha1("commit " + <byte length> + "\0" + <those bytes>)`. A
 * signature is a detached OpenPGP signature over the same bytes **with the
 * `gpgsig` header removed**, which is what `.github/scripts/sign-commits.py`
 * builds with `git cat-file` and what this module builds from GitHub's JSON.
 *
 * ### Why this reproduces objects it did not create
 *
 * The Worker has no `git`, so a commit arrives as a JSON document — fields
 * GitHub chose, in an encoding GitHub chose — and the serialiser here has to
 * turn that back into the exact octets `git` wrote. Two of those conversions
 * are underspecified and neither can be looked up: whether `commit.message`
 * carries the object's trailing newline, and how a non-UTC author offset is
 * rendered.
 *
 * So nothing here *assumes*. {@link reproduceCommit} builds a candidate,
 * hashes it, and compares the result against the sha GitHub already told us —
 * and a commit whose bytes cannot be reproduced is refused rather than signed.
 * That turns every conversion in this file into a checked one: an encoding
 * header this code does not model, a `mergetag`, a field GitHub renders
 * differently next year, all land as "could not reproduce" rather than as a
 * signature over bytes that are not the commit.
 *
 * The same hash is what verifies the *other* end. A commit this service asks
 * GitHub to create is checked by recomputing the object it should have become
 * — payload plus the `gpgsig` we sent — and comparing that to the sha GitHub
 * returned, **before** any ref is moved. See `#utils/push-signing`.
 */

/** The all-zero object name git uses for "no such object". */
export const NULL_SHA = "0".repeat(40);

/** A 40-character lowercase hex object name, and nothing else. */
const SHA_PATTERN = /^[0-9a-f]{40}$/;

/** Is `value` a git object name this module is willing to handle? */
export function isObjectSha(value: unknown): value is string {
	return typeof value === "string" && SHA_PATTERN.test(value);
}

/** One side of a commit's authorship, as GitHub reports it. */
export interface CommitIdentity {
	name: string;
	email: string;
	/** ISO 8601, with the offset the commit was made in. */
	date: string;
}

/** A commit object's contents, without its name and without any signature. */
export interface CommitContents {
	tree: string;
	parents: string[];
	author: CommitIdentity;
	committer: CommitIdentity;
	message: string;
}

/**
 * How a commit's message ends in the object, which GitHub's JSON does not say.
 *
 * `git` writes a message with a trailing newline; GitHub's `message` field
 * usually has it stripped, and "usually" is not something to sign against. Both
 * are tried against the object's own sha, and the one that reproduces it is
 * carried forward so a commit created from this one ends the same way.
 */
export type MessageTermination = "newline" | "bare";

/** Every termination tried, in the order they are tried. */
const TERMINATIONS: readonly MessageTermination[] = ["newline", "bare"];

/** `message` as it appears in the object under `termination`. */
function terminate(message: string, termination: MessageTermination): string {
	if (termination === "bare") {
		return message;
	}
	return message.endsWith("\n") ? message : `${message}\n`;
}

/**
 * `<epoch seconds> <±HHMM>` for an ISO 8601 timestamp.
 *
 * The offset is carried through rather than normalised. Git stores the wall
 * clock the commit was made in, and a commit rewritten into UTC is a different
 * object with a different name — which the reproduction check would catch, but
 * only after the fact and only as a refusal.
 *
 * @throws When the value is not a timestamp with a readable offset. GitHub
 *   sends one; anything else means the assumptions here have stopped holding
 *   and the caller must refuse rather than guess.
 */
export function gitTimestamp(iso: string): string {
	const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})$/.exec(iso);
	if (match === null) {
		throw new Error("commit timestamp is not ISO 8601 with an offset");
	}

	const seconds = Math.floor(Date.parse(iso) / 1000);
	if (!Number.isFinite(seconds)) {
		throw new Error("commit timestamp is not a date");
	}

	const offset = match[2] as string;
	const zone = offset === "Z" ? "+0000" : offset.replace(":", "");

	return `${seconds} ${zone}`;
}

/** One `author`/`committer` line's value. */
function identityLine(identity: CommitIdentity): string {
	return `${identity.name} <${identity.email}> ${gitTimestamp(identity.date)}`;
}

/**
 * The bytes a signature covers: the commit object without its `gpgsig` header.
 *
 * @throws When a timestamp cannot be rendered. See {@link gitTimestamp}.
 */
export function commitPayload(contents: CommitContents, termination: MessageTermination): string {
	const headers = [
		`tree ${contents.tree}`,
		...contents.parents.map((parent) => `parent ${parent}`),
		`author ${identityLine(contents.author)}`,
		`committer ${identityLine(contents.committer)}`,
	];

	return `${headers.join("\n")}\n\n${terminate(contents.message, termination)}`;
}

/**
 * The complete object, with an armored signature folded into a `gpgsig` header.
 *
 * Placed directly after `committer`, which is where `git` writes it and
 * therefore where the object's name is computed from. Continuation lines carry
 * one leading space, exactly as in the reference implementation's
 * `with_signature`.
 */
export function commitWithSignature(payload: string, armoredSignature: string): string {
	const separator = payload.indexOf("\n\n");
	if (separator === -1) {
		throw new Error("commit payload has no header/message separator");
	}

	const header = payload.slice(0, separator);
	const rest = payload.slice(separator);

	const armor = armoredSignature.replace(/\n+$/, "").split("\n");
	const [first, ...continuation] = armor;
	const gpgsig = [`gpgsig ${first}`, ...continuation.map((line) => ` ${line}`)];

	return `${header}\n${gpgsig.join("\n")}${rest}`;
}

/** Lowercase hex for `bytes`. */
function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * The object name git would give these commit bytes.
 *
 * `sha1` because that is what a commit's name *is*. It is used here to compare
 * two byte strings for equality by a value a third party already published, not
 * as a security primitive: nothing is trusted because its sha1 matched, and a
 * mismatch only ever causes a refusal.
 */
export async function commitObjectSha(object: string): Promise<string> {
	const body = new TextEncoder().encode(object);
	const header = new TextEncoder().encode(`commit ${body.length}\0`);

	const framed = new Uint8Array(header.length + body.length);
	framed.set(header, 0);
	framed.set(body, header.length);

	return hex(await crypto.subtle.digest("SHA-1", framed));
}

/** A commit whose bytes this service could rebuild from GitHub's JSON. */
export interface ReproducedCommit {
	/** The signature payload — the object without any `gpgsig`. */
	payload: string;
	/** Which message termination reproduced the object. */
	termination: MessageTermination;
}

/**
 * The signature payload for `contents`, proven by hashing to `sha`.
 *
 * @param contents - A commit as GitHub described it
 * @param sha - The object name GitHub gave it
 * @param signature - Its armored `gpgsig`, when it carries one, because a
 *   signed commit's object includes the header and its name is computed over
 *   that
 * @returns The reproduction, or null when no candidate hashed to `sha` — which
 *   the caller must treat as "do not touch this commit". A commit that cannot
 *   be rebuilt is one this service does not fully understand, and rewriting
 *   history on a partial understanding is the failure mode this returns null to
 *   avoid.
 */
export async function reproduceCommit(
	contents: CommitContents,
	sha: string,
	signature: string | null = null,
): Promise<ReproducedCommit | null> {
	for (const termination of TERMINATIONS) {
		let payload: string;
		try {
			payload = commitPayload(contents, termination);
		} catch {
			// An unrenderable timestamp is not termination-specific, so no other
			// candidate can succeed either.
			return null;
		}

		const object = signature === null ? payload : commitWithSignature(payload, signature);
		if ((await commitObjectSha(object)) === sha) {
			return { payload, termination };
		}
	}

	return null;
}
