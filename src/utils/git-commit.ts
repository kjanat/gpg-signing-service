/**
 * Git commit objects, built and named the way Git itself builds and names them.
 *
 * Signing a commit is not signing "a commit". It is signing an exact byte
 * string — the commit object with every header in Git's order and none of the
 * fields normalised — and a signature over anything else is a signature Git
 * will report as bad. So this module reproduces that byte string rather than
 * approximating it, and then reproduces the object id over it, which is what
 * lets the handler check its own work against GitHub's answer instead of
 * assuming the two agreed.
 *
 * ### Why the object id is computed here at all
 *
 * GitHub's create-a-commit endpoint accepts a `signature` and inserts it into
 * the object as the `gpgsig` header; it does not tell you what payload it
 * assembled. If its assembly differs from ours by one byte — a date offset
 * normalised, a header we did not know about — the signature is over a
 * different object than the one that now exists, and the result is a commit
 * that says it is signed and verifies as broken. Nothing in the response
 * announces that.
 *
 * The object id does. {@link commitObjectId} over the signed object is the same
 * SHA-1 Git computes, so comparing it against the SHA GitHub returned is a
 * total check on the whole payload: equal ids mean the bytes were identical,
 * and there is no way for them to be equal and the signature to be wrong. The
 * handler makes that comparison *before* it moves a ref, so a mismatch costs a
 * dangling object nobody can reach rather than a branch of broken signatures.
 *
 * ### Dates are echoed, never recomputed
 *
 * `<epoch> <±HHMM>` is what a commit object stores, and the offset is part of
 * the object — two commits with the same instant and different offsets are
 * different commits. GitHub's API hands dates back as ISO 8601, so the offset
 * survives the round trip only if it is read out of that string and put back
 * unchanged. {@link gitTimestamp} does exactly that and computes nothing: no
 * local timezone, no `Date` formatting, no normalisation to UTC.
 */

/** An author or committer line's three parts, as the object stores them. */
export interface CommitIdentity {
	name: string;
	email: string;
	/** ISO 8601 with an offset, as GitHub's API returns it. */
	date: string;
}

/** Everything a commit object holds, minus the signature. */
export interface CommitObject {
	tree: string;
	parents: string[];
	author: CommitIdentity;
	committer: CommitIdentity;
	message: string;
}

/** ISO 8601, captured as an instant plus the offset the string carried. */
const ISO_WITH_OFFSET = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:\d{2})$/;

/**
 * `<epoch seconds> <±HHMM>`, the way a commit object writes a date.
 *
 * The offset is taken from the input string rather than derived from the
 * instant, because it cannot be derived: `2026-08-31T09:00:00+02:00` and
 * `2026-08-31T07:00:00Z` are the same moment and different commit objects. A
 * conversion that "helpfully" normalised to UTC would produce a payload that
 * hashes to something GitHub never built.
 *
 * @param iso - ISO 8601 with a `Z` or `±HH:MM` offset
 * @throws When the string carries no offset, or is not a date. A commit whose
 *   date cannot be reproduced exactly is one this service declines to sign,
 *   rather than one it signs approximately.
 */
export function gitTimestamp(iso: string): string {
	const match = ISO_WITH_OFFSET.exec(iso);
	if (!match) {
		throw new Error("Commit date is not ISO 8601 with an offset");
	}

	const seconds = Math.floor(Date.parse(iso) / 1000);
	if (!Number.isFinite(seconds)) {
		throw new Error("Commit date is not a date");
	}

	const offset = match[2] === "Z" ? "+0000" : (match[2] as string).replace(":", "");

	return `${seconds} ${offset}`;
}

/** One `author`/`committer` header line, without its trailing newline. */
function identityLine(field: string, identity: CommitIdentity): string {
	return `${field} ${identity.name} <${identity.email}> ${gitTimestamp(identity.date)}`;
}

/**
 * The exact bytes a signature is made over.
 *
 * This is the commit object *without* its `gpgsig` header — which is what Git
 * signs, and what GitHub's create-a-commit endpoint expects the `signature`
 * field to cover.
 */
export function commitPayload(commit: CommitObject): string {
	const lines = [
		`tree ${commit.tree}`,
		...commit.parents.map((parent) => `parent ${parent}`),
		identityLine("author", commit.author),
		identityLine("committer", commit.committer),
	];

	return `${lines.join("\n")}\n\n${commit.message}`;
}

/**
 * The commit object as it exists once the signature is in it.
 *
 * `gpgsig` goes after `committer` and before the blank line, and every
 * continuation line is prefixed with a single space — including the empty one
 * inside an armored block, which becomes a line containing just a space. That
 * is Git's folding rule for multi-line headers, and getting it wrong changes
 * the object id, which is precisely what the round-trip check would then catch.
 *
 * @param payload - The output of {@link commitPayload}
 * @param signature - An ASCII-armored detached signature over `payload`
 */
export function signedCommitObject(payload: string, signature: string): string {
	const folded = signature.replace(/\n+$/, "").split("\n").join("\n ");

	// The header block ends at the first blank line; the message is everything
	// after it. Split on the first occurrence only, because a commit message may
	// contain blank lines of its own and they are not header boundaries.
	const boundary = payload.indexOf("\n\n");
	if (boundary === -1) {
		throw new Error("Commit payload has no header boundary");
	}

	const headers = payload.slice(0, boundary);
	const rest = payload.slice(boundary);

	return `${headers}\ngpgsig ${folded}${rest}`;
}

/**
 * The SHA-1 Git would give this object.
 *
 * `sha1("commit " + <byte length> + "\0" + content)`. The length is in *bytes*,
 * not characters — a commit message with one emoji in it is longer than its
 * `String.length` — so the content is encoded first and measured after.
 *
 * SHA-1 is used because Git uses it. This is an object *name*, not a security
 * property: what makes the round-trip check meaningful is that GitHub computed
 * its answer the same way over the bytes it actually stored, so an equal id
 * means equal bytes. The signature underneath is SHA-256 or better, per the
 * signing key.
 */
export async function commitObjectId(content: string): Promise<string> {
	const body = new TextEncoder().encode(content);
	const header = new TextEncoder().encode(`commit ${body.byteLength}\0`);

	const object = new Uint8Array(header.byteLength + body.byteLength);
	object.set(header, 0);
	object.set(body, header.byteLength);

	const digest = await crypto.subtle.digest("SHA-1", object);

	return Array.from(new Uint8Array(digest))
		.map((byte) => byte.toString(16).padStart(2, "0"))
		.join("");
}
