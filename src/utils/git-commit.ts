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
 * ### Dates: the offset is recovered, because it is not in the JSON
 *
 * `<epoch> <±HHMM>` is what a commit object stores, and the offset is part of
 * the object — two commits with the same instant and different offsets are
 * different commits, with different ids.
 *
 * GitHub's Git Data API does not give it to you. `GET /git/commits/{sha}`
 * renders both dates in UTC (`…T05:01:37Z`) for a commit whose object says
 * `1788152497 +0200`, and so does `GET /commits/{sha}`, and so does GraphQL's
 * `GitTimestamp` despite its schema documentation. Echoing that string back
 * therefore *relocates every commit to UTC*, and the round-trip id check cannot
 * notice: both our assembly and GitHub's start from the same already-normalised
 * value and agree on the same wrong answer.
 *
 * So the offset is **recovered and proven** rather than read.
 * {@link recoverCommitObject} reconstructs the original object under candidate
 * offsets and keeps the one whose {@link commitObjectId} equals the sha the
 * commit already has. That sha was computed by Git over the real bytes, so a
 * match is proof — of the offsets, and of every other byte of the
 * reconstruction with them. A commit that no candidate reproduces is one this
 * service declines to rewrite rather than one it rewrites approximately.
 *
 * ### And the message, for the same reason and by the same proof
 *
 * The offsets are not the only thing that endpoint renders away. It also strips
 * a trailing newline from the message — the one `git commit` puts on every
 * message it writes — and the JSON looks identical whether the object had one or
 * not. So the reconstruction has to try both, and what it returns is not "the
 * offsets" but **the representation that reproduced the sha**: offsets *and*
 * message together, because they were proven together and only together.
 *
 * Carrying only half of that proof forward is the same class of bug as echoing
 * the date: the signature would be made over a message the author did not write,
 * the created object would hold that message, and the round-trip id check would
 * agree with itself about it — both sides having started from the same stripped
 * string. {@link CommitReconstruction} is what the proof is carried in, and
 * `RepositoryClient.getCommit` returns its message rather than the API's.
 *
 * With the offsets known, {@link isoWithOffset} renders them back into the ISO
 * 8601 that create-a-commit takes, and GitHub stores what it is given — verified
 * against the live API with an author at `+0545` and a committer at `-0330`,
 * both preserved. Which is what finally puts the round-trip id check on both
 * sides of a real disagreement: our payload now carries the original offset, so
 * if GitHub ever did normalise, the ids would differ and nothing would be
 * published.
 */

/** An author or committer line's three parts, as the object stores them. */
export interface CommitIdentity {
	name: string;
	email: string;
	/** ISO 8601 with an offset, as GitHub's API returns it — always `Z` in practice. */
	date: string;
	/**
	 * `±HHMM`, the offset the stored object actually carries.
	 *
	 * Supplied by {@link recoverCommitObject}, which proves it against the
	 * commit's own sha. When it is absent the offset in {@link date} is used —
	 * which, for anything that came out of GitHub's JSON, means `+0000`. So an
	 * absent offset is not "unknown, assume UTC"; it is "this identity was not
	 * read from that API", and every path in this service that *was* fills it in.
	 */
	offset?: string;
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

/** `±HHMM`, the only offset spelling a commit object uses. */
const GIT_OFFSET = /^[+-]\d{4}$/;

/**
 * `<epoch seconds> <±HHMM>`, the way a commit object writes a date.
 *
 * The offset is taken from the input string rather than derived from the
 * instant, because it cannot be derived: `2026-08-31T09:00:00+02:00` and
 * `2026-08-31T07:00:00Z` are the same moment and different commit objects. A
 * conversion that "helpfully" normalised to UTC would produce a payload that
 * hashes to something GitHub never built.
 *
 * `offset` overrides the one in the string, and is how a recovered offset gets
 * back into the object: the instant is the same either way, and the offset is
 * the part GitHub's JSON threw away.
 *
 * @param iso - ISO 8601 with a `Z` or `±HH:MM` offset
 * @param offset - `±HHMM` to write instead of the string's own
 * @throws When the string carries no offset, or is not a date, or `offset` is
 *   not `±HHMM`. A commit whose date cannot be reproduced exactly is one this
 *   service declines to sign, rather than one it signs approximately.
 */
export function gitTimestamp(iso: string, offset?: string): string {
	const match = ISO_WITH_OFFSET.exec(iso);
	if (!match) {
		throw new Error("Commit date is not ISO 8601 with an offset");
	}

	const seconds = Math.floor(Date.parse(iso) / 1000);
	if (!Number.isFinite(seconds)) {
		throw new Error("Commit date is not a date");
	}

	if (offset !== undefined && !GIT_OFFSET.test(offset)) {
		throw new Error("Commit date offset is not ±HHMM");
	}

	const written = offset ?? (match[2] === "Z" ? "+0000" : (match[2] as string).replace(":", ""));

	return `${seconds} ${written}`;
}

/**
 * The same instant, written with `offset` instead of whatever `iso` carried.
 *
 * This is the direction that puts a recovered offset back on the wire:
 * create-a-commit takes ISO 8601, and GitHub stores the offset it is handed
 * rather than normalising it — so an author date rendered `+05:45` here comes
 * out of the object as `+0545`.
 *
 * @param iso - ISO 8601 with a `Z` or `±HH:MM` offset
 * @param offset - `±HHMM`
 */
export function isoWithOffset(iso: string, offset: string): string {
	if (!GIT_OFFSET.test(offset)) {
		throw new Error("Commit date offset is not ±HHMM");
	}

	const instant = Date.parse(iso);
	if (!Number.isFinite(instant)) {
		throw new Error("Commit date is not a date");
	}

	const minutes = (offset.startsWith("-") ? -1 : 1) * (Number(offset.slice(1, 3)) * 60 + Number(offset.slice(3, 5)));

	// `toISOString` only renders UTC, so the wall clock is shifted onto the
	// instant first and the offset is appended as a literal. Truncated at seconds
	// because a commit object stores whole seconds and nothing finer.
	const shifted = new Date(instant + minutes * 60_000);

	return `${shifted.toISOString().slice(0, 19)}${offset.slice(0, 3)}:${offset.slice(3, 5)}`;
}

/** One `author`/`committer` header line, without its trailing newline. */
function identityLine(field: string, identity: CommitIdentity): string {
	return `${field} ${identity.name} <${identity.email}> ${gitTimestamp(identity.date, identity.offset)}`;
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

/**
 * Every `±HHMM` a real commit is likely to carry, nearest UTC first.
 *
 * UTC−12:00 through UTC+14:00 in quarter-hour steps — the range and granularity
 * IANA's zones actually use, which covers `+0545` (Kathmandu), `+0845` (Eucla)
 * and `+1245` (Chatham) as well as every whole and half hour. Ordered by
 * distance from UTC because that is the order that finds an answer soonest:
 * `+0000` is what CI produces and `±0100`/`±0200` is what most laptops do.
 *
 * A commit whose offset is outside this set — a historical `+0020`, a
 * hand-written oddity — is not reproduced, and therefore not rewritten. See
 * {@link recoverCommitObject}.
 */
export const GIT_OFFSET_CANDIDATES: readonly string[] = (() => {
	const minutes: number[] = [];
	for (let value = -12 * 60; value <= 14 * 60; value += 15) {
		minutes.push(value);
	}

	return minutes
		.sort((a, b) => Math.abs(a) - Math.abs(b) || a - b)
		.map((value) => {
			const sign = value < 0 ? "-" : "+";
			const absolute = Math.abs(value);
			return `${sign}${String(Math.floor(absolute / 60)).padStart(2, "0")}${String(absolute % 60).padStart(2, "0")}`;
		});
})();

/** The offsets an existing commit object turned out to carry. */
export interface CommitOffsets {
	author: string;
	committer: string;
}

/**
 * What reproducing an existing commit object proved about its bytes.
 *
 * Both fields come from the same successful match and neither is usable without
 * the other: the id that proves the offsets is the id over an object containing
 * this exact message, so a caller that took the offsets and kept the API's
 * message would be relying on a proof of something it then did not do.
 */
export interface CommitReconstruction {
	/** The `±HHMM` offsets the stored object carries. */
	offsets: CommitOffsets;
	/**
	 * The message exactly as the object holds it — trailing newline and all.
	 *
	 * `GET /git/commits/{sha}` strips a single trailing `\n`, which is precisely
	 * the byte `git commit` writes on every message it makes. So this is the API's
	 * message for a commit that had none and the API's message plus that newline
	 * for one that had it, and which of the two it is was decided by the object
	 * id rather than guessed. This is the message to sign and the message to send
	 * back — GitHub's create-a-commit endpoint stores the trailing newline it is
	 * given, verified against the live API.
	 */
	message: string;
}

/**
 * Work out what offsets `sha` was really written with, by reproducing it.
 *
 * The reconstruction is checked against the commit's own object id rather than
 * believed. That id was computed by Git over the bytes the repository holds, so
 * a candidate that reproduces it has reproduced *the whole object* — the two
 * offsets and everything alongside them — and one that does not has been
 * refuted. It is the only check available that GitHub's JSON cannot quietly
 * agree with, because the sha predates the JSON.
 *
 * Two ambiguities are resolved at once, because both change the bytes and
 * neither is answerable from the API alone:
 *
 * - **The offsets**, which `GET /git/commits/{sha}` renders away entirely.
 * - **A trailing newline on the message**, which that endpoint strips: some
 *   objects have one and some do not, and the JSON looks identical either way.
 *   The variant that matched is *returned*, not merely tried: it is the message
 *   the object holds, and signing the other one would publish a signature over
 *   bytes the author did not write.
 *
 * Author and committer offsets are searched together first, since a commit
 * whose two offsets differ is the exception (a rebase across a timezone, an
 * explicit `--date`). `authorOffset` pins one side so the other can be searched
 * alone; the caller supplies it from a source that kept it, which for GitHub
 * means the patch representation.
 *
 * @param commit - The commit as GitHub's JSON described it, offsets absent
 * @param sha - The object id that reconstruction has to reproduce
 * @param authorOffset - `±HHMM`, when it is already known
 * @returns The proven offsets and message, or null when nothing reproduced
 *   `sha` — a commit carrying a header this module does not model, or an offset
 *   outside {@link GIT_OFFSET_CANDIDATES}. Null means "do not rewrite this",
 *   never "assume UTC" and never "use the message as it arrived".
 */
export async function recoverCommitObject(
	commit: CommitObject,
	sha: string,
	authorOffset?: string,
): Promise<CommitReconstruction | null> {
	if (authorOffset !== undefined && !GIT_OFFSET.test(authorOffset)) {
		return null;
	}

	// As returned, then with the newline the API strips. Order matters only for
	// speed; both are tried before a candidate is discarded, and whichever one
	// matched is what comes back.
	const messages = [commit.message, `${commit.message}\n`];

	for (const candidate of GIT_OFFSET_CANDIDATES) {
		const offsets: CommitOffsets = { author: authorOffset ?? candidate, committer: candidate };

		for (const message of messages) {
			const payload = commitPayload({
				tree: commit.tree,
				parents: commit.parents,
				author: { ...commit.author, offset: offsets.author },
				committer: { ...commit.committer, offset: offsets.committer },
				message,
			});

			if ((await commitObjectId(payload)) === sha) {
				return { offsets, message };
			}
		}
	}

	return null;
}
