/**
 * The first thing a webhook can *cause*, and the ways it must not be causable.
 *
 * Everything before this slice refused; this one acts. So the suite is written
 * against the ways acting goes wrong rather than against the shape of the code
 * that acts, and four of those ways are worth naming up front because a
 * confirmatory test would pass while each of them was true:
 *
 * - **A handler that took the repository from the payload would sign the right
 *   commits in the wrong repository, and every happy-path test would still
 *   pass.** So the client stub *refuses* any path outside the authorized
 *   repository, and the payload in the cross-repository tests names a different
 *   one from the allowlist entry.
 * - **A handler that re-signed already-signed commits would produce a branch
 *   full of valid signatures and a destroyed history.** So the walk is asserted
 *   to stop at a signature it did not make, and the loop-suppression test is the
 *   exact commit state a push of this service's own work produces.
 * - **A handler that committed the delivery id before acting would look correct
 *   until the first failure.** So every recoverable failure is asserted by
 *   *redelivering it* and requiring the handler to be reached a second time, and
 *   the irreversible one is asserted by redelivering it and requiring that it is
 *   not.
 * - **A serialiser that agreed with the test that checks it proves nothing.**
 *   So `git-commit` is checked against a real commit out of this repository's
 *   history, object id and all.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import { signingBudgetIdentity } from "#routes/github-webhook";
import type { Env } from "#types";
import type { CommitOffsets } from "#utils/git-commit";
import {
	commitObjectId,
	commitPayload,
	GIT_OFFSET_CANDIDATES,
	gitTimestamp,
	isoWithOffset,
	recoverCommitOffsets,
	signedCommitObject,
} from "#utils/git-commit";
import { GITHUB_API_ORIGIN } from "#utils/github-app";
import { branchFromRef, MAX_SIGNABLE_COMMITS, planPush, signableRun } from "#utils/github-push";
import type { RepositoryCommit } from "#utils/github-repo";
import { patchAuthorOffset, RepositoryClient } from "#utils/github-repo";
import { SIGNATURE_PREFIX } from "#utils/github-webhook";
import { signPushedCommits } from "#utils/push-signing";
import {
	FIXTURE_OBJECT,
	FIXTURE_SHA,
	NON_UTC_API,
	NON_UTC_OBJECT,
	NON_UTC_PATCH,
	NON_UTC_SHA,
	SKEWED_API,
	SKEWED_OBJECT,
	SKEWED_PATCH,
	SKEWED_SHA,
} from "./helpers/git-commit-fixture";

const SECRET = "test-webhook-secret";
const INSTALLATION = 4242;
const REPOSITORY = "kjanat/service";
const OTHER_REPOSITORY = "kjanat/other";
const KEY = "62E75E54497815DD";

describe("reproducing a commit object", () => {
	// Against a real one. See `helpers/git-commit-fixture`.
	const boundary = FIXTURE_OBJECT.indexOf("\ngpgsig ");
	const headers = FIXTURE_OBJECT.slice(0, boundary);
	const folded = FIXTURE_OBJECT.slice(boundary + "\ngpgsig ".length);
	const signatureEnd = folded.indexOf("-----END PGP SIGNATURE-----") + "-----END PGP SIGNATURE-----".length;
	const signature = folded.slice(0, signatureEnd).split("\n ").join("\n");
	const rest = folded.slice(signatureEnd);

	/** The fixture's payload: the same object with its `gpgsig` header removed. */
	const payload = `${headers}${rest}`;

	it("names a real commit the way Git names it", async () => {
		expect(await commitObjectId(FIXTURE_OBJECT)).toBe(FIXTURE_SHA);
	});

	it("folds a signature back into the object Git stored, byte for byte", async () => {
		// The fold is the part most likely to be wrong and least likely to be
		// noticed: an armored block contains an empty line, which Git writes as a
		// line containing a single space. Getting it wrong changes the object id
		// and therefore invalidates the signature, silently.
		expect(signedCommitObject(payload, signature)).toBe(FIXTURE_OBJECT);
		expect(await commitObjectId(signedCommitObject(payload, signature))).toBe(FIXTURE_SHA);
	});

	it("rebuilds the payload from the parts a GitHub API response carries", () => {
		// The direction that matters in production: nothing hands us the object,
		// only fields, and the payload has to come back out of them exactly.
		const [, tree] = /^tree (\w+)$/m.exec(headers) as RegExpExecArray;
		const parents = [...headers.matchAll(/^parent (\w+)$/gm)].map((match) => match[1] as string);
		const [, authorName, authorEmail, authorSeconds, authorOffset] = /^author (.+) <(.+)> (\d+) (\S+)$/m.exec(
			headers,
		) as RegExpExecArray;
		const [, committerName, committerEmail, committerSeconds, committerOffset] =
			/^committer (.+) <(.+)> (\d+) (\S+)$/m.exec(headers) as RegExpExecArray;

		const iso = (seconds: string, offset: string) =>
			new Date(Number(seconds) * 1000).toISOString().replace("Z", offset === "+0000" ? "Z" : offset);

		expect(
			commitPayload({
				tree: tree as string,
				parents,
				author: {
					name: authorName as string,
					email: authorEmail as string,
					date: iso(authorSeconds as string, authorOffset as string),
				},
				committer: {
					name: committerName as string,
					email: committerEmail as string,
					date: iso(committerSeconds as string, committerOffset as string),
				},
				message: rest.slice(2),
			}),
		).toBe(payload);
	});

	it("keeps the offset the date carried rather than normalising it", () => {
		// Two strings for the same instant, and two different commit objects. A
		// conversion that helpfully normalised to UTC would produce a payload that
		// hashes to something GitHub never built — which the round-trip check would
		// catch, after wasting the signature.
		expect(gitTimestamp("2026-08-31T09:00:00+02:00")).toBe("1788159600 +0200");
		expect(gitTimestamp("2026-08-31T07:00:00Z")).toBe("1788159600 +0000");
		expect(gitTimestamp("2026-08-31T09:00:00+02:00")).not.toBe(gitTimestamp("2026-08-31T07:00:00Z"));
	});

	it("refuses a date whose offset it cannot reproduce", () => {
		// A commit whose date cannot be reproduced exactly is one this service
		// declines to sign, rather than one it signs approximately.
		expect(() => gitTimestamp("2026-08-31T09:00:00")).toThrow(/offset/);
		expect(() => gitTimestamp("not a date")).toThrow();
	});

	it("measures the object header in bytes, not characters", async () => {
		// A message with one emoji in it is longer than its `String.length`, and a
		// length header off by three bytes names a different object.
		const header = "tree a\nauthor a <a> 1 +0000\ncommitter a <a> 1 +0000\n\n";
		// One astral-plane character is two UTF-16 units and four UTF-8 bytes, so
		// these two strings have the same `String.length` and different byte
		// lengths. A header measured in characters names the same object for both.
		const withEmoji = `${header}fix: 🎉`;
		const ascii = `${header}fix: xx`;

		expect(withEmoji.length).toBe(ascii.length);
		expect(await commitObjectId(withEmoji)).not.toBe(await commitObjectId(ascii));
	});

	it("refuses a date that matches the shape and is not a date", () => {
		// The regex says the string is shaped like ISO 8601 with an offset; that is
		// not the same as being a date. A month of 13 gets past the shape and
		// produces NaN seconds, which would be written into a commit object.
		expect(() => gitTimestamp("2026-13-45T09:00:00Z")).toThrow(/not a date/);
	});

	it("refuses to fold a signature into something with no header block", () => {
		expect(() => signedCommitObject("no blank line anywhere", "sig")).toThrow(/header boundary/);
	});

	it("splits the header block at the first blank line, not at one in the message", () => {
		const message = "subject\n\nbody with\n\na blank line";
		const built = commitPayload({
			tree: "t",
			parents: [],
			author: { name: "a", email: "a@b", date: "2026-01-01T00:00:00Z" },
			committer: { name: "a", email: "a@b", date: "2026-01-01T00:00:00Z" },
			message,
		});

		const signed = signedCommitObject(built, "-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----");

		expect(signed).toContain("committer a <a@b> 1767225600 +0000\ngpgsig ");
		expect(signed.endsWith(`\n\n${message}`)).toBe(true);
	});
});

/**
 * The timezone offset, which is the one field GitHub's JSON does not carry.
 *
 * These are the tests that would have failed before the offset was recovered,
 * and they are written against real commits for the reason the whole fixture
 * file exists: the claim under test is "GitHub's JSON is not enough to rebuild
 * this object", and a fixture invented alongside the code would have been
 * invented from the same belief the code holds.
 */
describe("recovering the timezone offset GitHub does not report", () => {
	/** `NON_UTC_API`, shaped the way `commitPayload` takes it. */
	const fromApi = (api: typeof NON_UTC_API | typeof SKEWED_API) => ({
		tree: api.tree.sha,
		parents: api.parents.map((parent) => parent.sha),
		author: { ...api.author },
		committer: { ...api.committer },
		message: api.message,
	});

	it("the fixtures are the commits Git says they are", async () => {
		// Before anything is asserted *about* them: these bytes hash to these ids,
		// so a failure below is about the code rather than about a stale fixture.
		await expect(commitObjectId(NON_UTC_OBJECT)).resolves.toBe(NON_UTC_SHA);
		await expect(commitObjectId(SKEWED_OBJECT)).resolves.toBe(SKEWED_SHA);
	});

	it("does not reproduce a +0200 commit from GitHub's JSON alone", async () => {
		// The regression, stated as the bug rather than as its fix. Every date this
		// API reports is `Z`; echoing it back writes `+0000` into the object, and
		// the object that comes out is a different commit from the one that went
		// in — moved two hours, with a different id, and `git log` on the rewritten
		// branch showing a time the author never committed at.
		const normalised = commitPayload(fromApi(NON_UTC_API));

		expect(normalised).toContain("1788116700 +0000");
		await expect(commitObjectId(normalised)).resolves.not.toBe(NON_UTC_SHA);
	});

	it("recovers +0200 by reproducing the commit's own object id", async () => {
		const offsets = await recoverCommitOffsets(fromApi(NON_UTC_API), NON_UTC_SHA);

		expect(offsets).toEqual({ author: "+0200", committer: "+0200" });

		// And the proof is byte-for-byte, not just id-for-id: with the recovered
		// offsets the payload *is* what `git cat-file` prints.
		expect(
			commitPayload({
				...fromApi(NON_UTC_API),
				author: { ...NON_UTC_API.author, offset: (offsets as CommitOffsets).author },
				committer: { ...NON_UTC_API.committer, offset: (offsets as CommitOffsets).committer },
			}),
		).toBe(NON_UTC_OBJECT);
	});

	it("cannot recover a commit whose two offsets differ without help", async () => {
		// The cheap search tries the offsets *together*, because a commit whose
		// author and committer disagree is the exception. This is that exception,
		// and it has to answer null rather than settle for a near miss — a pair
		// that reproduces nothing is not a pair to sign with.
		await expect(recoverCommitOffsets(fromApi(SKEWED_API), SKEWED_SHA)).resolves.toBeNull();
	});

	it("recovers both halves once the patch pins the author's", async () => {
		const authorOffset = patchAuthorOffset(SKEWED_PATCH, SKEWED_SHA);
		expect(authorOffset).toBe("+0545");

		const offsets = await recoverCommitOffsets(fromApi(SKEWED_API), SKEWED_SHA, authorOffset as string);

		expect(offsets).toEqual({ author: "+0545", committer: "-0330" });

		// This fixture's message also ends in a newline, which is the other thing
		// the API strips and the other ambiguity the id resolves. Reproducing the
		// object exactly is the assertion that both were resolved the right way.
		expect(
			commitPayload({
				...fromApi(SKEWED_API),
				author: { ...SKEWED_API.author, offset: (offsets as CommitOffsets).author },
				committer: { ...SKEWED_API.committer, offset: (offsets as CommitOffsets).committer },
				message: `${SKEWED_API.message}\n`,
			}),
		).toBe(SKEWED_OBJECT);
	});

	it("refuses an author offset that is not ±HHMM rather than searching around it", async () => {
		await expect(recoverCommitOffsets(fromApi(SKEWED_API), SKEWED_SHA, "+05:45")).resolves.toBeNull();
		await expect(recoverCommitOffsets(fromApi(SKEWED_API), SKEWED_SHA, "nonsense")).resolves.toBeNull();
	});

	it("answers null for a commit it cannot reproduce at all", async () => {
		// A header this module does not model, an offset outside the candidates, a
		// sha that belongs to something else. All the same answer, and the answer
		// is "do not rewrite this" — never "assume UTC".
		await expect(recoverCommitOffsets(fromApi(NON_UTC_API), "0".repeat(40))).resolves.toBeNull();
	});

	it.each([
		["the offset out of a real GitHub patch", NON_UTC_PATCH, NON_UTC_SHA, "+0200"],
		["a subject folded across two lines", SKEWED_PATCH, SKEWED_SHA, "+0545"],
	])("reads %s", (_case, patch, sha, expected) => {
		expect(patchAuthorOffset(patch, sha)).toBe(expected);
	});

	it("refuses a patch whose first line names a different commit", () => {
		// The case that makes this safe on a merge: asking for a merge commit's
		// patch returns the patches of the commits it merged. Believing that
		// `Date:` would stamp one of *their* timezones onto the merge.
		expect(patchAuthorOffset(NON_UTC_PATCH, SKEWED_SHA)).toBeNull();
		expect(patchAuthorOffset("", NON_UTC_SHA)).toBeNull();
	});

	it("answers null for a header block with no `Date:` at all", () => {
		// A rendering that names the right commit and never says when. Falling
		// through the whole block is the same answer as finding the wrong one:
		// nothing to pin the author's offset with.
		expect(patchAuthorOffset(`From ${NON_UTC_SHA} Mon Sep 17 00:00:00 2001\nFrom: A <a@b>\n`, NON_UTC_SHA)).toBeNull();
		// And the same when the block simply ends: no blank line to stop at either.
		expect(patchAuthorOffset(`From ${NON_UTC_SHA} Mon Sep 17 00:00:00 2001\nFrom: A <a@b>`, NON_UTC_SHA)).toBeNull();
	});

	it("refuses an offset it can parse over a date it cannot", () => {
		expect(() => isoWithOffset("not a date", "+0200")).toThrow(/not a date/);
	});

	it("does not read a `Date:` out of the diff body", () => {
		// The mail header block ends at the first blank line. A patch that touches
		// a changelog can contain a line starting `Date:` further down, and it is
		// not the commit's.
		const patch = `From ${NON_UTC_SHA} Mon Sep 17 00:00:00 2001\nFrom: A <a@b>\nSubject: x\n\n+Date: Sun, 30 Aug 2026 21:05:00 +0900\n`;

		expect(patchAuthorOffset(patch, NON_UTC_SHA)).toBeNull();
	});

	it("writes a recovered offset back into the ISO create-a-commit takes", () => {
		// The direction that puts the offset on the wire. GitHub stores what it is
		// given — checked against the live API with an author at `+0545` and a
		// committer at `-0330`, both preserved — so this string is what decides
		// what the rewritten object says.
		expect(isoWithOffset("2026-08-30T19:05:00Z", "+0200")).toBe("2026-08-30T21:05:00+02:00");
		expect(isoWithOffset("2026-08-30T19:05:00Z", "+0545")).toBe("2026-08-31T00:50:00+05:45");
		expect(isoWithOffset("2026-08-30T19:05:00Z", "-0330")).toBe("2026-08-30T15:35:00-03:30");
		// Same instant either way: only the rendering moved.
		expect(Date.parse(isoWithOffset("2026-08-30T19:05:00Z", "-0330"))).toBe(Date.parse("2026-08-30T19:05:00Z"));
	});

	it.each(["+02:00", "0200", "+2", "", "Z"])("refuses %o as an offset", (offset) => {
		expect(() => isoWithOffset("2026-08-30T19:05:00Z", offset)).toThrow(/±HHMM/);
		expect(() => gitTimestamp("2026-08-30T19:05:00Z", offset)).toThrow(/±HHMM/);
	});

	it("writes the offset it is handed rather than the one in the string", () => {
		expect(gitTimestamp("2026-08-30T19:05:00Z", "+0200")).toBe("1788116700 +0200");
		expect(gitTimestamp("2026-08-30T21:05:00+02:00")).toBe("1788116700 +0200");
		expect(gitTimestamp("2026-08-30T19:05:00Z")).toBe("1788116700 +0000");
	});

	it("searches the offsets the world actually uses, nearest UTC first", () => {
		// Quarter-hour steps across UTC−12:00 to UTC+14:00, which is the range and
		// granularity IANA's zones use. Ordered so the common answers come first:
		// `+0000` is what CI produces, `±0100`/`±0200` what most laptops do.
		expect(GIT_OFFSET_CANDIDATES[0]).toBe("+0000");
		expect(GIT_OFFSET_CANDIDATES).toContain("+0545");
		expect(GIT_OFFSET_CANDIDATES).toContain("-0330");
		expect(GIT_OFFSET_CANDIDATES).toContain("+1245");
		expect(GIT_OFFSET_CANDIDATES).toContain("-1200");
		expect(GIT_OFFSET_CANDIDATES).toContain("+1400");
		expect(new Set(GIT_OFFSET_CANDIDATES).size).toBe(GIT_OFFSET_CANDIDATES.length);
		expect(GIT_OFFSET_CANDIDATES.every((offset) => /^[+-]\d{4}$/.test(offset))).toBe(true);
	});
});

describe("deciding what a push may cause", () => {
	it("acts on a branch push", () => {
		expect(planPush({ ref: "refs/heads/main", deleted: false })).toEqual({ act: true, branch: "main" });
		expect(planPush({ ref: "refs/heads/feature/x", deleted: false })).toEqual({ act: true, branch: "feature/x" });
	});

	it.each([
		["a tag", { ref: "refs/tags/v1", deleted: false }, "not_a_branch"],
		["a note", { ref: "refs/notes/commits", deleted: false }, "not_a_branch"],
		["a deletion", { ref: "refs/heads/main", deleted: true }, "branch_deleted"],
		["no ref at all", { deleted: false }, "malformed"],
		["a non-object payload", "refs/heads/main", "malformed"],
		["an array payload", [], "malformed"],
	])("refuses %s", (_case, payload, reason) => {
		expect(planPush(payload)).toEqual({ act: false, reason });
	});

	it.each([
		["absent", { ref: "refs/heads/main" }],
		["null", { ref: "refs/heads/main", deleted: null }],
		['the string "false"', { ref: "refs/heads/main", deleted: "false" }],
		['the string "true"', { ref: "refs/heads/main", deleted: "true" }],
		["the empty string", { ref: "refs/heads/main", deleted: "" }],
		["zero", { ref: "refs/heads/main", deleted: 0 }],
		["one", { ref: "refs/heads/main", deleted: 1 }],
		["NaN", { ref: "refs/heads/main", deleted: Number.NaN }],
		["an object", { ref: "refs/heads/main", deleted: {} }],
		["an empty array", { ref: "refs/heads/main", deleted: [] }],
		["an array holding false", { ref: "refs/heads/main", deleted: [false] }],
		["a boxed false", { ref: "refs/heads/main", deleted: new Boolean(false) }],
		["undefined, spelled out", { ref: "refs/heads/main", deleted: undefined }],
	])("refuses a payload whose `deleted` is %s", (_case, payload) => {
		// The rule is "prove you are not a deletion", not "do not look like one".
		// Every value here is falsy, or truthy-but-not-true, or absent — and under
		// a `deleted === true` test every single one of them would have acted. A
		// payload that is merely *silent* about being a deletion must not be able
		// to buy a branch rewrite by omitting the field that would have stopped it.
		expect(planPush(payload)).toEqual({ act: false, reason: "malformed" });
	});

	it("refuses a `deleted` it cannot believe before it reads the ref at all", () => {
		// Ordering, asserted rather than assumed: the ref is a value that ends up
		// interpolated into an API path, and a payload that failed the deletion
		// proof should not have that value examined, let alone used. A ref that
		// would otherwise be `not_a_branch` still answers `malformed`, which is
		// only true if the `deleted` gate ran first.
		expect(planPush({ ref: "refs/tags/v1", deleted: "false" })).toEqual({ act: false, reason: "malformed" });
		expect(planPush({ ref: "refs/heads/../../etc", deleted: null })).toEqual({ act: false, reason: "malformed" });
	});

	it("still tells a genuine deletion apart from a payload it cannot read", () => {
		// Fail-closed must not collapse the two: `branch_deleted` is a repository
		// state an operator can recognise in a log line, `malformed` is a delivery
		// nobody should have sent. Widening the refusal is not the same as losing
		// the distinction.
		expect(planPush({ ref: "refs/heads/main", deleted: true })).toEqual({ act: false, reason: "branch_deleted" });
		expect(planPush({ ref: "refs/heads/main", deleted: false })).toEqual({ act: true, branch: "main" });
	});

	it.each([
		["a traversal", "refs/heads/../../etc"],
		["a lock ref", "refs/heads/main.lock"],
		["a reflog selector", "refs/heads/main@{1}"],
		["a doubled separator", "refs/heads/a//b"],
		["a leading slash", "refs/heads//a"],
		["a trailing slash", "refs/heads/a/"],
		["an empty name", "refs/heads/"],
		["a space", "refs/heads/a b"],
		["a newline", "refs/heads/a\nb"],
		["a non-string", 42],
	])("refuses %s as a branch name", (_case, ref) => {
		// The branch is interpolated into an API path and then used to move a ref.
		// A name this rejects is not signed, rather than signed somewhere else.
		expect(branchFromRef(ref)).toBeNull();
	});
});

/**
 * A commit as the client would report it, with only the fields under test set.
 *
 * `offsets` is populated by default because that is what a commit that came out
 * of `RepositoryClient.getCommit` looks like: the offsets were recovered and
 * proven against the sha. Pass null for the commit the recovery could not
 * reproduce, which is the one the walk has to refuse.
 */
function commit(sha: string, parents: string[], signed = false, offset: string | null = "+0200"): RepositoryCommit {
	const identity = {
		name: "Kaj Kowalski",
		email: "info@kajkowalski.nl",
		date: "2026-08-31T07:00:00Z",
		...(offset === null ? {} : { offset }),
	};

	return {
		sha,
		message: `commit ${sha}`,
		tree: `tree-${sha}`,
		parents,
		author: { ...identity },
		committer: { ...identity },
		offsets: offset === null ? null : { author: offset, committer: offset },
		signed,
	};
}

/** A chain, newest first, resolvable by sha. */
function chain(commits: RepositoryCommit[]) {
	const byId = new Map(commits.map((c) => [c.sha, c]));
	return (sha: string) => {
		const found = byId.get(sha);
		if (!found) {
			throw new Error(`walked off the chain at ${sha}`);
		}
		return Promise.resolve(found);
	};
}

describe("choosing which commits to rewrite", () => {
	it("takes the unsigned run at the tip, oldest first", async () => {
		const run = await signableRun("c", chain([commit("c", ["b"]), commit("b", ["a"]), commit("a", [], true)]));

		expect(run.act && run.commits.map((c) => c.sha)).toEqual(["b", "c"]);
	});

	it("stops at a signature it did not make, and leaves everything beneath it", async () => {
		// The rule that makes "leave already-correct signatures alone" achievable
		// at all: rewriting a commit changes its id, which invalidates its
		// children's signatures. So an unsigned commit *below* a signed one stays
		// unsigned, and that is the honest outcome rather than an oversight.
		const run = await signableRun(
			"d",
			chain([commit("d", ["c"]), commit("c", ["b"], true), commit("b", ["a"]), commit("a", [])]),
		);

		expect(run.act && run.commits.map((c) => c.sha)).toEqual(["d"]);
	});

	it("stops on a head this service just signed, which is the loop suppression", async () => {
		// The exact commit state a push by this service produces: the head carries
		// a signature. The walk sees it immediately, the run is empty, and the plan
		// is `nothing_to_sign` — so the delivery raised by our own ref update signs
		// nothing and raises nothing further.
		//
		// Asserted as *state* rather than as a check on `sender`, `pusher` or the
		// event name, all of which are payload fields. A loop stopped by the object
		// graph stops whether or not those fields say what we expected.
		const run = await signableRun("signed-head", chain([commit("signed-head", ["b"], true), commit("b", [])]));

		expect(run).toEqual({ act: false, reason: "nothing_to_sign" });
	});

	it("follows first parents only, so a merge's other parents are untouched", async () => {
		const merge = commit("m", ["a", "side"]);
		const run = await signableRun("m", chain([merge, commit("a", [], true), commit("side", [])]));

		// `side` is never fetched — the stub throws for anything off the walk — and
		// it keeps whatever id and signature it has.
		expect(run.act && run.commits.map((c) => c.sha)).toEqual(["m"]);
	});

	it("reaches a root commit without walking off the end", async () => {
		const run = await signableRun("a", chain([commit("a", [])]));

		expect(run.act && run.commits.map((c) => c.sha)).toEqual(["a"]);
	});

	it("refuses the whole run when one commit could not be reproduced", async () => {
		// A commit whose exact bytes could not be rebuilt from what the API reports
		// is one this service must not rewrite: signing it would publish a
		// signature over something other than what the author wrote. And the
		// refusal is the *run*, not the commit — a run is rewritten as a chain, so
		// everything above the unreproducible one is disqualified with it.
		const run = await signableRun(
			"c",
			chain([commit("c", ["b"]), commit("b", ["a"], false, null), commit("a", [], true)]),
		);

		expect(run).toEqual({ act: false, reason: "unreproducible_commit" });
	});

	it("refuses before it has read past the commit it cannot reproduce", async () => {
		// Nothing beneath it is fetched, and nothing above it is signed. Asserted
		// against the walk's own reads rather than inferred from the answer.
		const read: string[] = [];
		const commits = [commit("c", ["b"]), commit("b", ["a"], false, null), commit("a", [], true)];
		const walk = chain(commits);

		const run = await signableRun("c", (sha) => {
			read.push(sha);
			return walk(sha);
		});

		expect(run).toEqual({ act: false, reason: "unreproducible_commit" });
		expect(read).toEqual(["c", "b"]);
	});

	it("refuses a run longer than one delivery may rewrite", async () => {
		// A bound, not a tuning parameter. A push of hundreds of unsigned commits
		// is a history event that wants a person looking at it.
		const commits = Array.from({ length: MAX_SIGNABLE_COMMITS + 2 }, (_unused, index) =>
			commit(`c${index}`, index === 0 ? [] : [`c${index - 1}`]),
		);
		const run = await signableRun(`c${commits.length - 1}`, chain(commits));

		expect(run).toEqual({ act: false, reason: "too_many_unsigned" });
	});
});

/**
 * A `RepositoryClient` double that records what was asked of it.
 *
 * Deliberately not a mock of the real class: what these tests are about is the
 * order of operations around the irreversible boundary, and a double that
 * records every call in sequence is what makes "nothing was published" an
 * assertion rather than an inference.
 */
function fakeClient(options: {
	commits: RepositoryCommit[];
	head: string;
	headOnSecondRead?: string | null;
	createFails?: boolean;
	createReturns?: (expected: string) => string;
	updateFails?: boolean;
}) {
	const calls: string[] = [];
	let reads = 0;

	const client = {
		repository: REPOSITORY,
		getBranch: (branch: string) => {
			reads += 1;
			calls.push(`getBranch:${branch}`);
			// `in` rather than `??`, so a deliberate `null` — the branch was deleted
			// while this worked — is not read as "unchanged".
			const sha =
				reads === 1 || !("headOnSecondRead" in options) ? options.head : (options.headOnSecondRead as string | null);
			return Promise.resolve(sha === null ? null : { ref: `refs/heads/${branch}`, sha });
		},
		getCommit: (sha: string) => {
			calls.push(`getCommit:${sha}`);
			return chain(options.commits)(sha);
		},
		createCommit: async (input: {
			parents: string[];
			message: string;
			tree: string;
			author: { name: string; email: string; date: string };
			committer: { name: string; email: string; date: string };
			signature: string;
		}) => {
			calls.push(`createCommit:${input.parents.join(",")}`);
			if (options.createFails) {
				throw new Error("GitHub refused a commit creation");
			}
			// By default the double behaves as GitHub does when it agrees: it
			// assembles the object from the fields it was handed and names it the
			// same way. So the round-trip check passes only when the module built
			// the payload from those same fields — which is the point of it.
			const expected = await commitObjectId(
				signedCommitObject(
					commitPayload({
						tree: input.tree,
						parents: input.parents,
						author: input.author,
						committer: input.committer,
						message: input.message,
					}),
					input.signature,
				),
			);
			return options.createReturns ? options.createReturns(expected) : expected;
		},
		updateBranch: (branch: string, sha: string) => {
			calls.push(`updateBranch:${branch}:${sha}`);
			if (options.updateFails) {
				throw new Error("GitHub refused a branch update");
			}
			return Promise.resolve();
		},
	};

	return { client: client as unknown as RepositoryClient, calls };
}

/** A real PGP key, so the signatures under test are real signatures. */
async function signingKey() {
	const { privateKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "ed25519Legacy",
		userIDs: [{ name: "Push Signing", email: "push@test.com" }],
		passphrase: env.KEY_PASSPHRASE,
		format: "armored",
	});

	return {
		keyId: KEY,
		armoredPrivateKey: privateKey,
		publicKey: "",
		algorithm: "eddsa",
		fingerprint: "f".repeat(40),
		createdAt: new Date().toISOString(),
	} as never;
}

/** Hooks that record whether the irreversible boundary was crossed. */
function hooks(budget: "ok" | "limited" | "unavailable" = "ok") {
	const state = { published: false, budgetAskedFor: 0 };
	return {
		state,
		hooks: {
			reserveBudget: (commits: number) => {
				state.budgetAskedFor = commits;
				return Promise.resolve(budget);
			},
			beforePublish: () => {
				state.published = true;
				return Promise.resolve();
			},
		},
	};
}

describe("the irreversible boundary", () => {
	// Every test here asserts *both* what was returned and whether the boundary
	// was crossed, because the second is what the delivery ledger acts on and a
	// result that says "failed" while having published is a different event from
	// one that says "failed" and has not.

	it("signs the run and moves the branch, in that order", async () => {
		const key = await signingKey();
		const { client, calls } = fakeClient({ commits: [commit("b", ["a"]), commit("a", [], true)], head: "b" });
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result.outcome).toBe("signed");
		expect(state.published).toBe(true);
		// The order is the property: create before publish, publish last.
		expect(calls.filter((call) => call.startsWith("updateBranch"))).toHaveLength(1);
		expect(calls.indexOf("createCommit:a")).toBeLessThan(calls.findIndex((c) => c.startsWith("updateBranch")));
	});

	it("asks the budget for one token per commit, before signing anything", async () => {
		// The webhook meter in front of the route counts requests per IP. That is
		// not a signing budget: one request can carry twenty signatures.
		const key = await signingKey();
		const { client } = fakeClient({
			commits: [commit("c", ["b"]), commit("b", ["a"]), commit("a", [], true)],
			head: "c",
		});
		const { state, hooks: h } = hooks();

		await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(state.budgetAskedFor).toBe(2);
	});

	it("publishes nothing when the budget refuses", async () => {
		const key = await signingKey();
		const { client, calls } = fakeClient({ commits: [commit("b", ["a"]), commit("a", [], true)], head: "b" });
		const { state, hooks: h } = hooks("limited");

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result).toEqual({ outcome: "refused", reason: "rate_limited" });
		expect(state.published).toBe(false);
		expect(calls.some((call) => call.startsWith("createCommit"))).toBe(false);
	});

	it("publishes nothing when the limiter cannot be reached", async () => {
		const key = await signingKey();
		const { client } = fakeClient({ commits: [commit("b", ["a"]), commit("a", [], true)], head: "b" });
		const { state, hooks: h } = hooks("unavailable");

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result).toEqual({ outcome: "refused", reason: "limiter_unavailable" });
		expect(state.published).toBe(false);
	});

	it("publishes nothing when GitHub refuses a commit creation", async () => {
		const key = await signingKey();
		const { client } = fakeClient({
			commits: [commit("b", ["a"]), commit("a", [], true)],
			head: "b",
			createFails: true,
		});
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result.outcome).toBe("failed");
		expect(result.outcome === "failed" && result.published).toBe(false);
		expect(state.published).toBe(false);
	});

	it("refuses when GitHub assembles a different object than the one signed", async () => {
		// The whole-payload check. If GitHub's assembly differs from ours by one
		// byte, the signature it stored is over a different object than the one
		// that now exists — and nothing in its response says so. The created object
		// is unreachable and gets collected, so refusing costs the call and nothing
		// else.
		const key = await signingKey();
		const { client } = fakeClient({
			commits: [commit("b", ["a"]), commit("a", [], true)],
			head: "b",
			createReturns: () => "0".repeat(40),
		});
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result.outcome === "failed" && result.reason).toContain("different commit object");
		expect(result.outcome === "failed" && result.published).toBe(false);
		expect(state.published).toBe(false);
	});

	it("abandons the run when the branch moved while it worked", async () => {
		// The update is a force update — a rewritten head is not a descendant of
		// the old one — so a concurrent push would be discarded silently. Re-reading
		// immediately before publishing does not close the window entirely, and
		// nothing available over this API does; it closes the one that is open in
		// practice.
		const key = await signingKey();
		const { client, calls } = fakeClient({
			commits: [commit("b", ["a"]), commit("a", [], true)],
			head: "b",
			headOnSecondRead: "somebody-elses-push",
		});
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result).toEqual({ outcome: "skipped", reason: "branch_moved" });
		expect(state.published).toBe(false);
		expect(calls.some((call) => call.startsWith("updateBranch"))).toBe(false);
	});

	it("reports a failed branch update as published, because it may have landed", async () => {
		// Past the boundary. The request was sent and the answer was lost, which is
		// exactly the case that makes committing the delivery id *before* the
		// update the only safe order: repeating a force update on the assumption it
		// failed is how a branch gets moved twice.
		const key = await signingKey();
		const { client } = fakeClient({
			commits: [commit("b", ["a"]), commit("a", [], true)],
			head: "b",
			updateFails: true,
		});
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result.outcome === "failed" && result.published).toBe(true);
		expect(state.published).toBe(true);
	});

	it("publishes nothing when the key will not sign", async () => {
		// A stored key that cannot be decrypted or parsed. Caught rather than
		// escaping, so the delivery is reported as unpublished and stays
		// redeliverable.
		const { client, calls } = fakeClient({ commits: [commit("b", ["a"]), commit("a", [], true)], head: "b" });
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(
			client,
			"main",
			// Its own key id, because decrypted keys are cached by id and one an
			// earlier test in this file already decrypted would be found instead of
			// this rubbish.
			{ keyId: "0000000000000000", armoredPrivateKey: "not a key", algorithm: "eddsa", fingerprint: "f" } as never,
			env.KEY_PASSPHRASE,
			h,
		);

		expect(result.outcome === "failed" && result.reason).toContain("Signing failed");
		expect(result.outcome === "failed" && result.published).toBe(false);
		expect(state.published).toBe(false);
		expect(calls.some((call) => call.startsWith("createCommit"))).toBe(false);
	});

	it("publishes nothing when the repository cannot be read at all", async () => {
		// A token failure, an outage, a 500 — all the same thing at this point:
		// nothing is known, so nothing is done, and the caller is told the world is
		// untouched.
		const key = await signingKey();
		const client = {
			repository: REPOSITORY,
			getBranch: () => {
				throw new Error("GitHub is unavailable");
			},
			getCommit: () => Promise.reject(new Error("unreachable")),
		} as unknown as RepositoryClient;
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result.outcome === "failed" && result.published).toBe(false);
		expect(state.published).toBe(false);
	});

	it("publishes nothing when the branch cannot be re-read before the update", async () => {
		// The last read before the boundary. A re-read that fails has not confirmed
		// the branch, so the branch is not moved.
		const key = await signingKey();
		let reads = 0;
		const { client: base } = fakeClient({ commits: [commit("b", ["a"]), commit("a", [], true)], head: "b" });
		const client = {
			...(base as unknown as Record<string, unknown>),
			getBranch: (branch: string) => {
				reads += 1;
				if (reads > 1) {
					throw new Error("GitHub is unavailable");
				}
				return Promise.resolve({ ref: `refs/heads/${branch}`, sha: "b" });
			},
		} as unknown as RepositoryClient;
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result.outcome === "failed" && result.published).toBe(false);
		expect(state.published).toBe(false);
	});

	it("signs a root commit, which has no parent to carry forward", async () => {
		const key = await signingKey();
		const { client, calls } = fakeClient({ commits: [commit("root", [])], head: "root" });
		const { hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result.outcome).toBe("signed");
		expect(calls).toContain("createCommit:");
	});

	it("treats a branch deleted mid-flight as moved rather than as something to force back", async () => {
		const key = await signingKey();
		const { client, calls } = fakeClient({
			commits: [commit("b", ["a"]), commit("a", [], true)],
			head: "b",
			headOnSecondRead: null as unknown as string,
		});
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result).toEqual({ outcome: "skipped", reason: "branch_moved" });
		expect(state.published).toBe(false);
		expect(calls.some((call) => call.startsWith("updateBranch"))).toBe(false);
	});

	it("survives a throw that is not an Error", async () => {
		// Nothing guarantees what a runtime throws. A reason built with
		// `error.message` on a string would read `undefined`, which is the least
		// useful thing an audit row can say.
		const key = await signingKey();
		const { client: base } = fakeClient({ commits: [commit("b", ["a"]), commit("a", [], true)], head: "b" });
		const client = {
			...(base as unknown as Record<string, unknown>),
			createCommit: () => Promise.reject("a string, not an Error"),
		} as unknown as RepositoryClient;
		const { hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result).toEqual({ outcome: "failed", reason: "Commit creation failed", published: false });
	});

	it("does nothing for a branch that no longer exists", async () => {
		const key = await signingKey();
		const { client } = fakeClient({ commits: [], head: null as unknown as string });
		const { state, hooks: h } = hooks();

		const result = await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		expect(result).toEqual({ outcome: "skipped", reason: "branch_missing" });
		expect(state.published).toBe(false);
	});

	it("refuses an X.509 key rather than storing a signature GitHub cannot verify", async () => {
		const { client, calls } = fakeClient({ commits: [], head: "b" });
		const { hooks: h } = hooks();

		const result = await signPushedCommits(
			client,
			"main",
			{ keyId: KEY, type: "x509", certificate: "", privateKeyPem: "" } as never,
			env.KEY_PASSPHRASE,
			h,
		);

		expect(result).toEqual({ outcome: "skipped", reason: "unsupported_key" });
		expect(calls).toHaveLength(0);
	});

	it("chains rewritten parents forward and keeps a merge's other parents", async () => {
		const key = await signingKey();
		const { client, calls } = fakeClient({
			commits: [commit("m", ["b", "side"]), commit("b", ["a"]), commit("a", [], true)],
			head: "m",
		});
		const { hooks: h } = hooks();

		await signPushedCommits(client, "main", key, env.KEY_PASSPHRASE, h);

		const creations = calls.filter((call) => call.startsWith("createCommit:")).map((call) => call.slice(13));
		// The oldest keeps its own parents; the merge takes the rewritten id in the
		// first slot and `side` unchanged in the second.
		expect(creations[0]).toBe("a");
		expect(creations[1]?.split(",")[1]).toBe("side");
		expect(creations[1]?.split(",")[0]).not.toBe("b");
	});
});

/**
 * A real RSA key for the App, so the JWT the token exchange mints is a real one.
 *
 * Generated once rather than pinned: what is under test is the path, not the
 * key, and a private key checked into a test file is a private key checked into
 * a repository.
 */
let APP_PRIVATE_KEY = "";

async function generateAppKey(): Promise<string> {
	const pair = (await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
	let binary = "";
	for (const byte of der) {
		binary += String.fromCharCode(byte);
	}
	const base64 = btoa(binary).replace(/(.{64})/g, "$1\n");

	return `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----\n`;
}

/** Everything a delivery needs to reach the acting handler. */
function enabled(allowlist: string) {
	return {
		GITHUB_APP_ENABLED: "true",
		GITHUB_WEBHOOK_SECRET: SECRET,
		GITHUB_APP_ALLOWED_REPOSITORIES: allowlist,
		GITHUB_APP_ID: "123456",
		GITHUB_APP_PRIVATE_KEY: APP_PRIVATE_KEY,
	};
}

async function hmac(body: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(SECRET),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));
	return SIGNATURE_PREFIX + [...mac].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Deliver a `push` to the real endpoint, through the real pipeline. */
async function deliverPush(options: {
	payload: unknown;
	allowlist: string;
	deliveryId?: string;
	overrides?: Record<string, unknown>;
}): Promise<{ response: Response; body: Record<string, unknown> }> {
	const body = JSON.stringify(options.payload);
	const ctx = createExecutionContext();
	const response = await app.fetch(
		new Request("https://sign.test/github/webhook", {
			method: "POST",
			body,
			headers: {
				"Content-Type": "application/json",
				"X-Hub-Signature-256": await hmac(body),
				"X-GitHub-Event": "push",
				"X-GitHub-Delivery": options.deliveryId ?? crypto.randomUUID(),
			},
		}),
		{ ...env, ...enabled(options.allowlist), ...options.overrides },
		ctx,
	);
	await waitOnExecutionContext(ctx);

	return { response, body: (await response.json()) as Record<string, unknown> };
}

function pushPayload(installationId: number, repository: string, ref = "refs/heads/main") {
	return {
		ref,
		deleted: false,
		before: "0".repeat(40),
		after: "1".repeat(40),
		installation: { id: installationId },
		repository: { full_name: repository, name: repository.split("/")[1] },
	};
}

describe("through the endpoint", () => {
	beforeAll(async () => {
		APP_PRIVATE_KEY = await generateAppKey();

		// The audit table with the constraint migration 0005 leaves behind. Written
		// out rather than relaxed to `TEXT`, so an insert of `push_sign` is checked
		// against the same closed set production checks it against — a migration
		// that forgot the value would fail here rather than in D1.
		for (const statement of [
			`CREATE TABLE IF NOT EXISTS audit_logs (
				id TEXT PRIMARY KEY,
				timestamp TEXT NOT NULL,
				request_id TEXT NOT NULL,
				action TEXT NOT NULL CHECK (action IN (
					'sign', 'key_upload', 'key_rotate', 'token_create', 'token_revoke',
					'subject_create', 'subject_revoke', 'push_sign'
				)),
				issuer TEXT NOT NULL,
				subject TEXT NOT NULL,
				key_id TEXT NOT NULL,
				success INTEGER NOT NULL DEFAULT 0,
				error_code TEXT,
				metadata TEXT
			)`,
			"CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC)",
			"CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action)",
		]) {
			await env.AUDIT_DB.prepare(statement).run();
		}

		// A real key under the id the allowlist entries below bind, so
		// `loadSigningKey` resolves against the real `KeyStorage` rather than a
		// stub. The one test that wants a *missing* key names a different id.
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Push Signing", email: "push@test.com" }],
			passphrase: env.KEY_PASSPHRASE,
			format: "armored",
		});

		const ctx = createExecutionContext();
		const upload = await app.fetch(
			new Request("https://sign.test/admin/keys", {
				method: "POST",
				headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}`, "Content-Type": "application/json" },
				body: JSON.stringify({ armoredPrivateKey: privateKey, keyId: KEY }),
			}),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(upload.status).toBe(201);
	});

	beforeEach(() => {
		vi.restoreAllMocks();
	});

	it("signs nothing for a repository the allowlist bound no key to", async () => {
		// Receiving events and causing signatures are separate grants. No key
		// suffix means the delivery is received, authorized, logged — and signs
		// nothing, with no fall back to `KEY_ID`.
		const reached: string[] = [];
		vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
			reached.push(new Request(input as RequestInfo).url);
			return Promise.resolve(new Response("{}", { status: 200 }));
		});

		const { response, body } = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist: `${INSTALLATION}:${REPOSITORY}`,
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("no_key_bound");
		expect(reached).toHaveLength(0);
	});

	it("refuses a push for a repository paired with a different installation", async () => {
		// Cross-installation confusion: one App has one webhook secret and as many
		// installations as accept it, so the HMAC on this delivery is as valid as
		// any other. The pair is what refuses it.
		const { response } = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist: `999:${REPOSITORY}=${KEY}`,
		});

		expect(response.status).toBe(401);
	});

	it("refuses a push whose payload names a repository the pair does not", async () => {
		// Cross-repository confusion. The delivery is signed and names an
		// allowlisted installation; the repository it names is somebody else's.
		const { response } = await deliverPush({
			payload: pushPayload(INSTALLATION, OTHER_REPOSITORY),
			allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
		});

		expect(response.status).toBe(401);
	});

	it("takes the repository it acts on from the allowlist, never from the payload", async () => {
		// The delivery names the authorized repository, so it is authorized — and
		// then every GitHub path is asserted to be under the *operator's* spelling.
		// A handler that read `payload.repository.full_name` would pass every test
		// above and fail this one only if the two differ, so they differ: the
		// payload's spelling has a different case.
		const paths: string[] = [];
		vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
			const request = new Request(input as RequestInfo, init as RequestInit);
			const url = new URL(request.url);
			expect(url.origin).toBe(GITHUB_API_ORIGIN);
			paths.push(url.pathname);

			if (url.pathname.endsWith("/access_tokens")) {
				return Promise.resolve(
					Response.json({ token: "ghs_x", expires_at: new Date(Date.now() + 3600_000).toISOString() }, { status: 201 }),
				);
			}
			// A head that is already signed: the walk stops immediately, so this test
			// is about the *paths*, not about signing.
			if (url.pathname.includes("/git/ref/heads/")) {
				return Promise.resolve(Response.json({ ref: "refs/heads/main", object: { sha: "headsha" } }));
			}
			return Promise.resolve(
				Response.json({
					sha: "headsha",
					message: "m",
					tree: { sha: "t" },
					parents: [],
					author: { name: "a", email: "a@b", date: "2026-08-31T07:00:00Z" },
					committer: { name: "a", email: "a@b", date: "2026-08-31T07:00:00Z" },
					verification: { signature: "-----BEGIN PGP SIGNATURE-----" },
				}),
			);
		});

		const { response, body } = await deliverPush({
			payload: pushPayload(INSTALLATION, "KJANAT/SERVICE"),
			allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("nothing_to_sign");
		const repoPaths = paths.filter((path) => path.startsWith("/repos/"));
		expect(repoPaths.length).toBeGreaterThan(0);
		for (const path of repoPaths) {
			expect(path.startsWith(`/repos/${REPOSITORY}/`)).toBe(true);
		}
	});

	it("keeps the delivery redeliverable when the key it is bound to is gone", async () => {
		// A missing key changed nothing, so the id goes back and the operator's
		// redelivery is a genuine retry rather than a `duplicate: true` that looks
		// like success. Asserted by redelivering: the handler must be reached twice.
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=AAAAAAAAAAAAAAAA`;

		const first = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });
		expect(first.response.status).toBe(503);
		expect(first.body.skipped).toBe("key_missing");

		const second = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });

		// Reached the handler a second time — `duplicate` is the guard's own field
		// and would be true had the id been committed rather than released.
		expect(second.body.duplicate).toBe(false);
		expect(second.body.skipped).toBe("key_missing");
	});

	it("keeps the delivery redeliverable when key storage cannot be reached", async () => {
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;
		const broken = {
			KEY_STORAGE: {
				idFromName: () => ({}),
				get: () => ({
					fetch: () => {
						throw new Error("key storage unavailable");
					},
				}),
			},
		};

		const first = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist,
			deliveryId: id,
			overrides: broken,
		});
		expect(first.body.skipped).toBe("key_storage_unavailable");

		const second = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist,
			deliveryId: id,
			overrides: broken,
		});

		expect(second.body.duplicate).toBe(false);
	});

	it("commits the delivery for a deterministic no-op, so a replay accomplishes nothing", async () => {
		// A tag push is refused the same way every time. Handing the id back would
		// make it replayable for no benefit, so it stays committed — release is for
		// failures that a *changed world* would resolve, not for every non-action.
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;
		const payload = pushPayload(INSTALLATION, REPOSITORY, "refs/tags/v1");

		const first = await deliverPush({ payload, allowlist, deliveryId: id });
		expect(first.body.skipped).toBe("not_a_branch");

		const second = await deliverPush({ payload, allowlist, deliveryId: id });

		expect(second.response.status).toBe(200);
		expect(second.body.duplicate).toBe(true);
	});

	it.each([
		["omits `deleted` entirely", {}],
		["sends `deleted: null`", { deleted: null }],
		['sends `deleted` as the string "false"', { deleted: "false" }],
		["sends `deleted` as `0`", { deleted: 0 }],
	])("reaches no GitHub call for a delivery that %s", async (_case, override) => {
		// The whole point of the fail-closed reading, at the boundary that matters:
		// not "the answer is malformed" but "nothing outside this Worker was
		// touched". A delivery that cannot prove it is a non-deletion is refused
		// before the installation token is minted, before the ref is read, and so
		// necessarily before anything is signed or moved. These payloads are
		// otherwise perfect — correctly signed, allowlisted installation, allowlisted
		// repository, a real branch ref — so the only thing refusing them is the
		// `deleted` proof. `signs the unsigned tip, moves the branch, and records
		// what it did` below is the same payload with `deleted: false` spelled
		// properly, and it signs; the difference between the two is this field.
		const reached: string[] = [];
		vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
			reached.push(new Request(input as RequestInfo).url);
			return Promise.resolve(new Response("{}", { status: 200 }));
		});

		const payload: Record<string, unknown> = { ...pushPayload(INSTALLATION, REPOSITORY), ...override };
		if (Object.keys(override).length === 0) {
			delete payload.deleted;
		}

		const { response, body } = await deliverPush({
			payload,
			allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("malformed");
		expect(reached).toHaveLength(0);
	});

	/**
	 * A `fetch` stub that behaves like GitHub for one two-commit branch.
	 *
	 * It assembles created commits the way GitHub does — from the fields it was
	 * handed — and names them with a real SHA-1, so the round-trip check in
	 * `signPushedCommits` is exercised rather than bypassed. Anything off
	 * `api.github.com` throws, so pinning is enforced by the stub itself rather
	 * than by an assertion somebody could forget to write.
	 */
	/**
	 * The unsigned commit the endpoint tests push, as a repository really holds it.
	 *
	 * Its sha is Git's — computed over the object bytes rather than made up — and
	 * those bytes are written in `+0200`, while the JSON below reports `Z` the way
	 * `GET /git/commits/{sha}` does. So a handler that echoed the JSON's date back
	 * would fail to reproduce this sha and refuse, and one that recovers the offset
	 * gets there. Nothing in these tests can pass by agreeing with itself about
	 * what a commit id is.
	 */
	const HEAD_TREE = "c93ec7f22ad2cabca76415f3389524a7d43c6435";
	const HEAD_MESSAGE = "second";
	const BASE_SHA = "cd01952d981ed9169dca0167e2a13b611db7de92";
	const HEAD_INSTANT = "2026-08-31T07:00:00Z";
	const HEAD_OFFSET = "+0200";
	const HEAD_LOCAL = "2026-08-31T09:00:00+02:00";

	async function headSha(): Promise<string> {
		const identity = { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: HEAD_INSTANT, offset: HEAD_OFFSET };
		return await commitObjectId(
			commitPayload({
				tree: HEAD_TREE,
				parents: [BASE_SHA],
				author: identity,
				committer: identity,
				message: HEAD_MESSAGE,
			}),
		);
	}

	function stubGitHub(
		options: {
			headSigned?: boolean;
			failTokens?: boolean;
			failUpdate?: boolean;
			/** Serve the head under a sha its bytes do not hash to. */
			headUnreproducible?: boolean;
		} = {},
	) {
		let calls: { method: string; path: string; body?: unknown }[] = [];
		const utc = { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: HEAD_INSTANT };

		// A sha the head's bytes do not hash to. Nothing reproduces it, the patch
		// fallback finds no `From <sha>` line either, and the commit is one this
		// service must refuse rather than rewrite into something the author did
		// not write.
		const advertisedHead = async () => (options.headUnreproducible ? `${"a".repeat(39)}0` : await headSha());
		const commits = new Map<string, Record<string, unknown>>([
			[
				BASE_SHA,
				{
					sha: BASE_SHA,
					message: "first",
					tree: { sha: "tree-1" },
					parents: [],
					author: utc,
					committer: utc,
					verification: { signature: "-----BEGIN PGP SIGNATURE-----" },
				},
			],
		]);

		vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
			const request = new Request(input as RequestInfo, init as RequestInit);
			const url = new URL(request.url);

			if (url.origin !== GITHUB_API_ORIGIN) {
				throw new Error(`outbound request left api.github.com: ${request.url}`);
			}

			// Only when there is one. The access-token exchange is a POST with no
			// body at all, and `.json()` on an empty body rejects — which would have
			// surfaced as "could not obtain a token" and sent a reader looking at the
			// wrong module entirely.
			const body = request.body === null ? undefined : await request.clone().json();
			calls.push({ method: request.method, path: url.pathname, body });

			if (url.pathname.endsWith("/access_tokens")) {
				if (options.failTokens) {
					return new Response("{}", { status: 401 });
				}
				return Response.json(
					{ token: "ghs_installationtoken", expires_at: new Date(Date.now() + 3600_000).toISOString() },
					{ status: 201 },
				);
			}

			if (url.pathname.includes("/git/ref/heads/")) {
				return Response.json({ ref: "refs/heads/main", object: { sha: await advertisedHead() } });
			}

			if (url.pathname.includes("/git/refs/heads/")) {
				return options.failUpdate
					? new Response("{}", { status: 422 })
					: Response.json({ ref: "refs/heads/main", object: { sha: "rewritten" } });
			}

			if (request.method === "POST" && url.pathname.endsWith("/git/commits")) {
				const input = body as {
					message: string;
					tree: string;
					parents: string[];
					author: { name: string; email: string; date: string };
					committer: { name: string; email: string; date: string };
					signature: string;
				};
				const sha = await commitObjectId(
					signedCommitObject(
						commitPayload({
							tree: input.tree,
							parents: input.parents,
							author: input.author,
							committer: input.committer,
							message: input.message,
						}),
						input.signature,
					),
				);
				return Response.json({
					sha,
					message: input.message,
					tree: { sha: input.tree },
					parents: input.parents.map((parent) => ({ sha: parent })),
					author: input.author,
					committer: input.committer,
				});
			}

			const sha = url.pathname.split("/").pop() as string;

			// The head, rendered the way the Git Data API renders one: `Z` on both
			// dates, offset gone. Built here rather than in the map above because its
			// sha is derived from the object bytes and the map is keyed by it.
			if (sha === (await advertisedHead())) {
				return Response.json({
					sha,
					message: HEAD_MESSAGE,
					tree: { sha: HEAD_TREE },
					parents: [{ sha: BASE_SHA }],
					author: utc,
					committer: utc,
					verification: { signature: options.headSigned ? "-----BEGIN PGP SIGNATURE-----" : null },
				});
			}

			const commit = commits.get(sha);
			return commit ? Response.json(commit) : new Response("{}", { status: 404 });
		});

		// `options` is handed back mutable and `reset` clears the log, so a test can
		// change GitHub's behaviour mid-way — which is what a redelivery after an
		// outage is — without re-spying on `fetch`, and can then assert about the
		// calls made *after* the change.
		return {
			calls: () => calls,
			options,
			reset: () => {
				calls = [];
			},
		};
	}

	it("signs the unsigned tip, moves the branch, and records what it did", async () => {
		const github = stubGitHub();
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;

		const { response, body } = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist,
			deliveryId: id,
		});

		expect(response.status).toBe(200);
		expect(body).toMatchObject({ handled: true, signed: 1 });

		// One commit created and one ref moved, in that order. `base` is already
		// signed, so it is not among them.
		const created = github.calls().filter((call) => call.method === "POST" && call.path.endsWith("/git/commits"));
		const moved = github.calls().filter((call) => call.method === "PATCH");
		expect(created).toHaveLength(1);
		expect(moved).toHaveLength(1);
		expect(moved[0]?.body).toMatchObject({ force: true });
		// The created commit keeps the original parent, tree and identities: this
		// signs history, it does not rewrite it into something else.
		expect(created[0]?.body).toMatchObject({ parents: [BASE_SHA], tree: HEAD_TREE, message: HEAD_MESSAGE });

		// And it keeps the *timezone*. The API reported both dates as `2026-08-31T07:00:00Z`;
		// what goes back out is the local time the commit was actually written at.
		// This is the assertion that fails the moment the handler starts echoing
		// GitHub's normalised date instead of the offset it recovered — and it is
		// not checkable by the object-id round trip, because that compares our
		// assembly to GitHub's and both would start from the same wrong string.
		expect(created[0]?.body).toMatchObject({
			author: { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: HEAD_LOCAL },
			committer: { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: HEAD_LOCAL },
		});
		expect(JSON.stringify(created[0]?.body)).not.toContain(HEAD_INSTANT);

		// And the audit trail says so, under the *authorized* repository.
		const row = await env.AUDIT_DB.prepare(
			"SELECT action, issuer, subject, key_id, success, metadata FROM audit_logs WHERE action = ? ORDER BY timestamp DESC LIMIT 1",
		)
			.bind("push_sign")
			.first<{ issuer: string; subject: string; key_id: string; success: number; metadata: string }>();

		expect(row).toMatchObject({ issuer: "github-app", subject: REPOSITORY, key_id: KEY, success: 1 });
		const metadata = JSON.parse(row?.metadata as string) as Record<string, unknown>;
		expect(metadata).toMatchObject({ branch: "main", commits: 1, previousHead: await headSha() });
		// No secret rides along: not the signature, not the token, not the key.
		expect(row?.metadata).not.toContain("PGP");
		expect(row?.metadata).not.toContain("ghs_");
	});

	it("does not act twice on the same delivery, even after it published", async () => {
		// The irreversible boundary, from outside. The id is committed *before* the
		// branch moves, so a redelivery — the operator's one recovery affordance —
		// cannot force-update the branch a second time.
		const github = stubGitHub();
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;

		const first = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });
		expect(first.response.status).toBe(200);

		github.reset();
		const second = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });

		expect(second.body.duplicate).toBe(true);
		expect(github.calls()).toHaveLength(0);
	});

	it("signs nothing when the head already carries a signature", async () => {
		// The loop, from outside: this is the state our own ref update produces, so
		// the delivery it raises must reach here and stop. No commit is created and
		// no ref is moved, which is what makes the cycle terminate rather than
		// merely slow down.
		const github = stubGitHub({ headSigned: true });

		const { response, body } = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("nothing_to_sign");
		expect(github.calls().some((call) => call.method === "POST" && call.path.endsWith("/git/commits"))).toBe(false);
		expect(github.calls().some((call) => call.method === "PATCH")).toBe(false);
	});

	it("signs nothing when the head's exact bytes cannot be rebuilt", async () => {
		// The refusal that keeps the timezone recovery honest, from outside. If the
		// object as GitHub reports it cannot be reproduced under any candidate
		// offset — a header this service does not model, an offset it does not
		// try — then the rewrite would publish a signature over something other
		// than what the author wrote. So it publishes nothing.
		//
		// Worth noticing what would happen without this: the handler would sign
		// *some* commit, GitHub would create it, the object-id round trip would
		// pass because both sides assembled it from the same wrong fields, and the
		// branch would move.
		const github = stubGitHub({ headUnreproducible: true });

		const { response, body } = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("unreproducible_commit");
		expect(github.calls().some((call) => call.method === "POST" && call.path.endsWith("/git/commits"))).toBe(false);
		expect(github.calls().some((call) => call.method === "PATCH")).toBe(false);
	});

	it("keeps the delivery redeliverable when GitHub refuses an installation token", async () => {
		// A token failure is a read failure: nothing was published, so the id goes
		// back. Left uncaught this would escape to the route, which cannot tell a
		// read failure from a publish failure and would have to assume the worse.
		//
		// Its own installation id, because tokens are cached in KV per installation
		// and one minted by an earlier test in this file would sail past the
		// refusal this is arranging.
		const installation = INSTALLATION + 1;
		const github = stubGitHub({ failTokens: true });
		const id = crypto.randomUUID();
		const allowlist = `${installation}:${REPOSITORY}=${KEY}`;

		const first = await deliverPush({ payload: pushPayload(installation, REPOSITORY), allowlist, deliveryId: id });
		expect(first.response.status).toBe(500);

		// GitHub recovers, and the operator redelivers.
		github.options.failTokens = false;
		github.reset();
		const second = await deliverPush({ payload: pushPayload(installation, REPOSITORY), allowlist, deliveryId: id });

		expect(second.body.duplicate).toBe(false);
		expect(second.response.status).toBe(200);
		expect(github.calls().some((call) => call.method === "PATCH")).toBe(true);
	});

	it("keeps the delivery redeliverable when the signing budget cannot be consulted", async () => {
		// Fail closed on the limiter, and give the id back: refusing to sign
		// because the budget is unknown changed nothing in the repository.
		const github = stubGitHub();
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;
		const broken = {
			RATE_LIMITER: {
				idFromName: () => ({}),
				get: () => ({
					fetch: () => {
						throw new Error("rate limiter unavailable");
					},
				}),
			},
		};

		const first = await deliverPush({
			payload: pushPayload(INSTALLATION, REPOSITORY),
			allowlist,
			deliveryId: id,
			overrides: broken,
		});
		expect(first.response.status).toBe(503);

		github.reset();
		const second = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });

		expect(second.response.status).toBe(200);
		expect(github.calls().some((call) => call.method === "PATCH")).toBe(true);
	});

	it("does not retry a branch update whose outcome is unknown", async () => {
		// Past the boundary: the request was sent and refused, and it might just as
		// easily have landed with the answer lost. Committed, not released.
		const github = stubGitHub({ failUpdate: true });
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;

		const first = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });
		expect(first.response.status).toBe(500);

		github.options.failUpdate = false;
		github.reset();
		const second = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });

		expect(second.body.duplicate).toBe(true);
		expect(github.calls()).toHaveLength(0);
	});

	it("never reaches GitHub for a delivery it refuses before authorization", async () => {
		// The installation token is a credential, and minting one for a delivery
		// that is about to be refused would be a way to make this service talk to
		// GitHub on an unauthorized delivery's behalf.
		const reached: string[] = [];
		vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
			reached.push(new Request(input as RequestInfo).url);
			return Promise.resolve(new Response("{}"));
		});

		await deliverPush({
			payload: pushPayload(INSTALLATION, OTHER_REPOSITORY),
			allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
		});

		expect(reached).toHaveLength(0);
	});

	/**
	 * A limiter double that answers the webhook meter normally and the push-signing
	 * meter however a test says.
	 *
	 * Overriding the whole binding would make the request fail at
	 * `webhookRateLimit`, which is in front of everything and would never reach the
	 * budget under test — so the two meters have to be told apart by identity.
	 */
	function limiterAnswering(pushMeter: () => Response) {
		return {
			RATE_LIMITER: {
				idFromName: () => ({}),
				get: () => ({
					fetch: (request: Request) => {
						const identity = new URL(request.url).searchParams.get("identity") ?? "";
						if (identity.startsWith("github-push:")) {
							return Promise.resolve(pushMeter());
						}
						return Promise.resolve(Response.json({ allowed: true, remaining: 99, resetAt: Date.now() + 60_000 }));
					},
				}),
			},
		};
	}

	describe("the signing budget", () => {
		// The meter in front of the route counts requests per source address. That is
		// not a signing budget: one request can carry twenty signatures, and a
		// repository's signing authority is what needs bounding. These are the three
		// answers the budget can give and what each does to the delivery.

		it("refuses and stays redeliverable when the repository is over its budget", async () => {
			const github = stubGitHub();
			const id = crypto.randomUUID();
			const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;

			const { response } = await deliverPush({
				payload: pushPayload(INSTALLATION, REPOSITORY),
				allowlist,
				deliveryId: id,
				overrides: limiterAnswering(() =>
					Response.json({ allowed: false, remaining: 0, resetAt: Date.now() + 30_000 }, { status: 429 }),
				),
			});

			expect(response.status).toBe(429);
			// Nothing signed and nothing moved — a refused budget is checked before the
			// first signature, not after.
			expect(github.calls().some((call) => call.method === "PATCH")).toBe(false);
			expect(github.calls().some((call) => call.method === "POST" && call.path.endsWith("/git/commits"))).toBe(false);

			github.reset();
			const second = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });

			expect(second.response.status).toBe(200);
			expect(github.calls().some((call) => call.method === "PATCH")).toBe(true);
		});

		it("fails closed when the limiter answers with an error rather than a verdict", async () => {
			stubGitHub();

			const { response } = await deliverPush({
				payload: pushPayload(INSTALLATION, REPOSITORY),
				allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
				overrides: limiterAnswering(() => new Response("boom", { status: 500 })),
			});

			// 503, not 429: the budget is unknown rather than exceeded, and telling a
			// caller it is rate limited when nothing counted it would be a lie.
			expect(response.status).toBe(503);
		});

		it("does not read a 429 as an outage", async () => {
			// The bug `/sign` carries a comment about, arriving here by a different
			// route: a denied consume *is* the verdict and arrives as a 429, so `!ok`
			// alone reads the one answer being asked for as a failure.
			stubGitHub();

			const { response } = await deliverPush({
				payload: pushPayload(INSTALLATION, REPOSITORY),
				allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
				overrides: limiterAnswering(() =>
					Response.json({ allowed: false, remaining: 0, resetAt: Date.now() + 30_000 }, { status: 429 }),
				),
			});

			expect(response.status).toBe(429);
			expect(response.status).not.toBe(503);
		});

		it("commits the delivery when something unmodelled goes wrong", async () => {
			// A limiter that answers 200 with a body that is not JSON. Nothing in the
			// signing path turns that into a result, so it reaches the route's outer
			// catch — which leaves the delivery committed, because an unknown state is
			// treated as "may have acted".
			stubGitHub();
			const id = crypto.randomUUID();
			const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;

			const first = await deliverPush({
				payload: pushPayload(INSTALLATION, REPOSITORY),
				allowlist,
				deliveryId: id,
				overrides: limiterAnswering(() => new Response("not json", { status: 200 })),
			});
			expect(first.response.status).toBe(500);

			const second = await deliverPush({ payload: pushPayload(INSTALLATION, REPOSITORY), allowlist, deliveryId: id });

			expect(second.body.duplicate).toBe(true);
		});

		it.each([
			["the installation", { installationId: 99, repository: REPOSITORY, keyId: KEY }],
			["the repository", { installationId: INSTALLATION, repository: OTHER_REPOSITORY, keyId: KEY }],
			["the key", { installationId: INSTALLATION, repository: REPOSITORY, keyId: "AAAAAAAAAAAAAAAA" }],
		])("counts signatures in a different bucket when %s differs", (_case, grant) => {
			// Asserted directly, because today it cannot be observed through the
			// endpoint: a pair may appear on the allowlist once, so a fixed pair has a
			// fixed key and no request can tell a bucket keyed on all three from one
			// keyed on the pair. The requirement is a per-key, per-subject budget, and
			// the moment a pair can bind more than one key a bucket keyed only on the
			// pair silently becomes shared.
			const base = signingBudgetIdentity(
				{ scope: "repository", installationId: INSTALLATION, repository: REPOSITORY, keyId: KEY },
				KEY,
			);

			expect(
				signingBudgetIdentity(
					{
						scope: "repository",
						installationId: grant.installationId,
						repository: grant.repository,
						keyId: grant.keyId,
					},
					grant.keyId,
				),
			).not.toBe(base);
		});

		it("keys the signing bucket in its own namespace", () => {
			// Not an issuer, so it cannot collide with the `<iss>:<sub>` buckets a
			// signing caller is metered on, nor with the `webhook` meter in front of
			// the route — which counts requests per address and is not a signing
			// budget.
			const identity = signingBudgetIdentity(
				{ scope: "repository", installationId: INSTALLATION, repository: REPOSITORY, keyId: KEY },
				KEY,
			);

			expect(identity.startsWith("github-push:")).toBe(true);
			expect(identity).toContain(REPOSITORY);
			expect(identity).toContain(KEY);
		});

		it("signs nothing for a delivery that names no repository to act on", async () => {
			// An `installation`-scope push: allowlisted installation, no repository in
			// the payload. There is no pair, so there is no key and no repository to
			// address, and the delivery is acknowledged having done nothing.
			const github = stubGitHub();
			const { installation, ...withoutRepository } = {
				...pushPayload(INSTALLATION, REPOSITORY),
				repository: undefined,
				installation: { id: INSTALLATION },
			};

			const { response, body } = await deliverPush({
				payload: { ...withoutRepository, installation },
				allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
			});

			expect(response.status).toBe(202);
			expect(body.skipped).toBe("not_repository_scope");
			expect(github.calls()).toHaveLength(0);
		});
	});
});

describe("the repository-scoped client", () => {
	// What makes this client safe is not what it does but what it has no
	// parameter for: there is no way to name a repository, and no way to name an
	// installation. These tests pin the rest — that a bad answer from GitHub is an
	// error rather than an `undefined` that reaches a commit payload, and that
	// nothing GitHub said is quoted back into one.

	const grant = {
		scope: "repository" as const,
		installationId: INSTALLATION,
		repository: REPOSITORY,
		keyId: KEY,
	};

	function client(handler: (request: Request) => Response | Promise<Response>) {
		const seen: string[] = [];
		vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
			const request = new Request(input as RequestInfo, init as RequestInit);
			const url = new URL(request.url);
			if (url.origin !== GITHUB_API_ORIGIN) {
				throw new Error(`outbound request left api.github.com: ${request.url}`);
			}
			seen.push(url.pathname);
			if (url.pathname.endsWith("/access_tokens")) {
				return Response.json(
					{ token: "ghs_x", expires_at: new Date(Date.now() + 3600_000).toISOString() },
					{ status: 201 },
				);
			}
			return handler(request);
		});

		const built = RepositoryClient.forAuthorization(
			{ ...env, ...enabled(""), GITHUB_APP_ID: "555555" } as unknown as Env,
			grant,
		);
		if (built === null) {
			throw new Error("expected a client for a repository-scoped grant");
		}

		return { client: built, seen };
	}

	it.each([
		["an installation-scope grant", { ...grant, scope: "installation" as const, repository: null }],
		["a none-scope grant", { ...grant, scope: "none" as const, repository: null, installationId: null }],
		["a repository grant with no installation", { ...grant, installationId: null }],
		["no authorization at all", undefined],
	])("cannot be built from %s", (_case, authorization) => {
		expect(RepositoryClient.forAuthorization(env as unknown as Env, authorization)).toBeNull();
	});

	it("answers null for a branch that does not exist, rather than throwing", async () => {
		const { client: repo } = client(() => new Response("{}", { status: 404 }));

		await expect(repo.getBranch("gone")).resolves.toBeNull();
	});

	it("keeps the slashes in a nested branch name", async () => {
		// `feature/x` is one ref whose path is `heads/feature/x`. Encoding the whole
		// thing would ask for `heads/feature%2Fx`, which is a different — and
		// non-existent — ref.
		const { client: repo, seen } = client(() => Response.json({ ref: "refs/heads/a", object: { sha: "s" } }));

		await repo.getBranch("feature/x y");

		expect(seen.some((path) => path.endsWith("/git/ref/heads/feature/x%20y"))).toBe(true);
	});

	it("reports a refusal by status, and quotes nothing GitHub said", async () => {
		// A body from this API can echo the request that produced it, and that
		// request carried an installation token.
		const { client: repo } = client(
			() => new Response(JSON.stringify({ message: "ghs_leakedtoken" }), { status: 403 }),
		);

		await expect(repo.getCommit("abc")).rejects.toMatchObject({ status: 403 });
		await expect(repo.getCommit("abc")).rejects.toThrow(/refused/);
		await expect(repo.getCommit("abc")).rejects.not.toThrow(/ghs_/);
	});

	it("reports a body it cannot read", async () => {
		const { client: repo } = client(() => new Response("not json", { status: 200 }));

		await expect(repo.getCommit("abc")).rejects.toThrow(/unreadable/);
	});

	it("reports a shape it did not expect, by count rather than by content", async () => {
		const { client: repo } = client(() => Response.json({ sha: 42 }));

		await expect(repo.getCommit("abc")).rejects.toThrow(/unexpected shape/);
		await expect(repo.getCommit("abc")).rejects.not.toThrow(/42/);
	});

	it("reads a commit with no verification block as unsigned rather than as an error", async () => {
		// GitHub sends one on every commit, and a schema failure here would turn an
		// unsigned commit — the only kind this service acts on — into an outage.
		const { client: repo } = client(() =>
			Response.json({
				sha: "abc",
				message: "m",
				tree: { sha: "t" },
				parents: [],
				author: { name: "a", email: "a@b", date: "2026-01-01T00:00:00Z" },
				committer: { name: "a", email: "a@b", date: "2026-01-01T00:00:00Z" },
			}),
		);

		await expect(repo.getCommit("abc")).resolves.toMatchObject({ signed: false });
	});

	/** Serves one commit as the API serves it, and its patch when asked. */
	function commitEndpoints(json: unknown, sha: string, patch: string | null) {
		return (request: Request) => {
			const url = new URL(request.url);
			if (url.pathname.endsWith(`/git/commits/${sha}`)) {
				return Response.json(json);
			}
			if (url.pathname.endsWith(`/commits/${sha}`)) {
				return patch === null ? new Response("", { status: 404 }) : new Response(patch, { status: 200 });
			}
			return new Response("{}", { status: 404 });
		};
	}

	it("recovers a real commit's +0200 without a second request", async () => {
		// The common case, and it costs exactly the request it always cost. The
		// offsets are worked out from the sha the response already carried rather
		// than fetched, so the patch representation is not touched — asserted, so
		// that a regression to "always fetch the patch" is a failing test and not
		// a quietly doubled API bill.
		const { client: repo, seen } = client(commitEndpoints(NON_UTC_API, NON_UTC_SHA, NON_UTC_PATCH));

		const commit = await repo.getCommit(NON_UTC_SHA);

		expect(commit.offsets).toEqual({ author: "+0200", committer: "+0200" });
		expect(commit.author.offset).toBe("+0200");
		expect(commit.committer.offset).toBe("+0200");
		expect(seen.filter((path) => path.endsWith(`/commits/${NON_UTC_SHA}`))).toHaveLength(1);
		expect(seen.some((path) => path.endsWith(`/git/commits/${NON_UTC_SHA}`))).toBe(true);
	});

	it("asks the patch representation only when the two offsets disagree", async () => {
		// The fallback, and the one media type GitHub still shows an offset in.
		const { client: repo, seen } = client(commitEndpoints(SKEWED_API, SKEWED_SHA, SKEWED_PATCH));

		const commit = await repo.getCommit(SKEWED_SHA);

		expect(commit.offsets).toEqual({ author: "+0545", committer: "-0330" });
		expect(seen.filter((path) => path === `/repos/${REPOSITORY}/commits/${SKEWED_SHA}`)).toHaveLength(1);
	});

	it("sends the patch request with the media type that carries the offset", async () => {
		// A `Accept: application/vnd.github+json` here would answer with the same
		// normalised JSON that failed a moment ago, so the header is the request.
		let accept: string | null = null;
		const { client: repo } = client((request) => {
			const url = new URL(request.url);
			if (url.pathname.endsWith(`/git/commits/${SKEWED_SHA}`)) {
				return Response.json(SKEWED_API);
			}
			accept = request.headers.get("Accept");
			return new Response(SKEWED_PATCH, { status: 200 });
		});

		await repo.getCommit(SKEWED_SHA);

		expect(accept).toBe("application/vnd.github.patch");
	});

	it("answers null offsets rather than failing the read when the patch is unreachable", async () => {
		// The fallback is a fallback. Its absence costs a refusal to rewrite one
		// commit, which is already the outcome without it — turning a network
		// failure here into an exception would instead turn that refusal into a
		// delivery-wide read failure that gets retried forever.
		let reads = 0;
		const { client: repo } = client((request) => {
			if (new URL(request.url).pathname.endsWith(`/git/commits/${SKEWED_SHA}`)) {
				reads += 1;
				return Response.json(SKEWED_API);
			}
			throw new Error("connection reset");
		});

		const commit = await repo.getCommit(SKEWED_SHA);

		expect(reads).toBe(1);
		expect(commit.offsets).toBeNull();
	});

	it("answers null offsets rather than throwing when nothing reproduces the commit", async () => {
		// A refusal to rewrite one commit, which `signableRun` turns into
		// `unreproducible_commit`. Not an exception: a read that failed would be
		// released as a retryable outage, and this is a deterministic property of
		// the commit that every redelivery would reach again.
		const { client: repo } = client(commitEndpoints(SKEWED_API, SKEWED_SHA, null));

		const commit = await repo.getCommit(SKEWED_SHA);

		expect(commit.offsets).toBeNull();
		expect(commit.author.offset).toBeUndefined();
	});

	it("does not go looking for the offsets of a commit it will never rewrite", async () => {
		// A signed commit's object holds a `gpgsig`, so no reconstruction can match
		// its sha — the search is guaranteed to fail and the patch fetch behind it
		// is guaranteed to be wasted. The walk stops at it either way.
		const { client: repo, seen } = client(
			commitEndpoints(
				{ ...NON_UTC_API, verification: { signature: "-----BEGIN PGP SIGNATURE-----" } },
				NON_UTC_SHA,
				NON_UTC_PATCH,
			),
		);

		const commit = await repo.getCommit(NON_UTC_SHA);

		expect(commit.signed).toBe(true);
		expect(commit.offsets).toBeNull();
		expect(seen.filter((path) => path === `/repos/${REPOSITORY}/commits/${NON_UTC_SHA}`)).toHaveLength(0);
	});

	it("puts the recovered offset back on the wire when it creates a commit", async () => {
		// The other half of the round trip. GitHub stores the offset it is given —
		// checked against the live API with an author at `+0545` and a committer at
		// `-0330`, both preserved in the created object — so what is written here
		// is what the rewritten commit will say. Echoing the `Z` the API reported
		// would relocate the commit to UTC, and no later check would notice.
		let sent: { author: { date: string }; committer: { date: string } } | null = null;
		const { client: repo } = client(async (request) => {
			sent = (await request.json()) as { author: { date: string }; committer: { date: string } };
			return Response.json({ ...SKEWED_API, verification: { signature: null } });
		});

		await repo.createCommit({
			message: SKEWED_API.message,
			tree: SKEWED_API.tree.sha,
			parents: [],
			author: { ...SKEWED_API.author, offset: "+0545" },
			committer: { ...SKEWED_API.committer, offset: "-0330" },
			signature: "-----BEGIN PGP SIGNATURE-----",
		});

		expect(sent).toMatchObject({
			author: { date: "2026-08-31T00:50:00+05:45" },
			committer: { date: "2026-08-30T15:35:00-03:30" },
		});
	});

	it("reports a refused branch update", async () => {
		const { client: repo } = client(() => new Response("{}", { status: 422 }));

		await expect(repo.updateBranch("main", "abc", true)).rejects.toMatchObject({ status: 422 });
	});

	it("reports an unreachable GitHub without re-raising what the runtime threw", async () => {
		vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("connection reset"));
		const repo = RepositoryClient.forAuthorization(
			{ ...env, ...enabled(""), GITHUB_APP_ID: "666666" } as unknown as Env,
			grant,
		) as RepositoryClient;

		await expect(repo.getBranch("main")).rejects.toThrow(/installation token/);
	});
});
