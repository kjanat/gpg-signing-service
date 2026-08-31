/**
 * The serialiser that decides what gets signed.
 *
 * Every other control on the push-signing path answers "may this happen". This
 * one answers "over which bytes", and it is the only one whose failure is
 * silent: a signature over almost-the-right-payload verifies against nothing,
 * produces no error, and leaves a branch rewritten with commits that will never
 * show as signed. So the tests are written against real git output rather than
 * against the code's own idea of a commit.
 *
 * The two fixtures below were produced by `git commit` and read back with `git
 * cat-file commit`, sha and all. They are the assertion: the JSON GitHub would
 * report for those commits is fed in, and the object name that comes out has to
 * be the one git gave them. A serialiser that renders an offset as UTC, drops
 * the message's trailing newline, or orders the headers differently fails here
 * and cannot fail anywhere else.
 *
 * The fixtures are deliberately not both UTC. `+0200` and `+0000` are rendered
 * by different branches of `gitTimestamp`, and a commit made outside UTC is the
 * ordinary case for a human contributor.
 */

import { describe, expect, it } from "vitest";
import type { CommitContents } from "#utils/git-commit";
import {
	commitObjectSha,
	commitPayload,
	commitWithSignature,
	gitTimestamp,
	isObjectSha,
	NULL_SHA,
	reproduceCommit,
} from "#utils/git-commit";

const KAJ = { name: "Kaj Kowalski", email: "info@kajkowalski.nl" };

/** A root commit made at `+0200`, exactly as `git cat-file commit` reports it. */
const ROOT = {
	sha: "ef525aa8064bcd8a2245b417d258b6d21b1add18",
	contents: {
		tree: "08585692ce06452da6f82ae66b90d98b55536fca",
		parents: [],
		author: { ...KAJ, date: "2026-08-30T12:34:56+02:00" },
		committer: { ...KAJ, date: "2026-08-30T12:34:56+02:00" },
		message: "first commit",
	} satisfies CommitContents,
	object:
		"tree 08585692ce06452da6f82ae66b90d98b55536fca\n" +
		"author Kaj Kowalski <info@kajkowalski.nl> 1788086096 +0200\n" +
		"committer Kaj Kowalski <info@kajkowalski.nl> 1788086096 +0200\n" +
		"\n" +
		"first commit\n",
};

/** Its child, at UTC, with a multi-paragraph message. */
const CHILD = {
	sha: "9fbd596919adda07ac07596cbdb4f15687d429c1",
	contents: {
		tree: "f4b354863caa9cea99b95422c9dab70465757d87",
		parents: [ROOT.sha],
		author: { ...KAJ, date: "2026-08-31T01:02:03Z" },
		committer: { ...KAJ, date: "2026-08-31T01:02:03Z" },
		message: "second commit\n\nwith a body and a trailing paragraph",
	} satisfies CommitContents,
};

describe("object names", () => {
	it("names a real commit object the way git does", async () => {
		// The whole file in one assertion: these bytes came out of `git cat-file`,
		// and this sha came out of `git log`.
		expect(await commitObjectSha(ROOT.object)).toBe(ROOT.sha);
	});

	it("counts bytes, not characters, in the object header", async () => {
		// `commit <length>\0` is a *byte* length. A serialiser using `String.length`
		// agrees with git on every ASCII commit and disagrees the first time
		// somebody writes a name with an accent in it — which is a silent wrong
		// answer, not an error, and it would put the signature on an object git
		// never names.
		//
		// Pinned against a digest computed outside this codebase rather than against
		// another call to the same function: two bodies that differ hash differently
		// whichever length the header claims, so a comparison of two calls proves
		// nothing about the header at all.
		expect(await commitObjectSha("é")).toBe("450b48e8a32562196c590ca27da181a541bb752b");
		// What the character count would have produced, named so the assertion above
		// cannot be satisfied by accident.
		expect(await commitObjectSha("é")).not.toBe("d92d40bc22f2aa10f225e5565a27a0a67d1356ad");
	});

	it("recognises object names and nothing else", () => {
		expect(isObjectSha(ROOT.sha)).toBe(true);
		expect(isObjectSha(NULL_SHA)).toBe(true);
		// Upper case is not what git writes and not what GitHub sends; accepting it
		// would make two spellings of one name compare unequal downstream.
		expect(isObjectSha(ROOT.sha.toUpperCase())).toBe(false);
		expect(isObjectSha(`${ROOT.sha}0`)).toBe(false);
		expect(isObjectSha(ROOT.sha.slice(1))).toBe(false);
		expect(isObjectSha(null)).toBe(false);
		expect(isObjectSha(42)).toBe(false);
	});
});

describe("timestamps", () => {
	it("keeps the offset the commit was made in", () => {
		// Normalising to UTC produces a different object with a different name, so
		// this is not a formatting preference.
		expect(gitTimestamp("2026-08-30T12:34:56+02:00")).toBe("1788086096 +0200");
		expect(gitTimestamp("2026-08-31T01:02:03Z")).toBe("1788138123 +0000");
		expect(gitTimestamp("2026-08-31T01:02:03-05:30")).toBe("1788157923 -0530");
	});

	it("accepts the offset without a colon", () => {
		expect(gitTimestamp("2026-08-31T01:02:03+0200")).toBe(gitTimestamp("2026-08-31T01:02:03+02:00"));
	});

	it("refuses a timestamp with no offset rather than guessing one", () => {
		// A local-time reading would be off by hours, which is a different commit.
		expect(() => gitTimestamp("2026-08-31T01:02:03")).toThrow();
		expect(() => gitTimestamp("2026-08-31")).toThrow();
		expect(() => gitTimestamp("")).toThrow();
	});
});

describe("payloads", () => {
	it("reproduces a real root commit byte for byte", () => {
		expect(commitPayload(ROOT.contents, "newline")).toBe(ROOT.object);
	});

	it("writes one parent line per parent, before the identities", async () => {
		const payload = commitPayload(CHILD.contents, "newline");

		expect(payload.split("\n")[1]).toBe(`parent ${ROOT.sha}`);
		expect(await commitObjectSha(payload)).toBe(CHILD.sha);
	});

	it("does not double a trailing newline the message already has", () => {
		const withNewline = commitPayload({ ...ROOT.contents, message: "first commit\n" }, "newline");

		expect(withNewline).toBe(ROOT.object);
	});
});

describe("reproduction", () => {
	it("finds the termination that reproduces the object", async () => {
		// GitHub's `message` field has an unspecified trailing-newline convention,
		// so which one this object used is discovered rather than assumed.
		const reproduced = await reproduceCommit(ROOT.contents, ROOT.sha);

		expect(reproduced?.termination).toBe("newline");
		expect(reproduced?.payload).toBe(ROOT.object);
	});

	it("finds the other termination when that is the one that matches", async () => {
		// A commit whose message genuinely does not end in a newline. git will not
		// make one from the command line, so it is built here from the bytes.
		const object = ROOT.object.replace(/\n$/, "");
		const sha = await commitObjectSha(object);

		const reproduced = await reproduceCommit(ROOT.contents, sha);

		expect(reproduced?.termination).toBe("bare");
		expect(reproduced?.payload).toBe(object);
	});

	it("refuses a commit whose bytes it cannot rebuild", async () => {
		// The fail-closed property the whole module rests on. An `encoding` header,
		// a `mergetag`, a field GitHub renders differently next year: all of them
		// arrive here as null, and null means *do not sign this*.
		expect(await reproduceCommit(ROOT.contents, CHILD.sha)).toBeNull();
	});

	it("refuses a commit it cannot render a timestamp for", async () => {
		// Returns rather than throws, so a malformed date is one more refusal
		// rather than a 500 on the webhook path.
		const contents = { ...ROOT.contents, author: { ...ROOT.contents.author, date: "yesterday" } };

		expect(await reproduceCommit(contents, ROOT.sha)).toBeNull();
	});

	it("will not accept a payload that hashes to a different object", async () => {
		// The check that makes reproduction meaningful. Without the sha comparison
		// this function would hand back its first guess, and a signature over that
		// guess would cover bytes that are not the commit.
		const wrongTree = { ...ROOT.contents, tree: "0".repeat(40) };

		expect(await reproduceCommit(wrongTree, ROOT.sha)).toBeNull();
	});
});

describe("folding a signature into the object", () => {
	const ARMOR = "-----BEGIN PGP SIGNATURE-----\n\nAAAA\nBBBB\n-----END PGP SIGNATURE-----";

	it("puts gpgsig after committer, with continuation lines indented", () => {
		const object = commitWithSignature(ROOT.object, ARMOR);
		const lines = object.split("\n");

		expect(lines[3]).toBe("gpgsig -----BEGIN PGP SIGNATURE-----");
		// The continuation convention git uses: exactly one leading space, including
		// on the armor's blank line, which becomes a line containing one space.
		expect(lines[4]).toBe(" ");
		expect(lines[5]).toBe(" AAAA");
		expect(lines[7]).toBe(" -----END PGP SIGNATURE-----");
		// And the message survives unchanged after the blank line.
		expect(object.endsWith("\n\nfirst commit\n")).toBe(true);
	});

	it("does not carry trailing newlines out of the armor into the header block", () => {
		const object = commitWithSignature(ROOT.object, `${ARMOR}\n\n`);

		// A blank continuation line at the end would terminate the header block
		// early, and the message would become part of the signature header.
		expect(object).toBe(commitWithSignature(ROOT.object, ARMOR));
	});

	it("reproduces a signed commit from its signature", async () => {
		const object = commitWithSignature(ROOT.object, ARMOR);
		const sha = await commitObjectSha(object);

		const reproduced = await reproduceCommit(ROOT.contents, sha, ARMOR);

		// The payload handed back is the *unsigned* one — the bytes a signature
		// covers — even though the sha it was proven against is the signed object's.
		expect(reproduced?.payload).toBe(ROOT.object);
	});

	it("refuses a payload with no header separator", () => {
		expect(() => commitWithSignature("tree deadbeef", ARMOR)).toThrow("separator");
	});
});
