/**
 * A real, service-signed commit out of this repository's own history.
 *
 * The fixture that keeps `#utils/git-commit` honest. Everything in that module
 * is a claim about what Git does — header order, the folding of a multi-line
 * `gpgsig`, the `<epoch> <offset>` date form, the `commit <len>\0` object
 * header — and a test written from the same understanding as the code proves
 * nothing about whether the understanding is right.
 *
 * So the fixture is not constructed. It is the byte-for-byte output of
 * `git cat-file commit b40f148bce8f`, whose SHA-1 is that commit's real
 * object id, and the suite requires the module to reproduce both from the
 * parts. A wrong assumption fails against Git rather than agreeing with itself.
 *
 * Stored JSON-encoded rather than as a template literal, because the message
 * contains backticks and a fixture that has to be edited to be stored is not
 * the bytes Git produced any more.
 *
 * It is also, incidentally, a commit this very service signed through the CI
 * shim — so the payload shape being reproduced is one openpgp.js has already
 * produced a Git-valid signature over.
 */

/** The commit's object id, as Git names it. */
export const FIXTURE_SHA = "b40f148bce8ffce3359d3dd6b5bc4ede5008c653";

/** `git cat-file commit <sha>`, exactly. */
export const FIXTURE_OBJECT =
	'tree 507157e584349cd17224adc04d9310af983358c4\nparent f02a76c621fa526ea2939aba91771da39216e5fc\nauthor Kaj Kowalski <info@kajkowalski.nl> 1788154977 +0000\ncommitter Kaj Kowalski <info@kajkowalski.nl> 1788154977 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n wrsEABYKAG0FgmqVFHIJEGLnXlRJeBXdRRQAAAAAABwAIHNhbHRAbm90YXRp\n b25zLm9wZW5wZ3Bqcy5vcmdWBuXWBtT/r/soB99Sro1FdWDi+kmY8FFyNZzM\n CZWmkRYhBIBtOhuflX1nMZULymLnXlRJeBXdAABGZgD/Ue730uywZTyZTN98\n C/IBdec47gYmTZB3YCZwjvLI7pIBAMXwV28F30vvdCEVsX++rKs44fedZfRd\n nkdw/xXf3KwC\n =C2F/\n -----END PGP SIGNATURE-----\n\ndocs(github-app): teach the config surfaces the new grant grammar\n\n`docs/github-app.md`, `docs/security-model.md` and the parser\'s own error\nmessage all learned about `=<keyId>`. The three places an operator reads\nwhile typing the value did not:\n\n- `wrangler.toml`, the comment directly above where the variable is\n  written. Still `<installationId>:<owner>/<repo>`, and still "a malformed\n  entry refuses every delivery" without the sentence that matters more \u2014\n  a repeated pair now refuses every delivery too, which is the one way a\n  configuration that works today starts answering 500 after this merges.\n- `Env.GITHUB_APP_ALLOWED_REPOSITORIES`, the JSDoc an editor shows on\n  hover. Same stale grammar, and "pairs rather than two independent\n  lists" without "and the key rides inside the entry for the same\n  reason", which is the whole argument.\n- The `AUTH_SUBJECT_UNTRUSTED` hint, which quotes the grammar back at\n  whoever hit it.\n\nAn operator following the wrangler.toml comment writes a bare pair, gets\n`202 {"signingKey": false}`, and finds out the binding is missing only\nonce a handler that signs exists.\n\nComments and one hint string. No behaviour, no generated drift.\n';

/**
 * A real *unsigned* commit whose object is written in `+0200`.
 *
 * The fixture the timezone recovery is checked against, and it is a commit out
 * of this repository rather than a constructed one for the reason above: the
 * claim under test is about what GitHub's API does and does not tell you, and
 * a fixture invented alongside the code would agree with whatever the code
 * believes.
 *
 * Both halves are recorded. {@link NON_UTC_OBJECT} is `git cat-file commit`
 * exactly, and {@link NON_UTC_API} is what `GET /git/commits/{sha}` returns for
 * that same commit — where both dates read `2026-08-30T19:05:00Z`, two hours
 * off the wall clock the author committed at and with the offset gone. A
 * rewrite built from the JSON alone cannot reproduce the object, and the
 * distance between the two is exactly the bug.
 */
export const NON_UTC_SHA = "11bf19bd9789cc6ff7a8fb63c55f973cb5420e27";

/** `git cat-file commit <NON_UTC_SHA>`, exactly. No `gpgsig`, no trailing newline. */
export const NON_UTC_OBJECT =
	"tree c93ec7f22ad2cabca76415f3389524a7d43c6435\nparent cd01952d981ed9169dca0167e2a13b611db7de92\nauthor Kaj Kowalski <info@kajkowalski.nl> 1788116700 +0200\ncommitter Kaj Kowalski <info@kajkowalski.nl> 1788116700 +0200\n\nci: remove the spent Dependabot activation patch";

/** `GET /repos/kjanat/gpg-signing-service/git/commits/<NON_UTC_SHA>`, reduced to the fields read. */
export const NON_UTC_API = {
	sha: NON_UTC_SHA,
	message: "ci: remove the spent Dependabot activation patch",
	tree: { sha: "c93ec7f22ad2cabca76415f3389524a7d43c6435" },
	parents: [{ sha: "cd01952d981ed9169dca0167e2a13b611db7de92" }],
	author: { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: "2026-08-30T19:05:00Z" },
	committer: { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: "2026-08-30T19:05:00Z" },
	verification: { signature: null },
} as const;

/** The first ten lines of `Accept: application/vnd.github.patch` for that commit, verbatim. */
export const NON_UTC_PATCH =
	"From 11bf19bd9789cc6ff7a8fb63c55f973cb5420e27 Mon Sep 17 00:00:00 2001\nFrom: Kaj Kowalski <info@kajkowalski.nl>\nDate: Sun, 30 Aug 2026 21:05:00 +0200\nSubject: [PATCH] ci: remove the spent Dependabot activation patch\n\n---\n .github/workflows-pending/activate.patch | 54 ------------------------\n 1 file changed, 54 deletions(-)\n delete mode 100644 .github/workflows-pending/activate.patch\n\n";

/**
 * A real commit whose author and committer offsets *differ*.
 *
 * Produced by Git — `git commit-tree` over this repository's own tree and
 * parent with `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE` set to `+0545` and
 * `-0330` — so the object bytes and the id below are Git's, not this suite's.
 * It exists because the cheap recovery searches the two offsets *together*, and
 * this is the shape that defeats it and sends the client to the patch
 * representation for the author's half.
 *
 * Its message also ends in a newline, which is the other thing
 * `GET /git/commits/{sha}` strips and the other ambiguity recovery has to
 * resolve. One fixture, both.
 */
export const SKEWED_SHA = "3d26402438b552e54f84471b198e03f814c18ec5";

/** `git cat-file commit <SKEWED_SHA>`, exactly. */
export const SKEWED_OBJECT =
	"tree c93ec7f22ad2cabca76415f3389524a7d43c6435\nparent cd01952d981ed9169dca0167e2a13b611db7de92\nauthor Kaj Kowalski <info@kajkowalski.nl> 1788116700 +0545\ncommitter Kaj Kowalski <info@kajkowalski.nl> 1788116700 -0330\n\nchore: a commit whose author and committer disagree about the clock\n";

/** The same commit as the API would report it: offsets gone, trailing newline gone. */
export const SKEWED_API = {
	sha: SKEWED_SHA,
	message: "chore: a commit whose author and committer disagree about the clock",
	tree: { sha: "c93ec7f22ad2cabca76415f3389524a7d43c6435" },
	parents: [{ sha: "cd01952d981ed9169dca0167e2a13b611db7de92" }],
	author: { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: "2026-08-30T19:05:00Z" },
	committer: { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: "2026-08-30T19:05:00Z" },
	verification: { signature: null },
} as const;

/**
 * `git format-patch`'s header for it, which is the one rendering that keeps `+0545`.
 *
 * The `Date:` line is Git's own — `git log -1 --format='Date: %aD'` over the
 * real object — not a hand-computed one, because the whole point of this
 * fixture is that the offset is not recomputed from an instant.
 */
export const SKEWED_PATCH =
	"From 3d26402438b552e54f84471b198e03f814c18ec5 Mon Sep 17 00:00:00 2001\nFrom: Kaj Kowalski <info@kajkowalski.nl>\nDate: Mon, 31 Aug 2026 00:50:00 +0545\nSubject: [PATCH] chore: a commit whose author and committer disagree about the\n clock\n\n---\n a | 1 +\n 1 file changed, 1 insertion(+)\n\n";
