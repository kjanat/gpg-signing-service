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
