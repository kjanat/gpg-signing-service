// Package gitsign applies PGP signatures from the signing service to existing
// Git commits.
//
// Requesting a signature and applying one are different operations. The
// [github.com/kjanat/gpg-signing-service/client/pkg/client] SDK does the first:
// it posts commit bytes and returns a detached armored signature. This package
// does the second, which is destructive — embedding a signature rewrites the
// commit object, changes its SHA, and forces every descendant to be rewritten
// too.
//
// [Run] stops at "git update-ref HEAD". It never pushes. Publishing the
// rewritten history is left to the operator, who is the only one who can weigh
// branch protection, concurrent writers, and the blast radius of a force push.
//
// Object access shells out to the system git binary, which is the authority on
// its own repository format, config, worktrees and alternates; only git is
// required on PATH. Everything above the object store is a library: commit
// objects are parsed and their signature headers stripped with go-git's
// [github.com/go-git/go-git/v6/plumbing/object], and signatures are checked
// in-process with [github.com/ProtonMail/go-crypto/openpgp] against a keyring
// holding the service key alone.
//
// Both hash algorithms are signed. git names the signature header after the
// repository's object format — gpgsig for sha1, gpgsig-sha256 for sha256 — and
// checks that spelling alone, so a run reads and writes the one git will look
// at. A repository in hash-algorithm compatibility mode carries both, over
// payloads only git can rebuild; a rewrite there replaces the header git
// verifies and warns that the other is gone.
//
// Reparenting a commit is a decode, a change to its parent hashes, and a
// re-encode without its signature — no byte-level surgery on the header block.
// That keeps every byte git wrote and this run did not deliberately change,
// but only against the go-git the go.mod replace directive selects: a fork
// that decodes headers wherever git put them and replays the ones a rewrite
// did not touch. Released go-git normalizes idents it re-encodes and reads an
// author or committer outside its canonical slot as empty, so the same rewrite
// there would move dates and drop names git itself reads back without
// complaint.
package gitsign
