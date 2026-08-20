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
// [github.com/go-git/go-git/v5/plumbing/object], and signatures are checked
// in-process with [github.com/ProtonMail/go-crypto/openpgp] against a keyring
// holding the service key alone.
//
// Parent lines are moved at the byte level rather than by mutating and
// re-encoding a decoded commit. go-git only reproduces an object's bytes while
// its decoded fields still match it, and its encoder canonicalizes author and
// committer lines that git itself accepts unchanged — an ident with no space
// before the date is read as a different timestamp entirely. Every byte git
// wrote and this run did not deliberately change is kept.
package gitsign
