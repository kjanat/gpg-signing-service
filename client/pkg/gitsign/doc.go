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
// All object access shells out to the system git binary, and verification
// shells out to gpg against a throwaway keyring holding only the service key.
// Both binaries must be on PATH.
package gitsign
