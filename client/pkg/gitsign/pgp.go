package gitsign

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
)

// The explanations verify hands back. They are named so the tests assert on
// the same strings the operator reads.
const (
	reasonUnsigned     = "the commit carries no signature"
	reasonWrongHeader  = "the only signature is under the header for the other object format"
	reasonRevokedKey   = "the signing key was revoked"
	reasonExpiredKey   = "the signing key has expired"
	reasonExpiredSig   = "the signature has expired"
	reasonUnknownKey   = "signed by a key this service does not carry"
	reasonMultipleSigs = "the commit carries more than one signature"
	reasonMismatch     = "the signature does not match the commit"
)

// signingKey is the service's public key, parsed once per run.
//
// Verification runs against this key alone, never the caller's own keyring:
// the question is not "does some key the operator trusts cover this commit",
// it is "does *this service's* key cover it".
type signingKey struct {
	entities openpgp.EntityList
}

// newSigningKey parses the armored public key the service handed back.
func newSigningKey(armored string) (*signingKey, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("could not read the signing key: %w", err)
	}
	if len(entities) == 0 {
		return nil, errors.New("the signing key carries no OpenPGP key")
	}
	return &signingKey{entities: entities}, nil
}

// identities returns the lowercased e-mail addresses the key still claims. A
// commit is "ours" when its committer matches one of them.
//
// Revoked and expired user IDs are left out. An address the key revoked is no
// longer one the key speaks for, and signing under it anyway would be the tool
// asserting something the key itself withdrew.
func (k *signingKey) identities(now time.Time) (map[string]bool, error) {
	emails := make(map[string]bool)
	for _, entity := range k.entities {
		if entity.Revoked(now) {
			continue
		}
		for _, identity := range entity.Identities {
			if identity.Revoked(now) || identity.UserId == nil {
				continue
			}
			self := identity.SelfSignature
			if self == nil || self.SigExpired(now) || entity.PrimaryKey.KeyExpired(self, now) {
				continue
			}
			if email := strings.ToLower(identity.UserId.Email); email != "" {
				emails[email] = true
			}
		}
	}

	if len(emails) == 0 {
		return nil, errors.New("the signing key carries no current user ID with an email address")
	}
	return emails, nil
}

// verify reports whether the raw commit object carries a signature this key
// accepts, alongside an explanation when it does not. format selects the
// header spelling, which is the one git itself would check.
//
// The check is done here rather than through go-git's Commit.Verify for two
// reasons. Verify reads the gpgsig field alone, so it cannot see a sha256
// repository's signature at all; and it re-parses the armored keyring on every
// call, while the scan for the last signed commit calls this once per commit
// over all of reachable history.
func (k *signingKey) verify(raw []byte, format objectFormat) (bool, string) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return false, err.Error()
	}
	signature := format.signatureOf(commit)
	if signature == "" {
		// A signature under the other spelling is not a fallback, but it is a
		// different story from an unsigned commit, and the two have different
		// remedies: an unsigned tip is what --sign-others fixes, while this is
		// a signature written for a repository this one is not.
		if commit.Signature != "" || commit.SignatureSHA256 != "" {
			return false, reasonWrongHeader
		}
		return false, reasonUnsigned
	}
	// git stops at the first status line of a second signature rather than
	// picking a winner, so a commit with more than one block has no single
	// signer to report and is refused here too.
	if signatureBlocks(signature) > 1 {
		return false, reasonMultipleSigs
	}

	// The payload is the object with every signature header stripped, which is
	// what the service signed and what git reconstructs before verifying.
	payload, err := encodeObject(commit.EncodeWithoutSignature)
	if err != nil {
		return false, err.Error()
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(
		k.entities, bytes.NewReader(payload), strings.NewReader(signature), nil,
	); err != nil {
		return false, verifyReason(err)
	}
	return true, ""
}

// signatureBeginnings are the armor lines git reads as the start of a
// signature. Only the OpenPGP ones are blocks this package can verify, but all
// four are counted: a commit carrying a PGP block and an SSH block is one git
// refuses, and reading it as singly signed here would leave a signature git
// does not honor in place.
var signatureBeginnings = []string{
	"-----BEGIN PGP SIGNATURE-----",
	"-----BEGIN PGP MESSAGE-----",
	"-----BEGIN SIGNED MESSAGE-----",
	"-----BEGIN SSH SIGNATURE-----",
}

// signatureBlocks counts the armored blocks a signature header carries.
func signatureBlocks(signature string) int {
	blocks := 0
	for line := range strings.SplitSeq(signature, "\n") {
		for _, beginning := range signatureBeginnings {
			if strings.HasPrefix(line, beginning) {
				blocks++
				break
			}
		}
	}
	return blocks
}

// verifyReason turns a verification failure into an explanation an operator
// can act on. The library's sentinel errors replace the status-code scraping
// this package used to do against gpg's --raw output.
func verifyReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, pgperrors.ErrKeyRevoked):
		return reasonRevokedKey
	case errors.Is(err, pgperrors.ErrKeyExpired):
		return reasonExpiredKey
	case errors.Is(err, pgperrors.ErrSignatureExpired):
		return reasonExpiredSig
	case errors.Is(err, pgperrors.ErrUnknownIssuer):
		return reasonUnknownKey
	}

	// A wrong signature over the right key is reported as a typed
	// SignatureError rather than a sentinel.
	var mismatch pgperrors.SignatureError
	if errors.As(err, &mismatch) {
		return reasonMismatch
	}
	// Anything else — an SSH signature in the gpgsig header, a truncated armor
	// block — is more useful spelled out than flattened into "did not verify".
	return err.Error()
}
