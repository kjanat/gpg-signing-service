package gitsign

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// The explanations verify hands back. They are named so the tests assert on
// the same strings the operator reads.
const (
	reasonUnsigned     = "the commit carries no signature"
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
	// armored is kept because go-git's Commit.Verify takes the armored form.
	armored  string
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
	return &signingKey{armored: armored, entities: entities}, nil
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
// accepts, alongside an explanation when it does not.
func (k *signingKey) verify(raw []byte) (bool, string) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return false, err.Error()
	}
	if commit.Signature == "" {
		return false, reasonUnsigned
	}
	if _, err := commit.Verify(k.armored); err != nil {
		return false, verifyReason(err)
	}
	return true, ""
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
	case errors.Is(err, object.ErrMultipleSignatures):
		return reasonMultipleSigs
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
