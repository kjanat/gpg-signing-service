package gitsign

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// now is the instant the identity tests are evaluated at. Every fixture below
// is dated relative to it, so none of them depend on the wall clock.
var now = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// testKey wraps a freshly generated entity as the engine would see it.
func testKey(t *testing.T, entity *openpgp.Entity) *signingKey {
	t.Helper()
	return &signingKey{armored: exportKey(t, entity), entities: openpgp.EntityList{entity}}
}

// backdatedEntity generates a key stamped a day before now, so the identity
// tests can be evaluated at a fixed instant instead of the wall clock. A
// self-signature dated in the future counts as expired, which is exactly what
// a freshly generated key looks like from the past.
func backdatedEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	entity := newEntity(t, serviceName, serviceEmail)
	entity.PrimaryKey.CreationTime = now.Add(-24 * time.Hour)
	for _, identity := range entity.Identities {
		identity.SelfSignature.CreationTime = now.Add(-24 * time.Hour)
	}
	return entity
}

func TestIdentitiesReturnsTheAddressesTheKeyClaims(t *testing.T) {
	key := testKey(t, backdatedEntity(t))

	emails, err := key.identities(now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !emails[serviceEmail] || len(emails) != 1 {
		t.Errorf("expected exactly %s, got %v", serviceEmail, emails)
	}
}

// An address the key revoked is one the key stopped speaking for. Signing a
// commit under it would assert something the key itself withdrew.
func TestIdentitiesSkipsRevokedUserIDs(t *testing.T) {
	entity := backdatedEntity(t)
	for _, identity := range entity.Identities {
		identity.Revocations = append(identity.Revocations, &packet.Signature{
			SigType:      packet.SigTypeCertificationRevocation,
			CreationTime: now.Add(-time.Hour),
		})
	}

	if _, err := testKey(t, entity).identities(now); err == nil {
		t.Fatal("expected a revoked user ID to leave the key with no usable address")
	}
}

func TestIdentitiesSkipsExpiredUserIDs(t *testing.T) {
	entity := backdatedEntity(t)
	lifetime := uint32(3600)
	for _, identity := range entity.Identities {
		identity.SelfSignature.SigLifetimeSecs = &lifetime
	}

	if _, err := testKey(t, entity).identities(now); err == nil {
		t.Fatal("expected an expired self-signature to leave the key with no usable address")
	}
}

func TestIdentitiesSkipsExpiredKeys(t *testing.T) {
	entity := backdatedEntity(t)
	lifetime := uint32(3600)
	for _, identity := range entity.Identities {
		identity.SelfSignature.KeyLifetimeSecs = &lifetime
	}

	if _, err := testKey(t, entity).identities(now); err == nil {
		t.Fatal("expected an expired key to leave no usable address")
	}
}

func TestNewSigningKeyRejectsGarbage(t *testing.T) {
	if _, err := newSigningKey("not an armored key"); err == nil {
		t.Fatal("expected garbage input to be refused")
	}
}

// A run must not treat an unsigned commit as merely unverifiable: the two have
// different remedies.
func TestVerifyReportsAnUnsignedCommit(t *testing.T) {
	key := testKey(t, newEntity(t, serviceName, serviceEmail))
	raw := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")

	good, detail := key.verify(raw)
	if good || detail != reasonUnsigned {
		t.Errorf("expected an unsigned commit to be reported as such, got %v %q", good, detail)
	}
}

// A signature from a key the service does not hold is the case a commit signed
// by a colleague hits, and it needs its own words.
func TestVerifyRejectsAForeignSignature(t *testing.T) {
	service := newEntity(t, serviceName, serviceEmail)
	foreign := newEntity(t, foreignName, foreignEmail)

	payload := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, foreign, payload), "\n")))

	good, detail := testKey(t, service).verify(signed)
	if good {
		t.Fatal("expected a foreign signature to be refused")
	}
	if detail != reasonUnknownKey {
		t.Errorf("expected the unknown-issuer explanation, got %q", detail)
	}
}

// The signature covers the payload, so any edit to the commit after signing has
// to show up as a mismatch rather than a pass.
func TestVerifyRejectsATamperedCommit(t *testing.T) {
	entity := newEntity(t, serviceName, serviceEmail)
	payload := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, entity, payload), "\n")))

	tampered := strings.Replace(string(signed), "message\n", "tampered\n", 1)
	good, detail := testKey(t, entity).verify([]byte(tampered))
	if good {
		t.Fatal("expected a tampered commit to be refused")
	}
	if detail != reasonMismatch {
		t.Errorf("expected the mismatch explanation, got %q", detail)
	}
}

func TestVerifyAcceptsTheKeysOwnSignature(t *testing.T) {
	entity := newEntity(t, serviceName, serviceEmail)
	payload := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, entity, payload), "\n")))

	if good, detail := testKey(t, entity).verify(signed); !good {
		t.Errorf("expected the key's own signature to verify, got %q", detail)
	}
}

func TestVerifyReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "no error", err: nil, want: ""},
		{name: "revoked key", err: pgperrors.ErrKeyRevoked, want: reasonRevokedKey},
		{name: "expired key", err: pgperrors.ErrKeyExpired, want: reasonExpiredKey},
		{name: "expired signature", err: pgperrors.ErrSignatureExpired, want: reasonExpiredSig},
		{
			name: "unknown issuer",
			err:  pgperrors.ErrUnknownIssuer,
			want: "signed by a key this service does not carry",
		},
		{
			name: "multiple signatures",
			err:  object.ErrMultipleSignatures,
			want: reasonMultipleSigs,
		},
		{
			name: "bad signature",
			err:  pgperrors.SignatureError("hash tag doesn't match"),
			want: reasonMismatch,
		},
		{
			// An SSH signature in the gpgsig header lands here; the library's
			// own words beat flattening it into "did not verify".
			name: "anything else",
			err:  errors.New("openpgp: unsupported feature"),
			want: "openpgp: unsupported feature",
		},
		{
			name: "wrapped sentinel",
			err:  errors.Join(errors.New("checking the signature"), pgperrors.ErrKeyRevoked),
			want: reasonRevokedKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyReason(tt.err); got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestShortSHA(t *testing.T) {
	if got := short("1234567890abcdef"); got != "12345678" {
		t.Errorf("expected 12345678, got %s", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("expected the whole value for a short input, got %s", got)
	}
}
