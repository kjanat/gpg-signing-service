package gitsign

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// now is the instant the identity tests are evaluated at. Every fixture below
// is dated relative to it, so none of them depend on the wall clock.
var now = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// testKey wraps a freshly generated entity as the engine would see it.
func testKey(t *testing.T, entity *openpgp.Entity) *signingKey {
	t.Helper()
	return &signingKey{entities: openpgp.EntityList{entity}}
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

	good, detail := key.verify(raw, formatSHA1)
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
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, foreign, payload), "\n")), formatSHA1)

	good, detail := testKey(t, service).verify(signed, formatSHA1)
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
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, entity, payload), "\n")), formatSHA1)

	tampered := strings.Replace(string(signed), "message\n", "tampered\n", 1)
	good, detail := testKey(t, entity).verify([]byte(tampered), formatSHA1)
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
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, entity, payload), "\n")), formatSHA1)

	if good, detail := testKey(t, entity).verify(signed, formatSHA1); !good {
		t.Errorf("expected the key's own signature to verify, got %q", detail)
	}
}

// The header spelling is not bookkeeping: git strips and checks the one that
// matches the repository's hash algorithm and ignores the other, so a commit
// signed for a sha256 repository must verify under sha256 and read as unsigned
// under sha1 — the second is what makes a run re-sign it rather than trust a
// signature git would not honor.
func TestVerifyReadsTheHeaderForTheObjectFormat(t *testing.T) {
	entity := newEntity(t, serviceName, serviceEmail)
	payload := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, entity, payload), "\n")), formatSHA256)

	if good, detail := testKey(t, entity).verify(signed, formatSHA256); !good {
		t.Errorf("expected a gpgsig-sha256 signature to verify under sha256, got %q", detail)
	}
	// Not reasonUnsigned: the run's advice for an unsigned tip is --sign-others,
	// which fixes nothing here, and a commit signed under the other spelling is
	// not the same finding as one nobody ever signed.
	if good, detail := testKey(t, entity).verify(signed, formatSHA1); good || detail != reasonWrongHeader {
		t.Errorf("expected the wrong-header explanation, got %v %q", good, detail)
	}
}

// git bails at the second signature rather than picking a winner, so a commit
// carrying two blocks has no single signer to report and is refused here too.
func TestVerifyRejectsMoreThanOneSignatureBlock(t *testing.T) {
	entity := newEntity(t, serviceName, serviceEmail)
	payload := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")

	block := strings.Trim(detachSign(t, entity, payload), "\n")
	signed := withSignature(payload, []byte(block+"\n"+block), formatSHA1)

	if good, detail := testKey(t, entity).verify(signed, formatSHA1); good || detail != reasonMultipleSigs {
		t.Errorf("expected the multiple-signature explanation, got %v %q", good, detail)
	}
}

// Only the OpenPGP spellings can be verified here, but every armor git reads as
// a signature has to be counted, or a PGP block paired with an SSH one reads as
// singly signed.
func TestSignatureBlocksCountsEveryArmorGitReads(t *testing.T) {
	tests := []struct {
		name      string
		signature string
		want      int
	}{
		{name: "none", signature: "", want: 0},
		{name: "one pgp block", signature: testArmor, want: 1},
		{name: "two pgp blocks", signature: testArmor + "\n" + testArmor, want: 2},
		{
			name:      "pgp and ssh",
			signature: testArmor + "\n-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----",
			want:      2,
		},
		{
			name:      "armor named in the message body",
			signature: "not a signature: -----BEGIN PGP SIGNATURE-----",
			want:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signatureBlocks(tt.signature); got != tt.want {
				t.Errorf("expected %d block(s), got %d", tt.want, got)
			}
		})
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
