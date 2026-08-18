package gitsign

import "testing"

func TestVerifyReason(t *testing.T) {
	tests := []struct {
		name   string
		detail string
		want   string
	}{
		{
			name:   "bad signature",
			detail: "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG DEADBEEF Someone <a@b.test>",
			want:   "the signature does not match the commit",
		},
		{
			name:   "missing public key",
			detail: "[GNUPG:] ERRSIG DEADBEEF 22 8 00 0 9\n[GNUPG:] NO_PUBKEY DEADBEEF",
			want:   "signed by a key this service does not carry",
		},
		{
			name: "revocation wins over expiry",
			// gpg reports both for a revoked key that also expired; the
			// revocation is the actionable half.
			detail: "[GNUPG:] EXPKEYSIG DEADBEEF Someone\n[GNUPG:] REVKEYSIG DEADBEEF Someone",
			want:   "the signing key was revoked",
		},
		{
			name:   "expired signature",
			detail: "[GNUPG:] EXPSIG DEADBEEF Someone",
			want:   "the signature has expired",
		},
		{
			name:   "expired key",
			detail: "[GNUPG:] EXPKEYSIG DEADBEEF Someone",
			want:   "the signing key has expired",
		},
		{
			name:   "no recognizable status",
			detail: "gpg: Signature made Mon 01 Jan 2026",
			want:   "",
		},
		{
			name:   "empty output",
			detail: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyReason(tt.detail); got != tt.want {
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
