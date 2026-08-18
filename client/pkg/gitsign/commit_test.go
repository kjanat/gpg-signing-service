package gitsign

import (
	"errors"
	"strings"
	"testing"
)

const (
	treeSHA    = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	parentOne  = "1111111111111111111111111111111111111111"
	parentTwo  = "2222222222222222222222222222222222222222"
	newParent  = "9999999999999999999999999999999999999999"
	testArmor  = "-----BEGIN PGP SIGNATURE-----\n\nAAAA\nBBBB\n-----END PGP SIGNATURE-----"
	testAuthor = "author A U Thor <author@example.test> 1700000000 +0000"
)

// rawCommit builds a commit object out of header lines and a message.
func rawCommit(header []string, message string) []byte {
	return []byte(strings.Join(header, "\n") + "\n\n" + message)
}

func TestParentsOf(t *testing.T) {
	tests := []struct {
		name   string
		header []string
		want   []string
	}{
		{
			name:   "root commit",
			header: []string{"tree " + treeSHA, testAuthor},
			want:   nil,
		},
		{
			name:   "single parent",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor},
			want:   []string{parentOne},
		},
		{
			name:   "merge commit",
			header: []string{"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo, testAuthor},
			want:   []string{parentOne, parentTwo},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parentsOf(rawCommit(tt.header, "message\n"))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
			for index := range got {
				if got[index] != tt.want[index] {
					t.Errorf("parent %d: expected %s, got %s", index, tt.want[index], got[index])
				}
			}
		})
	}
}

func TestIsSigned(t *testing.T) {
	unsigned := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")
	signed := rawCommit([]string{
		"tree " + treeSHA,
		testAuthor,
		"gpgsig -----BEGIN PGP SIGNATURE-----",
		" ",
		" AAAA",
		" -----END PGP SIGNATURE-----",
	}, "message\n")

	if got, err := isSigned(unsigned); err != nil || got {
		t.Errorf("expected unsigned commit to report false, got %v (err %v)", got, err)
	}
	if got, err := isSigned(signed); err != nil || !got {
		t.Errorf("expected signed commit to report true, got %v (err %v)", got, err)
	}
}

func TestCommitterEmail(t *testing.T) {
	tests := []struct {
		name   string
		header []string
		want   string
	}{
		{
			name:   "lowercases the address",
			header: []string{"tree " + treeSHA, "committer C O Mitter <Committer@Example.Test> 1700000000 +0000"},
			want:   "committer@example.test",
		},
		{
			name:   "no committer header",
			header: []string{"tree " + treeSHA, testAuthor},
			want:   "",
		},
		{
			name:   "committer without an address",
			header: []string{"tree " + treeSHA, "committer C O Mitter 1700000000 +0000"},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := committerEmail(rawCommit(tt.header, "message\n"))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestCommitHeaderRejectsMalformedObject(t *testing.T) {
	if _, err := parentsOf([]byte("tree " + treeSHA)); !errors.Is(err, errMalformed) {
		t.Fatalf("expected errMalformed, got %v", err)
	}
}

// A commit's headers must stay in git's required order, so the remapped
// parents have to land where the originals were, not at the end.
func TestUnsignedObjectPlacesParentsInPlace(t *testing.T) {
	raw := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		testAuthor,
		"committer C O Mitter <committer@example.test> 1700000000 +0000",
	}, "message\n")

	got := string(unsignedObject(raw, []string{newParent}))
	want := "tree " + treeSHA + "\nparent " + newParent + "\n" + testAuthor +
		"\ncommitter C O Mitter <committer@example.test> 1700000000 +0000\n\nmessage\n"
	if got != want {
		t.Errorf("expected:\n%q\ngot:\n%q", want, got)
	}
}

func TestUnsignedObjectRemapsEveryMergeParent(t *testing.T) {
	raw := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		"parent " + parentTwo,
		testAuthor,
	}, "merge\n")

	got := string(unsignedObject(raw, []string{newParent, parentTwo}))
	if !strings.Contains(got, "parent "+newParent+"\nparent "+parentTwo+"\n") {
		t.Errorf("expected both parents in order, got:\n%q", got)
	}
	if strings.Contains(got, parentOne) {
		t.Errorf("expected the old parent to be gone, got:\n%q", got)
	}
}

func TestUnsignedObjectDropsSignatureAndContinuations(t *testing.T) {
	raw := rawCommit([]string{
		"tree " + treeSHA,
		testAuthor,
		"gpgsig -----BEGIN PGP SIGNATURE-----",
		" ",
		" AAAA",
		" -----END PGP SIGNATURE-----",
	}, "message\n")

	got := string(unsignedObject(raw, nil))
	if strings.Contains(got, "gpgsig") || strings.Contains(got, "AAAA") {
		t.Errorf("expected the signature and its continuations to be gone, got:\n%q", got)
	}
	if got != "tree "+treeSHA+"\n"+testAuthor+"\n\nmessage\n" {
		t.Errorf("unexpected object:\n%q", got)
	}
}

// A message body that itself contains a blank line must survive intact; the
// header/message split happens once, at the first blank line.
func TestUnsignedObjectKeepsMultiParagraphMessage(t *testing.T) {
	raw := rawCommit([]string{"tree " + treeSHA, testAuthor}, "subject\n\nbody paragraph\n")

	got := string(unsignedObject(raw, nil))
	if !strings.HasSuffix(got, "\n\nsubject\n\nbody paragraph\n") {
		t.Errorf("expected the whole message to survive, got:\n%q", got)
	}
}

func TestWithSignatureIndentsContinuations(t *testing.T) {
	payload := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")

	got := string(withSignature(payload, []byte(testArmor)))
	want := "tree " + treeSHA + "\n" + testAuthor +
		"\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n BBBB\n -----END PGP SIGNATURE-----\n\nmessage\n"
	if got != want {
		t.Errorf("expected:\n%q\ngot:\n%q", want, got)
	}
}

// Embedding a signature and stripping it again must be a round trip, or the
// bytes the service signed are not the bytes git will verify.
func TestWithSignatureRoundTrips(t *testing.T) {
	payload := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		testAuthor,
	}, "message\n")

	stripped := unsignedObject(withSignature(payload, []byte(testArmor)), []string{parentOne})
	if string(stripped) != string(payload) {
		t.Errorf("expected:\n%q\ngot:\n%q", payload, stripped)
	}
}
