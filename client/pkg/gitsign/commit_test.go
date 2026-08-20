package gitsign

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

const (
	treeSHA    = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	parentOne  = "1111111111111111111111111111111111111111"
	parentTwo  = "2222222222222222222222222222222222222222"
	newParent  = "9999999999999999999999999999999999999999"
	testArmor  = "-----BEGIN PGP SIGNATURE-----\n\nAAAA\nBBBB\n-----END PGP SIGNATURE-----"
	testAuthor = "author A U Thor <author@example.test> 1700000000 +0000"
	// sha256HexLength is how long a sha256 object name prints, which is how the
	// engine tests tell the two formats apart without re-asking git.
	sha256HexLength = 64
)

// rawCommit builds a commit object out of header lines and a message.
func rawCommit(header []string, message string) []byte {
	return []byte(strings.Join(header, "\n") + "\n\n" + message)
}

// signatureHeaderLines renders an armored signature the way git writes it into
// a commit header: the first armor line on the header itself, every later line
// indented by one space. key is the header name: gpgsig for sha1, gpgsig-sha256
// for sha256, and both on the same commit in hash-algorithm compatibility mode.
func signatureHeaderLines(key string) []string {
	return []string{
		key + " -----BEGIN PGP SIGNATURE-----",
		" ",
		" AAAA",
		" -----END PGP SIGNATURE-----",
	}
}

// mergeTagHeaderLines renders an embedded tag object the way git writes it into
// a merge commit header: "mergetag object <sha>" on the header line itself,
// every later line of the tag indented by one space. object names the parent
// the tag points at, and tag its name, so a merge carrying several of them
// stays distinguishable.
func mergeTagHeaderLines(object, tag string) []string {
	return []string{
		"mergetag object " + object,
		" type commit",
		" tag " + tag,
		" tagger T <t@example.test> 1700000000 +0000",
		" ",
		" tag message",
	}
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
	signed := rawCommit(append(
		[]string{"tree " + treeSHA, testAuthor},
		signatureHeaderLines("gpgsig")...,
	), "message\n")

	if got, err := isSigned(unsigned); err != nil || got {
		t.Errorf("expected unsigned commit to report false, got %v (err %v)", got, err)
	}
	if got, err := isSigned(signed); err != nil || !got {
		t.Errorf("expected signed commit to report true, got %v (err %v)", got, err)
	}

	// go-git v6 decodes gpgsig and gpgsig-sha256 into separate fields, and v5
	// discarded the sha256 spelling outright. A commit carrying only that
	// header is still signed, and treating it as unsigned would sign over an
	// attestation already there.
	sha256Signed := rawCommit(append(
		[]string{"tree " + treeSHA, testAuthor},
		signatureHeaderLines("gpgsig-sha256")...,
	), "message\n")
	if got, err := isSigned(sha256Signed); err != nil || !got {
		t.Errorf("expected a gpgsig-sha256 commit to report true, got %v (err %v)", got, err)
	}
}

// A format this package does not know spells its signature header some other
// way, so guessing gpgsig would write a signature that repository reads as
// absent. Refusing keeps the cause visible instead.
func TestParseObjectFormat(t *testing.T) {
	tests := []struct {
		name    string
		want    objectFormat
		refused bool
	}{
		{name: "sha1", want: formatSHA1},
		{name: "sha256", want: formatSHA256},
		{name: "sha3", refused: true},
		{name: "", refused: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseObjectFormat(tt.name)
			if tt.refused {
				if err == nil {
					t.Fatalf("expected %q to be refused, got %q", tt.name, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
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

func TestDecodeRejectsMalformedObject(t *testing.T) {
	if _, err := parentsOf([]byte("not a commit object")); !errors.Is(err, object.ErrMalformedCommit) {
		t.Fatalf("expected ErrMalformedCommit, got %v", err)
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

	got, err := unsignedObject(raw, []string{newParent})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "tree " + treeSHA + "\nparent " + newParent + "\n" + testAuthor +
		"\ncommitter C O Mitter <committer@example.test> 1700000000 +0000\n\nmessage\n"
	if string(got) != want {
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

	remapped, err := unsignedObject(raw, []string{newParent, parentTwo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(remapped)
	if !strings.Contains(got, "parent "+newParent+"\nparent "+parentTwo+"\n") {
		t.Errorf("expected both parents in order, got:\n%q", got)
	}
	if strings.Contains(got, parentOne) {
		t.Errorf("expected the old parent to be gone, got:\n%q", got)
	}
}

// Every signature spelling has to go, and a payload git will not reproduce is
// worse than a missed one: git strips gpgsig and gpgsig-sha256 both before it
// checks a signature, so leaving either behind signs bytes that verify nowhere.
// A commit carries both headers in hash-algorithm compatibility mode, which
// git rev-parse --show-object-format still reports as sha1.
func TestUnsignedObjectDropsSignatureAndContinuations(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
	}{
		{"sha1", signatureHeaderLines("gpgsig")},
		{"sha256", signatureHeaderLines("gpgsig-sha256")},
		{"both", append(signatureHeaderLines("gpgsig"), signatureHeaderLines("gpgsig-sha256")...)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := rawCommit(append(
				[]string{"tree " + treeSHA, testAuthor},
				test.headers...,
			), "message\n")

			stripped, err := unsignedObject(raw, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := string(stripped)
			if strings.Contains(got, "gpgsig") || strings.Contains(got, "AAAA") {
				t.Errorf("expected the signature and its continuations to be gone, got:\n%q", got)
			}
			if got != "tree "+treeSHA+"\n"+testAuthor+"\n\nmessage\n" {
				t.Errorf("unexpected object:\n%q", got)
			}
		})
	}
}

// A message body that itself contains a blank line must survive intact; the
// header/message split happens once, at the first blank line.
func TestUnsignedObjectKeepsMultiParagraphMessage(t *testing.T) {
	raw := rawCommit([]string{"tree " + treeSHA, testAuthor}, "subject\n\nbody paragraph\n")

	kept, err := unsignedObject(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(kept)
	if !strings.HasSuffix(got, "\n\nsubject\n\nbody paragraph\n") {
		t.Errorf("expected the whole message to survive, got:\n%q", got)
	}
}

// The header is named after the repository's hash algorithm, and git checks
// that spelling alone: the sha1 header in a sha256 repository is a signature
// git never looks at, so the commit reads as unsigned.
func TestWithSignatureIndentsContinuations(t *testing.T) {
	payload := rawCommit([]string{"tree " + treeSHA, testAuthor}, "message\n")

	tests := []struct {
		format objectFormat
		header string
	}{
		{format: formatSHA1, header: sha1SignatureHeader},
		{format: formatSHA256, header: sha256SignatureHeader},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			got := string(withSignature(payload, []byte(testArmor), tt.format))
			want := "tree " + treeSHA + "\n" + testAuthor + "\n" + tt.header +
				" -----BEGIN PGP SIGNATURE-----\n \n AAAA\n BBBB\n -----END PGP SIGNATURE-----\n\nmessage\n"
			if got != want {
				t.Errorf("expected:\n%q\ngot:\n%q", want, got)
			}
		})
	}
}

// Embedding a signature and stripping it again must be a round trip, or the
// bytes the service signed are not the bytes git will verify. Both spellings
// have to round-trip: the strip is spelling-blind on purpose, since git also
// removes both before it checks either.
func TestWithSignatureRoundTrips(t *testing.T) {
	payload := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		testAuthor,
	}, "message\n")

	for _, format := range []objectFormat{formatSHA1, formatSHA256} {
		t.Run(string(format), func(t *testing.T) {
			stripped, err := unsignedObject(withSignature(payload, []byte(testArmor), format), []string{parentOne})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(stripped) != string(payload) {
				t.Errorf("expected:\n%q\ngot:\n%q", payload, stripped)
			}
		})
	}
}

// The pin in go.mod is the subject here, not this package's own paths. Parents
// are moved at the byte level precisely so a rewrite never reaches go-git's
// struct encoder, which means nothing else in this suite would notice the
// replace directive falling out of the build — and released go-git reads
// "<author@example.test>1700000000" as the year 1992, then writes that back.
// Mutating ParentHashes is what forces the struct path here.
func TestPinnedStructEncoderKeepsAnIdentVerbatim(t *testing.T) {
	ident := "A U Thor <author@example.test>1700000000 +0000"
	raw := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		"author " + ident,
		"committer " + ident,
	}, "subject\n")

	commit, err := decodeCommit(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	moved, ok := plumbing.FromHex(newParent)
	if !ok {
		t.Fatalf("could not read the replacement parent %s", newParent)
	}
	commit.ParentHashes = []plumbing.Hash{moved}

	encoded, err := encodeObject(commit.EncodeWithoutSignature)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := string(encoded)
	if !strings.Contains(got, "parent "+newParent) {
		t.Fatalf("expected the moved parent, got:\n%q", got)
	}
	if !strings.Contains(got, "author "+ident) || !strings.Contains(got, "committer "+ident) {
		t.Errorf("go-git's struct encoder rewrote the ident, which means go.mod's replace directive is "+
			"not in this build:\n%q", got)
	}
}

// Moving a parent must not disturb any other byte. go-git re-encodes from
// struct fields the moment a decoded commit is mutated, and its encoder
// canonicalizes ident lines, drops an explicit "encoding UTF-8" header and
// reorders unknown headers. Every row below is an object git itself reads
// unchanged, so a round trip that swaps the parent back has to reproduce it.
func TestUnsignedObjectPreservesEveryOtherByte(t *testing.T) {
	tests := []struct {
		name   string
		header []string
	}{
		{
			name:   "canonical ident",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, strings.Replace(testAuthor, "author", "committer", 1)},
		},
		{
			name: "no space before the date",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				"author A U Thor <author@example.test>1700000000 +0000",
				"committer A U Thor <author@example.test>1700000000 +0000",
			},
		},
		{
			name: "no space before the email",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				"author A U Thor<author@example.test> 1700000000 +0000",
				"committer A U Thor<author@example.test> 1700000000 +0000",
			},
		},
		{
			name: "no timezone",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				"author A U Thor <author@example.test> 1700000000",
				"committer A U Thor <author@example.test> 1700000000",
			},
		},
		{
			name: "zero-padded timestamp",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				"author A U Thor <author@example.test> 0001700000000 +0000",
				"committer A U Thor <author@example.test> 0001700000000 +0000",
			},
		},
		{
			name: "explicit UTF-8 encoding",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne, testAuthor,
				strings.Replace(testAuthor, "author", "committer", 1), "encoding UTF-8",
			},
		},
		{
			name: "unknown header before encoding",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne, testAuthor,
				strings.Replace(testAuthor, "author", "committer", 1), "custom value", "encoding ISO-8859-1",
			},
		},
		{
			name: "mergetag with continuations",
			header: append([]string{
				"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo, testAuthor,
				strings.Replace(testAuthor, "author", "committer", 1),
			}, mergeTagHeaderLines(parentTwo, "v1")...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := rawCommit(tt.header, "subject\n\nbody\n")

			parents, err := parentsOf(original)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			moved := append([]string{newParent}, parents[1:]...)

			payload, err := unsignedObject(original, moved)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			restored, err := unsignedObject(payload, parents)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(restored) != string(original) {
				t.Errorf("a round trip through a moved parent changed the object:\n want %q\n  got %q",
					original, restored)
			}
		})
	}
}

// A reparented commit's ident has to survive verbatim even when go-git's own
// decoder misreads it, because git is what reads the object afterwards.
func TestUnsignedObjectKeepsAnIdentGoGitMisreads(t *testing.T) {
	raw := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		"author A U Thor <author@example.test>1700000000 +0000",
		"committer A U Thor <author@example.test>1700000000 +0000",
	}, "subject\n")

	payload, err := unsignedObject(raw, []string{newParent})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(payload), "<author@example.test>1700000000 +0000") {
		t.Errorf("the author date was rewritten: %q", payload)
	}
	if strings.Contains(string(payload), "700000000 +0000\n") &&
		!strings.Contains(string(payload), "1700000000 +0000\n") {
		t.Errorf("the leading digit of the timestamp was eaten: %q", payload)
	}
}

// A root commit that gains a parent still has to put it where git requires,
// straight after the tree line.
func TestUnsignedObjectPlacesParentsOnARootCommit(t *testing.T) {
	raw := rawCommit([]string{"tree " + treeSHA, testAuthor}, "subject\n")

	payload, err := unsignedObject(raw, []string{newParent})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "tree " + treeSHA + "\nparent " + newParent + "\n"
	if !strings.HasPrefix(string(payload), want) {
		t.Errorf("expected the parent straight after the tree, got %q", payload)
	}
}
