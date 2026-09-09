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
	// The ident git fsck calls missingSpaceBeforeDate: no space between the
	// closing bracket and the timestamp. git reads it as November 2023, and
	// go-git without the pin in go.mod reads it as March 1992.
	crampedAuthor    = "author A U Thor <author@example.test>1700000000 +0000"
	crampedCommitter = "committer A U Thor <author@example.test>1700000000 +0000"
	// customHeader is a header no encoder knows, which has to survive a
	// rewrite in place, and latin1Encoding a non-default encoding header the
	// same is true of.
	customHeader   = "custom value"
	latin1Encoding = "encoding ISO-8859-1"
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

// structEncoded moves a commit's parents the way go-git means them to be
// moved: mutate ParentHashes and re-encode. Nothing in this package does that
// — the byte path exists so a rewrite never reaches the struct encoder — so
// this is the only thing in the suite that exercises it.
func structEncoded(t *testing.T, raw []byte, parents []string) []byte {
	t.Helper()

	commit, err := decodeCommit(raw)
	if err != nil {
		t.Fatalf("could not decode the commit: %v", err)
	}
	hashes := make([]plumbing.Hash, 0, len(parents))
	for _, parent := range parents {
		hash, ok := plumbing.FromHex(parent)
		if !ok {
			t.Fatalf("could not read the replacement parent %s", parent)
		}
		hashes = append(hashes, hash)
	}
	commit.ParentHashes = hashes

	encoded, err := encodeObject(commit.EncodeWithoutSignature)
	if err != nil {
		t.Fatalf("could not encode the commit: %v", err)
	}
	return encoded
}

// The pin in go.mod is the subject here, not this package's own paths. This
// repository builds go-git from the fork carrying go-git/go-git#2328, where
// the struct encoder writes a decoded commit's ident and header bytes back
// unchanged; released go-git reads "<author@example.test>1700000000" as the
// year 1992 and then writes that back, drops an explicit "encoding UTF-8" and
// reorders unknown headers around it. Because no production path here reaches
// that encoder, nothing else in the suite would notice the replace directive
// falling out of the build, so every shape the fork fixes is driven through it
// directly and checked against the byte path's answer.
func TestPinnedStructEncoderKeepsEveryShapeVerbatim(t *testing.T) {
	committer := strings.Replace(testAuthor, "author", "committer", 1)

	tests := []struct {
		name   string
		header []string
	}{
		{
			name:   "canonical ident",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, committer},
		},
		{
			name: "no space before the date",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				crampedAuthor, crampedCommitter,
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
			name:   "explicit UTF-8 encoding",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, committer, "encoding UTF-8"},
		},
		{
			name: "unknown header before encoding",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne, testAuthor, committer,
				customHeader, latin1Encoding,
			},
		},
		{
			name: "mergetag with continuations",
			header: append([]string{
				"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo, testAuthor, committer,
			}, mergeTagHeaderLines(parentTwo, "v1")...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := rawCommit(tt.header, "subject\n\nbody\n")

			parents, err := parentsOf(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			moved := append([]string{newParent}, parents[1:]...)

			want, err := unsignedObject(raw, moved)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := structEncoded(t, raw, moved)

			if string(got) != string(want) {
				t.Errorf("go-git's struct encoder did not reproduce the object, which means go.mod's "+
					"replace directive is not in this build:\n want %q\n  got %q", want, got)
			}
		})
	}
}

// The shapes the fork does not fix, and the reason the parent lines are still
// moved a byte at a time rather than through the encoder above.
//
// Two causes, neither of them in #2328's scope. go-git reads the author and
// committer out of their canonical slots alone — straight after the parents,
// and straight after each other — so a header sitting before or between them
// decodes as no ident at all, and the encoder writes "author  <> 0 +0000" back
// over a real name and date. And an extra header with an empty value loses the
// space that separated the key from it.
//
// git reads every row here without complaint: an interposed gpgsig reports
// "an=A U Thor at=1700000000" from git log, the same as the canonical form.
// "git fsck" does call the ident shapes missingAuthor or missingCommitter,
// which is the company they keep — missingSpaceBeforeDate is flagged the same
// way — and importers write all of it. A rewrite that dropped authorship on
// the way past would be a far worse answer than a rewrite that moved a parent
// and left everything else alone.
func TestUnsignedObjectKeepsWhatTheStructPathLoses(t *testing.T) {
	committer := strings.Replace(testAuthor, "author", "committer", 1)
	signature := signatureHeaderLines("gpgsig")

	tests := []struct {
		name string
		// signed marks a row whose signature header the strip removes, so only
		// the ident assertion applies and not the round trip.
		signed bool
		header []string
	}{
		{
			name:   "signature before the author",
			signed: true,
			header: append(append([]string{"tree " + treeSHA, "parent " + parentOne}, signature...), testAuthor, committer),
		},
		{
			name:   "signature between author and committer",
			signed: true,
			header: append(append([]string{"tree " + treeSHA, "parent " + parentOne, testAuthor}, signature...), committer),
		},
		{
			name: "mergetag before the author",
			header: append([]string{
				"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo,
			}, append(mergeTagHeaderLines(parentTwo, "v1"), testAuthor, committer)...),
		},
		{
			name:   "unknown header before the author",
			header: []string{"tree " + treeSHA, "parent " + parentOne, customHeader, testAuthor, committer},
		},
		{
			name:   "encoding before the author",
			header: []string{"tree " + treeSHA, "parent " + parentOne, latin1Encoding, testAuthor, committer},
		},
		{
			name:   "unknown header between author and committer",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, customHeader, committer},
		},
		{
			name:   "committer before the author",
			header: []string{"tree " + treeSHA, "parent " + parentOne, committer, testAuthor},
		},
		{
			name:   "extra header with an empty value",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, committer, "custom "},
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
			if !strings.Contains(string(payload), "\n"+testAuthor+"\n") ||
				!strings.Contains(string(payload), "\n"+committer+"\n") {
				t.Errorf("moving a parent rewrote an ident go-git cannot decode:\n%q", payload)
			}

			if tt.signed {
				return
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

// Moving a parent must not disturb any other byte. Every row below is an
// object git itself reads unchanged, and each one is a shape some encoder has
// been caught normalizing: ident lines, an explicit "encoding UTF-8" header,
// unknown headers ordered around it. A round trip that swaps the parent back
// has to reproduce the object exactly.
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
				crampedAuthor, crampedCommitter,
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
				strings.Replace(testAuthor, "author", "committer", 1), customHeader, latin1Encoding,
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

// A reparented commit's ident has to survive verbatim whatever go-git's own
// decoder makes of it, because git is what reads the object afterwards. This
// shape is the one the pinned fork fixes at the decoder; the assertion holds
// either way, which is the point of moving the line rather than rewriting it.
func TestUnsignedObjectKeepsAnIdentGoGitMisreads(t *testing.T) {
	raw := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		crampedAuthor,
		crampedCommitter,
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
