package gitsign

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-git/go-git/v6/plumbing/object"
)

const (
	treeSHA     = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	parentOne   = "1111111111111111111111111111111111111111"
	parentTwo   = "2222222222222222222222222222222222222222"
	parentThree = "3333333333333333333333333333333333333333"
	newParent   = "9999999999999999999999999999999999999999"
	// A sha256 repository names the same objects at twice the width. Nothing
	// in this package measures a hash, so these exist to prove that.
	sha256TreeSHA   = "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"
	sha256Parent    = "1111111111111111111111111111111111111111111111111111111111111111"
	sha256NewParent = "9999999999999999999999999999999999999999999999999999999999999999"
	testArmor       = "-----BEGIN PGP SIGNATURE-----\n\nAAAA\nBBBB\n-----END PGP SIGNATURE-----"
	testAuthor      = "author A U Thor <author@example.test> 1700000000 +0000"
	// The ident git fsck calls missingSpaceBeforeDate: no space between the
	// closing bracket and the timestamp. git reads it as November 2023, and
	// go-git without the pin in go.mod reads it as March 1992.
	crampedAuthor    = "author A U Thor <author@example.test>1700000000 +0000"
	crampedCommitter = "committer A U Thor <author@example.test>1700000000 +0000"
	// An ident with no timezone at all, which git reads as UTC and released
	// go-git re-encodes with a "+0000" git never wrote.
	zonelessAuthor    = "author A U Thor <author@example.test> 1700000000"
	zonelessCommitter = "committer A U Thor <author@example.test> 1700000000"
	// A timestamp written with leading zeroes, which parses to the same
	// instant and re-encodes without them.
	paddedAuthor    = "author A U Thor <author@example.test> 0001700000000 +0000"
	paddedCommitter = "committer A U Thor <author@example.test> 0001700000000 +0000"
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

// A parent that is not an object name is refused rather than written. Every
// caller passes a SHA git itself printed, so none of these should ever arrive
// — but a commit reparented onto a truncated or zero hash is a valid object
// pointing at nothing, and go-git's own parser hands back exactly that: it
// accepts a partial hash and pads it out. A rewrite has to stop there rather
// than write it.
func TestUnsignedObjectRefusesAParentThatIsNotAnObjectName(t *testing.T) {
	raw := rawCommit([]string{"tree " + treeSHA, "parent " + parentOne, testAuthor}, "subject\n")

	for _, parent := range []string{
		"", "HEAD", "not-hex",
		parentOne[:39],           // an odd-length prefix, which no parser takes
		parentOne[:38],           // an even-length one, which FromHex zero-pads
		strings.ToUpper(treeSHA), // git prints object names in lower case
	} {
		t.Run(parent, func(t *testing.T) {
			if _, err := unsignedObject(raw, []string{parent}); err == nil {
				t.Errorf("expected %q to be refused as a parent", parent)
			}
		})
	}
}

// commitShape is a commit object git writes, reads back without complaint, and
// that some encoder has been caught normalizing on the way out again.
type commitShape struct {
	name   string
	header []string
	// message defaults to a two-paragraph body. A shape only sets it when the
	// body itself is the subject.
	message string
	// moved is the parent list to reparent onto. Empty means the ordinary
	// rewrite: the first parent is swapped for newParent and the rest kept, so
	// a merge stays a merge.
	moved []string
	// stripped names the headers unsignedObject removes as well as moving the
	// parents. Those rows expect them gone rather than replayed, and do not
	// round-trip.
	stripped []string
}

func (shape commitShape) body() string {
	if shape.message == "" {
		return "subject\n\nbody\n"
	}
	return shape.message
}

// reparent is the parent list this shape is rewritten onto, given the ones it
// arrived with.
func (shape commitShape) reparent(parents []string) []string {
	if shape.moved != nil {
		return shape.moved
	}
	moved := make([]string, len(parents))
	copy(moved, parents)
	moved[0] = newParent
	return moved
}

// historicalShapes is every commit layout this package has to reparent without
// disturbing a byte outside the parent lines.
//
// They are not hypothetical. git accepts all of them, importers and old git
// versions wrote them, and each one is a shape at least one encoder has been
// caught rewriting: idents git fsck calls missingSpaceBeforeDate, headers that
// arrive before or between the two idents, an explicit "encoding UTF-8" that
// released go-git deletes as redundant, unknown headers whose order around
// "encoding" it does not keep, an extra header with no value, and continuation
// lines under a mergetag.
func historicalShapes() []commitShape {
	committer := strings.Replace(testAuthor, "author", "committer", 1)
	signature := signatureHeaderLines("gpgsig")
	canonical := []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, committer}

	return []commitShape{
		{name: "canonical ident", header: canonical},
		{
			name: "no space before the date",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne, crampedAuthor, crampedCommitter,
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
				zonelessAuthor, zonelessCommitter,
			},
		},
		{
			name: "zero-padded timestamp",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				paddedAuthor, paddedCommitter,
			},
		},
		{name: "explicit UTF-8 encoding", header: append(slices.Clone(canonical), "encoding UTF-8")},
		{
			name:   "unknown header before encoding",
			header: append(slices.Clone(canonical), customHeader, latin1Encoding),
		},
		{
			name:   "extra header with an empty value",
			header: append(slices.Clone(canonical), "custom "),
		},
		{
			name: "octopus mergetag with continuations",
			header: slices.Concat(
				[]string{
					"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo,
					"parent " + parentThree, testAuthor, committer,
				},
				mergeTagHeaderLines(parentTwo, "v1"),
				mergeTagHeaderLines(parentThree, "v2"),
			),
		},
		{
			name: "mergetag before the author",
			header: slices.Concat(
				[]string{"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo},
				mergeTagHeaderLines(parentTwo, "v1"),
				[]string{testAuthor, committer},
			),
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
			name:     "signature before the author",
			header:   slices.Concat([]string{"tree " + treeSHA, "parent " + parentOne}, signature, []string{testAuthor, committer}),
			stripped: []string{sha1SignatureHeader},
		},
		{
			name:     "signature between author and committer",
			header:   slices.Concat([]string{"tree " + treeSHA, "parent " + parentOne, testAuthor}, signature, []string{committer}),
			stripped: []string{sha1SignatureHeader},
		},
		{
			name:     "sha256 signature spelling",
			header:   append(slices.Clone(canonical), signatureHeaderLines(sha256SignatureHeader)...),
			stripped: []string{sha256SignatureHeader},
		},
		{
			name: "both signature spellings",
			header: slices.Concat(canonical, signatureHeaderLines(sha1SignatureHeader),
				signatureHeaderLines(sha256SignatureHeader)),
			stripped: []string{sha1SignatureHeader, sha256SignatureHeader},
		},
		{
			name: "sha256 object",
			header: []string{
				"tree " + sha256TreeSHA, "parent " + sha256Parent, testAuthor, committer,
			},
			moved: []string{sha256NewParent},
		},
		{name: "CRLF body", header: canonical, message: "subject\r\n\r\nbody\r\n"},
		{name: "trailing blank lines", header: canonical, message: "subject\n\n\n\n"},
		{
			name:   "root commit gaining a parent",
			header: []string{"tree " + treeSHA, testAuthor, committer},
			moved:  []string{newParent},
		},
		{
			name: "merge losing a parent",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo, testAuthor, committer,
			},
			moved: []string{parentOne},
		},
	}
}

// splitPayload cuts a commit object into its header lines and its message.
func splitPayload(payload []byte) ([]string, string) {
	head, message, _ := strings.Cut(string(payload), "\n\n")
	return strings.Split(head, "\n"), message
}

// withoutHeader removes a header line and every continuation line git indents
// under it, which is how a stripped gpgsig disappears.
func withoutHeader(lines []string, key string) []string {
	kept := make([]string, 0, len(lines))
	dropping := false
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, key+" ") || line == key:
			dropping = true
		case dropping && strings.HasPrefix(line, " "):
		default:
			dropping = false
			kept = append(kept, line)
		}
	}
	return kept
}

// withoutParents drops the parent lines, leaving the header lines whose bytes
// a reparent is not allowed to touch.
func withoutParents(lines []string) []string {
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(line, "parent ") {
			kept = append(kept, line)
		}
	}
	return kept
}

// Reparenting must change the parent lines and nothing else. Rather than
// re-deriving the answer some other way, each row states it: the object git
// wrote, with its parent lines replaced by the requested ones, sitting where
// git requires them — directly after the tree line and before everything else.
//
// This is also what holds go.mod's replace directive down. unsignedObject
// reparents by mutating a decoded commit and re-encoding it, so every row here
// runs through go-git's struct encoder, and most of them come back wrong
// against a released go-git. Dropping the directive still compiles;
// TestUnsignedObjectNeedsThePinnedFork names what breaks.
func TestUnsignedObjectChangesOnlyParents(t *testing.T) {
	for _, shape := range historicalShapes() {
		t.Run(shape.name, func(t *testing.T) {
			original := rawCommit(shape.header, shape.body())

			parents, err := parentsOf(original)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			moved := shape.reparent(parents)

			payload, err := unsignedObject(original, moved)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			survives, wantMessage := splitPayload(original)
			for _, key := range shape.stripped {
				survives = withoutHeader(survives, key)
			}
			survives = withoutParents(survives)

			want := make([]string, 0, len(survives)+len(moved))
			want = append(want, survives[0]) // the tree line git requires first
			for _, parent := range moved {
				want = append(want, "parent "+parent)
			}
			want = append(want, survives[1:]...)

			gotLines, gotMessage := splitPayload(payload)
			if !slices.Equal(gotLines, want) {
				t.Errorf("reparenting changed a header byte it was not asked to:\n want %q\n  got %q",
					want, gotLines)
			}
			if gotMessage != wantMessage {
				t.Errorf("reparenting changed the message:\n want %q\n  got %q", wantMessage, gotMessage)
			}

			// Putting the original parents back has to reproduce the object
			// exactly. A row whose signature was stripped on the way cannot:
			// the header is gone for good, which is the point of stripping it.
			if len(shape.stripped) > 0 {
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

// The go.mod replace directive is the subject here, not this package's logic.
//
// unsignedObject reparents through go-git's struct encoder, which is only
// faithful in the fork carrying go-git/go-git#2328. Losing the directive is not
// a build failure — released go-git compiles here — so what it costs is written
// out row by row: the bytes git wrote, and the bytes a released go-git writes
// over them instead. Two causes, both fixed in the fork. It decodes the author
// and committer from their canonical slots alone, so a header interposed before
// or between them leaves both empty; and it re-renders the idents it did decode
// from parsed fields rather than replaying them.
//
// git reads every row below without complaint — an interposed gpgsig still
// reports "an=A U Thor at=1700000000" from git log. "git fsck" does call some
// of the ident shapes missingAuthor, missingCommitter or missingSpaceBeforeDate,
// which is the company they keep, and importers write all of it. Moving a
// commit's date or dropping its authorship while reparenting it would be a far
// worse outcome than refusing to run.
func TestUnsignedObjectNeedsThePinnedFork(t *testing.T) {
	committer := strings.Replace(testAuthor, "author", "committer", 1)
	emptyIdent := []string{"author  <> 0 +0000", "committer  <> 0 +0000"}

	tests := []struct {
		name   string
		header []string
		// keeps are header lines that have to come back verbatim, and rewrites
		// the lines a released go-git puts there instead. A rewrite of "" means
		// the header is dropped outright rather than replaced.
		keeps    []string
		rewrites []string
	}{
		{
			name:     "no space before the date",
			header:   []string{"tree " + treeSHA, "parent " + parentOne, crampedAuthor, crampedCommitter},
			keeps:    []string{crampedAuthor, crampedCommitter},
			rewrites: []string{"author A U Thor <author@example.test> 700000000 +0000"},
		},
		{
			name: "no timezone",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				zonelessAuthor, zonelessCommitter,
			},
			keeps:    []string{zonelessAuthor},
			rewrites: []string{testAuthor},
		},
		{
			name: "zero-padded timestamp",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne,
				paddedAuthor, paddedCommitter,
			},
			keeps:    []string{paddedAuthor},
			rewrites: []string{testAuthor},
		},
		{
			name:   "explicit UTF-8 encoding",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, committer, "encoding UTF-8"},
			keeps:  []string{"encoding UTF-8"},
		},
		{
			name: "unknown header before encoding",
			header: []string{
				"tree " + treeSHA, "parent " + parentOne, testAuthor, committer,
				customHeader, latin1Encoding,
			},
			keeps: []string{customHeader + "\n" + latin1Encoding},
		},
		{
			name: "signature before the author",
			header: slices.Concat([]string{"tree " + treeSHA, "parent " + parentOne},
				signatureHeaderLines(sha1SignatureHeader), []string{testAuthor, committer}),
			keeps:    []string{testAuthor, committer},
			rewrites: emptyIdent,
		},
		{
			name: "mergetag before the author",
			header: slices.Concat(
				[]string{"tree " + treeSHA, "parent " + parentOne, "parent " + parentTwo},
				mergeTagHeaderLines(parentTwo, "v1"), []string{testAuthor, committer}),
			keeps:    []string{testAuthor, committer},
			rewrites: emptyIdent,
		},
		{
			name:     "unknown header before the author",
			header:   []string{"tree " + treeSHA, "parent " + parentOne, customHeader, testAuthor, committer},
			keeps:    []string{testAuthor, committer},
			rewrites: emptyIdent,
		},
		{
			name:     "unknown header between author and committer",
			header:   []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, customHeader, committer},
			keeps:    []string{testAuthor, committer},
			rewrites: emptyIdent,
		},
		{
			name:     "committer before the author",
			header:   []string{"tree " + treeSHA, "parent " + parentOne, committer, testAuthor},
			keeps:    []string{committer + "\n" + testAuthor},
			rewrites: emptyIdent,
		},
		{
			name:   "extra header with an empty value",
			header: []string{"tree " + treeSHA, "parent " + parentOne, testAuthor, committer, "custom "},
			keeps:  []string{"custom "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := rawCommit(tt.header, "subject\n\nbody\n")

			parents, err := parentsOf(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			moved := slices.Clone(parents)
			moved[0] = newParent

			payload, err := unsignedObject(raw, moved)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := string(payload)

			for _, keep := range tt.keeps {
				if !strings.Contains(got, "\n"+keep+"\n") {
					t.Errorf("reparenting lost a header go.mod's replace directive is what keeps: "+
						"expected %q in\n%q", keep, got)
				}
			}
			for _, rewrite := range tt.rewrites {
				if strings.Contains(got, "\n"+rewrite+"\n") {
					t.Errorf("reparenting wrote %q, which is what a released go-git does and the "+
						"pinned fork does not — check go.mod still carries the replace directive:\n%q",
						rewrite, got)
				}
			}
		})
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
