package gitsign

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// headerSeparator is the blank line between a commit's headers and its
// message.
var headerSeparator = []byte("\n\n")

// The two spellings git stores a commit signature under, one per object
// format. Which one a repository uses is not a preference: git strips and
// verifies the spelling that matches its own hash algorithm and ignores the
// other, so writing the wrong one produces a commit git reports as unsigned.
const (
	sha1SignatureHeader   = "gpgsig"
	sha256SignatureHeader = "gpgsig-sha256"
)

// objectFormat is a repository's hash algorithm, as "git rev-parse
// --show-object-format" reports it.
//
// It decides the signature header spelling and nothing else here. Every other
// difference between the formats is a hex digest length, and the paths that
// move parents and embed signatures work on bytes they never measure.
type objectFormat string

const (
	formatSHA1   objectFormat = "sha1"
	formatSHA256 objectFormat = "sha256"
)

// parseObjectFormat maps what git reported onto the formats this package can
// sign. An unrecognized one is refused rather than guessed at: a format git
// grows later spells its header some other way, and defaulting to gpgsig would
// write a signature that repository reads as absent.
func parseObjectFormat(name string) (objectFormat, error) {
	switch format := objectFormat(name); format {
	case formatSHA1, formatSHA256:
		return format, nil
	default:
		return "", fmt.Errorf("this repository uses the %q object format; sign-commit knows the signature "+
			"header spelling for %s and %s only", name, formatSHA1, formatSHA256)
	}
}

// signatureHeader is the header git stores a signature under in this format.
func (f objectFormat) signatureHeader() string {
	if f == formatSHA256 {
		return sha256SignatureHeader
	}
	return sha1SignatureHeader
}

// signatureOf returns the armored block git checks a commit in this format
// against. The other spelling is not a fallback: in hash-algorithm
// compatibility mode a commit carries both, over different payloads, and the
// one that does not match the repository's format would never verify here.
func (f objectFormat) signatureOf(commit *object.Commit) string {
	if f == formatSHA256 {
		return commit.SignatureSHA256
	}
	return commit.Signature
}

// decodeCommit parses a raw commit object.
//
// go-git's decoder is used rather than a hand-rolled one because it already
// knows the cases this package would otherwise have to rediscover: mergetag
// and encoding headers, unknown headers that must survive a rewrite, the
// gpgsig-sha256 spelling, and space-indented continuations.
func decodeCommit(raw []byte) (*object.Commit, error) {
	source := &plumbing.MemoryObject{}
	source.SetType(plumbing.CommitObject)
	if _, err := source.Write(raw); err != nil {
		return nil, err
	}

	commit := &object.Commit{}
	if err := commit.Decode(source); err != nil {
		return nil, fmt.Errorf("could not read the commit object: %w", err)
	}
	return commit, nil
}

// encodeObject runs an encoder into a fresh in-memory object and returns its
// bytes.
func encodeObject(encode func(plumbing.EncodedObject) error) ([]byte, error) {
	encoded := &plumbing.MemoryObject{}
	if err := encode(encoded); err != nil {
		return nil, err
	}
	reader, err := encoded.Reader()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

// parentsOf returns the commit's parent SHAs in order.
func parentsOf(raw []byte) ([]string, error) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return nil, err
	}
	parents := make([]string, 0, len(commit.ParentHashes))
	for _, parent := range commit.ParentHashes {
		parents = append(parents, parent.String())
	}
	return parents, nil
}

// isSigned reports whether the commit already carries a signature header. It
// says nothing about whether that signature verifies, or even whether it is
// PGP: git writes an SSH signature into the same header.
//
// Both spellings count, and the repository's own format is deliberately not
// consulted: the question here is whether an attestation is present at all,
// and rewriting a commit destroys one written under either header.
func isSigned(raw []byte) (bool, error) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return false, err
	}
	return commit.Signature != "" || commit.SignatureSHA256 != "", nil
}

// mergeTagHeader is the header a merge commit carries the merged tag object
// in. go-git v6 models it as an ordinary extra header rather than a field of
// its own.
const mergeTagHeader = "mergetag"

// mergeTags returns the body of every merged tag object the commit embeds,
// each one beginning with its own "object <sha>" line.
//
// An octopus merge of several signed tags writes one mergetag header per tag.
// v5 concatenated their bodies into a single Commit.MergeTag string, where the
// second tag's "object" line was indistinguishable from a line of the first
// tag's message; v6 keeps them apart, so they are returned apart.
func mergeTags(commit *object.Commit) []string {
	var tags []string
	for _, header := range commit.ExtraHeaders {
		if header.Key == mergeTagHeader {
			tags = append(tags, header.Value)
		}
	}
	return tags
}

// committerEmail returns the lowercased address from the committer header, or
// the empty string if the header carries none.
func committerEmail(raw []byte) (string, error) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return "", err
	}
	return strings.ToLower(commit.Committer.Email), nil
}

// unsignedObject rebuilds the commit without any signature header and with the
// given parents in place of the originals. The result is the payload a
// signature is computed over.
//
// Both edits are go-git's own: EncodeWithoutSignature drops every signature
// spelling, and the parents move by mutating ParentHashes ahead of it. That is
// only a faithful rewrite because go.mod builds go-git from the fork carrying
// go-git/go-git#2328, which decodes a commit's headers wherever they sit and
// replays the bytes it did not change. Released go-git does neither: it reads
// the author and committer from their canonical slots alone, so any header
// interposed before or between them re-encodes as "author  <> 0 +0000", and it
// normalizes what it did decode — an ident with no space before the date loses
// the leading digit of its timestamp, a missing timezone gains one, an
// explicit "encoding UTF-8" disappears, and unknown headers change places
// around "encoding".
//
// Nothing about that difference is visible at compile time, so the pin is held
// down by tests instead: TestUnsignedObjectChangesOnlyParents drives every
// shape git writes and this package has been caught mangling, and
// TestUnsignedObjectNeedsThePinnedFork spells out the damage released go-git
// does to the ones it gets wrong.
func unsignedObject(raw []byte, parents []string) ([]byte, error) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return nil, err
	}

	hashes := make([]plumbing.Hash, 0, len(parents))
	for _, parent := range parents {
		// Round-tripping the name is the check, not FromHex's own verdict: it
		// accepts a partial hash for backwards compatibility and zero-pads it
		// to a full-width one, so a truncated SHA would be written out as a
		// real object name pointing at nothing rather than refused.
		hash, ok := plumbing.FromHex(parent)
		if !ok || hash.String() != parent {
			return nil, fmt.Errorf("cannot reparent onto %q: that is not an object name", parent)
		}
		hashes = append(hashes, hash)
	}
	commit.ParentHashes = hashes

	return encodeObject(commit.EncodeWithoutSignature)
}

// withSignature appends the armored signature to the payload's headers in
// git's multi-line header form: the first armor line on the signature header
// itself, every later line indented by one space. The header is named after
// the repository's object format, because that is the spelling git will strip
// before it checks the signature.
//
// This is a byte-level append rather than a re-encode on purpose. The service
// signed exactly these payload bytes, so stripping the header again has to
// return exactly these payload bytes; round-tripping through the commit struct
// would risk normalizing something the signature covers.
func withSignature(payload, signature []byte, format objectFormat) []byte {
	armor := bytes.Split(bytes.Trim(signature, "\n"), []byte("\n"))
	head, message, _ := bytes.Cut(payload, headerSeparator)

	lines := bytes.Split(head, []byte("\n"))
	out := make([][]byte, 0, len(lines)+len(armor))
	out = append(out, lines...)
	out = append(out, append([]byte(format.signatureHeader()+" "), armor[0]...))
	for _, line := range armor[1:] {
		out = append(out, append([]byte(" "), line...))
	}

	return assemble(out, message)
}

// assemble joins header lines back onto a message body.
func assemble(lines [][]byte, message []byte) []byte {
	head := bytes.Join(lines, []byte("\n"))

	body := make([]byte, 0, len(head)+len(headerSeparator)+len(message))
	body = append(body, head...)
	body = append(body, headerSeparator...)
	body = append(body, message...)
	return body
}
