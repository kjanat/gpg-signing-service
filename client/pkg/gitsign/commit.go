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
// Both spellings count. go-git v6 splits gpgsig and gpgsig-sha256 into two
// fields where v5 folded them into one, and a commit carrying only the sha256
// header is still a signed commit.
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
// The signature headers are stripped by go-git, but the parents are moved here
// rather than by mutating ParentHashes and re-encoding. EncodeWithoutSignature
// only reproduces the source bytes while the decoded fields still match the
// object it came from; any mutation sends it down the struct encoder, which
// canonicalizes author and committer lines that git itself accepts unchanged.
// An ident with no space before the date is the sharp case: released go-git
// reads "<a@x>1700000000" as 700000000, so a re-encode would move the commit
// from November 2023 to March 1992. Moving the parent lines by hand keeps every
// other byte exactly as git wrote it.
//
// go-git/go-git#2328 makes the struct encoder faithful for every shape this
// package's tests cover, and go.mod pins it. The byte path stays anyway: a
// replace directive applies only to the main module, so anything importing
// this package as a library builds against released go-git, where the struct
// encoder is still lossy.
func unsignedObject(raw []byte, parents []string) ([]byte, error) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return nil, err
	}

	stripped, err := encodeObject(commit.EncodeWithoutSignature)
	if err != nil {
		return nil, err
	}
	return replaceParents(stripped, parents), nil
}

// parentPrefix and treePrefix start the two header lines whose order git
// requires: tree first, then every parent, then author and committer.
var (
	parentPrefix = []byte("parent ")
	treePrefix   = []byte("tree ")
)

// replaceParents swaps a commit payload's parent lines for the given ones and
// leaves every other byte alone.
//
// Only header lines are considered: the payload is cut at the blank line that
// closes the header block, and a mergetag's continuation lines are indented by
// one space, so nothing inside one can be mistaken for a parent.
func replaceParents(payload []byte, parents []string) []byte {
	head, message, _ := bytes.Cut(payload, headerSeparator)
	lines := bytes.Split(head, []byte("\n"))

	kept := make([][]byte, 0, len(lines))
	insert, afterTree := -1, 0
	for _, line := range lines {
		if bytes.HasPrefix(line, parentPrefix) {
			if insert < 0 {
				insert = len(kept)
			}
			continue
		}
		kept = append(kept, line)
		if bytes.HasPrefix(line, treePrefix) && afterTree == 0 {
			afterTree = len(kept)
		}
	}
	// A commit with no parent lines to replace still has to put any new ones
	// straight after the tree line.
	if insert < 0 {
		insert = afterTree
	}

	out := make([][]byte, 0, len(kept)+len(parents))
	out = append(out, kept[:insert]...)
	for _, parent := range parents {
		out = append(out, append(append([]byte{}, parentPrefix...), parent...))
	}
	out = append(out, kept[insert:]...)

	return assemble(out, message)
}

// withSignature appends the armored signature to the payload's headers in
// git's multi-line header form: the first armor line on the gpgsig header
// itself, every later line indented by one space.
//
// This is a byte-level append rather than a re-encode on purpose. The service
// signed exactly these payload bytes, so stripping the header again has to
// return exactly these payload bytes; round-tripping through the commit struct
// would risk normalizing something the signature covers.
func withSignature(payload, signature []byte) []byte {
	armor := bytes.Split(bytes.Trim(signature, "\n"), []byte("\n"))
	head, message, _ := bytes.Cut(payload, headerSeparator)

	lines := bytes.Split(head, []byte("\n"))
	out := make([][]byte, 0, len(lines)+len(armor))
	out = append(out, lines...)
	out = append(out, append([]byte("gpgsig "), armor[0]...))
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
