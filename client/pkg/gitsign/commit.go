package gitsign

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
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
func isSigned(raw []byte) (bool, error) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return false, err
	}
	return commit.PGPSignature != "", nil
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
// When the parents are unchanged this returns the original bytes with the
// signature headers stripped verbatim, which is what git itself signs. Only a
// commit whose parents actually moved is re-encoded from its fields, and that
// one is being given a new SHA regardless.
func unsignedObject(raw []byte, parents []string) ([]byte, error) {
	commit, err := decodeCommit(raw)
	if err != nil {
		return nil, err
	}

	hashes := make([]plumbing.Hash, 0, len(parents))
	for _, parent := range parents {
		hashes = append(hashes, plumbing.NewHash(parent))
	}
	commit.ParentHashes = hashes

	return encodeObject(commit.EncodeWithoutSignature)
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
