package gitsign

import (
	"bytes"
	"errors"
	"strings"
)

var (
	headerSeparator = []byte("\n\n")
	gpgsigPrefix    = []byte("gpgsig ")
	parentPrefix    = []byte("parent ")
	committerPrefix = []byte("committer ")
	continuation    = []byte(" ")
)

// errMalformed is returned for a commit object with no header/message break.
var errMalformed = errors.New("malformed commit object: no header/message separator")

// commitHeader returns the header block of a raw commit object.
func commitHeader(raw []byte) ([]byte, error) {
	head, _, found := bytes.Cut(raw, headerSeparator)
	if !found {
		return nil, errMalformed
	}
	return head, nil
}

// headerLines splits the header into its lines, including the space-indented
// continuations of multi-line headers such as gpgsig.
func headerLines(raw []byte) ([][]byte, error) {
	head, err := commitHeader(raw)
	if err != nil {
		return nil, err
	}
	return bytes.Split(head, []byte("\n")), nil
}

// parentsOf returns the commit's parent SHAs in order.
func parentsOf(raw []byte) ([]string, error) {
	lines, err := headerLines(raw)
	if err != nil {
		return nil, err
	}
	parents := make([]string, 0, 2)
	for _, line := range lines {
		if bytes.HasPrefix(line, parentPrefix) {
			parents = append(parents, string(line[len(parentPrefix):]))
		}
	}
	return parents, nil
}

// isSigned reports whether the commit already carries a gpgsig header. It says
// nothing about whether that signature verifies, or even whether it is PGP.
func isSigned(raw []byte) (bool, error) {
	lines, err := headerLines(raw)
	if err != nil {
		return false, err
	}
	for _, line := range lines {
		if bytes.HasPrefix(line, gpgsigPrefix) {
			return true, nil
		}
	}
	return false, nil
}

// committerEmail returns the lowercased address from the committer header, or
// the empty string if the header carries none.
func committerEmail(raw []byte) (string, error) {
	lines, err := headerLines(raw)
	if err != nil {
		return "", err
	}
	for _, line := range lines {
		if !bytes.HasPrefix(line, committerPrefix) {
			continue
		}
		open := bytes.LastIndexByte(line, '<')
		closed := bytes.LastIndexByte(line, '>')
		if open < 0 || closed < open {
			continue
		}
		return strings.ToLower(string(line[open+1 : closed])), nil
	}
	return "", nil
}

// unsignedObject rebuilds the commit without any gpgsig header and with the
// given parents in place of the originals.
//
// The new parent lines land where the first original parent line was, because
// git requires the header order tree, parent..., author, committer. Appending
// them at the end would produce an object git refuses to read back.
func unsignedObject(raw []byte, parents []string) []byte {
	head, message, _ := bytes.Cut(raw, headerSeparator)
	lines := bytes.Split(head, []byte("\n"))

	out := make([][]byte, 0, len(lines)+len(parents))
	placed := false
	for index := 0; index < len(lines); index++ {
		line := lines[index]

		if bytes.HasPrefix(line, gpgsigPrefix) {
			// Drop the header and every space-indented continuation of it.
			for index+1 < len(lines) && bytes.HasPrefix(lines[index+1], continuation) {
				index++
			}
			continue
		}

		if bytes.HasPrefix(line, parentPrefix) {
			if !placed {
				for _, parent := range parents {
					out = append(out, append([]byte("parent "), parent...))
				}
				placed = true
			}
			continue
		}

		out = append(out, line)
	}

	return assemble(out, message)
}

// withSignature appends the armored signature to the payload's headers in
// git's multi-line header form: the first armor line on the gpgsig header
// itself, every later line indented by one space.
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
