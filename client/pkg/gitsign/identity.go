package gitsign

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// The two headers that carry an identity, and the message separator's role in
// bounding them. Only the header block is searched: a message line reading
// "author X" is prose, and a repair that rewrote it would corrupt the commit
// it was asked to preserve.
const (
	authorHeader    = "author"
	committerHeader = "committer"
)

// identityHeaders is the pair, in the order git writes them.
var identityHeaders = []string{authorHeader, committerHeader}

// Identity is the name and address a repaired commit claims.
type Identity struct {
	Name  string
	Email string
}

// String renders the identity the way a git header spells it.
func (i Identity) String() string { return i.Name + " <" + i.Email + ">" }

// ParseIdentity reads the "Name <address>" form an operator types.
//
// The address is required and the name is not optional either: a repair whose
// whole purpose is to make a commit claim the right person must be told who
// that is, and "<info@example.test>" alone would produce headers git renders
// with an empty name.
func ParseIdentity(value string) (Identity, error) {
	// The *last* bracket pair delimits the address, so a name that itself
	// contains a bracket splits in the operator's favour and is then refused
	// below by name rather than quietly becoming part of the address.
	trimmed := strings.TrimSpace(value)
	inner, closed := strings.CutSuffix(trimmed, ">")
	rawName, email, opened := strings.CutLast(inner, "<")
	if !closed || !opened || rawName == "" {
		return Identity{}, fmt.Errorf("identity %q is not in \"Name <address>\" form", value)
	}

	name := strings.TrimSpace(rawName)
	if name == "" {
		return Identity{}, fmt.Errorf("identity %q carries no name", value)
	}
	if email == "" || strings.ContainsAny(email, "<>\n") {
		return Identity{}, fmt.Errorf("identity %q carries no usable address", value)
	}
	if strings.ContainsAny(name, "<>\n") {
		return Identity{}, fmt.Errorf("identity name %q contains a character a git ident cannot hold", name)
	}
	return Identity{Name: name, Email: email}, nil
}

// ident is one parsed author or committer header: who, and when.
//
// when is kept as the verbatim "<seconds> <offset>" tail rather than a
// time.Time, because that tail is what a repair has to reproduce byte for
// byte. Parsing it into a timestamp and formatting it back would normalize an
// offset git recorded — "+0530" and "+0530" agree, but a zone git wrote and Go
// renders differently would silently move the commit.
type ident struct {
	name  string
	email string
	when  string
}

// display renders the identity half, which is what a refusal names.
func (i ident) display() string {
	if i.name == "" {
		return "<" + i.email + ">"
	}
	return i.name + " <" + i.email + ">"
}

// matches reports whether this header already claims the given identity.
func (i ident) matches(target Identity) bool {
	return i.name == target.Name && i.email == target.Email
}

// parseIdent reads the value of an author or committer header.
//
// The accepted shape is deliberately narrow — "Name <address> seconds ±hhmm" —
// because this is the input to a history rewrite. git itself tolerates idents
// with no space before the date and other historical damage; a repair that
// guessed at one of those would write a commit whose timestamp moved by
// decades, which is precisely the class of silent corruption the whole command
// exists to undo. Anything outside the shape is refused by name.
func parseIdent(header, value string) (ident, error) {
	malformed := func(why string) (ident, error) {
		return ident{}, fmt.Errorf("the %s header %q is not in \"Name <address> seconds ±hhmm\" form: %s", header, value, why)
	}

	beforeClose, when, closed := strings.CutLast(value, ">")
	if !closed {
		return malformed("no closing angle bracket")
	}
	name, email, opened := strings.CutLast(beforeClose, "<")
	if !opened {
		return malformed("no opening angle bracket")
	}

	if name != "" && !strings.HasSuffix(name, " ") {
		return malformed("no space between the name and the address")
	}
	if strings.ContainsAny(email, "<>") {
		return malformed("nested angle brackets around the address")
	}

	when, spaced := strings.CutPrefix(when, " ")
	if !spaced {
		return malformed("no space between the address and the timestamp")
	}

	seconds, offset, found := strings.Cut(when, " ")
	if !found {
		return malformed("no timezone offset after the timestamp")
	}
	if _, err := strconv.ParseInt(seconds, 10, 64); err != nil {
		return malformed("the timestamp is not a number of seconds")
	}
	if !validOffset(offset) {
		return malformed("the timezone offset is not ±hhmm")
	}

	return ident{name: strings.TrimSuffix(name, " "), email: email, when: when}, nil
}

// validOffset reports whether the string is a ±hhmm timezone offset.
func validOffset(offset string) bool {
	if len(offset) != 5 || (offset[0] != '+' && offset[0] != '-') {
		return false
	}
	for _, digit := range offset[1:] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// headerBlock returns the commit payload's headers, without the blank line
// that closes them.
func headerBlock(payload []byte) ([]byte, error) {
	head, _, found := bytes.Cut(payload, headerSeparator)
	if !found {
		return nil, fmt.Errorf("malformed commit object: no blank line between the headers and the message")
	}
	return head, nil
}

// messageBody returns everything after the blank line, verbatim.
func messageBody(payload []byte) ([]byte, error) {
	_, message, found := bytes.Cut(payload, headerSeparator)
	if !found {
		return nil, fmt.Errorf("malformed commit object: no blank line between the headers and the message")
	}
	return message, nil
}

// treeHeader returns the SHA on the commit's tree line.
func treeHeader(payload []byte) (string, error) {
	head, err := headerBlock(payload)
	if err != nil {
		return "", err
	}
	for line := range bytes.SplitSeq(head, []byte("\n")) {
		if bytes.HasPrefix(line, treePrefix) {
			return string(line[len(treePrefix):]), nil
		}
	}
	return "", fmt.Errorf("malformed commit object: no tree header")
}

// readIdents returns the commit's author and committer headers.
//
// Exactly one of each is required. git writes exactly one, and a commit
// carrying two author lines has no single author to rewrite — picking either
// would be this command inventing provenance rather than correcting it.
func readIdents(payload []byte) (author, committer ident, err error) {
	head, err := headerBlock(payload)
	if err != nil {
		return ident{}, ident{}, err
	}

	seen := map[string]int{}
	found := map[string]ident{}
	for line := range bytes.SplitSeq(head, []byte("\n")) {
		// A continuation line of a multi-line header is indented by one
		// space, so it can never be mistaken for a header of its own.
		for _, header := range identityHeaders {
			prefix := []byte(header + " ")
			if !bytes.HasPrefix(line, prefix) {
				continue
			}
			seen[header]++
			parsed, parseErr := parseIdent(header, string(line[len(prefix):]))
			if parseErr != nil {
				return ident{}, ident{}, parseErr
			}
			found[header] = parsed
		}
	}

	for _, header := range identityHeaders {
		switch seen[header] {
		case 1:
		case 0:
			return ident{}, ident{}, fmt.Errorf("malformed commit object: no %s header", header)
		default:
			return ident{}, ident{}, fmt.Errorf("malformed commit object: %d %s headers", seen[header], header)
		}
	}
	return found[authorHeader], found[committerHeader], nil
}

// replaceIdents rewrites the author and committer headers to claim target,
// keeping each one's own timestamp and offset exactly as git recorded them.
//
// Like replaceParents, this edits header lines in place rather than mutating a
// decoded commit and re-encoding it: every byte outside the two identity
// halves — the tree line, the parents, unknown headers, the message — has to
// come out of the repair unchanged.
func replaceIdents(payload []byte, target Identity) ([]byte, error) {
	author, committer, err := readIdents(payload)
	if err != nil {
		return nil, err
	}

	head, message, _ := bytes.Cut(payload, headerSeparator)
	replacement := map[string]ident{authorHeader: author, committerHeader: committer}

	lines := bytes.Split(head, []byte("\n"))
	out := make([][]byte, 0, len(lines))
	for _, line := range lines {
		rewritten := false
		for header, original := range replacement {
			prefix := []byte(header + " ")
			if !bytes.HasPrefix(line, prefix) {
				continue
			}
			out = append(out, []byte(header+" "+target.Name+" <"+target.Email+"> "+original.when))
			rewritten = true
			break
		}
		if !rewritten {
			out = append(out, line)
		}
	}

	return assemble(out, message), nil
}
