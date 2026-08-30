package gitsign

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseIdentityReadsTheOperatorsForm(t *testing.T) {
	got, err := ParseIdentity("  " + ownerIdentity + "  ")
	if err != nil {
		t.Fatalf("could not parse %q: %v", ownerIdentity, err)
	}
	if got.Name != ownerName || got.Email != ownerEmail {
		t.Errorf("parsed %+v, want name %q and address %q", got, ownerName, ownerEmail)
	}
	if got.String() != ownerIdentity {
		t.Errorf("rendered %q, want %q", got.String(), ownerIdentity)
	}
}

// A repair whose whole purpose is to make a commit claim the right person has
// to be told, unambiguously, who that is.
func TestParseIdentityRefusesAnythingAmbiguous(t *testing.T) {
	for name, value := range map[string]string{
		"empty":            "",
		"no address":       "Kaj Kowalski",
		"address only":     "<" + ownerEmail + ">",
		"unclosed":         "Kaj Kowalski <" + ownerEmail,
		"empty address":    "Kaj Kowalski <>",
		"newline in name":  "Kaj\nKowalski <" + ownerEmail + ">",
		"bracket in name":  "Kaj <Kowalski> <" + ownerEmail + ">",
		"trailing garbage": ownerIdentity + " 1756500000 +0200",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := ParseIdentity(value); err == nil {
				t.Errorf("parsed %q as %+v, want a refusal", value, got)
			}
		})
	}
}

func TestParseIdentReadsAGitHeaderValue(t *testing.T) {
	got, err := parseIdent(authorHeader, botName+" <"+botEmail+"> 1756538100 +0200")
	if err != nil {
		t.Fatalf("could not parse the header: %v", err)
	}
	if got.name != botName || got.email != botEmail {
		t.Errorf("parsed %+v, want %q and %q", got, botName, botEmail)
	}
	if got.when != "1756538100 +0200" {
		t.Errorf("kept %q as the timestamp, want the verbatim tail", got.when)
	}
	if got.display() != botName+" <"+botEmail+">" {
		t.Errorf("displayed %q", got.display())
	}
}

// git will write "<address> seconds ±hhmm" with no name at all, and a repair
// has to be able to read one back before it can refuse it by name. The parser
// splits on the *last* bracket pair, so the empty prefix is a legitimate
// result rather than a missing opening bracket, and display() spells it the
// way a refusal quotes it.
func TestParseIdentAcceptsAnIdentWithNoName(t *testing.T) {
	got, err := parseIdent(committerHeader, "<"+botEmail+"> 1756538100 +0200")
	if err != nil {
		t.Fatalf("could not parse a nameless ident: %v", err)
	}
	if got.name != "" || got.email != botEmail {
		t.Errorf("parsed %+v, want an empty name and %q", got, botEmail)
	}
	if got.display() != "<"+botEmail+">" {
		t.Errorf("displayed %q, want %q", got.display(), "<"+botEmail+">")
	}
}

// git tolerates idents this parser refuses, and that asymmetry is deliberate:
// released go-git reads an ident with no space before its date as a timestamp
// decades off, so a repair that guessed at one would move the commit rather
// than fail. Every shape outside the strict form stops the run by name.
func TestParseIdentRefusesEveryShapeItCannotReproduce(t *testing.T) {
	for name, value := range map[string]string{
		"no date":            botName + " <" + botEmail + ">",
		"no offset":          botName + " <" + botEmail + "> 1756538100",
		"no space before at": botName + " <" + botEmail + ">1756538100 +0200",
		"no space after at":  botName + "<" + botEmail + "> 1756538100 +0200",
		"unclosed address":   botName + " <" + botEmail + " 1756538100 +0200",
		"nested brackets":    botName + " <<" + botEmail + ">> 1756538100 +0200",
		"date not a number":  botName + " <" + botEmail + "> yesterday +0200",
		"short offset":       botName + " <" + botEmail + "> 1756538100 +02",
		"unsigned offset":    botName + " <" + botEmail + "> 1756538100 0200",
		"offset not digits":  botName + " <" + botEmail + "> 1756538100 +02xx",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseIdent(authorHeader, value); err == nil {
				t.Errorf("parsed %q as %+v, want a refusal", value, got)
			} else if !strings.Contains(err.Error(), authorHeader) {
				t.Errorf("the refusal does not name the header: %v", err)
			}
		})
	}
}

// A commit with two author headers has no single author to correct. Picking
// one would be this command inventing provenance rather than repairing it.
func TestReadIdentsRefusesADuplicatedOrMissingHeader(t *testing.T) {
	author := "author " + botName + " <" + botEmail + "> 1756538100 +0200\n"
	committer := "committer " + githubName + " <" + githubEmail + "> 1756538200 +0000\n"
	tree := "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"

	for name, payload := range map[string]string{
		"two authors":  tree + author + author + committer + "\nmessage\n",
		"no author":    tree + committer + "\nmessage\n",
		"no committer": tree + author + "\nmessage\n",
		"no separator": tree + author + committer,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := readIdents([]byte(payload)); err == nil {
				t.Errorf("accepted %q", payload)
			}
		})
	}
}

// The identity rewrite is a two-line edit. Every other byte git wrote — the
// tree line, the parents, an unknown header, a multi-line header's
// continuations, and the message — has to survive it untouched.
func TestReplaceIdentsChangesTheTwoIdentitiesAndNothingElse(t *testing.T) {
	payload := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"parent 1111111111111111111111111111111111111111\n" +
		"parent 2222222222222222222222222222222222222222\n" +
		"author " + botName + " <" + botEmail + "> 1756538100 +0200\n" +
		"committer " + githubName + " <" + githubEmail + "> 1756538200 -0500\n" +
		"encoding ISO-8859-1\n" +
		"mergetag object 3333333333333333333333333333333333333333\n" +
		" type commit\n" +
		" tag v1\n" +
		" author not-an-ident-line\n" +
		"\n" +
		"feat: subject\n\nA body mentioning author " + botName + " on purpose.\n")

	got, err := replaceIdents(payload, Identity{Name: ownerName, Email: ownerEmail})
	if err != nil {
		t.Fatalf("could not rewrite the identity headers: %v", err)
	}

	want := bytes.ReplaceAll(payload,
		[]byte("author "+botName+" <"+botEmail+"> 1756538100 +0200"),
		[]byte("author "+ownerIdentity+" 1756538100 +0200"))
	want = bytes.ReplaceAll(want,
		[]byte("committer "+githubName+" <"+githubEmail+"> 1756538200 -0500"),
		[]byte("committer "+ownerIdentity+" 1756538200 -0500"))

	if !bytes.Equal(got, want) {
		t.Errorf("the rewrite changed more than the two identity halves:\n got %q\nwant %q", got, want)
	}
	// The indented "author" line inside the mergetag is a continuation, and the
	// message mentions the bot in prose. Neither is a header.
	if !bytes.Contains(got, []byte(" author not-an-ident-line\n")) {
		t.Error("the rewrite touched a multi-line header's continuation")
	}
	if !bytes.Contains(got, []byte("A body mentioning author "+botName+" on purpose.\n")) {
		t.Error("the rewrite touched the message")
	}
}

func TestTreeHeaderAndMessageBodyReadTheirOwnHalves(t *testing.T) {
	payload := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nsubject\n\nbody\n")

	tree, err := treeHeader(payload)
	if err != nil {
		t.Fatalf("could not read the tree header: %v", err)
	}
	if tree != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
		t.Errorf("read tree %q", tree)
	}

	message, err := messageBody(payload)
	if err != nil {
		t.Fatalf("could not read the message: %v", err)
	}
	// The blank line inside the message is not a second separator.
	if string(message) != "subject\n\nbody\n" {
		t.Errorf("read message %q", message)
	}

	if _, err := treeHeader([]byte("parent x\n\nmessage\n")); err == nil {
		t.Error("accepted a commit with no tree header")
	}
}
