package gitsign

import (
	"bytes"
	"strings"
	"testing"
)

// The post-write assertions are the whole safety story of this command: every
// promise it makes is checked against the object git actually stored, not the
// bytes the run built. A check that never fires is a check that is not there,
// so each one is driven with a commit corrupted in exactly the way it exists
// to catch.
//
// Each case signs its corrupted payload honestly with the service key, so the
// signature verifies and the only thing standing between the corruption and a
// tip the workflow would push is the assertion under test.
func TestRepairAssertionsCatchEachCorruption(t *testing.T) {
	cases := map[string]struct {
		mutate  func(payload []byte) []byte
		parents func(remapped []string) []string
		want    string
	}{
		// The exact regression from the issue: a rewrite that signs the commit
		// but leaves it claiming the bot.
		"author left as the bot": {
			mutate: func(payload []byte) []byte {
				return swapIdent(payload, authorHeader, ownerName+" <"+ownerEmail+">", botName+" <"+botEmail+">")
			},
			want: "author header reads " + botName,
		},
		"committer left as GitHub": {
			mutate: func(payload []byte) []byte {
				return swapIdent(payload, committerHeader, ownerName+" <"+ownerEmail+">", githubName+" <"+githubEmail+">")
			},
			want: "committer header reads " + githubName,
		},
		"author timestamp moved": {
			mutate: func(payload []byte) []byte {
				return retime(payload, authorHeader, "1000000000 +0000")
			},
			want: "author timestamp reads",
		},
		"committer timezone flattened": {
			mutate: func(payload []byte) []byte {
				return retime(payload, committerHeader, "1756540800 +0000")
			},
			want: "committer timestamp reads",
		},
		"tree repointed": {
			mutate: func(payload []byte) []byte {
				head, message, _ := bytes.Cut(payload, headerSeparator)
				line, rest, _ := bytes.Cut(head, []byte("\n"))
				empty := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904")
				if !bytes.HasPrefix(line, treePrefix) {
					return payload
				}
				return assemble([][]byte{empty, rest}, message)
			},
			want: "points at tree",
		},
		"message edited": {
			mutate: func(payload []byte) []byte {
				return append(bytes.Clone(payload), []byte("tampered\n")...)
			},
			want: "message bytes differ",
		},
		// A parent left pointing at the pre-repair chain is how a repaired
		// commit ends up descending from the commits it was supposed to
		// replace.
		"parent left on the old chain": {
			parents: func(remapped []string) []string {
				return []string{strings.Repeat("0", len(remapped[0]))}
			},
			want: "parents are",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRepairFixture(t)
			err := f.rebuildCorrupted(t, tc.mutate, tc.parents)
			if err == nil {
				t.Fatalf("the assertions accepted a commit corrupted by %q", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the corruption (want %q): %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "no ref was moved") {
				t.Errorf("the refusal does not say the branch is untouched: %v", err)
			}
		})
	}
}

// The same harness with no corruption at all has to pass, or every case above
// would be proving nothing.
func TestRepairAssertionsAcceptAnHonestRebuild(t *testing.T) {
	f := newRepairFixture(t)
	if err := f.rebuildCorrupted(t, nil, nil); err != nil {
		t.Fatalf("the assertions rejected a correct rebuild: %v", err)
	}
}

// rebuildCorrupted repairs the fixture's second commit — one with a parent to
// remap — applying a payload mutation and a parent substitution, then runs the
// assertions the real walk runs.
func (f *repairFixture) rebuildCorrupted(t *testing.T, mutate func([]byte) []byte, parents func([]string) []string) error {
	t.Helper()

	r := f.repairer(t)
	ctx := t.Context()

	// The first commit is repaired honestly, so the second has a rewritten
	// parent to point at and the parent assertion has something to compare.
	first, err := r.plan(ctx, f.chain[:1])
	if err != nil {
		t.Fatalf("could not plan the first commit: %v", err)
	}
	firstSHA, err := r.rebuild(ctx, first[0], first[0].parents)
	if err != nil {
		t.Fatalf("could not rebuild the first commit: %v", err)
	}

	steps, err := r.plan(ctx, f.chain[1:2])
	if err != nil {
		t.Fatalf("could not plan the second commit: %v", err)
	}
	step := steps[0]
	remapped := []string{firstSHA}

	payload, err := unsignedObject(step.raw, remapped)
	if err != nil {
		t.Fatalf("could not strip the second commit: %v", err)
	}
	payload, err = replaceIdents(payload, r.target)
	if err != nil {
		t.Fatalf("could not rewrite the identity headers: %v", err)
	}
	if mutate != nil {
		payload = mutate(payload)
	}

	signature, err := r.sign(ctx, payload)
	if err != nil {
		t.Fatalf("could not sign the corrupted payload: %v", err)
	}
	newSHA, err := r.repo.hashObject(ctx, withSignature(payload, signature, r.format))
	if err != nil {
		t.Fatalf("could not write the corrupted commit: %v", err)
	}

	if parents != nil {
		remapped = parents(remapped)
	}
	return r.assertRepaired(ctx, step, remapped, newSHA)
}

// repairer builds the engine's own state without going through Repair, so the
// assertions can be driven one commit at a time.
func (f *repairFixture) repairer(t *testing.T) *repairer {
	t.Helper()

	target, allowed, err := repairBounds(RepairOptions{
		Base: f.base, ExpectedTip: f.tip, Identity: ownerIdentity,
		ExpectIdentities: []string{botEmail, githubEmail},
	})
	if err != nil {
		t.Fatalf("could not validate the repair bounds: %v", err)
	}
	key, err := newSigningKey(exportKey(t, f.entity))
	if err != nil {
		t.Fatalf("could not read the service key: %v", err)
	}
	return &repairer{
		repo:   &repo{dir: f.dir},
		signer: f.signer,
		opts:   RepairOptions{Dir: f.dir, Out: testWriter{t}},
		key:    key,
		format: repoFormat(t, f.dir),
		target: target, allowed: allowed,
		result: &RepairResult{},
	}
}

// testWriter sends the engine's progress into the test log.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// swapIdent puts a different identity back on one header, keeping its
// timestamp: the shape a half-finished repair leaves behind.
func swapIdent(payload []byte, header, from, to string) []byte {
	return replaceHeader(payload, header, func(value string) string {
		return strings.Replace(value, from, to, 1)
	})
}

// retime replaces one header's timestamp and offset, keeping its identity.
func retime(payload []byte, header, when string) []byte {
	return replaceHeader(payload, header, func(value string) string {
		if closing := strings.LastIndex(value, ">"); closing >= 0 {
			return value[:closing+1] + " " + when
		}
		return value
	})
}

// replaceHeader rewrites the value of one header line and nothing else.
func replaceHeader(payload []byte, header string, edit func(string) string) []byte {
	head, message, _ := bytes.Cut(payload, headerSeparator)
	prefix := []byte(header + " ")

	lines := bytes.Split(head, []byte("\n"))
	out := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if bytes.HasPrefix(line, prefix) {
			line = append(bytes.Clone(prefix), edit(string(line[len(prefix):]))...)
		}
		out = append(out, line)
	}
	return assemble(out, message)
}
