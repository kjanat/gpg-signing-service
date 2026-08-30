package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kjanat/gpg-signing-service/client/pkg/gitsign"
	"github.com/spf13/cobra"
)

// repairHistoryArgs builds the flag set the command reads, so tests can call
// RunE directly instead of parsing a command line.
type repairHistoryArgs struct {
	base        string
	expectedTip string
	identity    string
	expect      []string
	repo        string
	dryRun      bool
}

func (a repairHistoryArgs) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("key-id", "", "")
	cmd.Flags().String("base", a.base, "")
	cmd.Flags().String("expected-tip", a.expectedTip, "")
	cmd.Flags().String("identity", a.identity, "")
	cmd.Flags().StringArray("expect-identity", a.expect, "")
	cmd.Flags().Bool("dry-run", a.dryRun, "")
	cmd.Flags().String("repo", a.repo, "")
	return cmd
}

func TestRepairHistoryCommandIsRegistered(t *testing.T) {
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "repair-history" {
			return
		}
	}
	t.Error("repair-history is not registered on the root command")
}

// The four bounds have no defaults on purpose, and cobra is told so as well as
// the engine: a forgotten flag has to be usage text, not a run that reaches a
// repository and starts resolving revisions.
func TestRepairHistoryMarksItsDangerousFlagsRequired(t *testing.T) {
	for _, name := range []string{"base", "expected-tip", "identity", "expect-identity"} {
		flag := repairHistoryCmd.Flags().Lookup(name)
		if flag == nil {
			t.Errorf("--%s is not defined", name)
			continue
		}
		if flag.Annotations[cobra.BashCompOneRequiredFlag] == nil {
			t.Errorf("--%s is not marked required", name)
		}
	}
}

// Every missing bound is its own refusal, and none of them reaches the network.
func TestRepairHistoryCommandValidation(t *testing.T) {
	complete := repairHistoryArgs{
		base:        "0000000000000000000000000000000000000000",
		expectedTip: "1111111111111111111111111111111111111111",
		identity:    "Kaj Kowalski <info@kajkowalski.nl>",
		expect:      []string{"noreply@github.com"},
		repo:        t.TempDir(),
	}

	tests := map[string]struct {
		mutate func(*repairHistoryArgs)
		want   string
	}{
		"no base":         {func(a *repairHistoryArgs) { a.base = "" }, "base is required"},
		"no expected tip": {func(a *repairHistoryArgs) { a.expectedTip = "" }, "expected-tip is required"},
		"no identity":     {func(a *repairHistoryArgs) { a.identity = "" }, "is not in \"Name <address>\" form"},
		"identity has no name": {
			func(a *repairHistoryArgs) { a.identity = "<info@kajkowalski.nl>" },
			"is not in \"Name <address>\" form",
		},
		"no expect identity": {func(a *repairHistoryArgs) { a.expect = nil }, "expect-identity is required"},
		"not a repository":   {func(*repairHistoryArgs) {}, "repair-history failed"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			args := complete
			tt.mutate(&args)

			err := repairHistoryCmd.RunE(args.command(), nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), "repair-history failed") {
				t.Errorf("error %q is not prefixed by the command name", err)
			}
		})
	}
}

// A scripted caller in --json mode reads the failure document, not the
// progress text, so the two halves have to stay distinguishable.
func TestRepairHistoryFailureDocumentCarriesTheResult(t *testing.T) {
	document := repairHistoryFailure(&gitsign.RepairResult{Base: "abc", Scanned: 3}, errRepairTest)

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("could not encode the failure document: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("could not decode the failure document: %v", err)
	}
	if decoded["error"] != errRepairTest.Error() {
		t.Errorf("the document reports error %v", decoded["error"])
	}
	result, ok := decoded["result"].(map[string]any)
	if !ok {
		t.Fatalf("the document carries no result: %v", decoded)
	}
	if result["base"] != "abc" {
		t.Errorf("the result reports base %v", result["base"])
	}
	// A failed run must not look like one that produced something to push.
	if _, present := result["tip"]; present {
		t.Errorf("a failed run's document carries a tip: %v", result)
	}
}

// errRepairTest stands in for a run that got partway and stopped.
var errRepairTest = repairTestError("repair-history failed: the range moved")

type repairTestError string

func (e repairTestError) Error() string { return string(e) }
