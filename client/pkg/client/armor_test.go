package client

import "strings"

// armorMarker builds a PEM/OpenPGP armor boundary line without writing one down.
//
// A literal "-----BEGIN ... PRIVATE KEY-----" in a tracked file opens a gitleaks
// private-key match that runs to the next "KEY-----" at least 64 characters
// later, so a real key committed further down the same file becomes part of that
// one match instead of a finding of its own — and past roughly 35 kB of span the
// match is dropped entirely and nothing is reported at all. Suppressing the
// fixture with an allowlist entry is worse still: matched as a substring, it
// excuses everything the span swallowed (#146). Building the marker from parts
// means there is no match and nothing to excuse.
//
// The TypeScript side does the same thing in src/utils/armor.ts, and
// scripts/test-gitleaks-contract.sh plants a generated key beside each use.
func armorMarker(boundary, label string) string {
	dashes := strings.Repeat("-", 5)
	return dashes + boundary + " " + label + dashes
}
