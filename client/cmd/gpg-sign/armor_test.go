package main

import "strings"

// armorMarker builds a PEM/OpenPGP armor boundary line without writing one down.
// See client/pkg/client/armor_test.go and src/utils/armor.ts for why: a literal
// armor header opens a gitleaks private-key match that swallows any real key
// committed below it in the same file (#146).
func armorMarker(boundary, label string) string {
	dashes := strings.Repeat("-", 5)
	return dashes + boundary + " " + label + dashes
}
