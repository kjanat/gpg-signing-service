module github.com/kjanat/gpg-signing-service/client

go 1.27

require (
	github.com/ProtonMail/go-crypto v1.4.1
	github.com/getkin/kin-openapi v0.149.0
	github.com/go-git/go-git/v6 v6.0.0-alpha.5
	github.com/oapi-codegen/runtime v1.7.0
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dprotaso/go-yit v0.0.0-20220510233725-9ba8df137936 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-git/gcfg/v2 v2.0.2 // indirect
	github.com/go-git/go-billy/v6 v6.0.0-alpha.2 // indirect
	github.com/go-openapi/jsonpointer v1.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/oapi-codegen/oapi-codegen/v2 v2.7.2 // indirect
	github.com/oasdiff/yaml v0.1.1 // indirect
	github.com/oasdiff/yaml3 v0.0.14 // indirect
	github.com/onsi/gomega v1.34.1 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/speakeasy-api/jsonpath v0.6.3 // indirect
	github.com/speakeasy-api/openapi v1.19.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/vmware-labs/yaml-jsonpath v0.3.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen

// go-git is built from github.com/kjanat/go-git, the fork carrying
// go-git/go-git#2328, which decodes a commit's headers wherever git put them
// and replays the ones a rewrite did not touch. pkg/gitsign reparents commits
// through the struct encoder and needs both halves of that: released go-git
// reads an author or committer outside its canonical slot as no ident at all,
// and normalizes the idents it does decode.
//
// That fork is this repository's supported source for go-git, not a stopgap
// held until upstream moves: no released go-git carries the fix, and pkg/gitsign
// is a package whose whole subject is byte fidelity. The branch is cut from
// go-git main rather than from the alpha.5 tag required above, so this also
// builds the unreleased work in between; the require line names a version this
// build never uses.
//
// The pin is the fork's signed annotated tag v6.0.0-kjanat.1, which names
// commit ddab11a1c7762bda7dee392391d72e52a3cde07e — the same commit the
// pseudo-version here before it named, so nothing about what compiles changed
// with the spelling. What changed is what a reader can check: the tag is signed
// by the fork's maintainer, and `git cat-file tag` on it says which commit it
// promises. Nothing re-syncs it: Dependabot leaves a replaced module alone, so
// picking up an upstream go-git change — a security fix included — means
// rebasing kjanat/go-git by hand and moving the tag named below.
//
// The left side is unversioned on purpose. Pinning it to alpha.5 would stop
// matching the moment the require line moves and drop the fix out of the build
// in silence, which is the worse failure here. Losing the directive outright
// still compiles, so the tests are what catch it: every row of
// TestUnsignedObjectChangesOnlyParents runs through the encoder this selects,
// and TestUnsignedObjectNeedsThePinnedFork names the damage released go-git
// does instead.
//
// One more consequence to know about: "go install pkg@version" refuses a
// module that carries a replace, so tagging client/v* would not on its own
// make the CLI go-installable.
replace github.com/go-git/go-git/v6 => github.com/kjanat/go-git/v6 v6.0.0-kjanat.1
