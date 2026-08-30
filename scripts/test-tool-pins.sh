#!/usr/bin/env bash
# Covers the invariant that every tool which can rewrite a file this repository
# commits resolves to exactly one explicit version.
#
# #123 was one instance of this: two wranglers, one of them `latest`, and
# whichever ran last decided what was in worker-configuration.d.ts.
# scripts/test-typegen-pin.sh holds that artifact down. This file holds down the
# class, because the artifact gate only ever sees the producer it already knows
# about:
#
#   * wrangler       writes worker-configuration.d.ts via `wrangler types`
#   * biome          rewrites imports via `biome check --fix`, which is what the
#                    pre-commit `lint:fix` job runs
#   * tombi          rewrites *.toml -- .dprint.jsonc shells out to it
#   * golangci-lint  rewrites *.go -- .dprint.jsonc shells out to it
#
# A floating linter is a nuisance; a floating producer is a repository mutation
# that depends on the day you ran `mise install`. On clean master before #125,
# `mise install` fetched biome 2.5.11, whose organizeImports orders differently
# from whatever wrote the tree, and the very next pre-commit reordered imports in
# two files that nobody had touched. `task lint` stayed green throughout, because
# it ran `biome lint`, and `lint` does not run assists.
#
# The other half of the same hole was resolution by accident:
# node_modules/.bin/wrangler existed only because bun hoisted a transitive
# dependency of @cloudflare/vitest-pool-workers, while thirteen package.json
# scripts spelled it as though it were ours. #124 then made that binary the
# single producer of a committed artifact, so it had to become a real
# devDependency rather than a hoist that a resolver change could take away.
#
# Every assertion below is made against a root directory rather than against the
# repository, so the second half of this file can point them at deliberately
# broken copies and require that they go red. A gate nobody has ever seen fail
# is a gate nobody knows the failure mode of.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

failures=0
case_name=""

new_case() {
	case_name="$1"
	printf '  case: %s\n' "${case_name}"
}

fail() {
	printf '    FAIL (%s): %s\n' "${case_name}" "$1" >&2
	failures=$((failures + 1))
}

# --- readers -----------------------------------------------------------------
#
# Deliberately textual. A JSON/TOML parser would be a tool resolved at run time,
# which is the thing this file exists to distrust, and bun.lock is not JSON
# anyway -- it carries trailing commas.

# The value of a `[tools]` entry in .mise.toml. Names are matched with the
# optional quoting mise allows (`"cargo:runner-run" = ...`) so a quoted pin is
# not read as absent.
mise_tool() {
	sed -nE "s/^[[:space:]]*\"?$2\"?[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" "$1/.mise.toml" | head -1
}

# A `"key": "value"` pair inside one named block, addressed by the block's own
# indentation. Scoping matters here: package.json's scripts contain the *word*
# wrangler thirteen times, and a file-wide grep for it would report a dependency
# that does not exist.
json_block_value() {
	local file="$1" indent="$2" block="$3" want="$4"
	awk -v ind="${indent}" -v block="${block}" -v want="${want}" '
		index($0, ind "\"" block "\": {") == 1 { inside = 1; next }
		inside && index($0, ind "}") == 1 { exit }
		inside {
			if (match($0, /"[^"]+": *"[^"]*"/)) {
				seg = substr($0, RSTART, RLENGTH)
				split(seg, p, "\"")
				if (p[2] == want) { print p[4]; exit }
			}
		}
	' "${file}"
}

# The version bun actually installed, read from the top-level entry in the
# "packages" map -- the same address scripts/test-typegen-pin.sh uses, and for
# the same reason: a package's own entry starts a line, a range it merely
# declares is written inline inside some other package's entry.
lock_resolved() {
	grep -E "^[[:space:]]*\"$2\": \\[" "$1/bun.lock" \
		| head -1 \
		| sed -nE "s/.*\"$2@([^\"]+)\".*/\1/p"
}

# An exact release, not a range, not a channel. `latest` is the case that
# prompted all of this; `^4.123.0` and `4.x` are the same bug wearing a version
# number, because the thing that varies is still the day you resolved it.
is_exact_version() {
	[[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]
}

# --- the assertions, as a function of a root ---------------------------------
#
# Prints one line per problem and returns the count, so a caller can either
# fold them into `failures` (the repository) or require that there were some
# (the mutants). PRODUCERS is the list this repository has decided it cannot
# afford to float; everything else in .mise.toml only ever reads.
PRODUCERS=(wrangler biome tombi golangci-lint)

check_root() {
	local root="$1"
	local problems=0
	local tool version

	note() {
		printf '%s\n' "$1"
		problems=$((problems + 1))
	}

	for tool in "${PRODUCERS[@]}"; do
		version="$(mise_tool "${root}" "${tool}")"
		if [[ -z ${version} ]]; then
			note "${tool} is not in .mise.toml [tools] -- it rewrites committed files, so it cannot be left to whatever is on PATH"
		elif ! is_exact_version "${version}"; then
			note "${tool} is pinned to '${version}' in .mise.toml -- a producer has to name one release, or 'mise install' becomes a repository mutation"
		fi
	done

	local declared_wrangler locked_wrangler mise_wrangler lock_direct
	declared_wrangler="$(json_block_value "${root}/package.json" '  ' devDependencies wrangler)"
	lock_direct="$(json_block_value "${root}/bun.lock" '      ' devDependencies wrangler)"
	locked_wrangler="$(lock_resolved "${root}" wrangler)"
	mise_wrangler="$(mise_tool "${root}" wrangler)"

	if [[ -z ${declared_wrangler} ]]; then
		note "package.json invokes wrangler but does not depend on it -- node_modules/.bin/wrangler then exists only while bun keeps hoisting it out of @cloudflare/vitest-pool-workers, and it is the producer of a committed artifact"
	elif ! is_exact_version "${declared_wrangler}"; then
		note "package.json depends on wrangler '${declared_wrangler}' -- the producer of worker-configuration.d.ts has to be an exact version"
	fi

	if [[ -z ${lock_direct} ]]; then
		note "bun.lock does not carry wrangler as a root devDependency -- package.json and the lockfile disagree about whether it is ours; run 'bun install'"
	fi

	if [[ -z ${locked_wrangler} ]]; then
		note "no resolved top-level wrangler entry in bun.lock"
	elif [[ -n ${declared_wrangler} && ${declared_wrangler} != "${locked_wrangler}" ]]; then
		note "package.json asks for wrangler ${declared_wrangler} but bun.lock resolved ${locked_wrangler}"
	fi

	# The two channels are allowed to exist; they are not allowed to be two
	# versions. `wrangler types` stamps its own workerd into the header of the
	# file it writes, so a split version is a split producer no matter which one
	# the Taskfile happens to name today.
	if [[ -n ${mise_wrangler} && -n ${locked_wrangler} && ${mise_wrangler} != "${locked_wrangler}" ]]; then
		note "the mise wrangler is ${mise_wrangler} and the bun.lock one is ${locked_wrangler} -- two channels are fine, two versions are two producers"
	fi

	unset -f note
	return "${problems}"
}

# --- the repository itself has to satisfy them -------------------------------

new_case 'every producer in .mise.toml is pinned and the two wranglers agree'
set +e
check_output="$(check_root "${repo_root}")"
set -e
if [[ -n ${check_output} ]]; then
	while IFS= read -r line; do
		fail "${line}"
	done <<<"${check_output}"
else
	printf '    wrangler %s (mise and bun.lock), biome %s, tombi %s\n' \
		"$(lock_resolved "${repo_root}" wrangler)" \
		"$(mise_tool "${repo_root}" biome)" \
		"$(mise_tool "${repo_root}" tombi)"
fi

# --- and the second wrangler channel has to still be earning its keep --------
#
# The decision recorded here is "keep both, pin both", and it is only correct
# for as long as something genuinely runs wrangler without node_modules. Today
# one thing does: .github/workflows/d1-migrate.yml, which is checkout + mise and
# no bun at all. If that goes away the honest move is to drop the tool from
# .mise.toml and let package.json own wrangler outright -- so this case fails
# when the reason disappears, not when it holds.
#
# Every candidate is asked the same two questions -- does this file invoke
# wrangler, and does it do so before node_modules exists -- rather than being
# vouched for by name. scripts/cf.sh was on this list on the strength of
# `grep -q WORKERS_CI`, which is a string it contains for unrelated reasons:
# that branch runs `mise install` and then `bun install --frozen-lockfile` and
# never names wrangler at all, and the re-entrant `prepare` it fires returns at
# the CF_MISE_BOOTSTRAPPED guard before typegen. A clause that cannot go red for
# the reason it was written is not holding anything down.
new_case 'the mise wrangler channel still has a caller without node_modules'
nodeless_callers=()

# Names wrangler as a command, not merely in prose or a package name.
invokes_wrangler() {
	grep -qE '(^|[^[:alnum:]_./-])wrangler([[:space:]]|$)' "$1"
}

d1_workflow="${repo_root}/.github/workflows/d1-migrate.yml"
if [[ -f ${d1_workflow} ]] \
	&& invokes_wrangler "${d1_workflow}" \
	&& ! grep -q 'setup-bun' "${d1_workflow}"; then
	nodeless_callers+=('.github/workflows/d1-migrate.yml')
fi

# cf.sh's WORKERS_CI branch reaches a tree with no node_modules, so it counts --
# but only once it actually runs wrangler there.
cf_sh="${repo_root}/scripts/cf.sh"
if [[ -f ${cf_sh} ]] && invokes_wrangler "${cf_sh}"; then
	nodeless_callers+=('scripts/cf.sh')
fi

if ((${#nodeless_callers[@]} == 0)); then
	fail "nothing runs wrangler outside a tree with node_modules any more -- the .mise.toml wrangler is now a second producer with no operational reason, so remove it and let package.json own it"
else
	printf '    kept for: %s\n' "${nodeless_callers[*]}"
fi

# --- a clean checkout has to stay clean --------------------------------------
#
# The pin is only half the fix. The tree also had to be normalised once at the
# pinned version, because no biome in the 2.4/2.5 range agreed with the import
# order that was committed -- so a fresh clone, having run nothing but `mise
# install`, would still have had its first `git commit` rewrite two files.
#
# `check`, not `check --fix`: a fix would make this pass by mutating the very
# thing it is asserting. Clean here is exactly the statement that pre-commit's
# `biome check --fix` has nothing to do.
new_case 'biome at the pinned version leaves the checkout alone'
pinned_biome="$(mise_tool "${repo_root}" biome)"
if ! command -v mise >/dev/null 2>&1 || ! mise which biome >/dev/null 2>&1; then
	printf '    skip: no mise-provided biome\n'
else
	running_biome="$(mise exec -- biome --version 2>/dev/null | sed -nE 's/^Version: (.+)$/\1/p')"
	if [[ ${running_biome} != "${pinned_biome}" ]]; then
		fail "mise resolves biome ${running_biome} but .mise.toml pins ${pinned_biome} -- run 'mise install'"
	elif ! biome_out="$(cd "${repo_root}" && mise exec -- biome check 2>&1)"; then
		fail "biome ${pinned_biome} wants to change the checked-out tree, so the pre-commit lint:fix will rewrite it:"$'\n'"${biome_out}"
	fi
fi

# --- the mutants --------------------------------------------------------------
#
# Each one is the repository with a single deliberate regression applied, and
# each has to be caught by the assertion that names it. Copies are of the three
# files check_root reads; nothing here can touch the working tree.

mutant_root() {
	local name="$1" root="${tmp_dir}/mutants/$1"
	mkdir -p "${root}"
	cp "${repo_root}/.mise.toml" "${repo_root}/package.json" "${repo_root}/bun.lock" "${root}/"
	printf '%s' "${root}"
}

expect_caught() {
	local label="$1" root="$2" expected="$3"
	local out
	new_case "${label}"
	set +e
	out="$(check_root "${root}")"
	set -e
	if [[ -z ${out} ]]; then
		fail 'the mutation was not caught at all'
	elif ! grep -qF -- "${expected}" <<<"${out}"; then
		fail "caught something, but not the mutation: ${out}"
	fi
}

root="$(mutant_root biome-latest)"
sed -i -E 's/^([[:space:]]*biome[[:space:]]*=[[:space:]]*)".*"/\1"latest"/' "${root}/.mise.toml"
expect_caught 'mutant: biome = "latest" is rejected' "${root}" "biome is pinned to 'latest'"

root="$(mutant_root wrangler-latest)"
sed -i -E 's/^([[:space:]]*wrangler[[:space:]]*=[[:space:]]*)".*"/\1"latest"/' "${root}/.mise.toml"
expect_caught 'mutant: wrangler = "latest" is rejected' "${root}" "wrangler is pinned to 'latest'"

root="$(mutant_root tombi-latest)"
sed -i -E 's/^([[:space:]]*tombi[[:space:]]*=[[:space:]]*)".*"/\1"latest"/' "${root}/.mise.toml"
expect_caught 'mutant: a floating dprint-invoked formatter is rejected' "${root}" "tombi is pinned to 'latest'"

# The pre-#125 state exactly: scripts calling a binary that is only there while
# some other package keeps depending on it.
root="$(mutant_root wrangler-undeclared)"
sed -i -E '/^[[:space:]]*"wrangler": "[^"]*",?$/d' "${root}/package.json"
expect_caught 'mutant: dropping the direct wrangler dep is rejected' "${root}" 'does not depend on it'

root="$(mutant_root wrangler-range)"
sed -i -E 's/^([[:space:]]*"wrangler": )"[^"]*"/\1"^4.123.0"/' "${root}/package.json"
expect_caught 'mutant: a floating wrangler range is rejected' "${root}" 'has to be an exact version'

root="$(mutant_root wrangler-split)"
sed -i -E 's/^([[:space:]]*wrangler[[:space:]]*=[[:space:]]*)".*"/\1"4.127.1"/' "${root}/.mise.toml"
expect_caught 'mutant: two pinned-but-different wranglers are rejected' "${root}" 'two versions are two producers'

# --- and the typegen gate has to read a resolution, not a declaration ---------
#
# scripts/test-typegen-pin.sh compares the workerd in the generated header
# against bun.lock. Which workerd it reads is the whole question. Reading the
# one inside wrangler's own dependency map is reading what wrangler *asked for*;
# the fixtures below are built so that the asked-for and the installed versions
# differ, which is the only condition under which the two readers disagree.
#
# The fixture is a real git repository because the gate reads the committed blob
# out of the index rather than the worktree -- that is #124's fix, and it is
# preserved here rather than worked around.

typegen_fixture() {
	local name="$1" declared_workerd="$2" resolved_workerd="$3" header_workerd="$4"
	local root="${tmp_dir}/typegen/${name}"
	mkdir -p "${root}/scripts"

	cp "${repo_root}/Taskfile.yml" "${root}/Taskfile.yml"
	cp "${repo_root}/scripts/cf.sh" "${root}/scripts/cf.sh"

	cat >"${root}/bun.lock" <<EOF
{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "devDependencies": {
        "wrangler": "4.123.0",
      },
    },
  },
  "packages": {
    "workerd": ["workerd@${resolved_workerd}", "", {}, "sha512-fixture"],
    "wrangler": ["wrangler@4.123.0", "", { "dependencies": { "workerd": "${declared_workerd}" } }, "sha512-fixture"],
  }
}
EOF

	printf '// Runtime types generated with workerd@%s 2026-07-12 nodejs_compat\n' "${header_workerd}" \
		>"${root}/worker-configuration.d.ts"

	git -C "${root}" init -q
	git -C "${root}" add -A
	printf '%s' "${root}"
}

run_typegen_gate() {
	TYPEGEN_PIN_ROOT="$1" bash "${repo_root}/scripts/test-typegen-pin.sh" >"$2" 2>&1
}

new_case 'typegen gate: a fixture whose header matches the resolution passes'
root="$(typegen_fixture agreeing 1.20260811.1 1.20260811.1 1.20260811.1)"
if ! run_typegen_gate "${root}" "${tmp_dir}/agreeing.log"; then
	fail "the gate failed on a consistent fixture: $(cat "${tmp_dir}/agreeing.log")"
fi

new_case 'typegen gate: a header from another workerd is caught'
root="$(typegen_fixture drifted 1.20260811.1 1.20260811.1 1.20260101.9)"
if run_typegen_gate "${root}" "${tmp_dir}/drifted.log"; then
	fail 'the gate passed a tree whose committed types came from a different workerd'
elif ! grep -q 'regenerate with' "${tmp_dir}/drifted.log"; then
	fail "the gate failed for some other reason: $(cat "${tmp_dir}/drifted.log")"
fi

# The regression this file was extended for. Everything installed is consistent
# -- workerd 1.20260811.1 is what bun resolved and what wrote the header -- and
# the only oddity is that wrangler declares a range. A gate reading that range
# reports "committed with 1.20260811.1 but the lockfile says ^1.20260811.0",
# which is not a fact about anything: the caret is not a build, no wrangler ever
# stamped it into a header, and there is nothing the reader could do to make it
# agree. Worse in the other direction, a range wide enough to spell a version
# that is not installed would let a genuinely stale artifact through.
new_case 'typegen gate: a declared range does not manufacture a mismatch'
root="$(typegen_fixture ranged '^1.20260811.0' 1.20260811.1 1.20260811.1)"
declared="$(grep -E '^[[:space:]]*"wrangler": \[' "${root}/bun.lock" | sed -nE 's/.*"workerd": ?"([^"]+)".*/\1/p')"
if [[ ${declared} != '^1.20260811.0' ]]; then
	fail "the fixture does not actually distinguish the two readers (declared '${declared}')"
elif ! run_typegen_gate "${root}" "${tmp_dir}/ranged.log"; then
	fail "the gate read wrangler's declared workerd spec rather than the resolved entry: $(cat "${tmp_dir}/ranged.log")"
fi

new_case 'typegen gate: a lockfile with no resolved workerd is an error, not a pass'
root="$(typegen_fixture no-workerd 1.20260811.1 1.20260811.1 1.20260811.1)"
sed -i -E '/^[[:space:]]*"workerd": \[/d' "${root}/bun.lock"
git -C "${root}" add -A
if run_typegen_gate "${root}" "${tmp_dir}/no-workerd.log"; then
	fail 'the gate passed a lockfile it could not read a workerd out of'
elif ! grep -q 'no resolved top-level "workerd" entry' "${tmp_dir}/no-workerd.log"; then
	fail "the gate failed for some other reason: $(cat "${tmp_dir}/no-workerd.log")"
fi

if ((failures > 0)); then
	printf '\n%d tool pin assertion(s) failed\n' "${failures}" >&2
	exit 1
fi

printf '\ntool pin gate: all assertions passed\n'
