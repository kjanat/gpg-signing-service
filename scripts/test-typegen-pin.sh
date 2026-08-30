#!/usr/bin/env bash
# Covers the invariant that worker-configuration.d.ts has exactly one producer.
#
# There are two wranglers reachable from this repo:
#
#   * `.mise.toml`'s, which reaches checkouts that have no node_modules --
#     .github/workflows/d1-migrate.yml and scripts/cf.sh's WORKERS_CI branch
#   * node_modules/.bin/wrangler, pinned by bun.lock and now a *direct*
#     devDependency rather than a hoisted transitive of vitest-pool-workers
#
# #125 pinned the first to the version the second resolves, so the two channels
# ship one workerd; scripts/test-tool-pins.sh is what holds that down. This file
# stays as it was written for #123/#124 -- it does not care what `.mise.toml`
# says, only that the committed artifact matches the lockfile and that no task
# regenerates it through anything but the lockfile binary. That is deliberate:
# if the mise pin is ever lost these assertions still fail on the artifact.
#
# `wrangler types` stamps its own workerd into the header of the generated file,
# so whichever one ran last decides what is in the tree. That is #123: the
# committed file came from the mise wrangler, then `bun install` inside CI fired
# `prepare` -> scripts/cf.sh -> `run typegen`, which is the node_modules one,
# rewrote it, and `.github/actions/check-api-changes` -- which diffs the whole
# worktree, not just the API files -- went red on a tree where `task
# generate:api` is clean. Nothing local reproduced it because `generate:api`
# depends on `install:noscripts` and never fires `prepare`.
#
# The lockfile wrangler is the correct producer, because its workerd is the one
# the vitest-pool-workers suite actually executes on; types describing a
# different runtime than the tests run against are wrong even when CI is green.
# So the two assertions below are: the header records the lockfile's workerd,
# and no task regenerates the file through the mise tool. Both fail on
# the pre-fix tree. Neither needs a network or a wrangler run.
set -euo pipefail

# A fixture root so the gate itself is testable: scripts/test-tool-pins.sh
# assembles mutated bun.lock/Taskfile/artifact trees under a temporary git repo
# and asserts this script actually goes red on each of them. Unset -- which is
# every real invocation -- it is the repository.
repo_root="${TYPEGEN_PIN_ROOT:-$(git rev-parse --show-toplevel)}"

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

types_file="${repo_root}/worker-configuration.d.ts"
lockfile="${repo_root}/bun.lock"
taskfile="${repo_root}/Taskfile.yml"

for required in "${types_file}" "${lockfile}" "${taskfile}"; do
	if [[ ! -f ${required} ]]; then
		printf 'missing %s\n' "${required}" >&2
		exit 1
	fi
done

# Entries in bun.lock's "packages" map are keyed by package name at the start of
# a line, e.g.
#   "wrangler": ["wrangler@4.123.0", "", { "dependencies": { ... } }, "sha512-..."],
# while a dependency *of* some package is written inline inside that package's
# own line. Anchoring the address to the line start is therefore what separates
# "the version bun installed" from "a range someone declared".
lock_entry() {
	grep -E "^[[:space:]]*\"$1\": \\[" "${lockfile}" | head -1 || true
}

wrangler_entry="$(lock_entry wrangler)"
if [[ -z ${wrangler_entry} ]]; then
	printf 'no resolved "wrangler" entry in bun.lock -- did the dependency move?\n' >&2
	exit 1
fi
locked_wrangler="$(sed -nE 's/.*"wrangler@([^"]+)".*/\1/p' <<<"${wrangler_entry}")"

# Read workerd from its *own* resolved entry rather than from the "workerd":
# "..." that appears inside wrangler's dependency map. Those are two different
# things: the latter is the range wrangler asked for, the former is the single
# build bun actually installed and therefore the one `wrangler types` runs and
# stamps into the header. They are equal today only because wrangler happens to
# declare an exact version; the day it declares "^1.2026...." or a workspace
# override moves the resolution, comparing the header against the *declared*
# spec starts reporting a mismatch that is not one -- or, worse, masks a real
# one. This is the address of the thing on disk.
workerd_entry="$(lock_entry workerd)"
if [[ -z ${workerd_entry} ]]; then
	printf 'no resolved top-level "workerd" entry in bun.lock -- did the dependency move?\n' >&2
	exit 1
fi
locked_workerd="$(sed -nE 's/.*"workerd@([^"]+)".*/\1/p' <<<"${workerd_entry}")"

if [[ -z ${locked_wrangler} || -z ${locked_workerd} ]]; then
	printf 'could not read the wrangler/workerd pin out of bun.lock\n' >&2
	exit 1
fi

printf 'bun.lock resolves wrangler@%s and workerd@%s\n' "${locked_wrangler}" "${locked_workerd}"

new_case 'the committed types record the lockfile wrangler workerd'
# Read the *committed* blob out of the index, not the copy on disk. Every CI job
# that uses .github/actions/setup-bun runs a bare `bun install` first, which
# fires `prepare` -> scripts/cf.sh -> `run typegen` and rewrites
# worker-configuration.d.ts in place with the very wrangler this case compares
# against -- and the Test job, the one that runs this script, is one of them.
# Off disk the comparison is therefore between the pinned wrangler and itself:
# it passes unconditionally, including on a tree carrying exactly the #123
# drift. `:path` is the index, which is the checked-out commit in CI and still
# holds the pre-regeneration content after `bun install` has run.
#
# Header line written by `wrangler types`:
#   // Runtime types generated with workerd@1.20260811.1 2026-07-12 nodejs_compat
committed_types="$(git -C "${repo_root}" cat-file blob :worker-configuration.d.ts 2>/dev/null || true)"
if [[ -z ${committed_types} ]]; then
	fail 'worker-configuration.d.ts is not in the index -- cannot check what is committed'
else
	header_workerd="$(sed -nE 's|^// Runtime types generated with workerd@([^ ]+).*|\1|p' <<<"${committed_types}" | head -1)"
	if [[ -z ${header_workerd} ]]; then
		fail 'worker-configuration.d.ts has no "Runtime types generated with workerd@..." header'
	elif [[ ${header_workerd} != "${locked_workerd}" ]]; then
		fail "worker-configuration.d.ts is committed as generated with workerd ${header_workerd}, but bun.lock resolves workerd@${locked_workerd} (under wrangler@${locked_wrangler}) -- regenerate with 'task typegen' and commit the result"
	fi
fi

new_case 'typegen does not regenerate through the mise wrangler'
# Only the recipe matters, so read the command lines of the typegen task rather
# than the whole file: `mise exec -- wrangler dev` and the d1/kv tasks are
# deliberately on the current tool and emit no committed artifact.
typegen_recipe="$(awk '
	/^  typegen:/ { inside = 1; next }
	inside && /^  [a-z]/ { inside = 0 }
	inside { print }
' "${taskfile}")"

if [[ -z ${typegen_recipe} ]]; then
	fail 'no typegen task found in Taskfile.yml'
fi

# Comments in the recipe describe the trap; they are not what runs.
typegen_cmds="$(grep -vE '^[[:space:]]*#' <<<"${typegen_recipe}")"
if grep -q 'wrangler' <<<"${typegen_cmds}"; then
	fail "the typegen task invokes wrangler directly -- that resolves .mise.toml's tool rather than the bun.lock pin, and the two are equal only for as long as someone keeps them equal"
fi
if ! grep -qE '\brun typegen\b' <<<"${typegen_cmds}"; then
	fail 'the typegen task no longer runs the package.json "typegen" script, so it can drift from what the prepare hook fires on bun install'
fi

new_case 'the prepare hook still routes through the same package.json script'
# If cf.sh stops calling typegen the case above stops meaning anything: the two
# producers would simply be one again by accident rather than by construction.
if ! grep -q 'typegen' "${repo_root}/scripts/cf.sh"; then
	fail 'scripts/cf.sh no longer runs typegen -- re-check whether the typegen task and the prepare hook still share a producer'
fi

new_case 'the installed wrangler agrees with the lockfile'
installed_pkg="${repo_root}/node_modules/wrangler/package.json"
if [[ ! -f ${installed_pkg} ]]; then
	printf '    skip: node_modules/wrangler absent\n'
else
	installed_wrangler="$(sed -nE 's/.*"version": ?"([^"]+)".*/\1/p' "${installed_pkg}" | head -1)"
	if [[ ${installed_wrangler} != "${locked_wrangler}" ]]; then
		fail "node_modules/wrangler is ${installed_wrangler} but bun.lock pins ${locked_wrangler} -- run 'bun install'"
	fi
fi

if ((failures > 0)); then
	printf '\n%d typegen pin assertion(s) failed\n' "${failures}" >&2
	exit 1
fi

printf '\ntypegen pin gate: all assertions passed\n'
