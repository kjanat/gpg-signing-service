#!/usr/bin/env bash
# Covers the invariant that worker-configuration.d.ts has exactly one producer.
#
# There are two wranglers reachable from this repo and they ship different
# workerd builds:
#
#   * `.mise.toml` has `wrangler = "latest"`, an unpinned tool whose version is
#     whatever the machine resolved the day mise installed it
#   * node_modules/.bin/wrangler, pinned to an exact version by bun.lock as a
#     transitive dependency of @cloudflare/vitest-pool-workers
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
# and no task regenerates the file through the unpinned mise tool. Both fail on
# the pre-fix tree. Neither needs a network or a wrangler run.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"

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

# The resolved `wrangler` entry in bun.lock, e.g.
#   "wrangler": ["wrangler@4.123.0", "", { "dependencies": { ..., "workerd": "1.20260811.1" }, ... }, "sha512-..."],
# The address is the top-level key, so a nested "wrangler" under some other
# package's dependency map cannot be picked up by accident.
wrangler_entry="$(grep -E '^[[:space:]]*"wrangler": \[' "${lockfile}" || true)"
if [[ -z ${wrangler_entry} ]]; then
	printf 'no resolved "wrangler" entry in bun.lock -- did the dependency move?\n' >&2
	exit 1
fi

locked_wrangler="$(sed -nE 's/.*"wrangler@([^"]+)".*/\1/p' <<<"${wrangler_entry}")"
locked_workerd="$(sed -nE 's/.*"workerd": ?"([^"]+)".*/\1/p' <<<"${wrangler_entry}")"

if [[ -z ${locked_wrangler} || -z ${locked_workerd} ]]; then
	printf 'could not read the wrangler/workerd pin out of bun.lock\n' >&2
	exit 1
fi

printf 'bun.lock pins wrangler@%s (workerd %s)\n' "${locked_wrangler}" "${locked_workerd}"

new_case 'the committed types record the lockfile wrangler workerd'
# Header line written by `wrangler types`:
#   // Runtime types generated with workerd@1.20260811.1 2026-07-12 nodejs_compat
header_workerd="$(sed -nE 's|^// Runtime types generated with workerd@([^ ]+).*|\1|p' "${types_file}" | head -1)"
if [[ -z ${header_workerd} ]]; then
	fail 'worker-configuration.d.ts has no "Runtime types generated with workerd@..." header'
elif [[ ${header_workerd} != "${locked_workerd}" ]]; then
	fail "worker-configuration.d.ts was generated with workerd ${header_workerd}, but bun.lock pins wrangler@${locked_wrangler} which ships workerd ${locked_workerd} -- regenerate with 'task typegen'"
fi

new_case 'typegen does not regenerate through the unpinned mise wrangler'
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
	fail "the typegen task invokes wrangler directly -- that resolves .mise.toml's unpinned tool, not the bun.lock pin"
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
