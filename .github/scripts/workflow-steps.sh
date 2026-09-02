#!/usr/bin/env bash
# Read a workflow's steps for the properties its tests assert about them:
# which script a `run:` step actually executes, whether a `uses:` step is
# pinned to something immutable, and what one of a job's own keys says.
#
#   source .github/scripts/workflow-steps.sh
#   workflow_runs_script  <workflow.yml> <script-path>...
#   workflow_mutable_uses <workflow.yml> [--job <id>] [--expect-uses]
#   workflow_job_field    <workflow.yml> <job-id> <field>
#   workflow_input_field  <workflow.yml> <input> <field>
#   workflow_input_fields <workflow.yml> <input>
#
# Every one of these is a thin bridge to .github/scripts/workflow-steps.ts,
# which does the parsing with the `yaml` package this repository already pins.
# The shell half exists because the three suites that need these answers are
# shell, and because the failure mode has to be a non-zero status the caller
# cannot read past.
#
# THESE FUNCTIONS RETURN NON-ZERO WHEN THEY CANNOT ANSWER. Both queries have a
# meaningful empty answer — no step runs the script, every action is pinned —
# so a caller that only reads stdout would take "unparseable" for "clean". Call
# them into a variable so `set -e` sees the status:
#
#   got="$(workflow_runs_script "${workflow}" .github/scripts/x.sh)" || exit 1
#
# rather than inside `[[ ... ]]`, which swallows it.
#
# The same is true of a dispatch input's keys. `awk` from the input's name to
# the first `default:` it meets does not stop at the end of that input, so an
# input that has LOST its default reads back the next one's — a guard reporting
# a value nothing set. `workflow_input_field` reads the mapping the key is
# actually in.
#
# Sourced rather than duplicated because the suites that need it —
# test-sign-commits.sh, test-repair-history.sh and test-commit-provenance.sh —
# assert the same properties about different files, and a parser kept in three
# copies is a parser that stops agreeing with itself. Its own adversarial cases
# live in .github/scripts/test-workflow-steps.sh (`task test:workflow-steps`).
#
# The obvious spelling is `grep -Fq '<path>' workflow.yml`, and it answers a
# different question: whether the path is *mentioned*. Four things mention a
# path without running it, and all four are reachable in valid workflow YAML:
#
#   * a YAML comment. Both pending workflows quote the `run:` line they
#     replace, in a header explaining the replacement.
#   * a step that names it as data — `run: echo <path>`, `SCRIPT: <path>`.
#   * a shell comment inside a `run: |` block.
#   * a folded `run: >` block, whose lines the runner joins into ONE command —
#     so a path on its own source line can be an argument to the command above
#     it. That one is invisible to any line scanner, which is why the parsing
#     moved into a real parser.
#
# A wiring test exists to prove the workflow still calls the script the suite
# below it exercises. One built on `grep -F` passes on a workflow that has
# stopped calling it, which is the one tree it has to fail on.

# The interpreter for the parser. `bun` is this repository's runtime and the
# `yaml` package is one of its dependencies; `mise exec` is the fallback for a
# shell whose PATH has not been through mise. A machine with neither fails
# loudly here rather than quietly reducing every assertion below to "clean".
workflow_steps_run() {
	local script="${BASH_SOURCE[0]%/*}/workflow-steps.ts"

	if command -v bun >/dev/null 2>&1; then
		bun "${script}" "$@"
	elif command -v mise >/dev/null 2>&1; then
		mise exec -- bun "${script}" "$@"
	else
		printf 'workflow-steps.sh: bun is not on PATH, so the workflow parser cannot run.\n' >&2
		printf '                   Install it (see .github/actions/setup-bun) rather than skipping these checks.\n' >&2
		return 127
	fi
}

# The first of the given script paths that some step in the workflow executes.
# Prints nothing when no step runs any of them; returns non-zero when the file
# cannot be parsed.
workflow_runs_script() {
	workflow_steps_run runs-script "$@"
}

# Every `uses:` in a workflow — or in one named job, with `--job <id>` — that
# resolves an external action through something other than a full commit SHA,
# one per line. Empty output means every external action is pinned.
#
# `--expect-uses` fails when the scope has no `uses:` at all, which is the
# difference between "everything is pinned" and "nothing was looked at".
workflow_mutable_uses() {
	workflow_steps_run mutable-uses "$@"
}

# One scalar key of one job, as the parser read it — `if:`, say. Quoting and
# line folding are the parser's problem rather than the caller's, which is the
# point: `if: >-` over three lines is one expression to GitHub and has to be
# one string here.
workflow_job_field() {
	workflow_steps_run job-field "$@"
}

# One scalar key of one `workflow_dispatch` input, read from that input's own
# mapping and nowhere else. Returns non-zero when the input does not declare
# the key, because "no default" and "defaults to the empty string" are
# different facts about a dispatch form and a caller asserting a default's
# value must not read the first as the second.
workflow_input_field() {
	workflow_steps_run input-field "$@"
}

# The keys one `workflow_dispatch` input declares, one per line. This is the
# query for whether a key is there at all — an assertion that an input must
# have NO default is about the key's presence, not its value.
workflow_input_fields() {
	workflow_steps_run input-fields "$@"
}
