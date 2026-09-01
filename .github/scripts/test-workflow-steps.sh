#!/usr/bin/env bash
# The adversarial cases for .github/scripts/workflow-steps.{sh,ts}.
#
# That helper answers two questions the signing and provenance suites decide
# their whole verdict on: does this workflow still RUN the script the suite is
# about to exercise, and is every external action it resolves pinned to a
# commit. Both were answered by line scanners, and both had a bypass a valid
# GitHub Actions workflow reaches:
#
#   * a folded `run: >` block joins its lines into one command, so a script
#     path on its own source line can be an ARGUMENT to the command above it.
#     A scanner reading the block's lines separately calls that "wired", which
#     is a false pass on exactly the tree the assertion exists to fail on.
#   * `uses` is a mapping key and a mapping key may be quoted. `"uses":
#     actions/checkout@v7` is the same step to GitHub as the unquoted spelling,
#     and an anchored `uses:` pattern does not see it — so the pin guard
#     reported clean while a mutable action ran first in a job holding
#     `contents: write` and an OIDC token.
#
# Both fixtures below are checked against a naive `grep` first, so they are
# demonstrably the bypass rather than a strawman: the case has to fool the
# implementation it replaced before it is worth asserting against the one that
# replaced it.
#
# Every "cannot answer" is asserted to be a non-zero status, not an empty line.
# Empty output is a real answer for both queries — no step runs the script,
# every action is pinned — so a parser that degraded to silence would report
# the safest possible result for the least intelligible input.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"

# shellcheck source=.github/scripts/workflow-steps.sh
source "${repo_root}/.github/scripts/workflow-steps.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

workflow="${tmp_dir}/workflow.yml"
script='.github/scripts/sign-commits.sh'

# fixture <yaml>
fixture() { printf '%s\n' "$1" >"${workflow}"; }

# --- which script a step runs --------------------------------------------------

# runs_case <description> <expected> <yaml>
runs_case() {
	local description="$1" expected="$2" got status=0
	fixture "$3"
	got="$(workflow_runs_script "${workflow}" "${script}")" || status=$?
	if ((status != 0)); then
		printf 'FAIL: the wiring matcher failed to parse %s (exit %d)\n' "${description}" "${status}" >&2
		exit 1
	fi
	if [[ "${got}" != "${expected}" ]]; then
		printf 'FAIL: the wiring matcher read %s as %q, expected %q\n' \
			"${description}" "${got}" "${expected}" >&2
		exit 1
	fi
}

runs_case 'an inline step that runs the script' "${script}" \
	"jobs:
  sign:
    steps:
      - run: ${script}"

runs_case 'a step that runs it through an interpreter' "${script}" \
	"jobs:
  sign:
    steps:
      - run: bash ${script} --flag"

runs_case 'a step that runs it behind an environment assignment' "${script}" \
	"jobs:
  sign:
    steps:
      - run: GPG_SIGN_BIN=/tmp/x ${script}"

runs_case 'a literal block whose last line runs it' "${script}" \
	"jobs:
  sign:
    steps:
      - run: |
          export SOMETHING=1
          ${script}
      - run: git push"

runs_case 'a literal block with a chomping indicator' "${script}" \
	"jobs:
  sign:
    steps:
      - run: |-
          ${script}"

runs_case 'a step written as a flow mapping' "${script}" \
	"jobs:
  sign:
    steps: [{ run: ${script} }]"

runs_case 'a step whose run key is quoted' "${script}" \
	"jobs:
  sign:
    steps:
      - \"run\": ${script}"

# The bypass. YAML folds these two lines into `echo hello <path>`, one command,
# which prints the path rather than running it.
folded_argument="jobs:
  sign:
    steps:
      - run: >
          echo hello
          ${script}"

runs_case 'a folded block where the path is an argument to the line above' '' "${folded_argument}"

# ...and the same shape once a blank line ends the fold, where the path really
# is its own command. The two differ by one empty line and by nothing a line
# scanner can see.
runs_case 'a folded block where a blank line makes the path its own command' "${script}" \
	"jobs:
  sign:
    steps:
      - run: >
          echo hello

          ${script}"

runs_case 'a folded block that runs the script with its arguments folded in' "${script}" \
	"jobs:
  sign:
    steps:
      - run: >-
          ${script}
          --base main"

runs_case 'a comment quoting the run line it replaces' '' \
	"# - run: ${script}
jobs:
  sign:
    steps:
      - run: git push"

runs_case 'a step that only prints the path' '' \
	"jobs:
  sign:
    steps:
      - run: echo ${script}"

runs_case 'a shell comment inside a run block' '' \
	"jobs:
  sign:
    steps:
      - run: |
          # ${script} used to run here
          git push"

runs_case 'an env value naming the path' '' \
	"jobs:
  sign:
    steps:
      - env:
          SCRIPT: ${script}
        run: git push"

# The fixture is only worth asserting against if it defeats what it replaced.
# `grep -F` is what read these files before; it says "wired" for both of the
# cases the matcher above says '' for.
for bypass in "${folded_argument}" "jobs:
  sign:
    steps:
      - run: echo ${script}"; do
	if ! grep -Fq "${script}" <<<"${bypass}"; then
		printf 'FAIL: a negative fixture no longer even mentions %s, so it proves nothing\n' \
			"${script}" >&2
		exit 1
	fi
done

# --- failing closed ------------------------------------------------------------

# unparseable_case <description> <yaml>
unparseable_case() {
	local description="$1" got status=0
	fixture "$2"
	got="$(workflow_runs_script "${workflow}" "${script}" 2>/dev/null)" || status=$?
	if ((status == 0)); then
		printf 'FAIL: the wiring matcher accepted %s and answered %q; it has to fail closed\n' \
			"${description}" "${got}" >&2
		exit 1
	fi
	status=0
	got="$(workflow_mutable_uses "${workflow}" 2>/dev/null)" || status=$?
	if ((status == 0)); then
		printf 'FAIL: the pin guard accepted %s and reported %q; it has to fail closed\n' \
			"${description}" "${got}" >&2
		exit 1
	fi
}

unparseable_case 'malformed YAML' \
	'jobs:
  sign:
   - x
  bad: [1,'

unparseable_case 'a file with no jobs: at all' \
	'name: Sign
on: { workflow_dispatch: {} }'

unparseable_case 'a jobs: that is a sequence rather than a mapping' \
	'jobs:
  - sign'

unparseable_case 'a step that is not a mapping' \
	'jobs:
  sign:
    steps:
      - just a string'

# A `run:` that is not a string is only the wiring matcher's problem — the pin
# guard never reads it — so this one is asserted against that query alone.
fixture 'jobs:
  sign:
    steps:
      - run: [one, two]'
status=0
got="$(workflow_runs_script "${workflow}" "${script}" 2>/dev/null)" || status=$?
if ((status == 0)); then
	printf 'FAIL: the wiring matcher accepted a run: that is not a string and answered %q\n' "${got}" >&2
	exit 1
fi

status=0
missing="$(workflow_runs_script "${tmp_dir}/not-here.yml" "${script}" 2>/dev/null)" || status=$?
if ((status == 0)); then
	printf 'FAIL: the wiring matcher answered %q for a file that does not exist\n' "${missing}" >&2
	exit 1
fi

# --- which actions are pinned --------------------------------------------------

pinned_sha='3d3c42e5aac5ba805825da76410c181273ba90b1'

# uses_case <description> <expected, newline-separated> <yaml> [option...]
uses_case() {
	local description="$1" expected="$2" got status=0
	fixture "$3"
	shift 3
	got="$(workflow_mutable_uses "${workflow}" "$@")" || status=$?
	if ((status != 0)); then
		printf 'FAIL: the pin guard failed to parse %s (exit %d)\n' "${description}" "${status}" >&2
		exit 1
	fi
	if [[ "${got}" != "${expected}" ]]; then
		printf 'FAIL: the pin guard read %s as %q, expected %q\n' "${description}" "${got}" "${expected}" >&2
		exit 1
	fi
}

uses_case 'a tag' 'actions/checkout@v7' \
	'jobs:
  sign:
    steps:
      - uses: actions/checkout@v7'

# The second bypass: the key is quoted, so an anchored `uses:` pattern misses
# the step while GitHub runs it exactly as if it were not.
quoted_key="jobs:
  sign:
    steps:
      - \"uses\": actions/checkout@v7"

uses_case 'a double-quoted uses key' 'actions/checkout@v7' "${quoted_key}"

uses_case 'a single-quoted uses key in a flow mapping' 'actions/github-script@v9' \
	"jobs:
  sign:
    steps:
      - { 'uses': actions/github-script@v9 }"

uses_case 'a quoted mutable value' 'actions/checkout@v7' \
	'jobs:
  sign:
    steps:
      - uses: "actions/checkout@v7"'

uses_case 'a branch name that looks like a short SHA' 'actions/checkout@3d3c42e' \
	"jobs:
  sign:
    steps:
      - uses: actions/checkout@3d3c42e"

uses_case 'a job calling a reusable workflow through a tag' 'kjanat/other/.github/workflows/x.yml@v1' \
	'jobs:
  call:
    uses: kjanat/other/.github/workflows/x.yml@v1'

uses_case 'a quoted full-SHA pin' '' \
	"jobs:
  sign:
    steps:
      - \"uses\": \"actions/checkout@${pinned_sha}\" # v7.0.1"

uses_case 'a full-SHA pin in a flow mapping with inputs' '' \
	"jobs:
  sign:
    steps:
      - { uses: actions/checkout@${pinned_sha}, with: { fetch-depth: 0 } }"

uses_case 'local actions in this checkout' '' \
	'jobs:
  sign:
    steps:
      - uses: ./
      - uses: ./.github/actions/setup-bun'

uses_case 'only the named job' '' \
	"jobs:
  sign:
    steps:
      - uses: actions/checkout@${pinned_sha}
  other:
    steps:
      - uses: actions/checkout@v7" --job sign

# A guard that looked at nothing is green for the wrong reason.
status=0
got="$(workflow_mutable_uses "${workflow}" --job missing 2>/dev/null)" || status=$?
if ((status == 0)); then
	printf 'FAIL: the pin guard reported %q for a job that is not in the file\n' "${got}" >&2
	exit 1
fi

fixture 'jobs:
  sign:
    steps:
      - run: git push'
status=0
got="$(workflow_mutable_uses "${workflow}" --expect-uses 2>/dev/null)" || status=$?
if ((status == 0)); then
	printf 'FAIL: --expect-uses reported %q for a job with no actions in it\n' "${got}" >&2
	exit 1
fi

# The quoted-key fixture has to defeat the pattern it replaced, or it proves
# nothing either.
if grep -Eq '^[[:space:]]*(-[[:space:]]+)?uses:' <<<"${quoted_key}"; then
	printf 'FAIL: the quoted-uses fixture is still matched by an anchored uses: pattern\n' >&2
	exit 1
fi

# --- a job's own keys ----------------------------------------------------------

fixture "jobs:
  provenance:
    if: github.event_name == 'push' && github.event.deleted == false
    steps:
      - uses: actions/checkout@${pinned_sha}"
condition="$(workflow_job_field "${workflow}" provenance if)"
if [[ "${condition}" != "github.event_name == 'push' && github.event.deleted == false" ]]; then
	printf 'FAIL: job-field read the condition as %q\n' "${condition}" >&2
	exit 1
fi

# A folded condition is one expression to GitHub, so it has to be one string
# here. This is the shape a line-oriented `grep` of the `if:` line reads as
# half a condition.
fixture "jobs:
  provenance:
    if: >-
      github.event_name == 'push' &&
      github.event.deleted == false
    steps:
      - uses: actions/checkout@${pinned_sha}"
condition="$(workflow_job_field "${workflow}" provenance if)"
if [[ "${condition}" != "github.event_name == 'push' && github.event.deleted == false" ]]; then
	printf 'FAIL: job-field read a folded condition as %q\n' "${condition}" >&2
	exit 1
fi

status=0
got="$(workflow_job_field "${workflow}" provenance runs-on 2>/dev/null)" || status=$?
if ((status == 0)); then
	printf 'FAIL: job-field answered %q for a key the job does not have\n' "${got}" >&2
	exit 1
fi

printf 'workflow step parser: all cases passed\n'
