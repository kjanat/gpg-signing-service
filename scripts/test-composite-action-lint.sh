#!/usr/bin/env bash
# Covers the invariant that shell embedded in a composite action cannot regress
# without a lint failure.
#
# #124 repaired two bugs in .github/actions/check-api-changes/action.yml that
# every existing gate was structurally blind to:
#
#   * `CHANGED="$(git diff --exit-code)"; EXIT_CODE=$?` -- the runner executes
#     composite `shell: bash` as `bash --noprofile --norc -e -o pipefail {0}`, an
#     assignment from a command substitution carries that command's status, so
#     the step aborted at the assignment and the `EXIT_CODE=$?` reporting path
#     was never reached. The job failed correctly and said nothing.
#   * `::notice:` instead of `::notice::` -- not a workflow command at all, so
#     the success annotation was printed as literal text and never appeared.
#
# `task lint:actions` feeds actionlint only .github/workflows/**, and actionlint
# has no composite-action schema, so pointing it at an action.yml stops it at
# `"jobs" section is missing in workflow` before its ShellCheck integration ever
# runs. `task lint:shell` globs *.sh. Neither could see a byte of this.
#
# ShellCheck on its own would not have closed the hole either: on the historical
# assignment shape, even at `-o all --enable=all`, it reports SC2250 about brace
# style and nothing about the dead `$?`. That is why the gate is
# scripts/lint-composite-actions.ts -- ShellCheck plus rules for the runner's own
# semantics -- and why the mutation cases below matter more than the clean run.
#
# Every mutation is applied to a copy of the real action file, so these assert
# against the shipping shell rather than against a fixture that resembles it.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

failures=0
case_name=""
workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

new_case() {
	case_name="$1"
	printf '  case: %s\n' "${case_name}"
}

fail() {
	printf '    FAIL (%s): %s\n' "${case_name}" "$1" >&2
	failures=$((failures + 1))
}

linter="${repo_root}/scripts/lint-composite-actions.ts"
api_action=".github/actions/check-api-changes/action.yml"
taskfile="${repo_root}/Taskfile.yml"

for required in "${linter}" "${repo_root}/${api_action}" "${taskfile}"; do
	if [[ ! -f ${required} ]]; then
		printf 'missing %s\n' "${required}" >&2
		exit 1
	fi
done

# `mise exec` so the checker reaches the same pinned shellcheck `lint:shell`
# uses, rather than whatever older copy happens to sit in /usr/bin.
run_linter() { # run_linter <root> [args...] -> stdout+stderr on fd 1, status returned
	local root="$1"
	shift
	COMPOSITE_ACTION_LINT_ROOT="${root}" GITHUB_ACTIONS='' \
		mise exec -- bun "${linter}" "$@" 2>&1
}

# Builds a tree holding one mutated copy of a real action file, and publishes its
# root in ${mutated_root}. A global rather than stdout because the "the sed no
# longer matches" branch has to be able to raise a failure, and a fail() inside a
# $(...) increments a counter in a subshell that then exits -- which would let a
# mutation case that stopped mutating anything pass silently. That is precisely
# the class of hole this suite exists to close, so it must not have one.
mutated_root=""
mutate_action() { # mutate_action <name> <source-rel> <sed-expr>
	local name="$1" source_rel="$2" expr="$3"
	local root="${workdir}/${name}"
	mutated_root=""
	mkdir -p "${root}/$(dirname "${source_rel}")"
	sed -e "${expr}" "${repo_root}/${source_rel}" >"${root}/${source_rel}"
	if diff -q "${repo_root}/${source_rel}" "${root}/${source_rel}" >/dev/null; then
		fail "mutation '${name}' changed nothing -- the sed expression no longer matches ${source_rel}"
		return 1
	fi
	mutated_root="${root}"
}

# Writes a synthetic composite action and echoes the tree root.
fixture_action() { # fixture_action <name> <<<body
	local name="$1"
	local root="${workdir}/${name}"
	mkdir -p "${root}/.github/actions/${name}"
	cat >"${root}/.github/actions/${name}/action.yml"
	printf '%s\n' "${root}"
}

printf 'composite-action lint gate\n'

# ---------------------------------------------------------------------------
# The tree as it stands must pass, or every mutation case below proves nothing.
# ---------------------------------------------------------------------------
new_case "the repository's own composite actions pass the gate"
if ! output="$(run_linter "${repo_root}")"; then
	fail "gate rejects the current tree:"$'\n'"${output}"
fi

# ---------------------------------------------------------------------------
# Coverage: every run block in every composite action is actually visited.
#
# Computed against an independent grep for `run:` rather than trusting the
# checker's own idea of scope, so an action file dropping out of discovery --
# a new directory, a renamed key, a parser that stops understanding a file --
# fails here instead of silently shrinking the gate.
# ---------------------------------------------------------------------------
new_case "every composite action holding a run block is in scope"
listed="$(run_linter "${repo_root}" --list)"
mapfile -t action_files < <(
	{
		[[ -f ${repo_root}/action.yml ]] && printf 'action.yml\n'
		find .github/actions -name 'action.yml' -o -name 'action.yaml' | sed 's|^\./||'
	} | sort
)
if ((${#action_files[@]} == 0)); then
	fail "found no composite action files to check -- the test itself has gone blind"
fi
for action_file in "${action_files[@]}"; do
	grep -qE '(^|[[:space:],{])run:' "${repo_root}/${action_file}" || continue
	if ! grep -qF "${action_file}:" <<<"${listed}"; then
		fail "${action_file} holds a run: block but the gate does not list it"
	fi
done

# setup-bun writes its steps as a flow sequence of single-line flow mappings, so
# it is the file that proves the extractor is a YAML parse and not a line regex:
# nothing anchored to `^\s*run:` can see its `bun install`.
new_case "flow-style steps are extracted, not just block-style ones"
if ! grep -qF '.github/actions/setup-bun/action.yml:' <<<"${listed}"; then
	fail "setup-bun's flow-mapping run: block is not in scope -- the extractor is line-based"
fi

# ---------------------------------------------------------------------------
# Mutation 1: restore the historical assignment shape on the real file.
# ---------------------------------------------------------------------------
new_case "the historical \`CHANGED=\"\$(... --exit-code)\"; EXIT_CODE=\$?\` shape is rejected"
if mutate_action errexit-status "${api_action}" 's/" || EXIT_CODE=\$?/"; EXIT_CODE=\$?/'; then
	if output="$(run_linter "${mutated_root}" "${api_action}")"; then
		fail "gate accepted the shape #124 had to repair:"$'\n'"${output}"
	elif ! grep -q 'CA001' <<<"${output}"; then
		fail "gate failed but not with CA001 (the errexit rule):"$'\n'"${output}"
	fi
fi

# The guarded form is the fix, and a rule that rejected it too would just get
# switched off. This is the false-positive half of the same invariant.
new_case "the guarded \`|| EXIT_CODE=\$?\` form is accepted"
if output="$(run_linter "${repo_root}" "${api_action}")"; then
	:
else
	fail "gate rejects the repaired form:"$'\n'"${output}"
fi

# A grep-shaped implementation would trip over the comment in that same step
# that quotes the historical shape verbatim while explaining it.
new_case "the historical shape quoted inside a comment does not trigger CA001"
root="$(
	fixture_action commented <<'YAML'
name: Commented
description: the broken shape appears only inside a comment
runs:
  using: composite
  steps:
    - name: Explain
      shell: bash
      run: |
        # CHANGED="$(git diff --exit-code)"; EXIT_CODE=$? aborted the step here.
        EXIT_CODE=0
        CHANGED="$(git diff --exit-code)" || EXIT_CODE=$?
        printf '%s %s\n' "${CHANGED}" "${EXIT_CODE}"
YAML
)"
if ! output="$(run_linter "${root}")"; then
	fail "a comment quoting the broken shape was flagged as the shape itself:"$'\n'"${output}"
fi

# CA001's false-positive surface is the part that decides whether this gate
# survives contact: there is no `# composite-lint disable`, so every one of
# these is an unsuppressible red `task lint`.
new_case "errexit-legitimate \`\$?\` reads are not flagged"
root="$(
	fixture_action errexit-ok <<'YAML'
name: Errexit OK
description: shapes where a $? read is live under errexit
runs:
  using: composite
  steps:
    - name: Trap
      shell: bash
      run: |
        echo start
        # Deliberately no variable: ShellCheck's own SC2154 does not track an
        # assignment inside a single-quoted trap body, and this case is about
        # CA001, not about that.
        trap 'echo "step died with $?"' ERR
        git diff
    - name: Function body
      shell: bash
      run: |
        report() {
          echo "rc=$?"
        }
        git diff || report
    - name: Guarded compound
      shell: bash
      run: |
        if ! out="$(git diff)"; then
          rc=$?
          echo "${rc} ${out}"
        fi
YAML
)"
if ! output="$(run_linter "${root}")"; then
	fail "CA001 fired on a live \$? read (trap body, function body, or guarded compound):"$'\n'"${output}"
fi

# The repo's own root action.yml is 77 lines of `shell: pwsh`, where `$?` is
# PowerShell's boolean success variable and reading it is the idiom. CA001
# describes `bash -e` and must not be aimed at a shell it does not model.
new_case "CA001 is scoped to the shells it models, but CA002 is not"
root="$(
	fixture_action pwsh-status <<'YAML'
name: Pwsh status
description: PowerShell $? plus a malformed command from a non-shell step
runs:
  using: composite
  steps:
    - name: Pwsh
      shell: pwsh
      run: |
        git diff
        if (-not $?) { Write-Host "::error::git diff failed" }
YAML
)"
if ! output="$(run_linter "${root}")"; then
	fail "CA001 was applied to a pwsh block, where \$? is a boolean, not a status:"$'\n'"${output}"
fi
root="$(
	fixture_action python-command <<'YAML'
name: Python command
description: a malformed workflow command is lost whatever printed it
runs:
  using: composite
  steps:
    - name: Py
      shell: python
      run: |
        print("::notice:lost")
YAML
)"
if output="$(run_linter "${root}")"; then
	fail "CA002 stopped covering non-shell steps:"$'\n'"${output}"
elif ! grep -q 'CA002' <<<"${output}"; then
	fail "python step failed but not with CA002:"$'\n'"${output}"
fi

# A `set -e` in the ShellCheck prelude is a command, and ShellCheck only honours
# a file-level directive when nothing executable precedes it -- so a prelude that
# executes anything silently voids every `# shellcheck disable=` written at the
# top of a run block, with no error to say so.
new_case "a file-level shellcheck directive in a run block is honoured"
root="$(
	fixture_action directive <<'YAML'
name: Directive
description: block-scoped shellcheck disable must reach the whole block
runs:
  using: composite
  steps:
    - name: Disabled
      shell: bash
      run: |
        # shellcheck disable=SC2086
        files=$(ls)
        printf '%s\n' $files
        printf '%s\n' $files
YAML
)"
if ! output="$(run_linter "${root}")"; then
	fail "a file-level \`# shellcheck disable\` at the top of a run block was ignored:"$'\n'"${output}"
fi

# ---------------------------------------------------------------------------
# Mutation 2: restore the malformed workflow command on the real file.
# ---------------------------------------------------------------------------
new_case "the malformed \`::notice:\` command is rejected"
if mutate_action notice-typo "${api_action}" 's/::notice::/::notice:/'; then
	if output="$(run_linter "${mutated_root}" "${api_action}")"; then
		fail "gate accepted the ::notice: typo #124 had to repair:"$'\n'"${output}"
	elif ! grep -q 'CA002' <<<"${output}"; then
		fail "gate failed but not with CA002 (the workflow-command rule):"$'\n'"${output}"
	fi
fi

# The typo class is wider than the one instance that shipped: a prefix can be
# truncated, unterminated, or simply misspelled, and all three are silent.
new_case "other malformed command prefixes are rejected too"
while read -r command description; do
	[[ -z ${command} ]] && continue
	root="$(
		fixture_action "cmd-${description}" <<YAML
name: Command ${description}
description: malformed workflow command -- ${description}
runs:
  using: composite
  steps:
    - name: Emit
      shell: bash
      run: |
        echo "${command}"
YAML
	)"
	if output="$(run_linter "${root}")"; then
		fail "gate accepted ${description}: ${command}"$'\n'"${output}"
	elif ! grep -q 'CA002' <<<"${output}"; then
		fail "${description} failed but not with CA002:"$'\n'"${output}"
	fi
done <<'CASES'
::error:missing second colon
::warning single-colon-props
::group unterminated-properties
::endgroup unterminated-endgroup
::notic::misspelled-name
CASES

new_case "well-formed workflow commands are accepted"
root="$(
	fixture_action cmd-valid <<'YAML'
name: Valid commands
description: every accepted workflow-command form, plus a PowerShell type literal
runs:
  using: composite
  steps:
    - name: Emit
      shell: bash
      run: |
        echo "::error::plain message"
        echo "::notice title=Up to date::with properties"
        printf '::add-mask::%s\n' "${SECRET-}"
        echo "::group::open"
        echo "::endgroup::"
    - name: Emit from PowerShell
      shell: pwsh
      run: |
        $temp = [System.IO.Path]::GetTempPath()
        Write-Host "::notice::$temp"
YAML
)"
if ! output="$(run_linter "${root}")"; then
	fail "gate rejects well-formed commands or a PowerShell type literal:"$'\n'"${output}"
fi

# ---------------------------------------------------------------------------
# ShellCheck has to actually reach the extracted block. Without this, a broken
# pipe into the tool would leave the gate green on anything it alone can catch.
# ---------------------------------------------------------------------------
new_case "ShellCheck findings surface from inside a run block"
root="$(
	fixture_action shellcheck <<'YAML'
name: Shellcheck reachability
description: an unquoted expansion ShellCheck alone is expected to catch
runs:
  using: composite
  steps:
    - name: Unquoted
      shell: bash
      run: |
        files=$(ls)
        printf '%s\n' $files
YAML
)"
if output="$(run_linter "${root}")"; then
	fail "gate accepted an unquoted expansion -- ShellCheck is not reaching the block:"$'\n'"${output}"
elif ! grep -q 'SC2086' <<<"${output}"; then
	fail "gate failed but not with SC2086:"$'\n'"${output}"
fi

new_case "ShellCheck findings point at the action.yml's own line"
if ! grep -qE 'action\.yml:10:[0-9]+: \[SC2086\]' <<<"${output}"; then
	fail "SC2086 was not reported at line 10 of the action file:"$'\n'"${output}"
fi

# ---------------------------------------------------------------------------
# A composite `run:` step without `shell:` is rejected by the runner at load
# time, which is a red job for a reason no log explains well.
# ---------------------------------------------------------------------------
new_case "a run step with no shell: is rejected"
root="$(
	fixture_action noshell <<'YAML'
name: No shell
description: composite run step missing its required shell
runs:
  using: composite
  steps:
    - name: Missing
      run: echo hello
YAML
)"
if output="$(run_linter "${root}")"; then
	fail "gate accepted a run: step with no shell::"$'\n'"${output}"
elif ! grep -q 'CA003' <<<"${output}"; then
	fail "gate failed but not with CA003:"$'\n'"${output}"
fi

# ---------------------------------------------------------------------------
# Wiring. A gate nobody runs is the state this whole change exists to leave.
# ---------------------------------------------------------------------------
new_case "the gate is reachable from task lint"
lint_plan="$(mise exec -- task --list-all 2>/dev/null || true)"
if ! grep -q 'lint:actions:composite' <<<"${lint_plan}"; then
	fail "lint:actions:composite is not a task"
fi
if ! grep -qF 'task: lint:actions:composite' "${taskfile}"; then
	fail "no task calls lint:actions:composite, so \`task lint\` does not reach it"
fi

# The point is a gate that is added to, not swapped in: #124's workflow and
# standalone-shell coverage has to survive this change.
new_case "actionlint and standalone-shell linting are not weakened"
if ! grep -qF 'xargs -r mise exec -- actionlint' "${taskfile}"; then
	fail "lint:actions no longer runs actionlint over the workflows"
fi
if ! grep -qF 'shellcheck -x .github/scripts/*.sh scripts/*.sh' "${taskfile}"; then
	fail "lint:shell no longer shellchecks the standalone scripts"
fi

new_case "this suite runs as part of task test"
if ! grep -qF 'task: test:composite-actions' "${taskfile}"; then
	fail "test:composite-actions is not in the test aggregates"
fi

# ---------------------------------------------------------------------------
# The gap itself, asserted rather than remembered: if actionlint ever grows a
# composite-action schema this fails, and the note above stops being true.
# ---------------------------------------------------------------------------
new_case "actionlint still cannot read a composite action (the gap this closes)"
if actionlint_out="$(mise exec -- actionlint "${repo_root}/${api_action}" 2>&1)"; then
	fail "actionlint now accepts composite actions -- re-evaluate whether this gate is still the right tool"
elif ! grep -qF '"jobs" section is missing' <<<"${actionlint_out}"; then
	fail "actionlint failed for a new reason; the recorded gap needs revisiting:"$'\n'"${actionlint_out}"
fi

if ((failures > 0)); then
	printf '\n%d case(s) failed\n' "${failures}" >&2
	exit 1
fi

printf '\nall cases passed\n'
