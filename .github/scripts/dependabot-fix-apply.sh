#!/usr/bin/env bash
# Apply a patch to a Dependabot pull request branch and push it, in a job that
# holds a write token and never runs a line of the code it is pushing.
#
# This is the privileged half of .github/workflows/claude-dependabot-fix.yml.
# The unprivileged half checked out the pull request, let Claude run the test
# suite against it and produced a diff. That job had `contents: read` and no
# more, because it executed Dependabot's branch. This one has `contents: write`
# and, for exactly that reason, is not allowed to execute anything from it.
#
# THE BOUNDARY, STATED ONCE
#
#   The workspace this script runs in is the default-branch checkout and is
#   never switched to the pull request. The branch is fetched into a scratch
#   repository under RUNNER_TEMP by object id, the patch is applied there with
#   git and nothing else, and the commit is made there. No install, no build,
#   no test, no hook, no `.github/` file from the branch is ever read as code.
#   The commit-signing shim is addressed through GITHUB_WORKSPACE precisely so
#   that it keeps pointing at the default branch's copy.
#
# Everything below is a consequence of that sentence. The path allowlist is
# there because a diff is data until git writes it to disk, and the moment it
# lands on `.github/workflows/` or `Taskfile.yml` it becomes the next run's
# behaviour. Modifications-only is there because a new file, a mode change or a
# symlink are the three ways a patch turns into an executable.
#
#   usage:  dependabot-fix-apply.sh PATCH_FILE
#
#   env:    GITHUB_REPOSITORY  owner/repo
#           PR_NUMBER          validated by dependabot-fix-gate.sh
#           HEAD_REF           validated; the branch to push to
#           HEAD_SHA           validated; the only commit this may build on
#           GH_TOKEN           write token, read from the environment at push
#                              time by a credential helper and never placed in
#                              argv, in a file, or in the log
#           GITHUB_WORKSPACE   the default-branch checkout
#           RUNNER_TEMP        scratch space for the branch
#           SIGNING_ENABLED    "true" when setup-claude-signing configured this
#                              job to sign; anything else means the escape hatch
#                              was pulled and the commit is deliberately unsigned
#           GIT_REMOTE_URL     optional; defaults to the GitHub remote. A seam
#                              for the test suite, which pushes to a bare repo.
#           GITHUB_STEP_SUMMARY  optional
#
#   exit:   0  a commit was pushed
#           3  there was nothing to apply; not a failure
#           1  refused, or the push was rejected
set -Eeuo pipefail

# Bounded so a runaway diff cannot be committed unreviewed. bun.lock churn is
# the large end of what this legitimately sees, and it is far below either.
readonly MAX_PATCH_BYTES=$((2 * 1024 * 1024))
readonly MAX_FILES=50

# The mechanical-fix surface, and nothing else. `*` matches `/` in a bash
# pattern comparison, so `src/*.ts` covers the whole tree beneath it.
#
# What is deliberately absent is the point of the list: `.github/` in any form,
# `Taskfile.yml`, `scripts/`, `.mise.toml`, `.lefthook.yml`, `action.yml`,
# `bunfig.toml`, `.claude/`. Those decide what CI runs. A patch that could edit
# them would make this script a way to run arbitrary code in a privileged job,
# which is the thing the whole design is arranged to prevent — including for
# the github-actions ecosystem, whose bumps land in `.github/workflows/` and
# must stay a human's decision.
readonly ALLOWED_PATHS=(
	'bun.lock'
	'package.json'
	'go.work'
	'go.work.sum'
	'client/go.mod'
	'client/go.sum'
	'client/openapi.json'
	'src/*.ts'
	'client/*.go'
)

# Patch headers that mean the diff does something other than change the bytes of
# a file that already exists. Each is a way to end up with something executable,
# or with a path the allowlist never saw.
readonly FORBIDDEN_HEADERS='^(new file mode|deleted file mode|old mode|new mode|rename (from|to)|copy (from|to)|GIT binary patch|index [0-9a-f]+\.\.[0-9a-f]+ 1(20|007))'

readonly patch_file="${1-}"
readonly this_repo="${GITHUB_REPOSITORY-}"
readonly pr_number="${PR_NUMBER-}"
readonly head_ref="${HEAD_REF-}"
readonly head_sha="${HEAD_SHA-}"
readonly workspace="${GITHUB_WORKSPACE-}"
readonly runner_temp="${RUNNER_TEMP-}"
readonly signing_enabled="${SIGNING_ENABLED-}"

note() { printf '::notice title=Dependabot fix::%s\n' "$1"; }

summary() {
	[[ -n "${GITHUB_STEP_SUMMARY-}" ]] || return 0
	printf '%s\n' "$1" >>"${GITHUB_STEP_SUMMARY}" || true
}

# refuse REASON — a validation failure. Loud, because unlike the gate's
# declines these mean something produced a patch this path will not accept, and
# somebody should look at why.
refuse() {
	printf '::error title=Dependabot fix refused::%s\n' "$1"
	summary "### :no_entry: Dependabot fix refused

$1"
	exit 1
}

[[ -n "${patch_file}" ]] || refuse 'usage: dependabot-fix-apply.sh PATCH_FILE'
[[ -f "${patch_file}" ]] || refuse "Patch file not found: ${patch_file}"
[[ -n "${this_repo}" ]] || refuse 'GITHUB_REPOSITORY is not set'
[[ -n "${workspace}" && -d "${workspace}/.git" ]] || refuse 'GITHUB_WORKSPACE is not a checkout'
[[ -n "${runner_temp}" && -d "${runner_temp}" ]] || refuse 'RUNNER_TEMP is not set'

# Re-validated here rather than trusted from the job that produced them. These
# three values decide which branch gets written to; an upstream step that stops
# validating them must not silently become this script's problem.
[[ "${pr_number}" =~ ^[1-9][0-9]*$ ]] || refuse "PR_NUMBER is not a positive integer: '${pr_number}'"
[[ "${head_sha}" =~ ^[0-9a-f]{40}$ ]] || refuse "HEAD_SHA is not a full commit id: '${head_sha}'"
[[ "${head_ref}" == dependabot/* ]] || refuse "HEAD_REF is not a Dependabot branch: '${head_ref}'"
[[ "${head_ref}" =~ ^[A-Za-z0-9._/-]+$ ]] || refuse "HEAD_REF contains characters this path will not push: '${head_ref}'"
[[ "${head_ref}" != *'..'* ]] || refuse "HEAD_REF contains '..': '${head_ref}'"

readonly remote_url="${GIT_REMOTE_URL:-https://github.com/${this_repo}.git}"

# --- is there anything to do? ------------------------------------------------

patch_bytes="$(wc -c <"${patch_file}")"
if ((patch_bytes == 0)); then
	note "Nothing to apply for pull request #${pr_number}."
	exit 3
fi
((patch_bytes <= MAX_PATCH_BYTES)) \
	|| refuse "Patch is ${patch_bytes} bytes, over the ${MAX_PATCH_BYTES} limit."

# --- what the patch claims to do, before git is allowed to act on it ---------

if grep -nEm1 "${FORBIDDEN_HEADERS}" "${patch_file}" >/dev/null; then
	offending="$(grep -nEm1 "${FORBIDDEN_HEADERS}" "${patch_file}")"
	refuse "This path applies modifications to existing files only. The patch does more: ${offending}"
fi

# --- the branch, fetched by object id into scratch space ---------------------
#
# `git init` + `fetch <sha>` rather than a clone of the ref: the object id is
# what the gate validated, and fetching the ref by name would re-resolve it and
# could bring back a different commit than the one the patch was computed from.

work_dir="$(mktemp -d "${runner_temp}/dependabot-fix-${pr_number}.XXXXXX")"
cleanup() { rm -rf "${work_dir}"; }
trap cleanup EXIT

git init -q -b main "${work_dir}"
git -C "${work_dir}" remote add origin "${remote_url}"

# The helper is a shell function written into git's config, so the token is read
# from this process's environment when git asks for it. It never appears in a
# command line (visible in /proc to anything else on the runner), never lands in
# a config file on disk that outlives the job, and never reaches a log.
git -C "${work_dir}" config --local credential.helper ''
# shellcheck disable=SC2016  # git expands ${GH_TOKEN}, not this shell — that is the point
git -C "${work_dir}" config --local --add credential.helper \
	'!f() { printf "username=x-access-token\npassword=%s\n" "${GH_TOKEN}"; }; f'

if ! git -C "${work_dir}" fetch -q --depth=1 origin "${head_sha}" 2>/dev/null; then
	refuse "Could not fetch ${head_sha:0:12} from ${this_repo}; the branch may have been force-pushed."
fi
git -C "${work_dir}" checkout -q --detach FETCH_HEAD

# Belt and braces against a server that answered the fetch with something else.
actual="$(git -C "${work_dir}" rev-parse HEAD)"
[[ "${actual}" == "${head_sha}" ]] \
	|| refuse "Fetched ${actual:0:12} but the gate authorized ${head_sha:0:12}."

# --- which paths the patch touches, per git rather than per grep -------------

if ! numstat="$(git -C "${work_dir}" apply --numstat -- "${patch_file}" 2>&1)"; then
	refuse "git could not read the patch: ${numstat}"
fi

mapfile -t paths < <(awk -F'\t' 'NF >= 3 { print $3 }' <<<"${numstat}")
((${#paths[@]} > 0)) || {
	note "The patch touches no files; nothing to do for pull request #${pr_number}."
	exit 3
}
((${#paths[@]} <= MAX_FILES)) \
	|| refuse "The patch touches ${#paths[@]} files, over the ${MAX_FILES} limit."

for path in "${paths[@]}"; do
	[[ "${path}" =~ ^[A-Za-z0-9._/-]+$ ]] \
		|| refuse "Refusing a path with unexpected characters: '${path}'"
	[[ "${path}" != /* && "${path}" != *'..'* ]] \
		|| refuse "Refusing a path that escapes the worktree: '${path}'"

	allowed=false
	for pattern in "${ALLOWED_PATHS[@]}"; do
		# shellcheck disable=SC2053  # the right-hand side is a pattern on purpose
		if [[ "${path}" == ${pattern} ]]; then
			allowed=true
			break
		fi
	done
	"${allowed}" \
		|| refuse "'${path}' is not on the mechanical-fix allowlist; this path will not write it."

	# Modifications only. The forbidden-header check above already rejects a
	# patch that announces a new file, so a path that is not in the tree means
	# the patch and the branch disagree about what is there.
	git -C "${work_dir}" cat-file -e "HEAD:${path}" 2>/dev/null \
		|| refuse "'${path}' does not exist at ${head_sha:0:12}; this path only modifies existing files."
done

# --- apply --------------------------------------------------------------------

if ! output="$(git -C "${work_dir}" apply --check --whitespace=nowarn -- "${patch_file}" 2>&1)"; then
	refuse "The patch does not apply cleanly to ${head_sha:0:12}: ${output}"
fi
git -C "${work_dir}" apply --whitespace=nowarn -- "${patch_file}"

# Staged by explicit path. `git add -A` would also pick up anything the patch
# did not account for, and the allowlist would then have been checked against
# the wrong set.
git -C "${work_dir}" add -- "${paths[@]}"

if git -C "${work_dir}" diff --cached --quiet; then
	note "The patch applied to no net change; nothing to push for pull request #${pr_number}."
	exit 3
fi

# --- sign, commit, push -------------------------------------------------------

git -C "${work_dir}" config --local user.name "${GIT_COMMITTER_NAME:-claude[bot]}"
git -C "${work_dir}" config --local user.email "${GIT_COMMITTER_EMAIL:-claude[bot]@users.noreply.github.com}"

# The shim is addressed inside GITHUB_WORKSPACE, which is the default-branch
# checkout and is never switched to the pull request. That is what keeps
# `gpg.program` from becoming a file the branch controls — git would otherwise
# execute it, with this job's write token in the environment.
if [[ "${signing_enabled}" == 'true' ]]; then
	shim="${workspace}/.github/scripts/gpg-sign-git-program.sh"
	[[ -x "${shim}" ]] || refuse "Commit signing is on but the shim is missing at ${shim}"
	git -C "${work_dir}" config --local gpg.program "${shim}"
	git -C "${work_dir}" config --local gpg.format openpgp
	git -C "${work_dir}" config --local commit.gpgsign true
else
	# Written rather than left to the default, for the same reason
	# setup-claude-signing writes it: an inherited `commit.gpgsign true` with no
	# gpg.program is git's own "failed to sign the data", not an unsigned commit.
	git -C "${work_dir}" config --local commit.gpgsign false
fi

# Fixed text. Nothing Dependabot controls — not the pull request title, not the
# body, not a commit message from the branch — is interpolated here.
git -C "${work_dir}" commit -q -m "fix(deps): repair $(printf '%s' "${head_ref#dependabot/}") build

Applied by the trusted Dependabot fix path for #${pr_number}. The change was
computed in an unprivileged job that ran the test suite against the branch;
this commit was made by a job that never executed the branch's code.

See docs/dependabot-fix-path.md for the trust boundary."

# Not a force push, ever. A plain push is rejected if the branch moved since the
# gate looked at it, and being rejected is the correct outcome there: Dependabot
# has rebased, the patch describes a tree that no longer exists, and the next CI
# failure will start this over against the new head.
if ! push_output="$(GH_TOKEN="${GH_TOKEN-}" git -C "${work_dir}" push origin "HEAD:refs/heads/${head_ref}" 2>&1)"; then
	# Printed to stderr rather than through refuse(): git can echo the remote
	# URL back in its errors, and although the token lives in a helper rather
	# than the URL, this keeps the whole class out of the annotation.
	printf '%s\n' "${push_output}" >&2
	refuse "Push to ${head_ref} was rejected. The branch has most likely moved since ${head_sha:0:12}."
fi

pushed="$(git -C "${work_dir}" rev-parse HEAD)"
note "Pushed ${pushed:0:12} to ${head_ref} for pull request #${pr_number}."

path_list=''
for path in "${paths[@]}"; do
	path_list+="- \`${path}\`"$'\n'
done

summary "### :white_check_mark: Dependabot fix pushed

Pull request #${pr_number} — \`${head_ref}\` is now at \`${pushed:0:12}\`.

${path_list}
Signed: \`${signing_enabled:-false}\`."
