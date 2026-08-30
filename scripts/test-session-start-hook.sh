#!/usr/bin/env bash
# Covers .claude/hooks/session-start.sh, which is the only thing standing
# between a cloud session and a toolchain it cannot use.
#
# Three of its properties are invisible from a passing session and only show up
# as a wasted or broken one, so they are asserted here rather than trusted:
#
#   * it uses the mise tree provisioning filled, not a second one under $HOME
#   * it trusts this repository's .mise.toml, and only this repository's
#   * it does not reinstall tools that are already there, and does not retry an
#     install the session's network has already refused
#
# Every external command the hook runs is stubbed. Nothing here touches the
# network, and the assertions are made against the argv each stub recorded.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
hook="${repo_root}/.claude/hooks/session-start.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

bin="${tmp_dir}/bin"
mkdir -p "${bin}"

# --- the stubs ---------------------------------------------------------------
#
# Each one appends its argv to a per-command log, so "was this called, and how"
# is a question the cases can answer. The mise stub is the interesting one: it
# reports a tool as installed when the case listed it in STUB_MISE_TOOLS, which
# is how "provisioning already did this" is expressed.

cat >"${bin}/mise" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${STUB_LOG_DIR}/mise"
case "${1-}" in
	--version) printf 'mise 2026.1.0\n' ;;
	trust) : ;;
	which)
		# Space-padded so `task` never matches `taskfile`.
		case " ${STUB_MISE_TOOLS-} " in
			*" ${2-} "*) printf '%s/installs/%s/bin/%s\n' "${MISE_DATA_DIR}" "${2}" "${2}" ;;
			*) exit 1 ;;
		esac
		;;
	install) exit "${STUB_MISE_INSTALL_RC:-0}" ;;
	reshim) : ;;
	*) : ;;
esac
EOF

# The toolchain this stub reports is deliberately *not* the one the repo pins
# today: the hook has to take whatever `go env GOVERSION` answers, so a fixture
# that matched client/go.mod would pass even if the hook hardcoded a version.
# GOTOOLCHAIN is logged alongside the arguments because that is where the hook
# passes it, and passing the derived one is the whole point of the rebuild.
cat >"${bin}/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'GOTOOLCHAIN=%s %s\n' "${GOTOOLCHAIN-unset}" "$*" >>"${STUB_LOG_DIR}/go"
case "${1-} ${2-}" in
	'env GOVERSION') printf '%s\n' "${STUB_GO_VERSION:-go1.99.0}" ;;
	*) : ;;
esac
EOF

cat >"${bin}/golangci-lint" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${STUB_LOG_DIR}/golangci-lint"
case "${1-}" in
	--version) printf 'golangci-lint has version 2.13.2\n' ;;
	config) exit "${STUB_GOLANGCI_RC:-0}" ;;
	*) : ;;
esac
EOF

for stub in curl bun task; do
	cat >"${bin}/${stub}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >>"\${STUB_LOG_DIR}/${stub}"
exit 0
EOF
done

chmod +x "${bin}"/*

# --- the fake repository -----------------------------------------------------
# Only the parts the hook reaches: the config it has to trust, and the Go module
# it probes for a toolchain.
fake_repo="${tmp_dir}/repo"
mkdir -p "${fake_repo}/client"
: >"${fake_repo}/.mise.toml"
: >"${fake_repo}/client/.golangci.yml"

# run_hook [VAR=value ...]
#
# A session-shaped environment with nothing real on PATH, then whatever the case
# overrides. HOME and MISE_DATA_DIR are per-case so one case cannot see another's
# tree.
run_hook() {
	local rc=0
	rm -rf "${tmp_dir}/log"
	mkdir -p "${tmp_dir}/log"
	env -i \
		PATH="${bin}:/usr/bin:/bin" \
		HOME="${case_home}" \
		STUB_LOG_DIR="${tmp_dir}/log" \
		CLAUDE_CODE_REMOTE=true \
		CLAUDE_PROJECT_DIR="${fake_repo}" \
		CLAUDE_ENV_FILE="${case_env_file}" \
		"$@" \
		bash "${hook}" >"${tmp_dir}/out" 2>&1 || rc=$?
	printf '%s' "${rc}"
}

# new_case <name> — a fresh HOME and env file, so nothing leaks between cases.
new_case() {
	case_name="$1"
	case_home="${tmp_dir}/home/${case_name}"
	case_env_file="${tmp_dir}/env/${case_name}"
	mkdir -p "${case_home}" "${tmp_dir}/env"
	: >"${case_env_file}"
}

fail() {
	echo "FAIL (${case_name}): $*" >&2
	echo '--- hook output' >&2
	cat "${tmp_dir}/out" >&2
	exit 1
}

stub_log() { cat "${tmp_dir}/log/$1" 2>/dev/null || true; }

expect_rc() {
	[[ "$2" == "$1" ]] || fail "expected exit $1, got $2"
}

expect_called() {
	grep -qF -- "$2" <<<"$(stub_log "$1")" || fail "expected \`$1 $2\` to run, log was: $(stub_log "$1")"
}

refute_called() {
	if grep -qF -- "$2" <<<"$(stub_log "$1")"; then
		fail "expected \`$1 $2\` NOT to run, log was: $(stub_log "$1")"
	fi
}

expect_env_file() {
	grep -qF -- "$1" "${case_env_file}" || fail "expected CLAUDE_ENV_FILE to contain: $1
--- env file
$(cat "${case_env_file}")"
}

refute_env_file() {
	if grep -qF -- "$1" "${case_env_file}"; then
		fail "expected CLAUDE_ENV_FILE NOT to contain: $1
--- env file
$(cat "${case_env_file}")"
	fi
}

# Every tool the hook probes for, so the default case is "provisioning worked".
readonly ALL_TOOLS='task run shellcheck biome wrangler golangci-lint tombi'

# --- a local session is untouched -------------------------------------------
#
# The hook installs things. Running it on a laptop would be a surprise, and the
# only guard is one environment variable, so pin it.
new_case local-session
rc=0
env -i PATH="${bin}:/usr/bin:/bin" HOME="${case_home}" \
	STUB_LOG_DIR="${tmp_dir}/log" CLAUDE_PROJECT_DIR="${fake_repo}" \
	CLAUDE_ENV_FILE="${case_env_file}" \
	bash "${hook}" >"${tmp_dir}/out" 2>&1 || rc=$?
expect_rc 0 "${rc}"
[[ ! -s "${case_env_file}" ]] || fail 'a local session wrote to CLAUDE_ENV_FILE'

# --- the provisioned tree is the one that gets used --------------------------
#
# This is the whole point of the change. A shared MISE_DATA_DIR that already has
# installs in it must be adopted as-is: no second tree under $HOME, and no
# install pass, because everything is already there.
new_case shared-tree
shared="${tmp_dir}/shared-mise"
mkdir -p "${shared}/installs" "${shared}/shims"
rc="$(run_hook MISE_DATA_DIR="${shared}" STUB_MISE_TOOLS="${ALL_TOOLS}")"
expect_rc 0 "${rc}"
refute_called mise install
expect_env_file "export MISE_DATA_DIR=\"${shared}\""
expect_env_file "${shared}/shims"
refute_env_file '.local/share/mise'
grep -q 'skipping install' "${tmp_dir}/out" || fail 'expected the hook to say it skipped the install'

# The trust call names one path — this repository's config — and never --all.
expect_called mise "trust ${fake_repo}/.mise.toml"
refute_called mise 'trust --all'
expect_env_file "export MISE_TRUSTED_CONFIG_PATHS=\"${fake_repo}\""

# Writing the environment twice must not prepend a second copy of everything.
before="$(wc -l <"${case_env_file}")"
rc="$(run_hook MISE_DATA_DIR="${shared}" STUB_MISE_TOOLS="${ALL_TOOLS}")"
expect_rc 0 "${rc}"
after="$(wc -l <"${case_env_file}")"
[[ "${before}" == "${after}" ]] || fail "resuming appended to CLAUDE_ENV_FILE (${before} -> ${after} lines)"

# --- an unset MISE_DATA_DIR still finds a provisioned tree -------------------
#
# The environment-variables box is set by hand, so a session started before it
# was added has to keep working. The hook's literal default and the one in
# docs/cloud-sessions.md are the same path, and this is what pins them together.
default_dir="$(sed -n 's/^MISE_SHARED_DEFAULT="\(.*\)"$/\1/p' "${hook}")"
[[ -n "${default_dir}" ]] || fail 'could not read the hook default for MISE_DATA_DIR'
grep -qxF "MISE_DATA_DIR=${default_dir}" "${repo_root}/docs/cloud-sessions.md" \
	|| fail "docs/cloud-sessions.md does not document MISE_DATA_DIR=${default_dir}"
grep -qF "\${MISE_DATA_DIR:-${default_dir}}" "${repo_root}/docs/cloud-sessions.md" \
	|| fail "the documented setup script does not default MISE_DATA_DIR to ${default_dir}"

# --- a provisioned tree this user cannot write to is still used --------------
#
# Read and execute is all `mise exec` and the shims need. Falling back to $HOME
# here would rebuild, over a network that cannot, what is already on disk.
new_case readonly-tree
ro_shared="${tmp_dir}/ro-mise"
mkdir -p "${ro_shared}/installs" "${ro_shared}/shims"
chmod a-w "${ro_shared}"
rc="$(run_hook MISE_DATA_DIR="${ro_shared}" STUB_MISE_TOOLS='task shellcheck')"
chmod u+w "${ro_shared}"
expect_rc 0 "${rc}"
expect_env_file "export MISE_DATA_DIR=\"${ro_shared}\""
# Missing tools and nowhere to put them: report, do not install, do not fall
# back to a private tree that the session would then have to fill itself.
refute_called mise install
grep -q 'not writable' "${tmp_dir}/out" || fail 'expected a warning naming the unwritable tree'

# --- one install attempt, never a retry loop ---------------------------------
#
# The session proxy answers api.github.com with 403, which the aqua: and cargo:
# backends both need. That is a property of the network, not a transient error,
# so a second attempt only costs the session its first minutes.
new_case failed-install
rw_shared="${tmp_dir}/rw-mise"
mkdir -p "${rw_shared}"
rc="$(run_hook MISE_DATA_DIR="${rw_shared}" STUB_MISE_TOOLS='task' STUB_MISE_INSTALL_RC=1)"
expect_rc 0 "${rc}"
installs="$(stub_log mise | grep -c '^install$' || true)"
[[ "${installs}" == 1 ]] || fail "expected exactly one \`mise install\`, got ${installs}"
grep -q 'still missing after install' "${tmp_dir}/out" || fail 'expected the hook to name what is still missing'

# --- no shared tree, and none can be made ------------------------------------
#
# Then and only then does the session pay for its own tree, under $HOME.
new_case home-fallback
rc="$(run_hook MISE_DATA_DIR=/proc/nonexistent/mise STUB_MISE_TOOLS="${ALL_TOOLS}")"
expect_rc 0 "${rc}"
expect_env_file "export MISE_DATA_DIR=\"${case_home}/.local/share/mise\""

# ...and it then has to actually fill it. The fallback directory does not exist
# yet, and `[ -w ]` on an absent path is false, so a writability test taken
# before the directory is created reports the one tree this session is free to
# write as read-only and installs nothing — leaving a session with no tools at
# all, which is the case the fallback exists for.
new_case home-fallback-installs
rc="$(run_hook MISE_DATA_DIR=/proc/nonexistent/mise STUB_MISE_TOOLS='')"
expect_rc 0 "${rc}"
expect_called mise install
if grep -q 'not writable' "${tmp_dir}/out"; then
	fail 'the HOME fallback tree was reported unwritable instead of being created'
fi

# --- .mise.toml and the probe list do not drift ------------------------------
#
# A tool the loop forgets is a tool the hook reports as present, and the session
# then discovers it is missing halfway through `task format`. Every bin the
# Taskfile or dprint reaches for has to be probed.
case_name=probe-list-drift
for tool in task shellcheck biome wrangler golangci-lint tombi; do
	grep -qF "${tool}" <<<"${ALL_TOOLS}" \
		|| fail "the hook does not probe for ${tool}, which .mise.toml provides"
	grep -q "for tool in .*\b${tool}\b" "${hook}" \
		|| fail "the hook's probe loop is missing ${tool}"
done

# --- golangci-lint is judged by whether it works, not by whether it exists ----
#
# The base image always has the binary and it is the incompatible one, so
# `command -v` is not a test. Both directions are asserted: a binary that loads
# client/.golangci.yml is left alone, and one that cannot is rebuilt.
new_case golangci-usable
rc="$(run_hook MISE_DATA_DIR="${tmp_dir}/gl-ok" STUB_MISE_TOOLS="${ALL_TOOLS}" STUB_GOLANGCI_RC=0)"
expect_rc 0 "${rc}"
expect_called golangci-lint 'config path --config=.golangci.yml'
refute_called go 'install github.com/golangci/golangci-lint'

new_case golangci-incompatible
rc="$(run_hook MISE_DATA_DIR="${tmp_dir}/gl-bad" STUB_MISE_TOOLS="${ALL_TOOLS}" STUB_GOLANGCI_RC=7)"
expect_rc 0 "${rc}"
expect_called golangci-lint 'config path --config=.golangci.yml'
expect_called go 'install github.com/golangci/golangci-lint'
# The rebuild is worthless unless it uses the toolchain client/go.mod asks for,
# so pin that it forwards the *probed* version rather than a version baked into
# the hook. The stub answers go1.99.0, which no go.mod in this repo names.
expect_called go 'GOTOOLCHAIN=go1.99.0 install github.com/golangci/golangci-lint'

# --- a stale GOTOOLCHAIN pin must not decide the rebuild ----------------------
#
# docs/cloud-sessions.md has you pin GOTOOLCHAIN in the environment, and a pin
# beats go.mod. Probing without GOTOOLCHAIN=auto would therefore report the
# pinned version and exit 0 — rebuilding golangci-lint with the very toolchain
# that causes the mismatch, while logging success. Both halves are asserted:
# the probe overrides the pin, and the rebuild follows the probe.
new_case golangci-stale-toolchain-pin
rc="$(run_hook MISE_DATA_DIR="${tmp_dir}/gl-pin" STUB_MISE_TOOLS="${ALL_TOOLS}" \
	STUB_GOLANGCI_RC=7 STUB_GO_VERSION=go1.98.0 GOTOOLCHAIN=go1.1.0)"
expect_rc 0 "${rc}"
expect_called go 'GOTOOLCHAIN=auto env GOVERSION'
expect_called go 'GOTOOLCHAIN=go1.98.0 install github.com/golangci/golangci-lint'
refute_called go 'GOTOOLCHAIN=go1.1.0 install github.com/golangci/golangci-lint'

printf 'session-start hook tests passed\n'
