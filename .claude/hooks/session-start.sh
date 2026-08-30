#!/bin/bash
# SessionStart hook: make `task t`, `task lint`, and `task format` work in a
# fresh Claude Code cloud session.
#
# Cloud sessions ship Ubuntu 24.04 with bun, go, dprint and node preinstalled,
# but three things this repo depends on are missing or wrong out of the box:
#
#   1. `task` (Taskfile) is not installed at all, and CLAUDE.md requires every
#      command to go through it. The root Taskfile also shells out to `mise`
#      for wrangler/biome/typecheck, so `task lint` and `task typecheck` need
#      mise on PATH too, not just task.
#   2. The preinstalled golangci-lint is built with an older Go than
#      client/go.mod targets, so it refuses to run:
#        "the Go language version (goX) used to build golangci-lint is lower
#         than the targeted Go version (Y)"
#      This breaks `task client:lint` AND `task format` / `dprint fmt`, because
#      dprint shells out to golangci-lint for .go files. A binary being on PATH
#      says nothing about this, so every check below loads the real config
#      instead of asking `command -v`.
#   3. This repo has a checked-in `.mise.toml`, and mise refuses to read an
#      untrusted config: "Config files in .../.mise.toml are not trusted".
#      That fires on a fresh clone before anything else here can work.
#
# The division of labour with the environment setup script (docs/cloud-sessions.md)
# is the point of the first section below. Provisioning runs as root, once, on a
# network where api.github.com is reachable; this hook runs as the session user,
# every session, on a network where it is not — the agent proxy answers GitHub
# API calls with 403, which is fatal to mise's `aqua:` and `cargo:` backends. So
# the two share one mise tree, and this hook installs only what provisioning
# genuinely failed to leave behind. It never retries a refused download: one
# attempt, one warning naming what is still missing, and the session continues.
set -euo pipefail

# Cloud-only. CLAUDE_CODE_REMOTE is "true" only inside a cloud session, so a
# laptop running the same repo is untouched.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
	exit 0
fi

REPO="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$REPO"

log() { echo "[session-start] $*"; }

# --- 0. one mise tree, shared with provisioning -----------------------------
# The setup script runs as root and this hook runs as the session user. Left to
# mise's own default that is two data directories — /root/.local/share/mise and
# ~/.local/share/mise — so every tool provisioning installed is invisible here
# and gets installed a second time, over the very GitHub API the session cannot
# reach. Pointing both at one directory is the fix, and MISE_DATA_DIR is how:
# docs/cloud-sessions.md sets it in the environment-variables box, which applies
# to the setup script and the session alike.
#
# The literal default matches the one in that document so a session started
# before the variable was added still lands in the provisioned tree rather than
# quietly rebuilding it under $HOME.
MISE_SHARED_DEFAULT="/opt/mise"

# Populated beats writable. A tree provisioning filled is the right one to use
# even when this user cannot write to it — reading and executing is all that
# `mise exec` and the shims need, and an unwritable shared tree is a reason to
# skip installing, not a reason to go build a second copy under $HOME.
pick_mise_data_dir() {
	local shared="${MISE_DATA_DIR:-$MISE_SHARED_DEFAULT}"

	if [ -d "$shared/installs" ] || [ -d "$shared/shims" ]; then
		printf '%s\n' "$shared"
		return 0
	fi

	if mkdir -p "$shared" 2>/dev/null && [ -w "$shared" ]; then
		printf '%s\n' "$shared"
		return 0
	fi

	# No shared tree and no permission to make one: this session was started
	# without the environment variable and without a provisioning pass. Falling
	# back keeps the session usable; it just pays for the installs itself.
	printf '%s\n' "$HOME/.local/share/mise"
}

export MISE_DATA_DIR
MISE_DATA_DIR="$(pick_mise_data_dir)"
MISE_SHIMS="$MISE_DATA_DIR/shims"
log "mise data dir: $MISE_DATA_DIR"

# Installed here rather than a system dir so nothing needs root, and so the
# paths survive into $CLAUDE_ENV_FILE below.
export GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$GOBIN:$MISE_SHIMS:$HOME/.local/bin:$HOME/.bun/bin:$PATH"

# --- 1. mise: the repo's tool manager ---------------------------------------
# `.mise.toml` pins task, golangci-lint, biome, shellcheck, wrangler and more,
# and the root Taskfile invokes several of them as `mise exec -- <tool>`, so a
# session without mise cannot run `task lint` or `task typecheck` at all.
#
# The installer downloads a release *asset*, which the proxy allows — it is the
# releases API that returns 403 — so this one still works in a session.
if ! command -v mise >/dev/null 2>&1; then
	log "installing mise"
	curl -fsSL https://mise.run | MISE_QUIET=1 sh >/dev/null 2>&1 \
		|| log "WARN: mise install failed; falling back to per-tool installs"
fi

if command -v mise >/dev/null 2>&1; then
	log "mise present: $(mise --version 2>&1 | head -1)"

	# --- 2. trust this repo's config, and only this repo's ------------------
	# mise refuses to read an untrusted config file, so on a fresh clone every
	# command below fails before it starts. `mise trust` takes the one path
	# rather than `--all`, which would trust whatever else is on disk.
	#
	# Trust is recorded per user under the state directory, so provisioning's
	# root-side trust does not carry over even with the data directory shared —
	# this has to run here regardless.
	if mise trust "$REPO/.mise.toml" >/dev/null 2>&1; then
		log "trusted $REPO/.mise.toml"
	else
		log "WARN: could not trust $REPO/.mise.toml"
	fi
	# Belt and braces for anything that reads the environment instead of the
	# trust store — scoped to this repository, never a broader path.
	export MISE_TRUSTED_CONFIG_PATHS="$REPO"

	# --- 3. install only what provisioning did not leave behind -------------
	# Every tool here is fetched through a GitHub-API-backed backend (`aqua:`,
	# `cargo:` via cargo-binstall), and the session proxy answers that API with
	# 403. So the common case has to be *no install at all*: provisioning
	# already put these in the shared tree, and asking mise to reinstall them
	# burns a minute to arrive at the same 403 every time.
	# Bin names, not tool names, because that is what `mise which` resolves.
	# Keep this in step with .mise.toml: a tool missing from the list is a tool
	# the hook will report as present. `tombi` is here because .dprint.jsonc
	# shells out to it for TOML, so `task format` fails without it exactly the
	# way it does without golangci-lint.
	missing=()
	for tool in task run shellcheck biome wrangler golangci-lint tombi; do
		mise which "$tool" >/dev/null 2>&1 || missing+=("$tool")
	done

	if [ ${#missing[@]} -eq 0 ]; then
		log "mise tools present, skipping install"
	elif ! mkdir -p "$MISE_DATA_DIR" 2>/dev/null || [ ! -w "$MISE_DATA_DIR" ]; then
		# Shared, provisioned, and read-only to this user. Installing is not an
		# option and neither is silence. The mkdir comes first because the $HOME
		# fallback names a directory that does not exist yet, and `-w` on a path
		# that is absent is false — which would report the one tree this session
		# is free to fill as unwritable and install nothing at all.
		log "WARN: missing mise tools (${missing[*]}) and $MISE_DATA_DIR is not writable"
	else
		# One attempt. A 403 from the GitHub API is a property of the session's
		# network, not a transient error, so retrying it only spends the
		# session's first minutes arriving at the same answer.
		log "installing missing mise tools: ${missing[*]}"
		if ! mise install >/dev/null 2>&1; then
			log "WARN: mise install failed (the session proxy answers api.github.com"
			log "      with 403, which the aqua: and cargo: backends need). Install"
			log "      these in the environment setup script instead — see"
			log "      docs/cloud-sessions.md."
		fi
		mise reshim >/dev/null 2>&1 || true

		still_missing=()
		for tool in "${missing[@]}"; do
			mise which "$tool" >/dev/null 2>&1 || still_missing+=("$tool")
		done
		if [ ${#still_missing[@]} -gt 0 ]; then
			log "WARN: still missing after install: ${still_missing[*]}"
		fi
	fi
fi

# --- 4. Taskfile ------------------------------------------------------------
# Normally provided by mise above. The upstream install.sh pulls from the GitHub
# releases API, which the session's proxy answers with 403, so the fallback is
# the npm package.
if command -v task >/dev/null 2>&1; then
	log "task present: $(task --version)"
else
	log "installing task via bun"
	bun add -g @go-task/cli >/dev/null 2>&1 || log "WARN: task install failed"
fi

# --- 5. golangci-lint matching the module's Go version ----------------------
# `go env GOVERSION` inside client/ resolves the toolchain go.mod actually asks
# for, so this keeps working when client/go.mod bumps its go directive.
#
# GOTOOLCHAIN=auto is not redundant: docs/cloud-sessions.md has you pin
# GOTOOLCHAIN to an exact version in the environment, and a pin wins over
# go.mod. Probing without the override then reports the *pinned* version and
# exits 0, so a stale pin would have this rebuild golangci-lint with the very
# toolchain that causes the mismatch — while logging success.
GO_TOOLCHAIN="$(cd client && GOTOOLCHAIN=auto go env GOVERSION 2>/dev/null || echo "")"

lint_ok() {
	# The version mismatch only surfaces on config load, so probe for real
	# rather than parsing version strings. `command -v` alone is the bug this
	# replaced: the base image always has a binary, and it is the incompatible
	# one.
	command -v golangci-lint >/dev/null 2>&1 \
		&& (cd client && golangci-lint config path --config=.golangci.yml >/dev/null 2>&1)
}

if lint_ok; then
	# The mise-provided binary lands here; the rebuild below is only for sessions
	# where mise could not be installed.
	log "golangci-lint OK: $(golangci-lint --version 2>&1 | head -1)"
elif [ -n "$GO_TOOLCHAIN" ]; then
	# Building with GOTOOLCHAIN pinned is the fix: a plain `go install` builds
	# golangci-lint with the Go version *its own* go.mod requests (older), which
	# reproduces the exact error we are trying to avoid.
	log "rebuilding golangci-lint with $GO_TOOLCHAIN (takes ~1-2 min, cached afterwards)"
	GOTOOLCHAIN="$GO_TOOLCHAIN" go install \
		github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 >/dev/null 2>&1 \
		|| log "WARN: golangci-lint install failed; 'task format' and 'task c:l' may fail on Go files"
else
	log "WARN: could not resolve Go toolchain from client/go.mod"
fi

# --- 6. Project dependencies ------------------------------------------------
# install (not `ci`/`--frozen-lockfile`) so the environment cache can be reused
# across small lockfile changes.
if [ -d node_modules ]; then
	log "node_modules present, skipping bun install"
else
	log "bun install"
	bun install >/dev/null 2>&1 || log "WARN: bun install failed"
fi

log "go mod download"
(cd client && go mod download >/dev/null 2>&1) || log "WARN: go mod download failed"

# --- 7. Persist the environment for the rest of the session -----------------
# Bash tool invocations don't inherit this script's environment, so anything set
# above has to be written here to survive. Three things have to match what this
# script just used, or the session lands back in a second mise tree:
#
#   MISE_DATA_DIR              the shared tree, so `mise exec --` in the
#                              Taskfile resolves the provisioned tools
#   $MISE_DATA_DIR/shims       the same tools on PATH directly
#   MISE_TRUSTED_CONFIG_PATHS  this repo's config, so mise reads .mise.toml
#                              without a trust prompt
#
# They are written as literal values rather than as $HOME-relative expressions
# on purpose: the whole point of MISE_DATA_DIR is that it is not under $HOME.
#
# The matcher is startup|resume, so this runs more than once against the same
# file if it survives a resume. Appending twice is not fatal, but each pass
# prepends another copy of the same directories to PATH, so skip when the marker
# line is already there.
if [ -z "${CLAUDE_ENV_FILE:-}" ]; then
	:
elif grep -q '^# gpg-signing-service session-start$' "$CLAUDE_ENV_FILE" 2>/dev/null; then
	log "CLAUDE_ENV_FILE already carries the environment"
else
	{
		echo "# gpg-signing-service session-start"
		echo "export GOBIN=\"$GOBIN\""
		echo "export MISE_DATA_DIR=\"$MISE_DATA_DIR\""
		echo "export MISE_TRUSTED_CONFIG_PATHS=\"$REPO\""
		echo "export PATH=\"$GOBIN:$MISE_SHIMS:\$HOME/.local/bin:\$HOME/.bun/bin:\$PATH\""
	} >>"$CLAUDE_ENV_FILE"
	log "wrote environment to CLAUDE_ENV_FILE"
fi

log "ready"
exit 0
