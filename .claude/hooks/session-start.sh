#!/bin/bash
# SessionStart hook: make `task t`, `task lint`, and `task format` work in a
# fresh Claude Code cloud session.
#
# Cloud sessions ship Ubuntu 24.04 with bun, go, dprint and node preinstalled,
# but two things this repo depends on are missing or wrong out of the box:
#
#   1. `task` (Taskfile) is not installed at all, and CLAUDE.md requires every
#      command to go through it.
#   2. The preinstalled golangci-lint is built with an older Go than
#      client/go.mod targets, so it refuses to run:
#        "the Go language version (goX) used to build golangci-lint is lower
#         than the targeted Go version (Y)"
#      This breaks `task client:lint` AND `task format` / `dprint fmt`, because
#      dprint shells out to golangci-lint for .go files.
#
# Everything here is idempotent and skipped when the tool is already good, so
# the common case (setup script already provisioned the VM, see
# docs/cloud-sessions.md) costs a few seconds. Local sessions exit immediately.
set -euo pipefail

# Cloud-only. CLAUDE_CODE_REMOTE is "true" only inside a cloud session, so a
# laptop running the same repo is untouched.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
	exit 0
fi

REPO="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$REPO"

# Installed here rather than a system dir so nothing needs root, and so the
# paths survive into $CLAUDE_ENV_FILE below.
export GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$GOBIN:$HOME/.bun/bin:$PATH"

log() { echo "[session-start] $*"; }

# --- 1. Taskfile ------------------------------------------------------------
# Not preinstalled. The upstream install.sh pulls from GitHub releases, which
# the session's proxy blocks for repos not attached to the session (403), so
# use the npm package instead.
if command -v task >/dev/null 2>&1; then
	log "task present: $(task --version)"
else
	log "installing task via bun"
	bun add -g @go-task/cli >/dev/null 2>&1 || log "WARN: task install failed"
fi

# --- 2. golangci-lint matching the module's Go version ----------------------
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
	# rather than parsing version strings.
	command -v golangci-lint >/dev/null 2>&1 \
		&& (cd client && golangci-lint config path --config=.golangci.yml >/dev/null 2>&1)
}

if lint_ok; then
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

# --- 3. Project dependencies ------------------------------------------------
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

# --- 4. Persist PATH for the rest of the session ----------------------------
# Bash tool invocations don't inherit this script's environment, so anything
# added to PATH above has to be written here to survive.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
	{
		echo "export GOBIN=\"$GOBIN\""
		echo "export PATH=\"$GOBIN:\$HOME/.bun/bin:\$PATH\""
	} >>"$CLAUDE_ENV_FILE"
	log "wrote PATH to CLAUDE_ENV_FILE"
fi

log "ready"
exit 0
