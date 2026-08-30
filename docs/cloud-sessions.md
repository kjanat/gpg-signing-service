# Claude Code cloud sessions

How to configure a cloud environment so an agent session can actually run this
repo's `task` commands. Two layers do the work, and they are configured in
different places:

| Layer                                                      | Lives in                                                 | Runs                                            | Good for                               |
| ---------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------- | -------------------------------------- |
| **Setup script + env vars**                                | The environment dialog at [claude.ai/code], not the repo | Once per environment, then cached as a snapshot | Installing tools onto the VM           |
| **[SessionStart hook](../.claude/hooks/session-start.sh)** | This repo (`.claude/settings.json`)                      | Every session, cloud and local                  | Project deps, and repairing a stale VM |

Prefer the setup script for anything slow. Its result is cached as a filesystem
snapshot and reused by later sessions, so a tool installed there costs nothing
on subsequent starts. The hook re-runs every session, so it only does cheap
work — and repairs the toolchain if the environment was never configured.

## What a bare cloud session gets wrong

Cloud VMs ship Ubuntu 24.04 with `bun`, `go`, `node`, `dprint`, `jq`, and
`golangci-lint` preinstalled. Four things still break:

1. **`task` and `mise` are not installed.** `CLAUDE.md` requires every command
   to go through Taskfile, so without `task` the agent cannot run tests or
   linters at all. `mise` is needed too, and not only as a way to get `task`:
   the root `Taskfile.yml` invokes wrangler, biome and the typechecker as
   `mise exec -- <tool>`, so `task lint` and `task typecheck` fail outright
   without it.

   Installing mise is the whole fix, because `.mise.toml` lists `task` and a
   prebuilt `golangci-lint` alongside everything else — the same mechanism CI
   uses via `jdx/mise-action`. Note the upstream Taskfile
   `install.sh` pulls from GitHub releases via the API, which the session proxy
   answers with `403` for repos not attached to the session; the npm package is
   the fallback if mise itself cannot be fetched.

2. **`golangci-lint` is built with the wrong Go.** The preinstalled binary is
   compiled with an older Go than `client/go.mod` targets, so it refuses to
   load its config:

   ```text
   can't load config: the Go language version (go1.25) used to build
   golangci-lint is lower than the targeted Go version (1.26)
   ```

   This breaks more than Go linting: `task format` and `dprint fmt` shell out
   to `golangci-lint` for `.go` files, so _formatting the whole repo fails_,
   including on files that have nothing to do with Go.

   **A binary being on `PATH` therefore proves nothing here** — the base image
   always has one, and it is the broken one. `command -v golangci-lint` was the
   original guard and it never fired, so the fallback below never ran. Both the
   setup script and the hook now ask the binary to load this repo's config
   instead:

   ```bash
   (cd client && golangci-lint config path --config=.golangci.yml)
   ```

   That is the cheapest call that reaches the version check — it parses the
   config and exits, linting nothing — and it is the same call whose failure
   `task format` would hit later.

   `.mise.toml` asks mise for a prebuilt `golangci-lint`, which today resolves
   to a binary compiled with a current Go, so once mise is installed and its
   shims are on `PATH` this resolves itself. Nothing _holds_ that, though — the
   entry is `latest` and there is no `mise.lock` — so pin an exact version there
   if the mismatch ever comes back.

   The rest of this item applies only to the fallback path, where mise cannot
   supply a usable binary and it has to be built locally.

   There, reinstalling is not enough on its own. A plain `go install` builds
   golangci-lint with the Go version _its own_ `go.mod` asks for — currently
   older than ours — reproducing the same error. The build has to be pinned to
   the toolchain this repo targets.

3. **mise will not read this repo's `.mise.toml` until it is trusted.** The
   config is checked in, so on a fresh clone the first mise command fails with
   `Config files in .../.mise.toml are not trusted` before any of the above
   matters. The setup script and the hook both run `mise trust` on that one
   path — never `mise trust --all`, which would trust whatever else happens to
   be on disk.

4. **Provisioning and the session do not share `$HOME`.** The setup script runs
   as `root`; the session runs as an unprivileged user. mise's data directory
   defaults to `$HOME/.local/share/mise`, so left alone those are two separate
   trees and every tool provisioning installed is invisible to the session,
   which then installs it again.

   That second install is not merely slow — it usually **fails**. The session
   proxy answers `api.github.com` with `403`, and mise's `aqua:` and `cargo:`
   backends are both GitHub-API-backed (`cargo-binstall` exits 94; with
   `binstall_only = true` there is no compile fallback), so `cargo:runner-run`
   never lands and `task typecheck`, `task lint` and `task format` all break.
   Provisioning runs on a network where that API _is_ reachable, which is
   exactly why the session must inherit its work rather than repeat it.

   The fix is `MISE_DATA_DIR`, set in the environment-variables box below so
   that it applies to the setup script and the session alike.

## Environment variables

In the environment dialog's **Environment variables** box, `.env` format, one
`KEY=value` per line:

```text
MISE_DATA_DIR=/opt/mise
GOTOOLCHAIN=go1.26.5
GIT_AUTHOR_NAME=Kaj Kowalski
GIT_AUTHOR_EMAIL=info@kajkowalski.nl
GIT_COMMITTER_NAME=Kaj Kowalski
GIT_COMMITTER_EMAIL=info@kajkowalski.nl
GPG_SIGN_URL=https://gpg.kajkowalski.nl
```

`MISE_DATA_DIR` is the one that has to be here rather than in the setup script.
The box applies to both the root provisioning pass and the session, which is the
only way the two end up in the same mise tree — a `MISE_DATA_DIR` exported
inside the setup script would die with it and leave the session back on
`$HOME/.local/share/mise`. `/opt/mise` is outside every `$HOME` on purpose.

Set it and the session inherits the whole provisioned toolchain, `mise install`
becomes a no-op, and nothing reaches for the GitHub API the proxy blocks. Leave
it out and the hook still finds `/opt/mise` — it defaults to the same literal —
so an environment configured before this variable existed keeps working; the
variable is what makes provisioning write there in the first place.

`GOTOOLCHAIN` only matters on the fallback path, where it makes `go install`
compile golangci-lint with a Go new enough for `client/go.mod`. When mise is
available it is redundant, because `.mise.toml` supplies a prebuilt binary. You can
leave it out entirely; it is listed here for environments where mise cannot be
installed.

> **If you set it, keep `GOTOOLCHAIN` in step with `client/go.mod`.** It pins an
> exact toolchain, so when the `go` directive moves past it, plain `go build`
> starts failing with a toolchain error. Bump it in the same change that bumps
> `go.mod`. The SessionStart hook probes with `GOTOOLCHAIN=auto` so it derives
> the version from `go.mod` at runtime rather than from a stale pin.

The git identity variables mirror the repository variables the CI workflows
use, so commits an agent makes look the same whether they come from a cloud
session or from Actions.

**Treat everything here as public.** The dialog warns about this and it is not
a formality: values are readable by anyone who uses the environment, and cloud
environments have no secrets store. Never put `CLOUDFLARE_API_TOKEN` or
`ADMIN_TOKEN` here — both are broad, long-lived and unattributable once leaked.

A `gst_` service token in `GPG_SIGN_TOKEN` is the one deliberate exception, and
only in a **personal** environment: it is scoped to one key, expiring, and
independently revocable, which makes the trade defensible where the other two
are not. In a shared environment it is not — every member's sessions would sign
as you. The full trade-off is in
[Signing commits](#signing-commits-from-a-cloud-session).

Leave `GH_TOKEN` and `GITHUB_TOKEN` unset. The GitHub proxy authenticates for
you and keeps the real credential outside the VM; both variables then read as
the literal string `proxy-injected`, which is expected. A script that reads
`GITHUB_TOKEN` directly gets that placeholder rather than a usable token.

## Setup script

Paste into the dialog's **Setup script** box. It runs as root before Claude
Code launches, and only when no cached environment exists.

```bash
#!/bin/bash
# Provision tools this repo needs that the base image lacks. Everything here
# lands in the cached snapshot, so later sessions start with it already on disk.
#
# Deliberately never exits non-zero: a non-zero exit makes the session fail to
# start, and a broken tool is better than no session. The repo's SessionStart
# hook re-checks and repairs anything that failed here.

repo="${CLAUDE_PROJECT_DIR:-$PWD}"

# One mise tree for root and for the session user. MISE_DATA_DIR comes from the
# environment-variables box above; the default here matches the one the hook
# falls back to, so the two agree even if the variable was never set.
export MISE_DATA_DIR="${MISE_DATA_DIR:-/opt/mise}"
mkdir -p "$MISE_DATA_DIR"

# mise, which installs everything .mise.toml lists (task, golangci-lint, biome,
# shellcheck, wrangler, ...) and is what the root Taskfile's `mise exec --`
# calls need on PATH. Its installer downloads the release asset directly, which
# the proxy allows — it is the releases *API* that returns 403.
curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh || true

# mise refuses to read a checked-in config it has not been told to trust, and
# `mise install` below is the first thing that needs it. One path, not --all.
[ -f "$repo/.mise.toml" ] && mise trust "$repo/.mise.toml" || true

(cd "$repo" && mise install) || true

# Hand the tree to the session user. Provisioning runs as root and the session
# does not, so a tree only root can write is one the session cannot repair when
# .mise.toml later gains a tool. Prefer chown to the account the agent actually
# runs as; widen the mode only when there is no such account to name. (The hook
# copes with either: an unwritable tree is still fully usable, it just makes the
# hook report a missing tool instead of installing it.)
session_user="$(stat -c %U /home/* 2>/dev/null | grep -v '^root$' | head -1)"
if [ -n "$session_user" ]; then
  chown -R "$session_user" "$MISE_DATA_DIR" || true
else
  chmod -R a+rwX "$MISE_DATA_DIR" || true
fi

# Fallbacks, in case the mise install above did not take. Harmless when it did.
export PATH="$MISE_DATA_DIR/shims:$PATH"
command -v task >/dev/null 2>&1 || npm install -g @go-task/cli || true

# golangci-lint that can actually load this repo's config. Testing for the
# *binary* is what the earlier version of this script got wrong: the base image
# always ships one, so `command -v` always succeeded and this rebuild never ran
# — while the preinstalled binary went on refusing every `task format` with
# "the Go language version used to build golangci-lint is lower than the
# targeted Go version". Loading client/.golangci.yml is the cheapest call that
# reaches that check, and mise's binary (now first on PATH) usually passes it.
#
# GOTOOLCHAIN comes from the environment variables above; without it this
# rebuild is pointless, because go install would use golangci-lint's own older
# toolchain.
(cd "$repo/client" && golangci-lint config path --config=.golangci.yml) \
  >/dev/null 2>&1 \
  || GOBIN=/usr/local/bin go install \
    github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 || true

# Optional: the released gpg-sign CLI. Use the direct download URL — the
# releases API returns 403 through the proxy, but the asset URL itself is fine.
curl -sSLf -o /usr/local/bin/gpg-sign \
  https://github.com/kjanat/gpg-signing-service/releases/latest/download/gpg-sign-linux-amd64 \
  && chmod +x /usr/local/bin/gpg-sign || true

exit 0
```

The install targets (`/opt/node22/bin` for npm globals, `/usr/local/bin` for
`GOBIN` and the mise binary) are already on `PATH`. The tools mise manages live
in `$MISE_DATA_DIR/shims`, which the SessionStart hook adds to `PATH` and writes
into `$CLAUDE_ENV_FILE` for you — that is what carries this provisioning pass
into every Bash call the agent makes.

Budget roughly 60 seconds when mise succeeds, or 90 when the fallback
golangci-lint build runs. Either is well inside the five-minute limit, and it
only runs when the cache is cold.

### What the hook does _not_ redo

The hook checks each tool with `mise which` and runs `mise install` only for the
ones actually missing. That is deliberate: the session cannot reach
`api.github.com`, so a reinstall of anything on the `aqua:` or `cargo:` backend
fails no matter how often it is attempted. When something is still missing it
makes **one** attempt, then logs which tools are absent and moves on — a 403 is
a property of the session network, not a transient error, and retrying it only
spends the first minutes of the session arriving at the same answer. If you see
that warning, the fix belongs in this setup script, not in the hook.

### When the setup script re-runs

The snapshot is rebuilt when you edit the setup script or the allowed-domain
list, and when the cache expires after about seven days. Resuming an existing
session never re-runs it. The snapshot keeps files, not processes — so anything
that needs to be _running_ has to start per session.

## Network access

**Trusted** is enough for everything above: npm, the Go module proxy, and
GitHub release assets are all on the default allowlist.

Choose **Full**, or **Custom** with `gpg.kajkowalski.nl` added, only if you want
sessions to reach the deployed service directly — for example to run the
`/verify-live` audit against production. MCP connectors do not need an
allowlist entry, since their traffic goes through Anthropic's servers rather
than the session network.

## Signing commits from a cloud session

By default a cloud session signs commits as `Claude <noreply@anthropic.com>`
with an agent-runtime SSH key, not as you and not through this service.

Redirecting that to your own identity is environment configuration and is
covered in full by **[cloud-session-signing.md](cloud-session-signing.md)** —
including the trap that `gpg.program` is ignored unless you also set
`gpg.format=openpgp`, which otherwise leaves you silently signing with the
agent's key.

## Verifying it works

Ask the agent to run these; all three should pass in a correctly configured
session:

```bash
mise where task            # under $MISE_DATA_DIR, not under $HOME
task --version             # Taskfile present
task c:l                   # Go lint — fails loudly if the toolchain mismatch is back
task t                     # test suite
```

The first one is the check that catches a half-configured environment. If it
answers with a path under the session user's home directory, `MISE_DATA_DIR` did
not reach the setup script and the session has rebuilt its own tree — which
works today only because the tools it needed happened to be fetchable, and will
stop working the moment one of them is not.

[claude.ai/code]: https://claude.ai/code
