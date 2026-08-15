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
`golangci-lint` preinstalled. Two things still break:

1. **`task` and `mise` are not installed.** `CLAUDE.md` requires every command
   to go through Taskfile, so without `task` the agent cannot run tests or
   linters at all. `mise` is needed too, and not only as a way to get `task`:
   the root `Taskfile.yml` invokes wrangler, biome and the typechecker as
   `mise exec -- <tool>`, so `task lint` and `task typecheck` fail outright
   without it.

   Installing mise is the whole fix, because `.mise.toml` pins `task` and a
   correctly-built `golangci-lint` alongside everything else — the same
   mechanism CI uses via `jdx/mise-action`. Note the upstream Taskfile
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

   `.mise.toml` pins a prebuilt `golangci-lint` compiled with a current Go, so
   once mise is installed this resolves itself. The rest of this item applies
   only to the fallback path, where mise is unavailable and the binary has to be
   built locally.

   There, reinstalling is not enough on its own. A plain `go install` builds
   golangci-lint with the Go version _its own_ `go.mod` asks for — currently
   older than ours — reproducing the same error. The build has to be pinned to
   the toolchain this repo targets.

## Environment variables

In the environment dialog's **Environment variables** box, `.env` format, one
`KEY=value` per line:

```text
GOTOOLCHAIN=go1.26.5
GIT_AUTHOR_NAME=Kaj Kowalski
GIT_AUTHOR_EMAIL=info@kajkowalski.nl
GIT_COMMITTER_NAME=Kaj Kowalski
GIT_COMMITTER_EMAIL=info@kajkowalski.nl
GPG_SIGN_URL=https://gpg.kajkowalski.nl
```

`GOTOOLCHAIN` only matters on the fallback path, where it makes `go install`
compile golangci-lint with a Go new enough for `client/go.mod`. When mise is
available it is redundant, because `.mise.toml` pins a prebuilt binary. You can
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

# mise, which installs everything .mise.toml pins (task, golangci-lint, biome,
# shellcheck, wrangler, ...) and is what the root Taskfile's `mise exec --`
# calls need on PATH. Its installer downloads the release asset directly, which
# the proxy allows — it is the releases *API* that returns 403.
curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh || true
mise install || true

# Fallbacks, in case the mise install above did not take. Harmless when it did.
command -v task >/dev/null 2>&1 || npm install -g @go-task/cli || true

# golangci-lint built with the Go version client/go.mod targets. GOTOOLCHAIN
# comes from the environment variables above; without it this rebuild is
# pointless, because go install would use golangci-lint's own older toolchain.
command -v golangci-lint >/dev/null 2>&1 || GOBIN=/usr/local/bin go install \
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
in its shims directory, which the SessionStart hook adds to `PATH` for you.

Budget roughly 60 seconds when mise succeeds, or 90 when the fallback
golangci-lint build runs. Either is well inside the five-minute limit, and it
only runs when the cache is cold.

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
task --version   # Taskfile present
task c:l         # Go lint — fails loudly if the toolchain mismatch is back
task t           # test suite
```

[claude.ai/code]: https://claude.ai/code
