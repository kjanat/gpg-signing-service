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

1. **`task` is not installed.** `CLAUDE.md` requires every command to go
   through Taskfile, so without it the agent cannot run tests or linters at
   all. Note the upstream `install.sh` pulls from GitHub releases via the API,
   which the session proxy answers with `403` for repos not attached to the
   session — install the npm package instead.

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

   Reinstalling is not enough on its own. A plain `go install` builds
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

`GOTOOLCHAIN` is the load-bearing one: it makes `go install` compile
golangci-lint with a Go new enough for `client/go.mod`.

> **Keep `GOTOOLCHAIN` in step with `client/go.mod`.** It pins an exact
> toolchain, so when the `go` directive moves past it, plain `go build` starts
> failing with a toolchain error. Bump it in the same change that bumps
> `go.mod`. The SessionStart hook derives the version from `go.mod` at runtime
> and does not depend on this variable.

The git identity variables mirror the repository variables the CI workflows
use, so commits an agent makes look the same whether they come from a cloud
session or from Actions.

**No secrets here.** The dialog warns about this and it is not a formality:
values are readable by anyone who uses the environment, and cloud environments
have no secrets store. That means no `CLOUDFLARE_API_TOKEN`, no `ADMIN_TOKEN`,
and no `gst_` service token, which in turn means a cloud session cannot call
`/sign` — see [Signing commits](#signing-commits-from-a-cloud-session).

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

# Taskfile. The npm package, not the upstream install.sh, which fetches from
# GitHub releases through the API and gets a 403 from the session proxy.
npm install -g @go-task/cli || true

# golangci-lint built with the Go version client/go.mod targets. GOTOOLCHAIN
# comes from the environment variables above; without it this rebuild is
# pointless, because go install would use golangci-lint's own older toolchain.
GOBIN=/usr/local/bin go install \
  github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest || true

# Optional: the released gpg-sign CLI. Use the direct download URL — the
# releases API returns 403 through the proxy, but the asset URL itself is fine.
curl -sSLf -o /usr/local/bin/gpg-sign \
  https://github.com/kjanat/gpg-signing-service/releases/latest/download/gpg-sign-linux-amd64 \
  && chmod +x /usr/local/bin/gpg-sign || true

exit 0
```

Both install targets (`/opt/node22/bin` for npm globals, `/usr/local/bin` for
`GOBIN`) are already on `PATH`, so nothing needs to touch `PATH` afterwards.

Budget roughly 90 seconds; the golangci-lint build dominates. That is well
inside the five-minute limit, and it only runs when the cache is cold.

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

CI signs its commits through this service using a per-signature GitHub OIDC
token (see [`gpg-sign-git-program.sh`](../.github/scripts/gpg-sign-git-program.sh)).
A cloud session has no OIDC issuer, so that path is unavailable, and the only
alternatives — a `gst_` service token or the admin token — are credentials that
must not go in the environment dialog.

So commits from cloud sessions are unsigned by default. If you want them
signed, pass a narrowly scoped `gst_` token into the session by other means,
accepting that a static token is weaker than CI's short-lived ones, then point
git at a shim that reads `GPG_SIGN_TOKEN` instead of minting an OIDC token.

## Verifying it works

Ask the agent to run these; all three should pass in a correctly configured
session:

```bash
task --version   # Taskfile present
task c:l         # Go lint — fails loudly if the toolchain mismatch is back
task t           # test suite
```

[claude.ai/code]: https://claude.ai/code
