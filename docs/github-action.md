# Install `gpg-sign` in GitHub Actions

The root action installs the released `gpg-sign` CLI. It does not authenticate
to a signing service or sign a commit.

## Quick start

Fix the action implementation to a commit and select a binary release:

```yaml
name: Check signing service

on: workflow_dispatch

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - id: install
        uses: kjanat/gpg-signing-service@cbcb8600547bd6799cdca0b339e8dad044481435
        with:
          version: v1.2.0

      - name: Check service
        env:
          GPG_SIGN_URL: ${{ vars.SIGNING_SERVICE_URL }}
        run: gpg-sign health
```

The install directory is added to `PATH` for subsequent steps in the job.

## Who can use it

The action can run in a GitHub Actions job that:

- is allowed by repository or organization policy to use this public action;
- runs on Linux, macOS, or Windows with an x64 or ARM64 processor; and
- has PowerShell Core (`pwsh`). GitHub-hosted runners include it; self-hosted
  runners must provide it.

The composite action is specific to GitHub Actions. GitLab and other CI systems
can download a release asset or install the CLI with Go.

## Inputs

| Input        | Default                      | Meaning                                                    |
| ------------ | ---------------------------- | ---------------------------------------------------------- |
| `version`    | `latest`                     | Release tag to install, or `latest`                        |
| `repository` | `kjanat/gpg-signing-service` | Repository that publishes the release assets               |
| `token`      | `${{ github.token }}`        | GitHub API token used only for release lookup and download |

The `token` input is not an OIDC JWT, `gst_` service token, or admin token. Do
not pass a signing credential to this input.

For a private release repository, provide a token that can read that
repository's release assets:

```yaml
- uses: your-org/gpg-signing-service@v1.2.0
  with:
    repository: your-org/gpg-signing-service
    version: v1.2.0
    token: ${{ secrets.RELEASE_READ_TOKEN }}
```

## Outputs

| Output    | Meaning                               |
| --------- | ------------------------------------- |
| `version` | Resolved release tag                  |
| `path`    | Full path to the installed executable |

```yaml
- id: install
  uses: kjanat/gpg-signing-service@cbcb8600547bd6799cdca0b339e8dad044481435
  with:
    version: v1.2.0

- shell: bash
  env:
    INSTALLED_PATH: ${{ steps.install.outputs.path }}
    INSTALLED_VERSION: ${{ steps.install.outputs.version }}
  run: printf 'Installed %s at %s\n' "$INSTALLED_VERSION" "$INSTALLED_PATH"
```

## Pinning and trust limits

These values control different code:

- `uses: ...@<commit-sha>` selects the action implementation.
- `with.version: v1.2.0` selects the downloaded binary release.

If `version` is omitted, an immutable action ref still downloads the moving
latest release. There is currently no floating `v1` tag.

A full action commit SHA is immutable. A release tag, its assets, and its
colocated checksum remain controlled by the release publisher. The action also
has no input for an independently recorded digest and does not fail when
`checksums.txt` is absent.

For a supply-chain-sensitive installation, require the expected release and
checksum to exist, compare the binary with a digest obtained through your
independent release policy, and install it without relying on this action's
warning-only checksum fallback.

### How the assets you download are built

The job that produces them is the `release` job of
`.github/workflows/release.yml`, and the contract it is held to has three
parts.

**It runs no code it has not pinned.** Every external action is resolved by
full commit SHA, with the version as a trailing comment for readability and for
Dependabot. A tag would be a mutable pointer in a repository this project does
not control, one repoint away from running inside the artifact publisher.

**It holds exactly `contents: write`.** Not `id-token:`, not `packages:` — a
publish step inherits every permission the job was granted.

**It publishes only the commit its tag already names.** The requested tag is
one expression spent in three places: it selects the checkout `ref`, it is the
`RELEASE_TAG` that `validate-release-tag.sh` validates, and it is the `tag_name`
the release is published under. That script runs before the build and refuses
unless `<tag>^{commit}` equals `HEAD`, which is what makes the manual
`workflow_dispatch(tag: vX.Y.Z)` path safe: on that path the tag is an operator
string and nothing else in the job re-reads the object. The step creates, moves
and fetches nothing — a tag that is not already in the checkout is a refusal.

**The tag check does not come from the tag.** A `run:` step executes in
`$GITHUB_WORKSPACE`, and the checkout above it replaced `$GITHUB_WORKSPACE` with
the requested tag's tree — so a script named there is a file the published tag
has to supply, and every tag cut before this workflow landed supplies none. The
job therefore checks out twice: the requested tag into the workspace, and
`github.workflow_sha` — the commit this workflow file itself came from — into
`.release-tooling/`, with the same pinned `actions/checkout` and the same
`persist-credentials: false`. The validator runs as
`.release-tooling/.github/scripts/validate-release-tag.sh` and reads the objects
of the release workspace, which is still the working directory. Two consequences,
both intended: `workflow_dispatch(tag:)` can publish a tag older than the check,
and the code deciding whether a ref is safe is never code that ref supplied.

A step being present is not the same as a step being effective, so the tag
check is also held to running: no `if:`, no `continue-on-error:`, after the
tooling checkout, ahead of the publish step, and executed by the same step that
is handed `RELEASE_TAG`. Each of those is a shape that parses exactly like a
working guard and validates nothing.

All of it is asserted rather than reviewed, by `task test:release-workflow`,
over a real YAML parse rather than a line scan — and over _every_ copy of the
workflow in the tree, including any staged in `.github/workflows-pending/`
awaiting a maintainer's `git mv`. Activation is a rename, so while two files
claim to be the release workflow the suite holds both to the contract and stays
red until the live one meets it. A hardened copy that has not been activated
cannot report the file that actually publishes clean.

## Supported assets

The action expects exact asset names:

| Runner        | Asset                        |
| ------------- | ---------------------------- |
| Linux x64     | `gpg-sign-linux-amd64`       |
| Linux ARM64   | `gpg-sign-linux-arm64`       |
| macOS x64     | `gpg-sign-darwin-amd64`      |
| macOS ARM64   | `gpg-sign-darwin-arm64`      |
| Windows x64   | `gpg-sign-windows-amd64.exe` |
| Windows ARM64 | `gpg-sign-windows-arm64.exe` |

Releases up to `v1.1.1` carry no Windows ARM64 asset. On that runner the
installer falls back to `gpg-sign-windows-amd64.exe` when the pinned release
has no native build, and verifies the checksum of the asset it downloaded.

## Download mechanics

The PowerShell step:

1. detects the operating system and architecture;
2. requests `/releases/latest` or `/releases/tags/<version>`;
3. finds the platform asset, or the Windows x64 asset on a Windows ARM64 runner
   whose pinned release has no native build;
4. downloads it through the GitHub asset API;
5. downloads `checksums.txt`, when present;
6. compares the asset's SHA-256 with its checksum entry;
7. marks non-Windows binaries executable; and
8. appends the temporary install directory to `GITHUB_PATH`.

A checksum mismatch or missing entry fails the action. A release with no
`checksums.txt` only emits a warning and continues without verification. Do not
use that fallback where verified installation is mandatory.

## Common failures

| Message                                        | Cause                                                                          |
| ---------------------------------------------- | ------------------------------------------------------------------------------ |
| `Unsupported OS` or `Unsupported architecture` | Runner is outside the supported matrix                                         |
| `Asset ... not found`                          | Release does not follow the expected naming contract                           |
| `No checksum entry`                            | `checksums.txt` exists but omits the selected asset                            |
| `Checksum mismatch`                            | Downloaded asset does not match the release checksum                           |
| GitHub API `401` or `404`                      | Tag/repository is wrong or the token cannot read it                            |
| `gpg-sign: command not found`                  | Command ran in the same script that writes `GITHUB_PATH`, or the action failed |

For signing credentials and a complete CI request, continue with
[Authentication](authentication.md) and [CI integrations](integrations.md).
