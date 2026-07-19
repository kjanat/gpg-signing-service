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
        uses: kjanat/gpg-signing-service@43a5c6b9aa5e796e2967d054167ffe3ab9e4b3b1
        with:
          version: v1.1.1

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
- uses: your-org/gpg-signing-service@v1.1.1
  with:
    repository: your-org/gpg-signing-service
    version: v1.1.1
    token: ${{ secrets.RELEASE_READ_TOKEN }}
```

## Outputs

| Output    | Meaning                               |
| --------- | ------------------------------------- |
| `version` | Resolved release tag                  |
| `path`    | Full path to the installed executable |

```yaml
- id: install
  uses: kjanat/gpg-signing-service@43a5c6b9aa5e796e2967d054167ffe3ab9e4b3b1
  with:
    version: v1.1.1

- shell: bash
  env:
    INSTALLED_PATH: ${{ steps.install.outputs.path }}
    INSTALLED_VERSION: ${{ steps.install.outputs.version }}
  run: printf 'Installed %s at %s\n' "$INSTALLED_VERSION" "$INSTALLED_PATH"
```

## Pinning and trust limits

These values control different code:

- `uses: ...@<commit-sha>` selects the action implementation.
- `with.version: v1.1.1` selects the downloaded binary release.

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

## Supported assets

The action expects exact asset names:

| Runner        | Asset                                         |
| ------------- | --------------------------------------------- |
| Linux x64     | `gpg-sign-linux-amd64`                        |
| Linux ARM64   | `gpg-sign-linux-arm64`                        |
| macOS x64     | `gpg-sign-darwin-amd64`                       |
| macOS ARM64   | `gpg-sign-darwin-arm64`                       |
| Windows x64   | `gpg-sign-windows-amd64.exe`                  |
| Windows ARM64 | Currently falls back to the Windows x64 asset |

Release `v1.1.1` predates the native Windows ARM64 asset. The current release
workflow can publish one, but the installer still selects the compatibility
fallback.

## Download mechanics

The PowerShell step:

1. detects the operating system and architecture;
2. requests `/releases/latest` or `/releases/tags/<version>`;
3. finds the exact platform asset;
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
