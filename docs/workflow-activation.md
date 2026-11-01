# Activating the staged workflows

The automation that edits this repository cannot write under
`.github/workflows/` (a GitHub App token has no `workflows` permission), so
two workflow changes are staged in `.github/workflows-pending/` and go live
together in one maintainer commit:

| Staged file    | What it changes                                                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `autofix.yml`  | `jdx/mise-action` (the repository pin) runs before `kjanat/actions@fmt`, which shells out to `mise`; the timeout grows from 2 to 10 minutes. |
| `security.yml` | The OpenPGP.js licence exemption described in [security-license-policy.md](security-license-policy.md).                                      |

## Activation

A maintainer, with an ordinary credential, runs exactly:

```bash
git mv -f .github/workflows-pending/autofix.yml .github/workflows/autofix.yml && git mv -f .github/workflows-pending/security.yml .github/workflows/security.yml && git commit -m "ci: activate staged workflows"
```

`task test:pending-workflows` passes before and after, and before activation it
runs this command in a scratch repository and checks that it makes one commit
touching those four paths and nothing else. `claude.yml` in the same directory is
a separate staged change and is not part of this commit.

## Red checks until then

While the staged files are not live, the workflows that run on a pull request
are the live ones, and one check is expected to be red for that reason alone.
It is not a defect of the change under review:

- **`Dependency Review`**: the live `security.yml` has no OpenPGP.js exemption,
  so a pull request that bumps `openpgp` reads as introducing an LGPL package.

Any other red check is a real failure. Do not call a pull request fully green
before this commit lands.
