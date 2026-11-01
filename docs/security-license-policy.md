# Security workflow licence policy

The Security workflow's dependency review denies GPL and LGPL for everything a
pull request introduces: `GPL-2.0, GPL-3.0, LGPL-2.0, LGPL-2.1, LGPL-3.0`.

[OpenPGP.js](https://github.com/openpgpjs/openpgpjs) (`openpgp`) is licensed
LGPL-3.0-or-later and is the signing library this service is built on. It is
already a dependency, but dependency review judges the version a pull request
adds, so every bump of it reads as a newly introduced LGPL package and fails.

The policy is therefore one named exemption, not a relaxed list:

```yaml
deny-licenses: "GPL-2.0, GPL-3.0, LGPL-2.0, LGPL-2.1, LGPL-3.0"
allow-dependencies-licenses: "pkg:npm/openpgp"
```

`allow-dependencies-licenses` is the dependency-review-action input for
"these packages may use any licence"; the purl has no version so it keeps
applying as `openpgp` moves between versions. It names no other package. Any
other GPL/LGPL dependency still fails, and adding to the exemption is a change
to this file's workflow that has to be reviewed.

## Activation

The replacement lives at `.github/workflows-pending/security.yml` because the
automation that wrote it cannot push to `.github/workflows/` (a GitHub App token
has no `workflows` permission). A maintainer activates it with an ordinary
credential, by moving it over the live workflow, together with the other staged ones:

```bash
git mv -f .github/workflows-pending/autofix.yml .github/workflows/autofix.yml && git mv -f .github/workflows-pending/security.yml .github/workflows/security.yml && git commit -m "ci: activate staged workflows"
```

That one commit activates both staged workflows; see
[workflow-activation.md](workflow-activation.md) for the other one and for the
checks that stay red until it lands.

`task test:security-license-policy` passes before and after. Before, it asserts
that the staged file is actionlint-valid, differs from the live workflow only
by the exemption, and that the live workflow is still unexempted; after, that
the live workflow carries exactly the exemption and the staged copy is gone.

Until activation the one expected failure is the Dependency Review check of a
pull request that bumps `openpgp` — it runs the live, unexempted workflow.
Nothing else is waiting on it.
