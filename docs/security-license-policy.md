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

`.github/workflows/security.yml` carries the exemption.
`task test:security-license-policy` checks that the workflow passes actionlint
and that its dependency review has exactly these inputs.
