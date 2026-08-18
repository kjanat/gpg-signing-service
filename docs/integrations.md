# CI integrations

## Requesting versus applying a signature

`gpg-sign sign` returns a detached signature. That is useful for testing,
artifact signing, or a later Git plumbing step, but it does not modify a commit.

Applying a PGP signature to an existing commit reconstructs the commit object,
changes its SHA, and may require rewriting descendants and force-pushing a
branch. Treat that as a separate, privileged workflow.

The examples below stop after requesting `commit.sig`.

## GitHub Actions with OIDC

> [!IMPORTANT]
> This example returns `401` until the deployment trusts the calling
> repository. OIDC authorization is a table of trusted subjects: register the
> repository's issuer and subject prefix through `/admin/subjects` first — see
> [trusted OIDC subjects](authentication.md#trusted-oidc-subjects). An empty
> table denies everyone.

```yaml
name: Request commit signature

on: workflow_dispatch

permissions:
  contents: read
  id-token: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - uses: kjanat/gpg-signing-service@cbcb8600547bd6799cdca0b339e8dad044481435
        with:
          version: v1.1.2

      - id: oidc
        uses: actions/github-script@v9
        with:
          script: |
            const token = await core.getIDToken("gpg-signing-service");
            core.setSecret(token);
            core.setOutput("token", token);

      - name: Request detached signature
        env:
          GPG_SIGN_TOKEN: ${{ steps.oidc.outputs.token }}
          GPG_SIGN_URL: ${{ vars.SIGNING_SERVICE_URL }}
        run: |
          git cat-file commit HEAD |
            gpg-sign sign --key-id 62E75E54497815DD > commit.sig

      - uses: actions/upload-artifact@v6
        with:
          name: detached-commit-signature
          path: commit.sig
```

The workflow needs `id-token: write` only for OIDC. Add `contents: write` only
if a later step intentionally updates repository refs. A `401` here is almost
always the missing subject row rather than a token fault; the error `gpg-sign`
prints carries the service's own message.

## GitHub Actions with a service token

This path works without OIDC and can restrict the credential to selected keys:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0

  - uses: kjanat/gpg-signing-service@cbcb8600547bd6799cdca0b339e8dad044481435
    with:
      version: v1.1.2

  - name: Request detached signature
    env:
      GPG_SIGN_TOKEN: ${{ secrets.GPG_SIGN_SERVICE_TOKEN }}
      GPG_SIGN_URL: ${{ vars.SIGNING_SERVICE_URL }}
    run: |
      git cat-file commit HEAD |
        gpg-sign sign --key-id 62E75E54497815DD > commit.sig
```

The service token belongs in the caller repository's secret store, not in the
installer action's `token` input.

## GitLab CI with OIDC

The root GitHub Action cannot run in GitLab. Install the binary separately, then
declare a GitLab ID token:

```yaml
request-signature:
  image: alpine:3.22
  id_tokens:
    GPG_SIGN_TOKEN:
      aud: gpg-signing-service
  variables:
    GPG_SIGN_VERSION: v1.1.2
    GPG_SIGN_SHA256: <digest recorded for that release>
    GPG_SIGN_URL: $SIGNING_SERVICE_URL
  before_script:
    - apk add --no-cache curl git
    - cd /tmp
    - curl --fail --location --remote-name
      "https://github.com/kjanat/gpg-signing-service/releases/download/${GPG_SIGN_VERSION}/gpg-sign-linux-amd64"
    - printf '%s  %s\n' "$GPG_SIGN_SHA256"
      'gpg-sign-linux-amd64' | sha256sum --check
    - install -m 0755 gpg-sign-linux-amd64 /usr/local/bin/gpg-sign
    - cd "$CI_PROJECT_DIR"
  script:
    - git cat-file commit HEAD |
      gpg-sign sign --key-id 62E75E54497815DD > commit.sig
  artifacts:
    paths: [commit.sig]
```

This example assumes a Linux x64 runner. Select the corresponding release asset
for another architecture.

## Other CI systems

Use an operator-minted `gst_` token:

```bash
export GPG_SIGN_URL="https://your-worker.example"
export GPG_SIGN_TOKEN="$GPG_SIGN_SERVICE_TOKEN"

git cat-file commit HEAD |
  gpg-sign sign --key-id 62E75E54497815DD > commit.sig
```

Prefer an expiration and key allowlist when the token is created. See
[Authentication](authentication.md#service-tokens).

## Applying a PGP signature

The repository's
[`sign-commits.yml`](../.github/workflows/sign-commits.yml) demonstrates the
low-level `gpgsig` reconstruction sequence. It is an internal example, not a
drop-in reusable workflow:

- it uses repository-local setup actions;
- it handles PGP signatures only;
- updating the commit changes its SHA; and
- its final force push can rewrite branch history.

Review branch protection, concurrency, merge-commit handling, descendants, and
the exact push target before adapting it. Never silently add a force push to a
general CI workflow.

## X.509

The service can create detached PKCS#7 signatures for Git's
`gpg.format=x509`, but the current `gpg-sign` high-level client rejects
non-PGP response markers. Use the HTTP API or generated raw Go client until the
CLI supports X.509 end to end.
