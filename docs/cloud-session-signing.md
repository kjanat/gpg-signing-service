# Signing cloud agent commits with your own identity

How to make commits from a Claude Code cloud session be authored **and signed
as you**, through this service, instead of the default agent identity.

All of it is environment configuration — the **Environment variables** box in
the cloud environment dialog at [claude.ai/code]. No repo changes are required
beyond the shim that already ships here.

## What happens if you do nothing

A cloud session VM comes with git already configured to sign, using an identity
that is not yours:

```console
$ git config --global --list | grep -iE 'user\.|gpg|sign'
user.name=Claude
user.email=noreply@anthropic.com
user.signingkey=/home/claude/.ssh/commit_signing_key.pub
gpg.format=ssh
gpg.ssh.program=/tmp/code-sign
commit.gpgsign=true
```

So commits are signed, just with an ephemeral SSH key belonging to the agent
runtime, and attributed to `Claude <noreply@anthropic.com>`. Two separate things
therefore have to be overridden: **who the commit says it is from**, and **what
key signs it**.

## The trap: `gpg.format` must be changed too

Setting `gpg.program` alone does nothing. Git only consults `gpg.program` when
`gpg.format` is `openpgp`; while `gpg.format=ssh` it uses `gpg.ssh.program` and
ignores `gpg.program` completely.

This fails **silently in the worst possible way**: the commit succeeds, git
reports it as signed, and the signature is the agent's SSH key rather than
yours. Verified against a real session — a commit made with `gpg.program`
pointed at this service, but `gpg.format` left alone, came out carrying a
`BEGIN SSH SIGNATURE` block and never contacted the service at all.

Always set `gpg.format=openpgp` alongside `gpg.program`.

## Configuration

Git reads configuration from the environment via `GIT_CONFIG_COUNT` plus
numbered `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` pairs, which is what makes
this possible with no files and no setup script. Keys must be numbered
contiguously from `0`, and `GIT_CONFIG_COUNT` must match exactly, or git ignores
the lot.

Paste into **Environment variables**, adjusting the identity:

```text
GPG_SIGN_URL=https://gpg.kajkowalski.nl

GIT_AUTHOR_NAME=Kaj Kowalski
GIT_AUTHOR_EMAIL=info@kajkowalski.nl
GIT_COMMITTER_NAME=Kaj Kowalski
GIT_COMMITTER_EMAIL=info@kajkowalski.nl

GIT_CONFIG_COUNT=5
GIT_CONFIG_KEY_0=commit.gpgSign
GIT_CONFIG_VALUE_0=true
GIT_CONFIG_KEY_1=gpg.format
GIT_CONFIG_VALUE_1=openpgp
GIT_CONFIG_KEY_2=gpg.program
GIT_CONFIG_VALUE_2=/home/claude/gpg-signing-service/.github/scripts/gpg-sign-git-program.sh
GIT_CONFIG_KEY_3=user.name
GIT_CONFIG_VALUE_3=Kaj Kowalski
GIT_CONFIG_KEY_4=user.email
GIT_CONFIG_VALUE_4=info@kajkowalski.nl
```

Notes on the individual pieces:

- `gpg.program` is an **absolute path**, and the checkout path differs between
  environments. Confirm yours by asking the agent to run `echo $CLAUDE_PROJECT_DIR`,
  and use `<that>/.github/scripts/gpg-sign-git-program.sh`.
- The global config sets `user.signingkey` to the agent's SSH public key. With
  `gpg.format=openpgp` git passes it through as a key id, which the shim
  ignores — it signs with the service's default key. Harmless, but if you serve
  multiple keys, override `user.signingkey` to empty (add it as another
  `GIT_CONFIG_KEY_n` with an empty value) so intent stays obvious.
- `GIT_AUTHOR_*` / `GIT_COMMITTER_*` and the `user.*` config overlap
  deliberately: the former win for commits, the latter cover tools that read
  config directly.

## The credential

The shim needs a token for `/sign`. In CI it mints a short-lived GitHub OIDC
token per signature, but a cloud session has no OIDC issuer, so it falls back to
a **`gst_` service token** read from `GPG_SIGN_TOKEN`.

Mint one scoped and expiring, rather than reusing the admin token:

```bash
curl -X POST "$GPG_SIGN_URL/admin/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"cloud-agent-<who>","keyIds":["<key-id>"],"expiresInDays":30}'
```

The plaintext token comes back exactly once. Revoke it with
`DELETE /admin/tokens/{id}`, and list live ones with `GET /admin/tokens`.

Then add it to the environment:

```text
GPG_SIGN_TOKEN=gst_...
```

### Read this before you paste a token

Environment variable values are **visible to anyone who can use that
environment**, and cloud environments have no secrets store. The consequences
differ sharply:

- **Personal environment** — the only reader is you. A scoped, expiring,
  independently revocable `gst_` token is a reasonable trade, and materially
  weaker than CI's per-signature OIDC tokens only in that it is long-lived.
- **Organization-shared environment** — every member's sessions get the token,
  and it signs as _you_. Don't. Give each person their own environment and their
  own token, so a leak is attributable and revocable without disrupting others.

Scope each token to the key it needs, set an expiry, and give one token per
person or per purpose. That way revocation is precise.

## Verifying

Ask the agent to make a throwaway commit, then:

```bash
git log -1 --format='%an <%ae>'   # expect your identity, not Claude
git cat-file commit HEAD | grep -A1 gpgsig
```

The signature block must say `BEGIN PGP SIGNATURE`. If it says
`BEGIN SSH SIGNATURE`, `gpg.format` did not take effect and you are still
signing with the agent key.

A misconfiguration is loud rather than silent once `gpg.format=openpgp` is set:
with a bad or expired token the commit is refused outright, verified against the
live service —

```console
$ git commit -m "test"
error: gpg failed to sign the data:
Error: signing failed: unexpected status code: 401
fatal: failed to write commit object
```

— and no commit object is written, so a failed signature can never masquerade as
an unsigned commit that slipped through.

## GitHub will still say "Unverified"

Signing correctly is not the same as GitHub displaying a green badge. GitHub
verifies a commit only when the signing key is registered to an account whose
verified email matches the committer address. To get the badge:

1. Fetch the service's public key: `curl $GPG_SIGN_URL/public-key`
2. Add it at [github.com/settings/keys] as a **GPG key**.
3. Ensure the key's user id email matches `GIT_COMMITTER_EMAIL`, and that the
   address is verified on the account.

Until then the signature is real and verifiable locally — import the key and run
`git log --show-signature` — GitHub simply doesn't recognise the signer.

## Why not just reuse the CI mechanism

The CI workflows sign through the same shim and the same service, but
authenticate with a GitHub OIDC token minted fresh for every signature and valid
for a few minutes. That is strictly better and needs no stored credential, but
it only exists inside a GitHub Actions job with `id-token: write`. A cloud
session has no issuer to ask, which is why the static service token exists as
the fallback. The shim tries `GPG_SIGN_TOKEN` first and only reaches for OIDC
when it is absent, so the same script covers CI, cloud sessions, and laptops
without branching per environment.

[claude.ai/code]: https://claude.ai/code
[github.com/settings/keys]: https://github.com/settings/keys
