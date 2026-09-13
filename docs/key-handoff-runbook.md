# Key handoff runbook

The 2026-09-08 rotation moved production from signing key `62E75E54497815DD` to
`AFD5E3EC68371856`. Everything that could be done from this repository, from CI
or from the Cloudflare account is done ([#147], [#148], [ADR-004]). Two things
are left, and both need material that exists only on the operator's machine:

1. prove the replacement credentials are **retrievable from backup**, with the
   private-key backup stored apart from its passphrase;
2. **publish the retired key's revocation** and verify the revoked state through
   the public distribution path.

`scripts/key-handoff.sh` is that procedure. It is the only part of #147 that
runs on a laptop rather than in CI, so it is written to fail rather than to
reassure: an unreadable file, an unexpected key id, a passphrase that does not
unlock, a keyserver that accepts an upload and then serves the key back
unrevoked — each of those stops the run.

It never generates a key, never generates a revocation certificate, never takes
a passphrase as a command-line argument, and never writes to the handoff
directory or to a backup.

## Before you start

You need the offline handoff material, which is **not** in any checkout of this
repository and must never be put into one. `.gitignore` excludes `.keys/`;
`task test:key-material` fails the build if key material reaches a tracked file
by any other route, and `task test:key-handoff` fails if anything under `.keys/`
becomes tracked.

Mount or copy the handoff directory to `.keys/rotation-20260908` (or pass
`--handoff DIR`). It should contain, in any filenames you like — the script
classifies by decoding each file, not by its name:

| Role                                      | Needed for             |
| ----------------------------------------- | ---------------------- |
| replacement secret key `AFD5E3EC68371856` | backup verification    |
| replacement public key                    | optional, derivable    |
| replacement revocation certificate        | validation             |
| retired public key `62E75E54497815DD`     | revocation publication |
| retired revocation certificate            | revocation publication |
| preserved key material `D8BC04E534E7706F` | backup verification    |

`D8BC04E534E7706F` is in this list because the rotation moved it onto the
replacement's passphrase. It was not part of the exposure, but it is part of the
same restore.

It should contain nothing else. Anything in it that `gpg` cannot decode stops
`validate` by name — a stray note, a checksum listing, a passphrase filed in the
wrong place, and a key that was truncated when it was written out all look
identical from the outside, and the last two are the failures this whole
procedure exists to catch. If a file is genuinely just a note, acknowledge it
with `--allow-note PATH`, once per file, after you have looked at it. There is
no blanket opt-out on purpose.

You also need `gpg` on `PATH`, **bash 4 or newer** — macOS still ships 3.2 at
`/bin/bash`, so `brew install bash` and run it with that one — and a terminal.

That is the whole list of things to install. Everything else the script runs is
in a stock POSIX userland: `awk`, `cat`, `chmod`, `date`, `find`, `gpgconf`,
`head`, `ln`, `mkdir`, `mktemp`, `od`, `readlink`, `rm`, `tr`. No GNU extension
of any of them is used — no `readlink -f`, no `sha256sum`, no `sort -z` — so a
Mac needs no `coreutils` from Homebrew and you do not have to assemble a GNU
userland by accident. Anything missing is named before a single file is read.

The script refuses to run when it detects CI, because material that reaches a
runner has already lost the property this whole exercise is protecting. The
refusal is deliberate and there is no flag for it; only
`KEY_HANDOFF_ALLOW_CI=yes-i-am-a-local-operator` in the environment, which exists
so the repository's own test suite can drive the script with throwaway keys.

Two things the script checks by doing them rather than by asking what platform
this is, at the start of every run, before it opens any handoff material:

- **path canonicalisation**, against a symlink and a `..` it makes itself. Every
  refusal that keeps a backup path from pointing back into the handoff directory
  rests on resolving paths, and a resolver that quietly hands back its own input
  turns all of them into string comparisons against the string the mistake
  supplied. If it does not resolve, the run stops there.
- **the SHA-256 digest**, against the digest of nothing. That is what "the backup
  files are byte-identical to how this run found them" is measured with.

## Handling the passphrase

The passphrase never appears as an argument. `/proc/*/cmdline` is world-readable
on Linux, so `--passphrase "$SECRET"` would publish it to every local user for
the lifetime of the process, and shells record it in history besides. The script
rejects `--passphrase` outright and explains why.

Three accepted sources, and which command accepts which is the point:

1. **`--passphrase-backup PATH`** — a file in the passphrase's own backup
   location. The only source `verify-backup` takes, because the only thing that
   command claims is that the file in that location is the right passphrase.
2. **`KEY_HANDOFF_PASSPHRASE_FILE`** — a path in the environment. A path, never
   a value: an environment variable holding the passphrase itself is inherited
   by every child process and shows up in `ps e` and in core dumps. It is
   otherwise identical to `--passphrase-backup`, including the distinctness
   check below — a path routed through the environment is not a way around it.
3. **the terminal prompt** — `validate --check-unlock` only, reading from
   `/dev/tty` without echo. The claim that command makes is "the passphrase I
   have is the passphrase for the key in the handoff directory", which is a
   thing a typed passphrase can support.

`verify-backup` **refuses** a typed passphrase and says so. Its closing sentence
is what your local copies get deleted on, and the acceptance criterion it stands
for is that the passphrase is retrievable from its own backup. A passphrase you
remember is precisely the thing that stops being true later; it is not evidence
about a backup, and a command that accepted it here would be reassuring rather
than correct.

Whichever you use, the passphrase reaches gpg as `--passphrase-file` pointing at
a file inside a mode-700 temporary directory, which is removed when the script
exits — including when you interrupt it. That file is the one place a
prompt-entered passphrase touches the disk; if `$TMPDIR` is not a tmpfs, point
it at one before a real run.

## 1. Validate the handoff

```bash
bash scripts/key-handoff.sh validate --handoff .keys/rotation-20260908
```

Reads every file in the directory, decodes it, and reports what each one is. It
asserts the replacement secret key is `AFD5E3EC68371856`, that a revocation
certificate for the replacement exists, that the retired key's revocation
certificate really revokes `62E75E54497815DD` and not something else, and that
the preserved key material is there.

It also imports each revocation certificate next to the key it names, in a
keyring that has never held either, and makes gpg report the key revoked. An
issuer id read off the packet only says the certificate was _written_ for that
key; a certificate that rotted in storage still says it, right up until the day
you need it, and there is no way to make another one without the secret key.

That proof is impossible against key material that already carries a revocation:
importing a certificate into a keyring that already reports the key revoked
changes nothing anyone can observe. The two keys are treated differently there,
on purpose:

- **the replacement** arriving already revoked is a **failure**, and the run
  stops. It is what production signs with, so either the wrong key was handed
  off or the live one has been retired without the rest of this saying so — and
  on top of that, the certificate meant to retire it one day has gone unchecked.
  Find out which key is actually live before going further.
- **the retired key** arriving already revoked is **fine** — it is the end state
  this whole procedure is pushing towards, and re-running `validate` after
  publication must not be punished. But the certificate was not checked in that
  state either, so the run says so in as many words and repeats it under _Not
  proved by this run_ at the end, rather than printing the line that means it
  was proved.

If you already hold the passphrase and want to check it against the originals
before restoring anything:

```bash
bash scripts/key-handoff.sh validate --handoff .keys/rotation-20260908 --check-unlock
```

That prompts, then makes the handoff's own replacement key sign a nonce. It says
nothing about any backup, and it prints that disclaimer itself.

This proves the material is present and internally consistent. It proves nothing
about whether any of it was backed up. That is the next step, and it is the one
the acceptance criterion turns on.

## 2. Prove the backups are retrievable

Restore from the backups first — read them back out of wherever they live, to a
scratch directory. Verifying the handoff directory itself proves nothing: it is
the original, not the backup.

```bash
bash scripts/key-handoff.sh verify-backup \
  --private-backup   /mnt/restored/replacement-secret.asc \
  --passphrase-backup /mnt/restored-elsewhere/passphrase.txt \
  --preserved-backup /mnt/restored/preserved-D8BC04E534E7706F.asc
```

All three paths are required, and all three are checked before anything is
imported or any file is opened — a missing flag discovered after you have already
fetched a passphrase out of a vault is the right refusal at the wrong moment.

Pointing any of them at a file inside `--handoff` is refused, and so is a symlink
or a `..` that lands back inside it: that file is the original, and reading it
proves the copy you already have is readable and nothing at all about the copy
you are about to rely on. If for some reason your restore really does live under
the handoff path, restore it somewhere else instead; the refusal is not
negotiable because this command's whole output is the evidence for deleting the
originals.

What it proves, in order:

- the backup locations are **distinct** — not the same file, and not even the
  same directory. A passphrase stored next to a key it protects is one
  compromised backup, not two, and the failure that actually happens is a single
  `cp -r` of a folder holding both. This applies to **both** key backups: the
  rotation moved `D8BC04E534E7706F` onto the replacement's passphrase, so a
  folder holding the preserved key and that passphrase is exactly as usable to
  whoever copies it as one holding the replacement and that passphrase. Three
  paths, three places.
- the private-key backup **imports** into a keyring that has never held it;
- the imported key **is `AFD5E3EC68371856`** and not some other key. Restoring
  the wrong key is indistinguishable from restoring no key until you need it;
- the key is **actually passphrase-protected** — it refuses to sign under a
  passphrase the run invents on the spot. A secret key whose protection was
  stripped signs without gpg ever reading the passphrase file, so the unlock
  proof below would succeed against any passphrase at all, including one
  belonging to a different key, over a private key sitting in the backup in the
  clear;
- the passphrase from the _separate_ location **unlocks** it. This is a signing
  operation over a nonce, not an import: gpg imports an encrypted secret key
  without ever consulting the passphrase, so "it imported" is not evidence;
- the preserved key `D8BC04E534E7706F` restores and unlocks the same way;
- the backup files are **byte-identical** to how the run found them.

Only delete your local copies after this passes. That is what it is for.

## 3. Publish the retired key's revocation

Start verify-only. This is the default: publication needs `--confirm-publish`
and cannot happen by accident.

```bash
bash scripts/key-handoff.sh publish-revocation --handoff .keys/rotation-20260908
```

That imports the retired public key and the existing revocation certificate into
a throwaway keyring, checks the certificate actually belongs to
`62E75E54497815DD`, and asserts gpg then reports the key as revoked. Nothing
leaves the machine.

When it passes, publish:

```bash
bash scripts/key-handoff.sh publish-revocation \
  --handoff .keys/rotation-20260908 --confirm-publish
```

The default targets are the ones [ADR-004] names:

- `hkps://keys.openpgp.org`
- `hkps://keyserver.ubuntu.com`

Override with `--keyserver URL`, repeatable; supplying any replaces both
defaults. `--dry-run` overrides `--confirm-publish`, so a command with both
uploads nothing.

Neither keyserver currently carries `62E75E54497815DD` at all, so publishing the
revocation means publishing the retired **public key** to carry it. That is
consistent with [ADR-004] decision 2 and is the reason the retired public key is
in the handoff list above: a revocation is a signature over a key, and a
keyserver that has never seen the key has nothing to attach it to.

After a successful upload the script fetches the key back from **each** target
into a keyring that has never seen it, and asserts it comes back revoked. A `200`
from an upload endpoint says the request was accepted, not that the key is being
served, and certainly not that it is being served as revoked. Keyservers also
apply uploads asynchronously; if the fetch-back says the key is still live, wait
and re-check rather than re-uploading:

```bash
bash scripts/key-handoff.sh verify-published
```

A partial publication fails the whole run. One target serving the revocation and
another still handing out a live key is the state that leaves a verifier
accepting a signature from a key everyone else knows is dead.

One difference between the test suite and the real targets, so it does not read
as a failure when you meet it: `scripts/mock-keyserver.py` serves back whatever
it was sent, user ids and all, because it speaks HKP and nothing else.
keys.openpgp.org applies a policy on top — it strips user ids that have not been
confirmed by email, and distributes the revocation without them. So the key that
comes back from that target may carry no user id at all while
`keyserver.ubuntu.com` returns one. That is the expected shape; what the script
asserts, and all it asserts, is that gpg reports the key **revoked** in a keyring
that has never seen it. If you want to see it before the real run, point
`verify-published --keyserver` at the two targets with a throwaway key id first.

## What must not happen

- **Do not rotate again.** The rotation is complete and re-running it would
  invalidate the evidence in [ADR-004] without addressing anything.
- **Do not generate a revocation certificate.** The one that exists was made
  when the key was; this procedure publishes it. `key-handoff.sh` has no code
  path that could mint one, and `task test:key-handoff` asserts that.
- **Do not delete the retired public key.** `v1.2.0` and every pre-cutover
  signature verify against it and nothing else. Revoking a key does not
  invalidate the signatures it made while valid; deleting its public half does.
- **Do not move, re-sign or recreate the `v1.2.0` tag.** Settled in [ADR-004]
  decision 3.
- **Do not put any of this material into the repository, Actions secrets,
  artifacts, caches, logs, or an issue comment.**

## After both steps

Both are operator-attested. Nothing in CI can confirm either, which is the whole
reason they are still open. When both have actually happened, tick the two
remaining acceptance criteria on [#147] and close it:

- replacement credentials backed up and retrieval verified, private key stored
  apart from the passphrase;
- the retired key's revocation published and the revoked state verified through
  the public distribution path.

Until then #147 stays open. It is not evidence that production needs another
rotation.

[#147]: https://github.com/kjanat/gpg-signing-service/issues/147
[#148]: https://github.com/kjanat/gpg-signing-service/pull/148
[ADR-004]: adr/ADR-004-retired-key-revocation.md
