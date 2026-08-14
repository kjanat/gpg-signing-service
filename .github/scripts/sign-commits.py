#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from typing import NoReturn

DEFAULT_BRANCH = os.environ.get("DEFAULT_BRANCH") or "master"
ALLOW_RESIGN = os.environ.get("ALLOW_RESIGN") == "true"
SIGN_OTHERS = os.environ.get("SIGN_OTHERS") == "true"
SCAN_LIMIT = os.environ.get("SCAN_LIMIT", "").strip()
BASE_REF = os.environ.get("BASE_REF", "").strip()

ARMOR_MARKER = b"BEGIN PGP SIGNATURE"


def escape(message: str) -> str:
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def warn(message: str) -> None:
    print(f"::warning::{escape(message)}")


def fail(message: str) -> NoReturn:
    sys.exit(f"::error::{escape(message)}")


def git(*args: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(["git", *args], input=stdin, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        fail(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def gpg_sign(*args: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(["gpg-sign", *args], input=stdin, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        fail(f"gpg-sign {' '.join(args)} failed: {detail}")
    return result.stdout


def gpg(*args: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(["gpg", *args], input=stdin, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        fail(f"gpg {' '.join(args)} failed: {detail}")
    return result.stdout


def request_signature(payload: bytes) -> bytes:
    signature = gpg_sign("sign", stdin=payload)
    if ARMOR_MARKER not in signature:
        fail(f"signing service returned no signature: {signature!r}")
    return signature.strip(b"\n")


def keyring(armored: bytes) -> str:
    home = tempfile.mkdtemp(prefix="sign-commits-")
    imported = subprocess.run(
        ["gpg", "--homedir", home, "--batch", "--quiet", "--import"],
        input=armored,
        capture_output=True,
    )
    listing = subprocess.run(
        ["gpg", "--homedir", home, "--batch", "--list-keys", "--with-colons"],
        capture_output=True,
    )
    if not listing.stdout.startswith(b"pub:") and b"\npub:" not in listing.stdout:
        detail = imported.stderr.decode(errors="replace").strip()
        fail(f"could not import the public key: {detail}")
    return home


def key_identities(armored: bytes) -> set[str]:
    listing = gpg("--show-keys", "--with-colons", stdin=armored)

    emails: set[str] = set()
    for line in listing.decode(errors="replace").splitlines():
        fields = line.split(":")
        if fields[0] == "uid" and len(fields) > 9 and "<" in fields[9]:
            emails.add(fields[9].rsplit("<", 1)[1].rstrip(">").lower())

    if not emails:
        fail("the signing key carries no user ID with an email address")
    return emails


def verify(commit: bytes, home: str) -> None:
    ok, detail = verify_status(commit, home)
    if not ok:
        fail(f"{commit.decode()} did not verify: {detail}")


def verify_status(commit: bytes, home: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["git", "verify-commit", "--raw", commit.decode()],
        capture_output=True,
        env={**os.environ, "GNUPGHOME": home},
    )
    detail = result.stderr.decode(errors="replace").strip()
    good = result.returncode == 0 and b"[GNUPG:] GOODSIG" in result.stderr
    return good, detail


def header_of(raw: bytes) -> bytes:
    header, separator, _ = raw.partition(b"\n\n")
    if not separator:
        fail("malformed commit object: no header/message separator")
    return header


def parents_of(raw: bytes) -> list[bytes]:
    return [
        line.split(b" ", 1)[1]
        for line in header_of(raw).split(b"\n")
        if line.startswith(b"parent ")
    ]


def is_signed(raw: bytes) -> bool:
    return any(line.startswith(b"gpgsig ") for line in header_of(raw).split(b"\n"))


def committer_email(raw: bytes) -> str:
    for line in header_of(raw).split(b"\n"):
        if line.startswith(b"committer ") and b"<" in line:
            return line.rsplit(b">", 1)[0].rsplit(b"<", 1)[1].decode().lower()
    return ""


def unsigned_object(raw: bytes, parents: list[bytes]) -> bytes:
    header, _, message = raw.partition(b"\n\n")
    lines = header.split(b"\n")
    out: list[bytes] = []
    index = 0
    placed = False

    while index < len(lines):
        line = lines[index]

        if line.startswith(b"gpgsig "):
            index += 1
            while index < len(lines) and lines[index].startswith(b" "):
                index += 1
            continue

        if line.startswith(b"parent "):
            if not placed:
                out.extend(b"parent " + parent for parent in parents)
                placed = True
            index += 1
            continue

        out.append(line)
        index += 1

    return b"\n".join(out) + b"\n\n" + message


def with_signature(payload: bytes, signature: bytes) -> bytes:
    armor = signature.split(b"\n")
    gpgsig = [b"gpgsig " + armor[0]] + [b" " + line for line in armor[1:]]
    header, _, message = payload.partition(b"\n\n")
    return b"\n".join(header.split(b"\n") + gpgsig) + b"\n\n" + message


def scan_bound() -> list[str]:
    if not SCAN_LIMIT:
        return []
    if not (SCAN_LIMIT.isascii() and SCAN_LIMIT.isdecimal() and SCAN_LIMIT.strip("0")):
        fail(f"scan_limit must be a positive integer, got {SCAN_LIMIT!r}")
    return [f"--max-count={SCAN_LIMIT}"]


def last_signed(home: str) -> str:
    objects = subprocess.run(
        ["git", "cat-file", "--batch"],
        input=git("rev-list", *scan_bound(), "HEAD"),
        capture_output=True,
    )
    if objects.returncode != 0:
        detail = objects.stderr.decode(errors="replace").strip()
        fail(f"git cat-file --batch failed: {detail}")

    data = objects.stdout
    offset = 0
    while offset < len(data):
        end = data.index(b"\n", offset)
        sha, _, size = data[offset:end].split(b" ")
        offset = end + 1
        if is_signed(data[offset : offset + int(size)]) and verify_status(sha, home)[0]:
            return sha.decode()
        offset += int(size) + 1

    scope = f"the last {SCAN_LIMIT} commit(s) on HEAD" if SCAN_LIMIT else "HEAD"
    fail(f"no verified commit in {scope}; pass base explicitly")


def resolve_base(branch: str, home: str) -> str:
    if BASE_REF:
        if SCAN_LIMIT:
            discarded = f"scan_limit={SCAN_LIMIT} was discarded because base={BASE_REF}"
            reason = "the scan for the last signed commit only runs when base is blank"
            warn(f"{discarded} pins the range; {reason}")
        return git("rev-parse", "--verify", f"{BASE_REF}^{{commit}}").strip().decode()
    if branch == DEFAULT_BRANCH:
        return last_signed(home)
    return git("merge-base", "HEAD", f"origin/{DEFAULT_BRANCH}").strip().decode()


def main() -> None:
    branch = git("rev-parse", "--abbrev-ref", "HEAD").strip().decode()
    if branch == "HEAD":
        fail("HEAD is detached; check out the branch you want signed")

    armored = gpg_sign("public-key")
    identities = key_identities(armored)
    home = keyring(armored)

    head = git("rev-parse", "HEAD").strip()
    base = resolve_base(branch, home)
    commits = git("rev-list", "--reverse", "--topo-order", f"{base}..HEAD").split()
    if not commits:
        if base != head.decode():
            warn(
                f"No commits in {base}..HEAD; nothing was signed. Check that base "
                "is an ancestor of HEAD on the branch you dispatched."
            )
        elif BASE_REF:
            remedy = "pass the commit before the first one you want signed"
            warn(
                f"base={BASE_REF} resolved to {base}, which is HEAD itself; base is "
                f"an exclusive lower bound, so the range is empty — {remedy}."
            )
        elif branch == DEFAULT_BRANCH:
            print(f"Nothing to sign; HEAD ({base}) is already signed and verified.")
        else:
            print(
                f"Nothing to sign; {branch} adds no commits on top of "
                f"origin/{DEFAULT_BRANCH} ({base})."
            )
        return

    raw = {commit: git("cat-file", "commit", commit.decode()) for commit in commits}
    mine = {commit: committer_email(raw[commit]) in identities for commit in commits}
    ours = {commit: SIGN_OTHERS or mine[commit] for commit in commits}

    stale: set[bytes] = set()
    for commit in commits:
        moved = any(parent in stale for parent in parents_of(raw[commit]))
        if moved or (ours[commit] and not is_signed(raw[commit])):
            stale.add(commit)

    if not stale:
        others = sum(1 for commit in commits if not mine[commit])
        if others == len(commits) and not SIGN_OTHERS:
            warn(
                f"Nothing was signed: all {others} commit(s) in {base}..HEAD were "
                "committed by identities the key does not carry — dispatch with "
                "sign_others to include them."
            )
        else:
            print(f"Nothing to sign in {base}..HEAD ({others} commit(s) by others).")
        return

    resign = [commit for commit in stale if is_signed(raw[commit])]
    if resign and not ALLOW_RESIGN:
        for commit in commits:
            if commit in resign:
                print(f"  would re-sign {commit.decode()[:8]}")
        blocked = f"would rewrite {len(resign)} already-signed commit(s) below the tip"
        remedy = "move the base forward or dispatch with allow_resign"
        fail(f"signing {len(stale)} commit(s) {blocked}; {remedy}")

    rewritten: dict[bytes, bytes] = {}
    for commit in commits:
        if commit not in stale:
            continue
        parents = [rewritten.get(p, p) for p in parents_of(raw[commit])]
        payload = unsigned_object(raw[commit], parents)
        if ours[commit]:
            body = with_signature(payload, request_signature(payload))
            mark = "signed  "
        else:
            body = payload
            mark = "reparent"
        new = git(
            "hash-object",
            "-t",
            "commit",
            "-w",
            "--stdin",
            stdin=body,
        ).strip()
        if ours[commit]:
            verify(new, home)
        rewritten[commit] = new
        print(f"  {mark} {commit.decode()[:8]} -> {new.decode()[:8]}")

    signed = sum(1 for commit in rewritten if ours[commit])
    print(f"Signed {signed} of {len(commits)} commit(s) in {base}..HEAD")
    _ = git("update-ref", "HEAD", rewritten.get(head, head).decode())


if __name__ == "__main__":
    main()
