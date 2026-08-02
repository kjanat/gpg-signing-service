#!/usr/bin/env python3
import os
import subprocess
import sys

SERVICE = os.environ["SIGNING_SERVICE_URL"].rstrip("/")
TOKEN = os.environ["OIDC_TOKEN"]
DEFAULT_BRANCH = os.environ.get("DEFAULT_BRANCH") or "master"
ALLOW_RESIGN = os.environ.get("ALLOW_RESIGN") == "true"
SIGN_OTHERS = os.environ.get("SIGN_OTHERS") == "true"

ARMOR_MARKER = b"BEGIN PGP SIGNATURE"


def git(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", *args], input=stdin, capture_output=True, check=True
    ).stdout


def request_signature(payload: bytes) -> bytes:
    result = subprocess.run(
        [
            "curl",
            "-sf",
            "-X",
            "POST",
            f"{SERVICE}/sign",
            "-H",
            f"Authorization: Bearer {TOKEN}",
            "-H",
            "Content-Type: text/plain",
            "--data-binary",
            "@-",
        ],
        input=payload,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        sys.exit(
            f"::error::signing request failed (curl {result.returncode}): {detail}"
        )

    signature = result.stdout
    if ARMOR_MARKER not in signature:
        sys.exit(f"::error::signing service returned no signature: {signature!r}")
    return signature.strip(b"\n")


def header_of(raw: bytes) -> bytes:
    header, separator, _ = raw.partition(b"\n\n")
    if not separator:
        sys.exit("::error::malformed commit object: no header/message separator")
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


def key_identities() -> set[str]:
    fetch = subprocess.run(
        ["curl", "-sf", f"{SERVICE}/public-key"], capture_output=True
    )
    if fetch.returncode != 0:
        detail = fetch.stderr.decode(errors="replace").strip()
        sys.exit(f"::error::could not fetch the public key: {detail}")

    listing = subprocess.run(
        ["gpg", "--show-keys", "--with-colons"], input=fetch.stdout, capture_output=True
    )
    if listing.returncode != 0:
        detail = listing.stderr.decode(errors="replace").strip()
        sys.exit(f"::error::could not read the public key: {detail}")

    emails: set[str] = set()
    for line in listing.stdout.decode(errors="replace").splitlines():
        fields = line.split(":")
        if fields[0] == "uid" and len(fields) > 9 and "<" in fields[9]:
            emails.add(fields[9].rsplit("<", 1)[1].rstrip(">").lower())

    if not emails:
        sys.exit("::error::the signing key carries no user ID with an email address")
    return emails


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


def resolve_base() -> str:
    base = os.environ.get("BASE_REF", "").strip()
    if base:
        return base
    return git("merge-base", "HEAD", f"origin/{DEFAULT_BRANCH}").strip().decode()


def main() -> None:
    branch = git("rev-parse", "--abbrev-ref", "HEAD").strip().decode()
    if branch == DEFAULT_BRANCH:
        sys.exit(f"::error::refusing to rewrite history on {DEFAULT_BRANCH}")

    base = resolve_base()
    commits = git("rev-list", "--reverse", "--topo-order", f"{base}..HEAD").split()
    if not commits:
        print(f"No commits in {base}..HEAD; nothing to sign.")
        return

    raw = {commit: git("cat-file", "commit", commit.decode()) for commit in commits}
    identities: set[str] = set() if SIGN_OTHERS else key_identities()
    ours = {
        commit: SIGN_OTHERS or committer_email(raw[commit]) in identities
        for commit in commits
    }

    stale: set[bytes] = set()
    for commit in commits:
        moved = any(parent in stale for parent in parents_of(raw[commit]))
        if moved or (ours[commit] and not is_signed(raw[commit])):
            stale.add(commit)

    if not stale:
        skipped = sum(1 for commit in commits if not ours[commit])
        print(f"Nothing to sign in {base}..HEAD ({skipped} commit(s) by others).")
        return

    resign = [commit for commit in stale if is_signed(raw[commit])]
    if resign and not ALLOW_RESIGN:
        for commit in commits:
            if commit in resign:
                print(f"  would re-sign {commit.decode()[:8]}")
        blocked = f"would rewrite {len(resign)} already-signed commit(s) below the tip"
        remedy = "move the base forward or dispatch with allow_resign"
        sys.exit(f"::error::signing {len(stale)} commit(s) {blocked}; {remedy}")

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
        rewritten[commit] = new
        print(f"  {mark} {commit.decode()[:8]} -> {new.decode()[:8]}")

    head = git("rev-parse", "HEAD").strip()
    signed = sum(1 for commit in rewritten if ours[commit])
    print(f"Signed {signed} of {len(commits)} commit(s) in {base}..HEAD")
    _ = git("update-ref", "HEAD", rewritten.get(head, head).decode())


if __name__ == "__main__":
    main()
