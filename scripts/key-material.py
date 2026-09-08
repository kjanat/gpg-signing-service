#!/usr/bin/env python3
"""Report OpenPGP key packets carried by tracked files.

#147: an encrypted secret-key packet belonging to the deployment's own signing
key -- `62E75E54497815DD`, the `KEY_ID` in wrangler.toml and the key that signed
v1.2.0 -- was in the test corpus in twelve places. Two of them were stamped with
that key's own creation time; the other ten carried the same public point and the
same S2K-protected secret bytes under an earlier timestamp, which is a different
fingerprint and the same key. A passphrase the repository does not hold was the
only thing between the public tree and a usable signing key.

gitleaks does not close this. Its `private-key` rule keys on a literal armor
header, and `src/utils/armor.ts` explains at length why this repository composes
those headers at run time instead of writing them -- so the material that matters
most here is precisely the material gitleaks is blindest to. This reads the
bytes instead: any base64 run in a tracked file is decoded and checked for an
OpenPGP packet header, header line or no header line.

Two rules, and they fail for different reasons:

  secret   A secret-key or secret-subkey packet (tags 5 and 7) in a tracked
           file, whatever key it belongs to. Tests generate keys at run time --
           `openpgp.generateKey` in fourteen suites already -- and shape fixtures
           come from `src/__tests__/helpers/private-key-fixture.ts`, so there is
           no remaining reason for a static private key to be in the tree. This
           rule needs no knowledge of which key is live, which is what makes it
           survive the rotation #147 asks for.

  retired  A packet, public or secret, whose public key material is a retired
           production key's. Keyed on a SHA-256 over the version byte, the
           algorithm byte and the public material -- everything the fingerprint
           covers *except* the four creation-time bytes. Re-stamping a key
           changes its fingerprint while leaving the secret exactly where it was,
           which is how ten of the twelve copies above hid in plain sight; this
           digest does not move when the timestamp does.

The retired digests below are derived from public material and identify a key
without reproducing any part of it, which is the constraint #147 sets: the guard
may not itself contain what it is guarding against.

There are no exclusions. An earlier version of this file excused `.gitleaks.toml`
-- whose historical allowlist matches pre-#147 findings by their exact text, and
so used to spell the ciphertext out -- and that was the wrong shape of fix: the
one file the gate skipped was the one file still carrying the packet, and it is
also the one file gitleaks itself will not scan, because its default allowlist
drops every path ending `gitleaks.toml` (measured in test-gitleaks-contract.sh,
not assumed). Those entries now write their literal runs one `\\xNN` per
character, which is the same regular language and no longer a base64 run, so the
config is read here like anything else. `scripts/allowlist-regex.py` performs and
checks that; `scripts/test-gitleaks-contract.sh` proves the two forms accept the
same strings against the scanner.

Usage:
    key-material.py PATH...              report findings, exit 1 if any
    key-material.py --identities PATH... print each packet's identity digest
    key-material.py --considered PATH... print each path that will be read
    key-material.py --retired DIGEST ... add a digest to the retired set

Exit codes: 0 clean, 1 findings, 2 usage error.
"""

from __future__ import annotations

import base64
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Retired production signing keys, by identity digest (see module docstring).
#
# These are not secrets and not key material: a SHA-256 cannot be run backwards
# into the point it summarises. The comment names each key by its public
# fingerprint, which is on every signature it ever made.
RETIRED_IDENTITIES = {
    # 806D3A1B9F957D6731950BCA62E75E54497815DD -- the key wrangler.toml's KEY_ID
    # names and the v1.2.0 tag carries. Also covers
    # 5D213ED994DD735E68FBC67411EB425655B81A8A, the same keypair re-stamped in
    # 2024, because the digest ignores creation time.
    "8fa75e7da087baa229d21bbed9acf069abf7b86341b622515a5a3597bbdf211e": (
        "806D3A1B9F957D6731950BCA62E75E54497815DD"
    ),
}

SECRET_TAGS = {5, 7}
PUBLIC_TAGS = {6, 14}
KEY_TAGS = SECRET_TAGS | PUBLIC_TAGS

# Public-key algorithms OpenPGP defines. An arbitrary byte landing here is what
# separates a key packet from 1-in-256 of every base64 blob in the repository.
ALGORITHMS = {1, 2, 3, 16, 17, 18, 19, 22, 23, 25, 26, 27, 28}

# A base64 run long enough to hold a v4 key packet on its own. Short runs --
# lockfile digests, inline images, git hashes -- cannot, so they are never
# decoded.
RUN = re.compile(r"[A-Za-z0-9+/=]{60,}")

# A run long enough to be one *line* of an armor body. Armor wraps at 64, and a
# line this long inside a quoted string, a TOML array or a Go slice is a line of
# a key that someone reindented rather than a coincidence.
LINE_RUN = re.compile(r"[A-Za-z0-9+/]{40,}")

# An `=` with more base64 behind it is not padding: it is the checksum line's
# `=`, or a `\z` anchor, glued on when the armor was folded onto one line.
# Decoding stops there rather than failing on the whole run.
EMBEDDED_PAD = re.compile(r"=(?=[A-Za-z0-9+/])")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.detail}"


def packet_header(raw: bytes) -> tuple[int, int, int] | None:
    """`(tag, header length, body length)` if `raw` opens with a packet."""
    if len(raw) < 2 or not raw[0] & 0x80:
        return None
    if raw[0] & 0x40:  # new format
        tag = raw[0] & 0x3F
        first = raw[1]
        if first < 192:
            return tag, 2, first
        if first < 224 and len(raw) >= 3:
            return tag, 3, ((first - 192) << 8) + raw[2] + 192
        if first == 255 and len(raw) >= 6:
            return tag, 6, int.from_bytes(raw[2:6], "big")
        return None  # partial lengths never open a key packet
    tag = (raw[0] & 0x3C) >> 2
    length_type = raw[0] & 0x03
    sizes = {0: (2, 1), 1: (3, 2), 2: (5, 4)}
    if length_type not in sizes:
        return None
    header, width = sizes[length_type]
    if len(raw) < header:
        return None
    return tag, header, int.from_bytes(raw[header - width : header], "big")


def public_material(body: bytes) -> bytes | None:
    """The public fields of a v4/v6 key packet body, minus its creation time.

    Everything the fingerprint is computed over except the four timestamp bytes,
    so a key that has been re-stamped still answers to the same digest.
    """
    if len(body) < 6 or body[0] not in (4, 5, 6) or body[5] not in ALGORITHMS:
        return None
    algorithm = body[5]
    offset = 6
    if algorithm in (18, 19, 22, 25, 26, 27, 28):  # curve algorithms carry an OID
        if offset >= len(body):
            return None
        offset += 1 + body[offset]
    # Then MPIs, or -- for the modern fixed-width algorithms -- raw octets. Both
    # are read the same way here: an MPI count is what v4 uses, and the fixed
    # forms appear as a single trailing field, so the walk stops when the
    # remaining bytes stop parsing as one.
    while offset + 2 <= len(body):
        bits = int.from_bytes(body[offset : offset + 2], "big")
        width = (bits + 7) // 8
        if bits == 0 or offset + 2 + width > len(body):
            break
        offset += 2 + width
    if offset <= 6:
        return None
    return body[0:1] + body[5:offset]


def identify(raw: bytes) -> tuple[int, str] | None:
    """`(tag, identity digest)` if `raw` opens with an OpenPGP key packet."""
    header = packet_header(raw)
    if header is None:
        return None
    tag, header_length, body_length = header
    if tag not in KEY_TAGS or body_length < 10:
        return None
    body = raw[header_length : header_length + body_length]
    if len(body) < body_length:  # truncated; not a whole key packet
        return None
    material = public_material(body)
    if material is None:
        return None
    return tag, hashlib.sha256(material).hexdigest()


def candidates(text: str) -> list[tuple[int, str]]:
    """`(line number, base64 run)` for every run that could hold a key packet.

    Runs are read two ways. Consecutive lines that each carry an armor-width run
    is armor as a file holds it -- and the run is taken from *within* each line,
    not from the whole line, so quoting and indentation do not hide it. A fixture
    written as a TypeScript array of strings, a Go slice or a YAML block is the
    same eight lines with decoration around them.

    A long enough run inside a single line is the other form: armor folded into
    one string literal, with `\\n` where its newlines were. That pass runs twice,
    once over an unescaped copy. `.gitleaks.toml` is the reason -- its historical
    entries are regexes, so the packet is there with `\\n` for its line breaks
    *and* `\\+` for every plus, and a reader that only knows about `\\n` decodes
    none of it. Anything that survives one round of regex escaping is still key
    material.
    """
    found: list[tuple[int, str]] = []
    lines = text.split("\n")

    run: list[str] = []
    start = 0
    for number, line in enumerate(lines, start=1):
        widest = max(LINE_RUN.findall(line), key=len, default="")
        if widest:
            if not run:
                start = number
            run.append(widest)
            continue
        if run:
            found.append((start, "".join(run)))
            run = []
    if run:
        found.append((start, "".join(run)))

    for number, line in enumerate(lines, start=1):
        folded = line.replace("\\n", "")
        unescaped = folded.replace("\\+", "+").replace("\\/", "/").replace("\\=", "=")
        for variant in {folded, unescaped}:
            for match in RUN.finditer(variant):
                found.append((number, match.group(0)))
    return found


def decode(run: str) -> list[bytes]:
    """Every plausible byte reading of `run`.

    A run lifted out of the middle of a line can start on any of four base64
    phases, and only one of them is the alignment the armor was written in.
    Trying all four is four decodes of a string that is already in memory.
    """
    out: list[bytes] = []
    for phase in range(4):
        chunk = EMBEDDED_PAD.split(run[phase:], maxsplit=1)[0]
        chunk = chunk[: len(chunk) - len(chunk) % 4]
        if len(chunk) < 20:
            continue
        try:
            out.append(base64.b64decode(chunk, validate=True))
        except (ValueError, base64.binascii.Error):
            continue
    return out


def contents(path: Path) -> str | None:
    """Every byte of `path` as text, or `None` if it could not be read at all.

    Decoded latin-1 rather than utf-8, because latin-1 cannot fail: a file that
    is not valid utf-8 is still a file that can hold a base64 run, and skipping
    it would be an exclusion by encoding rather than by name. Base64 is ASCII,
    which latin-1 and utf-8 agree on, so nothing is read differently.
    """
    try:
        return path.read_bytes().decode("latin-1")
    except OSError:
        return None


def scan(path: Path, root: Path, retired: dict[str, str]) -> list[Finding]:
    text = contents(path)
    if text is None:
        return []
    name = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for line, run in candidates(text):
        for raw in decode(run):
            result = identify(raw)
            if result is None:
                continue
            tag, digest = result
            if tag in SECRET_TAGS and (line, "secret") not in seen:
                seen.add((line, "secret"))
                findings.append(
                    Finding(
                        name,
                        line,
                        "secret",
                        "an OpenPGP secret-key packet is in a tracked file; "
                        "generate keys at run time instead "
                        "(src/__tests__/helpers/private-key-fixture.ts)",
                    )
                )
            if digest in retired and (line, "retired") not in seen:
                seen.add((line, "retired"))
                findings.append(
                    Finding(
                        name,
                        line,
                        "retired",
                        f"key material belonging to retired signing key "
                        f"{retired[digest]} is in a tracked file",
                    )
                )
    return findings


def identities(path: Path) -> list[str]:
    text = contents(path)
    if text is None:
        return []
    out: list[str] = []
    for _, run in candidates(text):
        for raw in decode(run):
            result = identify(raw)
            if result is not None and result[1] not in out:
                out.append(result[1])
    return out


def main(argv: list[str]) -> int:
    retired = dict(RETIRED_IDENTITIES)
    mode = "scan"
    paths: list[str] = []

    rest = list(argv)
    while rest:
        argument = rest.pop(0)
        if argument == "--identities":
            mode = "identities"
        elif argument == "--considered":
            mode = "considered"
        elif argument == "--retired":
            if not rest:
                print("--retired needs a digest", file=sys.stderr)
                return 2
            retired[rest.pop(0)] = "a key named on the command line"
        elif argument.startswith("-"):
            print(f"unknown option {argument}", file=sys.stderr)
            return 2
        else:
            paths.append(argument)

    if not paths:
        print(__doc__.split("Usage:")[1].strip(), file=sys.stderr)
        return 2

    root = Path.cwd()
    findings: list[Finding] = []
    for name in paths:
        path = Path(name)
        # The only thing that is not read is something that is not a file to
        # read: a directory, a submodule, a broken symlink. There is no name,
        # path or extension this treats differently, and
        # `scripts/test-key-material.sh` holds that open by comparing
        # `--considered` against every tracked regular file.
        if not path.is_file():
            continue
        if mode == "considered":
            print(name)
        elif mode == "identities":
            for digest in identities(path):
                print(digest)
        else:
            findings.extend(scan(path, root, retired))

    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
