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
most here is precisely the material gitleaks is blindest to. This reads the bytes
instead, and it reads them through each way a key gets written down:

  base64      any run of base64, decoded on all four phases, in the standard
              alphabet and in url-safe. Runs are joined across consecutive lines,
              so armor rewrapped to any width -- 64, 40, 32, 4 -- is the same run
              once the line breaks are gone. There is no minimum line width; a
              threshold there is a wrapping width an attacker gets to choose.

  hex         the same two passes over hex digits, separators removed first, so
              `948604...` and the `94 86 04` a hex dump prints are read like the
              bytes they spell.

  raw         the bytes themselves, because `gpg --export-secret-keys` without
              `--armor` writes packet bytes and a committed `secring.gpg` has no
              run of anything for a run reader to find.

  escaped     all of the above again over a copy with `\\n`, `\\+` and `\\xNN`
              undone, because a key folded into one string literal, run through
              regex escaping, or spelled a byte at a time is still a key. The
              `\\xNN` form is the one `.gitleaks.toml` uses, and it is the one
              route with a permitted case: see below.

Every decode is then searched at *every* offset for something that opens a key
packet, so a run that arrives with a prefix glued to it -- an indent, a quote, a
neighbouring line -- is not a run this walks past.

What that does not cover is a key that has been *transformed* rather than
encoded: compressed, encrypted again, split across files, spelled in some
alphabet nobody has thought of. No content scanner closes that, and this one does
not claim to. It is the second line. The first is that no fixture needs a key at
all -- `src/__tests__/helpers/private-key-fixture.ts` composes the shape ones,
fourteen suites generate real ones at run time -- so anything this would have to
catch had to be put there deliberately.

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

## The one permitted case, and why it is not an exclusion

There are no excluded files. An earlier version of this file excused
`.gitleaks.toml` by name -- whose historical allowlist matches pre-#147 findings
by their exact text, and so spells out every byte of the spans it matches -- and
that was the wrong shape of fix: the one file the gate skipped was the one file
still carrying the packet, and it is also the one file gitleaks itself will not
scan, because its default allowlist drops every path ending `gitleaks.toml`
(measured in test-gitleaks-contract.sh, not assumed).

What replaces it is a rule about the *shape of the text*, checked in whatever
file it appears in. A key packet reached only by undoing `\\xNN` escapes is
permitted when both of these hold, and reported when either does not:

  1. The escapes sit inside one complete, whole-match allowlist entry: a single
     `'''\\A...\\z'''` line inside a `regexes = [` array. A partial entry, an
     unanchored one, an entry split across lines, or the same escapes anywhere
     else in the same file are all reported.

  2. The key is one `RETIRED_IDENTITIES` already names. A freshly generated key
     is reported even inside a perfectly formed anchored entry, so the entry
     shape is not a smuggling route -- and after #147's rotation the replacement
     key cannot be written here either, because it is not retired.

That is what an exact-match regex over already-published history needs and
nothing beyond it. `scripts/allowlist-regex.py --check` holds the other side --
no entry may spell a long run out in plain base64 -- and
`scripts/test-gitleaks-contract.sh` proves against the scanner that the escaped
and plain forms accept the same strings.

This is a representation, not a secrecy measure. An exact-match entry cannot
stop describing the bytes it matches, and `allowlist-regex.py --decode` will
print them; the pre-#147 ciphertext is in published history either way. What
ends that exposure is the operator rotating the key. What this ends is a tracked
file carrying live-format key material, and a gate with a named hole in it.

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

# The shortest base64 run this will decode. Not a judgement about what looks like
# a key: it is the arithmetic floor. The smallest thing `identify` can accept is
# a two-byte header over a ten-byte body, and twelve bytes is sixteen base64
# characters, plus the three a phase shift can eat.
MIN_RUN = 20

# The same floor in hex, which spends two characters on a byte instead of four
# on three.
MIN_HEX_RUN = 24

# A base64 run inside a single line, `=` included -- armor folded into one string
# literal keeps its padding and its checksum line's `=`.
RUN = re.compile(r"[A-Za-z0-9+/=]{%d,}" % MIN_RUN)

# A base64 run inside one line of a *wrapped* block. No length floor: the width a
# block is wrapped at is chosen by whoever wrote it, so a floor here is a bypass
# with a number on it. Lines are joined and the joined run is what gets measured.
LINE_RUN = re.compile(r"[A-Za-z0-9+/]+")

# The same two, over hex digits. A key written `9486046a...`, or a byte at a time
# as `\x94\x86\x04\x6a...`, is a key.
HEX_RUN = re.compile(r"[0-9A-Fa-f]{%d,}" % MIN_HEX_RUN)
HEX_LINE_RUN = re.compile(r"[0-9A-Fa-f]+")

# What a hex dump puts between its bytes. Taken out before the hex passes run,
# because `94 86 04` and `948604` are the same three bytes and only one of them
# is a run. Nothing is lost by doing it always: removing separators can only join
# runs, never split one.
HEX_SEPARATOR = re.compile(r"[\s:;,]+")

# base64url, which spells the last two alphabet characters `-` and `_`. Trying
# the translation costs one pass and closes an encoding that every JWT in the
# corpus is already written in.
URLSAFE = str.maketrans("-_", "+/")

# An `=` with more base64 behind it is not padding: it is the checksum line's
# `=`, or a `\z` anchor, glued on when the armor was folded onto one line.
# Decoding stops there rather than failing on the whole run.
EMBEDDED_PAD = re.compile(r"=(?=[A-Za-z0-9+/])")

# `\xNN`, the form `.gitleaks.toml`'s historical entries write their literal runs
# in. Undoing it is how this file reads its own config; see the module docstring
# for the two conditions that make an undone run permitted rather than reported.
HEX_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")

# One complete whole-match allowlist entry: an entire `'''\A...\z'''` on its own
# line. Anchored at both ends, because the anchors are the property that makes an
# entry describe one historical finding rather than a prefix of anything longer;
# and with no `'''` inside, so the line is one entry rather than two with
# something parked between them.
WHOLE_MATCH_ENTRY = re.compile(r"\s*'''\\A(?:(?!''').)*\\z''',?\s*")
REGEX_ARRAY_OPEN = re.compile(r"\s*regexes\s*=\s*\[\s*")
REGEX_ARRAY_CLOSE = re.compile(r"\]\s*,?\s*")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.detail}"


@dataclass(frozen=True)
class Candidate:
    """A run of encoded bytes, the lines it came from, and how it was reached.

    `pieces` is `(index in run, source line)` for each line that contributed, so
    a packet found inside the run can be attributed to the lines its own bytes
    came from rather than to wherever the run happened to start. A finding points
    at the line the key begins on, and the permitted case in the module docstring
    is decided against every line the key covers.
    """

    run: str
    pieces: tuple[tuple[int, int], ...]
    escaped: bool
    reader: str = "base64"

    @property
    def line(self) -> int:
        return self.pieces[0][1]

    def covering(self, start: int, end: int) -> tuple[int, ...]:
        """The source lines holding run characters `start` through `end`."""
        out = []
        for index, (offset, line) in enumerate(self.pieces):
            following = (
                self.pieces[index + 1][0]
                if index + 1 < len(self.pieces)
                else len(self.run)
            )
            if offset < end and following > start:
                out.append(line)
        return tuple(out) or (self.line,)


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


def public_material(body: bytes) -> tuple[bytes, int] | None:
    """The public fields of a v4/v6 key packet body, and where they end.

    Everything the fingerprint is computed over except the four timestamp bytes,
    so a key that has been re-stamped still answers to the same digest. The end
    offset is where a secret-key packet's S2K fields start, which is what
    `secret_shape` reads to tell a key from a coincidence.
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
    return bytes(body[0:1]) + bytes(body[5:offset]), offset


# How a v4 secret-key packet says its secret half is protected: unencrypted,
# one of the legacy symmetric algorithm ids, or a checksummed/AEAD form.
S2K_USAGE = {0, 253, 254, 255} | set(range(1, 14))
SYMMETRIC = set(range(1, 14))


def secret_shape(body: bytes, offset: int) -> bool:
    """Whether a v4 secret-key body continues the way a real one does.

    Four base64 phases times every offset is a lot of readings, and a run that
    holds one key packet holds several near-misses of it -- the same bytes read
    one character out of alignment. Public fields alone let roughly half of those
    through: a version, an algorithm and a length are only three bytes of
    agreement. A secret-key packet has to say next how its secret half is
    protected, and that is the field that separates the key from its own shadow.
    Versions this does not model are left alone rather than guessed at, so an
    unfamiliar packet is still reported.
    """
    if body[0] != 4:
        return True
    if offset >= len(body) or body[offset] not in S2K_USAGE:
        return False
    if body[offset] in (253, 254, 255):
        return offset + 1 < len(body) and body[offset + 1] in SYMMETRIC
    return True


def identify(raw: bytes) -> tuple[int, str, int] | None:
    """`(tag, identity digest, packet length)` if `raw` opens with a key packet."""
    header = packet_header(raw)
    if header is None:
        return None
    tag, header_length, body_length = header
    if tag not in KEY_TAGS or body_length < 10:
        return None
    body = raw[header_length : header_length + body_length]
    if len(body) < body_length:  # truncated; not a whole key packet
        return None
    parsed = public_material(body)
    if parsed is None:
        return None
    material, offset = parsed
    if tag in SECRET_TAGS and not secret_shape(body, offset):
        return None
    return tag, hashlib.sha256(material).hexdigest(), header_length + body_length


# Packet first-bytes that could open a key packet, as a byte class, so a buffer
# is searched for the sixteen of them at the regex engine's speed rather than a
# byte at a time in Python. Everything that matches is then handed to `identify`,
# which rejects it on version, algorithm or length.
KEY_STARTS = bytes(
    sorted(
        byte
        for byte in range(0x80, 0x100)
        if (start := packet_header(bytes([byte, 0, 0, 0, 0, 0]))) is not None
        and start[0] in KEY_TAGS
    )
)
KEY_START = re.compile(b"[" + re.escape(KEY_STARTS) + b"]")


def openings(raw: bytes) -> list[tuple[int, int, int, str]]:
    """`(offset, end, tag, identity digest)` for every key packet inside `raw`.

    Every offset, not just the first, for two reasons that arrive together. An
    unarmored export is packet bytes with no framing, so there is nothing that
    says where to start reading. And a base64 run lifted out of a line can carry
    anything in front of the block -- an indent, a quote, the tail of the line
    above -- which moves the packet off the front of the decode. Measured over
    the tracked tree this reports nothing that is not a packet: a byte has to be
    one of sixteen, then carry a version, an algorithm and a length that parse.
    """
    view = memoryview(raw)
    found: list[tuple[int, int, int, str]] = []
    for match in KEY_START.finditer(raw):
        result = identify(view[match.start() :])
        if result is not None:
            tag, digest, length = result
            found.append((match.start(), match.start() + length, tag, digest))
    return found


def unescape(line: str) -> str:
    """A line with the escapes that hide a base64 run from a reader undone.

    `\\n` because armor folded into one string literal keeps its line breaks as
    escapes; `\\+`, `\\/` and `\\=` because a regex escapes the base64 characters
    that are also metacharacters. Anything that survives one round of escaping is
    still key material.
    """
    folded = line.replace("\\n", "")
    return folded.replace("\\+", "+").replace("\\/", "/").replace("\\=", "=")


def dehex(line: str) -> str:
    """A line with `\\xNN` byte escapes written back as the characters they name."""
    return HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), line)


def blocks(
    lines: list[str], pattern: re.Pattern[str], floor: int
) -> list[tuple[str, tuple[tuple[int, int], ...]]]:
    """`(joined run, pieces)` for each block of consecutive wrapped lines.

    Armor is a run of base64 with line breaks in it, and every fixture shape this
    has to see through -- a TypeScript array of strings, a Go slice, a YAML
    block, a rewrap to some other width -- is that same run with decoration
    between the pieces. Each line contributes its widest run and the block is
    what they concatenate to, so the width the block was wrapped at never comes
    into it. `pieces` records where each line landed in the join, which is what
    lets a packet found inside be attributed back to its own lines.
    """
    found: list[tuple[str, tuple[tuple[int, int], ...]]] = []
    run: list[str] = []
    pieces: list[tuple[int, int]] = []
    width = 0

    def close() -> None:
        nonlocal width
        if run and width >= floor:
            found.append(("".join(run), tuple(pieces)))
        run.clear()
        pieces.clear()
        width = 0

    for number, line in enumerate(lines, start=1):
        widest = max(pattern.findall(line), key=len, default="")
        if widest:
            pieces.append((width, number))
            run.append(widest)
            width += len(widest)
            continue
        close()
    close()
    return found


def candidates(text: str) -> list[Candidate]:
    r"""Every run in `text` that could hold a key packet, however it is written.

    Four questions asked of the text, and of an unescaped copy of it: does a
    block of wrapped lines join into base64, does one line hold a long enough
    run of it, and the same two over hex digits. The base64 passes run twice
    more against the url-safe alphabet, because `-` and `_` are one translation
    away from being the same run.

    The unescaped copy is what makes `.gitleaks.toml` readable here rather than
    excused -- its entries hold their runs a byte at a time -- and the `escaped`
    flag is what lets a finding from that copy be judged against the conditions
    in the module docstring instead of reported unconditionally.
    """
    found: dict[tuple[str, tuple[tuple[int, int], ...], str], bool] = {}

    def offer(
        run: str, pieces: tuple[tuple[int, int], ...], escaped: bool, reader: str
    ) -> None:
        # A run reachable without undoing escapes is never treated as escaped,
        # whichever pass reaches it first.
        key = (run, pieces, reader)
        found[key] = found.get(key, True) and escaped

    def sweep(source: list[str], escaped: bool) -> None:
        for variant in (source, [line.translate(URLSAFE) for line in source]):
            for run, pieces in blocks(variant, LINE_RUN, MIN_RUN):
                offer(run, pieces, escaped, "base64")
            for number, line in enumerate(variant, start=1):
                for match in RUN.finditer(unescape(line)):
                    offer(match.group(0), ((0, number),), escaped, "base64")
        digits = [HEX_SEPARATOR.sub("", unescape(line)) for line in source]
        for run, pieces in blocks(digits, HEX_LINE_RUN, MIN_HEX_RUN):
            offer(run, pieces, escaped, "hex")
        for number, line in enumerate(digits, start=1):
            for match in HEX_RUN.finditer(line):
                offer(match.group(0), ((0, number),), escaped, "hex")

    for source, escaped in sources(text):
        sweep(source, escaped)

    return [
        Candidate(run, pieces, escaped, reader)
        for (run, pieces, reader), escaped in found.items()
    ]


def sources(text: str) -> list[tuple[list[str], bool]]:
    r"""The text, and a copy with `\xNN` undone, each with whether it is escaped.

    The second is skipped when there is nothing to undo, which is not a file this
    treats differently: with no `\xNN` in it the unescaped copy is the same text.
    """
    lines = text.split("\n")
    if not HEX_ESCAPE.search(text):
        return [(lines, False)]
    return [(lines, False), ([dehex(line) for line in lines], True)]


def decode(candidate: Candidate) -> list[tuple[int, bytes]]:
    """`(phase, bytes)` for every plausible byte reading of a candidate's run.

    A run lifted out of the middle of a line can start on any of the phases its
    alphabet packs into a byte -- four for base64, two for hex -- and only one of
    them is the alignment the block was written in. Trying all of them is a
    handful of decodes of a string that is already in memory. The phase comes
    back out because it is what maps a byte offset in the decode to a character
    offset in the run, and from there to the line it was written on.
    """
    run = candidate.run
    out: list[tuple[int, bytes]] = []
    if candidate.reader == "hex":
        for phase in range(2):
            chunk = run[phase:]
            chunk = chunk[: len(chunk) - len(chunk) % 2]
            if len(chunk) < MIN_HEX_RUN - 1:
                continue
            out.append((phase, bytes.fromhex(chunk)))
        return out
    for phase in range(4):
        chunk = EMBEDDED_PAD.split(run[phase:], maxsplit=1)[0]
        chunk = chunk[: len(chunk) - len(chunk) % 4]
        if len(chunk) < MIN_RUN - 3:
            continue
        try:
            out.append((phase, base64.b64decode(chunk, validate=True)))
        except (ValueError, base64.binascii.Error):
            continue
    return out


# How many run characters a byte of a decode came from, per reader, for mapping
# a packet back to the lines it was written on.
PER_BYTE = {"base64": 4 / 3, "hex": 2.0}


def whole_match_entries(text: str) -> frozenset[int]:
    """Line numbers holding one complete `'''\\A...\\z'''` allowlist entry.

    The structural half of the permitted case. Not "this file is the config" --
    nothing here reads a path -- but "these bytes are inside one entry that
    matches exactly one historical finding and nothing longer". An entry that
    lost an anchor, one broken across lines, one outside a `regexes = [` array,
    or anything else on the line is not this, and a key reached through it is
    reported like a key anywhere else.
    """
    found: set[int] = set()
    inside = False
    for number, line in enumerate(text.split("\n"), start=1):
        if REGEX_ARRAY_OPEN.fullmatch(line):
            inside = True
            continue
        if inside and REGEX_ARRAY_CLOSE.fullmatch(line):
            inside = False
            continue
        if inside and WHOLE_MATCH_ENTRY.fullmatch(line):
            found.add(number)
    return frozenset(found)


def permitted(
    candidate: Candidate,
    lines: tuple[int, ...],
    digest: str,
    entries: frozenset[int],
    retired: dict[str, str],
) -> bool:
    """Whether this reading of a packet is the one thing the tree is allowed.

    All three, or it is a finding: reached only by undoing `\\xNN` escapes,
    written entirely inside complete whole-match allowlist entries, and a key
    already named as retired. The last is what stops the entry shape from being
    a smuggling route -- a freshly generated key written this way has no retired
    identity, so it is reported however well formed the entry around it is.
    """
    return (
        candidate.escaped
        and all(line in entries for line in lines)
        and digest in retired
    )


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


def readings(text: str) -> list[tuple[Candidate, tuple[int, ...], int, str]]:
    r"""`(candidate, lines, tag, digest)` for every key packet `text` yields.

    The raw pass has no run to attribute a finding to -- it is reading bytes, not
    something someone wrote down -- so it reports against a candidate that is not
    escaped and therefore never permitted. A key exported without `--armor`
    cannot be excused by the shape of the text around it, because there is no
    text around it. It runs over the unescaped copy as well: `\xNN` per byte is
    how a packet is written down when there is no base64 anywhere in it.
    """
    out: list[tuple[Candidate, tuple[int, ...], int, str]] = []
    for candidate in candidates(text):
        per_byte = PER_BYTE[candidate.reader]
        for phase, raw in decode(candidate):
            for offset, end, tag, digest in openings(raw):
                # A byte offset rounds outwards to the characters that could
                # have held it, which is what the run's pieces are indexed by.
                first = phase + int(offset * per_byte)
                last = phase + int(end * per_byte) + 4
                out.append((candidate, candidate.covering(first, last), tag, digest))
    for source, escaped in sources(text):
        raw_bytes = "\n".join(source).encode("latin-1")
        for offset, _, tag, digest in openings(raw_bytes):
            line = raw_bytes.count(b"\n", 0, offset) + 1
            out.append((Candidate("", ((0, line),), False), (line,), tag, digest))
    return out


def scan(path: Path, root: Path, retired: dict[str, str]) -> list[Finding]:
    text = contents(path)
    if text is None:
        return []
    name = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    entries = whole_match_entries(text)
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for candidate, lines, tag, digest in readings(text):
        if permitted(candidate, lines, digest, entries, retired):
            continue
        line = lines[0]
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
    return sorted(findings, key=lambda finding: (finding.line, finding.rule))


def identities(path: Path) -> list[str]:
    text = contents(path)
    if text is None:
        return []
    out: list[str] = []
    for _, _, _, digest in readings(text):
        if digest not in out:
            out.append(digest)
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
