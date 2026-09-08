#!/usr/bin/env python3
"""Write the literal base64 runs in an allowlist regex as bytes.

`.gitleaks.toml`'s global allowlist excuses findings that pre-date #145/#146 by
matching their exact text, `\\A`-anchored to `\\z`. Some of those findings are
armored key blocks, so an entry describing one used to spell the block out --
which put the deployment's own encrypted secret-key packet in a tracked file, in
the one file gitleaks structurally cannot scan (its default allowlist skips every
path ending `gitleaks.toml`, measured in test-gitleaks-contract.sh).

An exact-match regex cannot stop naming the bytes it matches; that is what makes
it exact. What it can stop doing is naming them in the form the tooling around
them reads. A literal run of base64 written per character as `\\xNN` is the same
regular language -- `\\x6c` and `l` parse to the same RE2 literal, which
`scripts/test-gitleaks-contract.sh` proves against the scanner rather than
asserting -- and it is not a base64 run, so nothing that reads base64 reads it by
accident.

`scripts/key-material.py` is not fooled by it and is not meant to be. It undoes
`\\xNN` like it undoes `\\n` and `\\+`, decodes what comes out, and permits the
result only where two things hold at once: the escapes are inside one complete
`\\A...\\z` entry of a `regexes = [` array, and the key they spell is one it
already knows as retired. A freshly generated key written this way is reported
wherever it is put, including inside a perfectly formed entry in this very
config. So the form below is not what makes the gate pass -- being the
already-published historical corpus, described exactly, is. The form is what
keeps those bytes from also being a base64 run that every other tool in the
repository would pick up.

This is therefore a representation change and not a secrecy one. `--decode`
below reverses it, and the bytes are recoverable from the config by anyone who
wants them, exactly as an exact-match regex requires. What ends the exposure is
the operator rotating the key (#147); what this ends is the tree carrying key
material in a live, directly readable form, and the gate having a named hole in
it.

Usage:
    allowlist-regex.py --plain            text on stdin -> an entry, runs spelled
    allowlist-regex.py --literal          the same entry, runs written as bytes
    allowlist-regex.py --encode           regex on stdin -> bytes form on stdout
    allowlist-regex.py --decode           the inverse
    allowlist-regex.py --check CONFIG...  fail if any entry spells a long run
    allowlist-regex.py --rewrite CONFIG   rewrite a config in place

Exit codes: 0 clean, 1 a run is spelled out, 2 usage error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# How long a literal base64 run may be before it has to be written as bytes.
#
# Just above the 20 characters `scripts/key-material.py` needs before it will
# decode a run at all -- which is the arithmetic floor for a whole key packet,
# not a taste judgement -- so this check and that one meet with nothing between
# them. The detector's permitted case covers escaped runs only; a run spelled out
# in plain base64 inside an entry is reported there like key material anywhere
# else, and this check is what says so first, with a message that names the fix.
# Well above the incidental, too: `=oEGo`, `abcd`, a hex digest, an
# `A1B2C3D4E5F67890` key id -- the short literals that make an entry readable
# stay readable.
MAX_LITERAL_RUN = 24

# Characters that are a base64 alphabet member *and* an RE2 literal on their own.
# `+` is not among them: bare it is a quantifier, so it only ever appears in
# these entries as `\+`, which the tokenizer reads as an escape.
BARE_BASE64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/=")

# `\+`, `\/` and `\=` are the escaped spellings of literals that are also base64.
ESCAPED_BASE64 = {"\\+": "+", "\\/": "/", "\\=": "="}

HEX_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")


def tokenize(pattern: str) -> list[str]:
    """Split a regex into tokens no rewriting may cut in half.

    An escape is its backslash and what it introduces; a character class and a
    repetition are each one token, because `-{5}`'s `5` and a class's contents
    are literal-looking text that is not a literal.
    """
    tokens: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            following = pattern[index + 1]
            if following == "x" and pattern[index + 2 : index + 3] == "{":
                end = pattern.index("}", index) + 1
            elif following == "x":
                end = index + 4
            elif following in "pP" and pattern[index + 2 : index + 3] == "{":
                end = pattern.index("}", index) + 1
            else:
                end = index + 2
            tokens.append(pattern[index:end])
            index = end
        elif char == "[":
            end = index + 1
            if pattern[end : end + 1] == "^":
                end += 1
            if pattern[end : end + 1] == "]":  # a `]` first in a class is literal
                end += 1
            while end < len(pattern) and pattern[end] != "]":
                end += 2 if pattern[end] == "\\" else 1
            tokens.append(pattern[index : end + 1])
            index = end + 1
        elif char == "{":
            end = pattern.find("}", index)
            if end == -1:  # a `{` that opens nothing is a literal brace
                tokens.append(char)
                index += 1
                continue
            tokens.append(pattern[index : end + 1])
            index = end + 1
        else:
            tokens.append(char)
            index += 1
    return tokens


def literal_base64(token: str) -> str | None:
    """The base64 character `token` spells out, if it spells one out.

    A `\\xNN` matches a base64 character too, and deliberately does not count:
    what a run is measured for is whether it is *written down* in a form
    something decodes, and the byte form is the answer to that rather than
    another instance of it. Encoding is therefore idempotent -- a second pass
    finds only the short plain runs between the escapes.
    """
    if len(token) == 1 and token in BARE_BASE64:
        return token
    return ESCAPED_BASE64.get(token)


def runs(pattern: str) -> list[tuple[int, int, str]]:
    """`(first token, last token + 1, the text)` of each literal base64 run."""
    tokens = tokenize(pattern)
    found: list[tuple[int, int, str]] = []
    start = None
    text = ""
    for index, token in enumerate(tokens + [None]):  # type: ignore[list-item]
        character = literal_base64(token) if token is not None else None
        if character is not None:
            if start is None:
                start = index
                text = ""
            text += character
        elif start is not None:
            found.append((start, index, text))
            start = None
    return found


def encode(pattern: str) -> str:
    """Rewrite every long literal base64 run as one `\\xNN` per character."""
    tokens = tokenize(pattern)
    for start, end, text in reversed(runs(pattern)):
        if len(text) < MAX_LITERAL_RUN:
            continue
        tokens[start:end] = [f"\\x{ord(character):02x}" for character in text]
    return "".join(tokens)


# Metacharacters that have to keep a backslash when they come back out of byte
# form. `+` is the only one a base64 alphabet can produce, and dropping its
# backslash would turn a literal into a quantifier -- a decode that is not the
# exact inverse of `encode` is not a proof of anything.
NEEDS_ESCAPE = set("+")


def decode(pattern: str) -> str:
    """The exact inverse of `encode`, for a reader who wants the plain form."""

    def plain(match: re.Match[str]) -> str:
        character = chr(int(match.group(1), 16))
        return f"\\{character}" if character in NEEDS_ESCAPE else character

    return HEX_ESCAPE.sub(plain, pattern)


# RE2 metacharacters, and the three whitespace characters the historical entries
# write as escapes rather than as themselves -- a single-line TOML entry cannot
# hold a real newline, and an entry nobody can read is an entry nobody reviews.
META = set("\\.+*?()|[]{}^$")
WHITESPACE = {"\n": "\\n", "\t": "\\t", "\r": "\\r"}


def literal(text: str) -> str:
    """An `\\A`-anchored regex accepting `text` and nothing else.

    What an allowlist entry is for: a finding that already happened, described
    exactly. Anchored at both ends because an unanchored entry is matched as a
    substring and excuses every longer span it sits inside -- the #146 bypass,
    which `scripts/test-gitleaks-contract.sh` still plants for.
    """
    out = []
    for character in text:
        if character in WHITESPACE:
            out.append(WHITESPACE[character])
        elif character in META:
            out.append("\\" + character)
        else:
            out.append(character)
    return "\\A" + "".join(out) + "\\z"


ENTRY = re.compile(r"^(\s*)'''(.*)''',?$")


class Unreadable(Exception):
    """An allowlist line this cannot parse, which is not the same as no findings."""


def entries(text: str) -> list[tuple[int, str]]:
    """`(line number, regex)` for each `'''...'''` allowlist entry.

    Raises rather than skipping a line it does not recognise. One entry written
    across several lines -- which `dprint check` accepts -- would otherwise go
    unread, and a checker that quietly reads nothing reports nothing;
    `scripts/test-gitleaks-contract.sh` refuses that shape for the same reason it
    refuses a scanner error that looks like a clean scan.
    """
    found: list[tuple[int, str]] = []
    inside = False
    for number, line in enumerate(text.split("\n"), start=1):
        if re.match(r"^regexes\s*=\s*\[", line):
            inside = True
            continue
        if inside and line.startswith("]"):
            inside = False
            continue
        if not inside or not line.strip() or line.lstrip().startswith("#"):
            continue
        match = ENTRY.match(line)
        if match is None:
            raise Unreadable(
                f"line {number} is inside the allowlist and is not one complete "
                f"'''...''' entry, so its content cannot be checked"
            )
        found.append((number, match.group(2)))
    return found


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    problems: list[str] = []
    for number, pattern in entries(text):
        longest = max((len(run[2]) for run in runs(pattern)), default=0)
        if longest >= MAX_LITERAL_RUN:
            problems.append(
                f"{path}:{number}: a literal base64 run of {longest} characters is "
                f"spelled out; write it as bytes "
                f"(scripts/allowlist-regex.py --rewrite {path})"
            )
    return problems


def rewrite(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    changed = 0
    for number, pattern in entries(text):
        encoded = encode(pattern)
        if encoded == pattern:
            continue
        lines[number - 1] = lines[number - 1].replace(pattern, encoded)
        changed += 1
    path.write_text("\n".join(lines), encoding="utf-8")
    return changed


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.split("Usage:")[1].strip(), file=sys.stderr)
        return 2
    mode, rest = argv[0], argv[1:]

    if mode == "--plain":
        sys.stdout.write(literal(sys.stdin.read().rstrip("\n")))
        return 0
    if mode == "--literal":
        sys.stdout.write(encode(literal(sys.stdin.read().rstrip("\n"))))
        return 0
    if mode == "--encode":
        sys.stdout.write(encode(sys.stdin.read().rstrip("\n")))
        return 0
    if mode == "--decode":
        sys.stdout.write(decode(sys.stdin.read().rstrip("\n")))
        return 0
    if mode == "--check":
        try:
            problems = [problem for name in rest for problem in check(Path(name))]
        except Unreadable as unreadable:
            print(unreadable, file=sys.stderr)
            return 1
        for problem in problems:
            print(problem)
        return 1 if problems else 0
    if mode == "--rewrite":
        for name in rest:
            print(f"{name}: {rewrite(Path(name))} entr(y|ies) rewritten")
        return 0

    print(f"unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
