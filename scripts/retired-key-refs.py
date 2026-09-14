#!/usr/bin/env python3
"""Report uses of the retired signing key id that a reader could act on.

`scripts/key-material.py` guards the bytes: no tracked file may carry a key
*packet*, and no file may carry the retired key's public material under any
encoding. This guards the other half, which is not material at all -- the
sixteen hex characters `62E75E54497815DD`, a public key id that appears on every
signature that key ever made and is a secret to nobody.

The failure it exists to stop is mundane and was real on master: thirty-odd
documentation and CLI examples still told a reader to pass that id. Production
answers `404 KEY_NOT_FOUND` for it since 2026-09-08, so those examples did not
leak anything -- they just did not work, and they pointed a new operator at a key
the incident retired. A reader who copies one gets a failure they have to go and
understand. That is the whole cost, and it is why this is a lint and not a
secret-scanner.

Deleting the id everywhere would be the wrong repair. The retired key is the
subject of ADR-004, of the key-handoff runbook and its tooling, of the
key-material guard's own retired set, and of fourteen unit suites that use it as
deterministic historical data. Those references have to stay: a containment
record that cannot name the key it contained is not a record.

So the rule is scoped two ways, and both scopes are needed.

  path       Only the files listed in `INCIDENT` and `FIXTURES` may mention the
             id at all. Every other tracked file must not, and there is no
             pattern, extension or directory exception: a new documentation page
             is Tier 3 the moment it is written, which is the point.

  semantic   A path allowlist alone rots the moment someone appends a live
             example to an allowlisted file -- and the runbook and ADR-004 are
             exactly the files where a `gpg-sign sign --key-id ...` line would
             look at home. So in `INCIDENT` files each occurrence must also sit
             within `WINDOW` lines of language that marks the key as retired.
             Prose that is *about* the retirement carries that vocabulary
             already; an operational example pasted in does not.

`FIXTURES` is exempt from the semantic rule on purpose. `src/__tests__/**` and
`wrangler.test.toml` use the id as a constant with no prose around it, and
requiring a retirement word next to every `keyIds: ["62E7..."]` would be asking
test data to argue for itself. Nothing in those paths is read as an instruction.

What this does not cover: the id written some other way -- split, interpolated,
built from a variable. A reader cannot act on those either, which is the property
being protected, so the gap is not one worth closing with more regex. The full
fingerprint is covered for free: it ends in the short id.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

# The key #147 retired. Matched case-insensitively: `62e75e54497815dd` names the
# same key, and the full fingerprint 806D3A1B9F957D6731950BCA62E75E54497815DD
# ends in it, so both are found without a second pattern.
RETIRED_KEY_ID = "62E75E54497815DD"

# Files whose subject *is* the retired key. Each one is here for a reason that
# survives the rotation; none of them is a place a reader is told what to run.
INCIDENT = {
    # The decision record for retiring and revoking the key.
    "docs/adr/ADR-004-retired-key-revocation.md",
    # The operator procedure for publishing its revocation.
    "docs/key-handoff-runbook.md",
    # The tooling that procedure runs, and its tests. `RETIRED_KEY` is the
    # script's subject; it refuses to touch any other key.
    "scripts/key-handoff.sh",
    "scripts/test-key-handoff.sh",
    # The packet-level guard. Its retired set is keyed on this key's identity
    # digest, and its tests assert that set still names it.
    "scripts/key-material.py",
    "scripts/test-key-material.sh",
    # This gate and its tests: naming the key is what they do.
    "scripts/retired-key-refs.py",
    "scripts/test-retired-key-refs.sh",
    # A dated (2025-11-25) assessment quoting wrangler.toml as it stood then.
    # Rewriting the quote would falsify the record rather than fix anything.
    "CICD_DEVOPS_ASSESSMENT.md",
}

# Paths where the id is deterministic test data. Prefix-matched for the test
# tree, exact for the single config.
FIXTURE_PREFIXES = ("src/__tests__/",)
FIXTURE_FILES = {"wrangler.test.toml"}

# Language that marks an occurrence as being about the retirement rather than
# about what to run. Matched case-insensitively over a window of lines, because
# a fenced code block's explanation is the prose above or below it, not the line
# the id happens to land on.
MARKERS = (
    "retire",
    "revoke",
    "revoked",
    "revocation",
    "expose",
    "exposure",
    "rotate",
    "rotated",
    "rotation",
    "incident",
    "historical",
    "key_not_found",
    "404",
    "#147",
    "adr-004",
    "no longer",
    "v1.2.0",
    "dated record",
)

# Lines either side of an occurrence that the marker search reads. Three is a
# fence, a blank line and a sentence -- enough to reach the paragraph that
# introduces a code block, and too few to reach an unrelated section.
WINDOW = 3

NEEDLE = re.compile(re.escape(RETIRED_KEY_ID), re.IGNORECASE)
MARKER = re.compile("|".join(re.escape(m) for m in MARKERS), re.IGNORECASE)

# A markdown link-reference definition -- `[ADR-004]: adr/ADR-004-retired-key-
# revocation.md` -- carries no prose. Its label and its destination are named
# after the incident, so `MARKER` matches it three times over while it says
# nothing about the occurrence beside it. Every guide in this tree collects
# those definitions at the bottom of the file, which is also where an appended
# example lands, so leaving them in the window meant the runbook's own footer
# vouched for the next thing written under it. Marker lookup skips them; the
# occurrence has to be introduced by a sentence.
LINK_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*\S+\s*$")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.detail}"


def tier(path: str) -> str:
    if path in FIXTURE_FILES or path.startswith(FIXTURE_PREFIXES):
        return "fixture"
    if path in INCIDENT:
        return "incident"
    return "live"


def read(path: str) -> str | None:
    """The file as text, or None if it could not be read at all.

    Bytes, not text: a file that is not valid UTF-8 is still a file, and
    skipping by encoding is an exclusion with another name.
    """
    try:
        return Path(path).read_bytes().decode("latin-1")
    except (IsADirectoryError, FileNotFoundError, PermissionError):
        # A submodule, a deleted-but-staged path, an unreadable file. Not a
        # place the id can be read from, so not a finding -- but not silently
        # dropped either: `--considered` reports it as `unread`, and the suite
        # fails if any tracked path lands there.
        return None


def scan(path: str) -> list[Finding]:
    """Findings for one tracked file."""
    text = read(path)
    if text is None:
        return []

    where = tier(path)
    if where == "fixture":
        return []

    # Not `splitlines()`: it also breaks on \x0b, \x0c, \x1c-\x1e and \x85,
    # and \x85 is the third byte of a UTF-8 `✅` read as latin-1. One emoji
    # in a file and every line number after it is wrong.
    lines = text.split("\n")
    findings: list[Finding] = []
    for index, line in enumerate(lines):
        if not NEEDLE.search(line):
            continue
        number = index + 1
        if where == "live":
            findings.append(
                Finding(
                    path,
                    number,
                    "live-facing",
                    f"names the retired key {RETIRED_KEY_ID}; use AFD5E3EC68371856 "
                    "for the deployed key or a placeholder such as A1B2C3D4E5F67890",
                )
            )
            continue
        window = lines[max(0, index - WINDOW) : index + WINDOW + 1]
        prose = [n for n in window if not LINK_DEF.match(n)]
        if not any(MARKER.search(neighbour) for neighbour in prose):
            findings.append(
                Finding(
                    path,
                    number,
                    "unmarked",
                    f"names the retired key {RETIRED_KEY_ID} with nothing within "
                    f"{WINDOW} lines saying it is retired; an incident file may "
                    "describe the key, not instruct anyone to use it",
                )
            )
    return findings


def main(argv: list[str]) -> int:
    paths = [a for a in argv if a != "--considered"]
    if "--considered" in argv:
        # Tier *and* whether the bytes were actually obtained. Printing one line
        # per argument would say only that the path was passed in, which the
        # caller already knew; the suite needs to know the file was opened.
        for path in paths:
            state = "unread" if read(path) is None else "read"
            print(f"{tier(path)}\t{state}\t{path}")
        return 0

    findings = [f for path in paths for f in scan(path)]
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
