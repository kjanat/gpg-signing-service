#!/usr/bin/env python3
"""Require durable publication after Claude, independently of its SDK verdict.

prepare copies this guard outside the editable checkout and appends a mandatory
SessionStart hook to the signing settings. The hook snapshots AFTER tag mode's
checkout/config restoration, once only. verify uses the workflow token for
read-only GitHub checks: the action's installation token is already revoked.
"""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote, urlencode


class PublicationError(Exception):
    """A completion claim could not be proved."""


def run(*args):
    result = subprocess.run(args, capture_output=True, check=False, timeout=60)
    if result.returncode:
        # Do not echo command arguments or stderr: either can carry credentials.
        raise PublicationError(f"{args[0]} {args[1]} failed (exit {result.returncode})")
    return result.stdout


def git(*args):
    return run("git", *args).decode().strip()


def api(endpoint, *, pages=False):
    try:
        return json.loads(
            run("gh", "api", endpoint, *(["--paginate", "--slurp"] if pages else []))
        )
    except PublicationError as error:
        raise PublicationError(
            f"GitHub lookup failed: {endpoint} (including 404, never no-change)"
        ) from error


def local_commits():
    refs = git("for-each-ref", "--format=%(refname)", "refs/heads/").splitlines()
    return set(git("rev-list", "HEAD", *refs).splitlines())


def dirty_files():
    """Fingerprint dirt, including staged, unstaged and non-ignored new files.

    A baseline may contain upstream's intentional restored config. Only its
    exact original diff is allowed; these paths are never blanket-exempted.
    """
    result = {}
    paths = (
        run("git", "diff", "--name-only", "--no-renames", "-z")
        + run("git", "diff", "--cached", "--name-only", "--no-renames", "-z")
    ).split(b"\0")
    for raw in filter(None, paths):
        path = os.fsdecode(raw)
        staged = run(
            "git", "diff", "--binary", "--no-ext-diff", "--cached", "HEAD", "--", path
        )
        unstaged = run("git", "diff", "--binary", "--no-ext-diff", "--", path)
        result[path] = hashlib.sha256(staged + b"\0" + unstaged).hexdigest()
    paths = run("git", "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    for raw in filter(None, paths):
        path = Path(os.fsdecode(raw))
        content = (
            os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        )
        result[str(path)] = hashlib.sha256(b"untracked\0" + content).hexdigest()
    return result


def prepare(settings_file):
    settings = json.loads(Path(settings_file).read_text())
    if not isinstance(settings, dict) or settings.get("disableAllHooks"):
        raise PublicationError(
            "Claude settings must permit the mandatory SessionStart hook"
        )
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repository = os.environ["GITHUB_REPOSITORY"]
    base = event["repository"]["default_branch"]
    pr = event.get("pull_request")
    if event.get("issue", {}).get("pull_request"):
        pr = api(f"repos/{repository}/pulls/{event['issue']['number']}")
    if pr and pr["state"] == "open":
        base = pr["base"]["ref"]
    # Agent-mode preparation already selected its base, including dispatches.
    base = os.environ.get("CLAUDE_BASE_BRANCH") or base
    mode = os.environ.get("CLAUDE_PUBLICATION_MODE") or "pull-request"
    reason = os.environ.get("CLAUDE_NO_PR_REASON", "").strip()
    if mode not in ("pull-request", "branch-only") or (
        mode == "branch-only" and not reason
    ):
        raise PublicationError(
            "branch-only requires an explicit CLAUDE_NO_PR_REASON; unknown modes refused"
        )
    directory = Path(
        tempfile.mkdtemp(prefix="claude-publication-", dir=os.environ["RUNNER_TEMP"])
    )
    script = directory / "guard.py"
    shutil.copyfile(__file__, script)
    (directory / "policy.json").write_text(
        json.dumps({
            "repository": repository,
            "base": base,
            "mode": mode,
            "reason": reason,
            "workspace": os.environ["GITHUB_WORKSPACE"],
        })
    )
    hooks = settings.setdefault("hooks", {}).setdefault("SessionStart", [])
    hooks.append({
        "matcher": "startup",
        "hooks": [
            {
                "type": "command",
                "timeout": 60,
                "command": shlex.join([
                    "python3",
                    str(script),
                    "snapshot",
                    str(directory),
                ]),
            }
        ],
    })
    settings_path = directory / "settings.json"
    settings_path.write_text(json.dumps(settings))
    settings_path.chmod(0o600)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"directory={directory}\nsettings-file={settings_path}\n")


def snapshot(directory):
    state = directory / "baseline.json"
    if state.exists():
        return  # A second session must never bless the first session's edits.
    baseline = {
        "head": git("rev-parse", "HEAD"),
        "commits": sorted(local_commits()),
        "dirty": dirty_files(),
    }
    # Exclusive creation: a racing/repeated hook cannot overwrite the baseline.
    with state.open("x") as output:
        json.dump(baseline, output)


def verify(directory, policy):
    baseline_path = directory / "baseline.json"
    if not baseline_path.exists():
        raise PublicationError(
            "SessionStart baseline missing; completion cannot be verified"
        )
    baseline = json.loads(baseline_path.read_text())
    dirty = dirty_files()
    changed = [
        path for path, digest in dirty.items() if baseline["dirty"].get(path) != digest
    ]
    if changed:
        raise PublicationError(
            "Unpublished working-tree changes: " + ", ".join(changed)
        )
    head = git("rev-parse", "HEAD")
    created = local_commits() - set(baseline["commits"])
    if not created and head == baseline["head"]:
        return "No implementation changes; no remote branch or PR required."
    branch = git("symbolic-ref", "--quiet", "--short", "HEAD")
    if branch == policy["base"]:
        raise PublicationError("Implementation ended on the base branch")
    reachable = set(git("rev-list", "HEAD").splitlines())
    if created - reachable:
        raise PublicationError(
            "New commits remain on another local branch; publication incomplete"
        )
    repository = policy["repository"]
    ref = api(f"repos/{repository}/git/ref/heads/{quote(branch, safe='')}")
    if (
        ref["ref"] != f"refs/heads/{branch}"
        or ref["object"]["type"] != "commit"
        or ref["object"]["sha"] != head
    ):
        raise PublicationError(
            f"Remote branch {branch} does not point at local commit {head}"
        )
    # The compare API has no head_commit field. Address the already-verified
    # immutable SHA directly; commits[] can be paginated/truncated at 250.
    comparison = api(
        f"repos/{repository}/compare/{quote(policy['base'], safe='')}...{head}"
    )
    if comparison["status"] not in ("ahead", "diverged") or comparison["ahead_by"] < 1:
        raise PublicationError(
            "Remote comparison does not prove the implementation commit"
        )
    if policy["mode"] == "branch-only":
        return f"Published {branch} at {head}; explicit no-PR mode: {policy['reason']}"
    query = urlencode({
        "state": "open",
        "head": f"{repository.split('/')[0]}:{branch}",
        "base": policy["base"],
        "per_page": 100,
    })
    pages = api(f"repos/{repository}/pulls?{query}", pages=True)
    matches = [
        pr
        for page in pages
        for pr in page
        if (
            pr["state"] == "open"
            and pr["head"]["ref"] == branch
            and pr["head"]["sha"] == head
            and pr["head"]["repo"]["full_name"] == repository
            and pr["base"]["ref"] == policy["base"]
            and pr["base"]["repo"]["full_name"] == repository
        )
    ]
    if len(matches) != 1:
        raise PublicationError(
            "Expected exactly one open PR for the published repository, branch and commit"
        )
    return f"Published {branch} at {head}; verified PR {matches[0]['html_url']}"


def main():
    try:
        command, argument = sys.argv[1:]
        if command == "prepare":
            prepare(argument)
            return
        directory = Path(argument).resolve()
        policy = json.loads((directory / "policy.json").read_text())
        os.chdir(policy["workspace"])
        if command == "snapshot":
            snapshot(directory)
        elif command == "verify":
            message = verify(directory, policy)
            print(message)
            if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
                with Path(summary).open("a") as output:
                    output.write(f"\nClaude publication: {message}\n")
        else:
            raise PublicationError("Unknown guard command")
    except (
        PublicationError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as error:
        # Escape annotation control characters from branch/path names.
        message = (
            str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        )
        print(
            f"::error title=Claude publication incomplete::{message}", file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
