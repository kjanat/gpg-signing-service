#!/usr/bin/env python3
"""Edit -> durable candidate -> clean verification -> trusted publication.

Input is uploaded before the model runs. Candidate bundles are untrusted data;
the privileged publisher never checks out or executes their contents.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote, urlencode
from urllib.error import HTTPError
from urllib.request import Request, urlopen

REF = "refs/claude/candidate"
IDENTITY = {
    "GIT_AUTHOR_NAME": "Kaj Kowalski",
    "GIT_AUTHOR_EMAIL": "info@kajkowalski.nl",
    "GIT_COMMITTER_NAME": "Kaj Kowalski",
    "GIT_COMMITTER_EMAIL": "info@kajkowalski.nl",
}


class PublicationError(Exception):
    """The result could not be preserved, verified or published."""


def run(*args, data=None, env=None):
    result = subprocess.run(
        args, input=data, capture_output=True, timeout=120, env=env, check=False
    )
    if result.returncode:
        # Arguments, stderr and response bodies can contain credentials.
        raise PublicationError(f"{args[0]} {args[1]} failed (exit {result.returncode})")
    return result.stdout


def git(*args, data=None, env=None):
    return (
        run("git", "-c", "core.hooksPath=" + os.devnull, *args, data=data, env=env)
        .decode()
        .strip()
    )


def api(endpoint, *args):
    try:
        return json.loads(run("gh", "api", endpoint, *args))
    except (PublicationError, ValueError) as error:
        raise PublicationError(
            "GitHub lookup failed (including 404, never no-change)"
        ) from error


def require(condition, message):
    if not condition:
        raise PublicationError(message)


def read_json(path):
    require(
        path.is_file() and not path.is_symlink(), f"Missing regular file: {path.name}"
    )
    require(path.stat().st_size <= 65536, f"Oversized metadata: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "Metadata must be an object")
    return value


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def output(name, value):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"{name}={value}\n")


def policy(directory):
    request = read_json(directory / "request.json")
    require(
        request.get("repository") == os.environ.get("GITHUB_REPOSITORY"),
        "Input repository does not match this workflow",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", request.get("start", "")), "Invalid starting SHA"
    )
    for name in ("branch", "base"):
        require(isinstance(request.get(name), str), "Missing branch")
        git("check-ref-format", "refs/heads/" + request[name])
    require(
        request["branch"] != request["base"], "Refusing publication to the base branch"
    )
    require(request.get("kind") in ("issue", "pull_request"), "Invalid request kind")
    require(
        isinstance(request.get("number"), int) and request["number"] > 0,
        "Invalid request number",
    )
    require(isinstance(request.get("new"), bool), "Missing original branch state")
    require(
        isinstance(request.get("initial_heads"), list)
        and all(
            isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha)
            for sha in request["initial_heads"]
        ),
        "Invalid starting refs",
    )
    require(
        request.get("mode") in ("pull-request", "branch-only"),
        "Invalid publication mode",
    )
    require(
        request["mode"] != "branch-only"
        or (isinstance(request.get("reason"), str) and request["reason"].strip()),
        "Branch-only completion requires an explicit maintainer reason",
    )
    git("cat-file", "-e", request["start"] + "^{commit}")
    return request


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=True)
    require(not git("status", "--porcelain"), "Starting checkout must be clean")
    require(
        git("branch", "--show-current") == os.environ["CLAUDE_WORK_BRANCH"],
        "Checkout does not match the authorized work branch",
    )
    require(
        os.environ["CLAUDE_BRANCH_IS_NEW"] in ("true", "false"), "Invalid branch state"
    )
    request = {
        "repository": os.environ["GITHUB_REPOSITORY"],
        "start": git("rev-parse", "HEAD"),
        "initial_heads": git(
            "for-each-ref", "--format=%(objectname)", "refs/heads/"
        ).splitlines(),
        "branch": os.environ["CLAUDE_WORK_BRANCH"],
        "base": os.environ["CLAUDE_BASE_BRANCH"],
        "kind": os.environ["CLAUDE_ENTITY_KIND"],
        "number": int(os.environ["CLAUDE_ENTITY_NUMBER"]),
        "new": os.environ["CLAUDE_BRANCH_IS_NEW"] == "true",
        "mode": os.environ.get("CLAUDE_PUBLICATION_MODE", "pull-request"),
        "reason": os.environ.get("CLAUDE_NO_PR_REASON", ""),
    }
    write_json(directory / "request.json", request)
    policy(directory)
    shutil.copyfile(os.environ["CLAUDE_CONTEXT_FILE"], directory / "request.md")
    output("start-sha", request["start"])


def snapshot_tree():
    # Capture the final working files without changing the agent's index.
    # Original staged/unstaged patches are preserved separately by export.
    with tempfile.TemporaryDirectory(prefix="claude-index-") as directory:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(directory) / "index"))
        git("read-tree", "HEAD", env=env)
        git("add", "-A", env=env)
        return git("write-tree", env=env)


def make_bundle(path, commit, start):
    git("update-ref", REF, commit)
    git("bundle", "create", str(path.resolve()), REF, "^" + start)


def export(directory, destination):
    destination.mkdir(parents=True, exist_ok=True)
    request = policy(directory)
    # Save local history first: even a later export failure leaves recovery data.
    git(
        "bundle",
        "create",
        str((destination / "recovery.bundle").resolve()),
        "--all",
        "HEAD",
    )
    for filename, flags in (("staged.patch", ["--cached"]), ("unstaged.patch", [])):
        (destination / filename).write_bytes(
            run("git", "diff", "--binary", "--no-ext-diff", *flags)
        )
    tree = snapshot_tree()
    (destination / "checkout.patch").write_bytes(
        run("git", "diff", "--binary", "--no-ext-diff", request["start"], tree)
    )
    env = dict(os.environ, **IDENTITY)
    candidate = git(
        "-c",
        "commit.gpgsign=false",
        "commit-tree",
        tree,
        "-p",
        request["start"],
        data=b"Temporary candidate; never published\n",
        env=env,
    )
    make_bundle(destination / "candidate.bundle", candidate, request["start"])
    require(
        git("branch", "--show-current") == request["branch"],
        "Editor switched branches; work retained in recovery artifact",
    )
    require(
        not git("rev-list", "--branches", "--not", "HEAD", *request["initial_heads"]),
        "Unpublished commits on another local branch; recovery retained",
    )
    if tree == git("rev-parse", request["start"] + "^{tree}"):
        require(
            git("rev-parse", "HEAD") == request["start"]
            and not (destination / "staged.patch").read_bytes(),
            "Local implementation cannot be classified as a no-change answer",
        )
    response = Path(os.environ.get("CLAUDE_RESPONSE_FILE", str(destination / "absent")))
    if response.is_file() and not response.is_symlink():
        require(
            response.stat().st_size <= 60000, "Response exceeds GitHub comment limit"
        )
        shutil.copyfile(response, destination / "response.md")


def import_candidate(directory, request, filename):
    bundle = directory / filename
    require(bundle.is_file() and not bundle.is_symlink(), "Candidate bundle missing")
    git("bundle", "verify", str(bundle.resolve()))
    heads = git("bundle", "list-heads", str(bundle.resolve())).splitlines()
    require(len(heads) == 1 and heads[0].split()[1] == REF, "Unexpected bundle refs")
    sha = heads[0].split()[0]
    require(re.fullmatch(r"[0-9a-f]{40}", sha), "Invalid candidate SHA")
    git("fetch", "--no-tags", str(bundle.resolve()), "+" + REF + ":" + REF)
    git("fsck", "--strict", "--no-reflogs", sha)
    require(
        git("show", "-s", "--format=%P", sha) == request["start"],
        "Candidate must have exactly the trusted starting commit as parent",
    )
    return sha, git("rev-parse", sha + "^{tree}")


def response_file(directory):
    response = directory / "response.md"
    require(
        response.is_file() and not response.is_symlink(), "Completion response missing"
    )
    require(
        0 < response.stat().st_size <= 60000, "Empty or oversized completion response"
    )
    require(response.read_text(encoding="utf-8").strip(), "Empty completion response")
    return response


def verify(directory, candidate_dir, destination):
    request = policy(directory)
    # Liveness signal only: the model can write step outputs. Candidate tests
    # are a quality check, not an attestation against hostile candidate code.
    require(
        os.environ.get("CLAUDE_OUTCOME") == "success",
        "Editing did not complete successfully; recovery artifact retained",
    )
    sha, tree = import_candidate(candidate_dir, request, "candidate.bundle")
    response = response_file(candidate_dir)
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(response, destination / "response.md")
    changed = tree != git("rev-parse", request["start"] + "^{tree}")
    write_json(
        destination / "verified.json",
        {"candidate": sha, "tree": tree, "changed": changed},
    )
    # This job has no signing or write credentials. The privileged job never
    # performs this checkout or runs the candidate's checks.
    git("checkout", "--detach", sha)
    output("status", "changed" if changed else "no-change")


def seal(directory, destination):
    request = policy(directory)
    state = read_json(destination / "verified.json")
    require(git("rev-parse", "HEAD") == state.get("candidate"), "Checks moved HEAD")
    require(not git("status", "--porcelain"), "Checks left unverified file changes")
    require(git("rev-parse", "HEAD^{tree}") == state.get("tree"), "Tested tree changed")
    require(
        git("show", "-s", "--format=%P", "HEAD") == request["start"],
        "Tested parent changed",
    )
    make_bundle(destination / "verified.bundle", state["candidate"], request["start"])


def http_json(url, *, token, body=None):
    headers = {"Authorization": "Bearer " + token}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    try:
        with urlopen(Request(url, data=data, headers=headers), timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        raise PublicationError(
            f"Credential request failed (HTTP {error.code})"
        ) from error


def publisher_token():
    # Same exchange as anthropics/claude-code-action src/github/token.ts at
    # ed670b4cf9de2a5a570d130d2f6197b9e543cd64; run only in the trusted publisher.
    # Never use ambient GH_TOKEN/GITHUB_TOKEN: a maintainer PAT could publish
    # comments as the owner and recursively trigger another implementation run.
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    oidc = http_json(
        url
        + ("&" if "?" in url else "?")
        + urlencode({"audience": "claude-code-github-action"}),
        token=os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
    )
    value = http_json(
        "https://api.anthropic.com/api/github/github-app-token-exchange",
        token=oidc["value"],
        body={
            "permissions": {
                "contents": "write",
                "pull_requests": "write",
                "issues": "write",
            }
        },
    )
    token = value.get("token") or value.get("app_token")
    require(
        isinstance(token, str) and token and "\n" not in token and "\r" not in token,
        "App token exchange returned no token",
    )
    print("::add-mask::" + token, flush=True)
    return token


def remote_sha(branch):
    text = git("ls-remote", "--heads", "origin", "refs/heads/" + branch)
    rows = text.splitlines()
    require(len(rows) <= 1, "Ambiguous remote branch")
    return rows[0].split()[0] if rows else ""


def check_publication(request, sha):
    require(
        remote_sha(request["branch"]) == sha,
        "Remote branch does not contain the published commit",
    )
    repo = request["repository"]
    ref = api(f"repos/{repo}/git/ref/heads/{quote(request['branch'], safe='')}")
    require(ref.get("object", {}).get("sha") == sha, "GitHub branch SHA does not match")
    comparison = api(f"repos/{repo}/compare/{quote(request['base'], safe='')}...{sha}")
    require(
        comparison.get("status") in ("ahead", "diverged")
        and comparison.get("ahead_by", 0) > 0,
        "Published commit has no implementation comparison",
    )


def check_pr(request, number, sha):
    pr = api(f"repos/{request['repository']}/pulls/{number}")
    require(
        pr.get("state") == "open"
        and pr.get("head", {}).get("sha") == sha
        and pr.get("head", {}).get("ref") == request["branch"]
        and pr.get("head", {}).get("repo", {}).get("full_name") == request["repository"]
        and pr.get("base", {}).get("ref") == request["base"]
        and pr.get("base", {}).get("repo", {}).get("full_name")
        == request["repository"],
        "PR does not point at the exact published branch, commit and base",
    )


def publish_result(directory, destination):
    request = policy(directory)
    _, tree = import_candidate(destination, request, "verified.bundle")
    # Enforce in this trusted job, independently of token permissions and any
    # candidate-controlled checks. NUL paths and no rename detection include
    # deletions/renames and names that Git would otherwise quote.
    touched = run(
        "git", "diff", "--name-only", "--no-renames", "-z", request["start"], tree
    ).split(b"\0")
    require(
        not any(
            path == b".github/workflows" or path.startswith(b".github/workflows/")
            for path in touched
        ),
        "Workflow changes need maintainer activation via .github/workflows-pending/",
    )
    response = response_file(destination)
    # Trusted guard from workflow_sha, never from the candidate.
    run(
        "bash",
        ".github/scripts/claude-agent-guard.sh",
        "attribution",
        str(response.resolve()),
    )
    repo = request["repository"]
    if tree == git("rev-parse", request["start"] + "^{tree}"):
        run(
            "gh",
            "api",
            f"repos/{repo}/issues/{request['number']}/comments",
            "-F",
            "body=@" + str(response.resolve()),
        )
        print("Question/review completed without repository changes.")
        return
    enabled = os.environ.get("SIGNING_ENABLED")
    require(enabled in ("true", "false"), "Signing policy unavailable")
    if enabled == "true":
        public_key = run("gpg-sign", "public-key")
        run("gpg", "--batch", "--import", data=public_key)
    run("gh", "auth", "setup-git")
    expected = "" if request["new"] else request["start"]
    require(
        remote_sha(request["branch"]) == expected,
        "Remote branch changed since preparation",
    )
    if request["kind"] == "pull_request":
        check_pr(request, request["number"], request["start"])
    entity = "issue" if request["kind"] == "issue" else "PR"
    title = f"chore: address {entity} #{request['number']}"
    signed = git(
        "-c",
        "commit.gpgsign=" + enabled,
        "commit-tree",
        *(["-S"] if enabled == "true" else []),
        tree,
        "-p",
        request["start"],
        data=(title + "\n").encode(),
        env=dict(os.environ, **IDENTITY),
    )
    if enabled == "true":
        git("verify-commit", signed)
    run(
        "bash",
        ".github/scripts/check-commit-provenance.sh",
        request["start"] + ".." + signed,
    )
    # Configure auth only in this trusted job. Explicit lease prevents a race;
    # the sole published commit is a child of the exact original branch tip.
    git(
        "push",
        "--force-with-lease=refs/heads/" + request["branch"] + ":" + expected,
        "origin",
        signed + ":refs/heads/" + request["branch"],
    )
    check_publication(request, signed)
    if request["mode"] == "pull-request":
        query = urlencode({
            "head": repo.split("/")[0] + ":" + request["branch"],
            "base": request["base"],
            "state": "open",
        })
        pulls = api(f"repos/{repo}/pulls?{query}")
        require(isinstance(pulls, list) and len(pulls) <= 1, "Ambiguous matching PR")
        if request["kind"] == "pull_request":
            number = request["number"]
        elif pulls:
            number = pulls[0]["number"]
        else:
            pr = api(
                f"repos/{repo}/pulls",
                "-f",
                "title=" + title,
                "-f",
                "head=" + request["branch"],
                "-f",
                "base=" + request["base"],
                "-F",
                "body=@" + str(response.resolve()),
            )
            number = pr["number"]
        check_pr(request, number, signed)
        completion = f"Published {signed} in #{number}."
    else:
        completion = (
            f"Published {signed} to {request['branch']}. No PR: {request['reason']}"
        )
    # Never post a completion claim until all mandatory remote checks pass.
    run(
        "gh",
        "api",
        f"repos/{repo}/issues/{request['number']}/comments",
        "-f",
        "body=" + completion,
    )
    print(completion)


def publish(directory, destination):
    token = publisher_token()
    previous = os.environ.get("GH_TOKEN")
    os.environ["GH_TOKEN"] = token
    try:
        publish_result(directory, destination)
    finally:
        try:
            run("gh", "api", "--method", "DELETE", "/installation/token")
        finally:
            if previous is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = previous


def main():
    commands = {
        "prepare": prepare,
        "export": export,
        "verify": verify,
        "seal": seal,
        "publish": publish,
    }
    try:
        require(
            len(sys.argv) > 1 and sys.argv[1] in commands, "Unknown publication command"
        )
        commands[sys.argv[1]](*(Path(value).resolve() for value in sys.argv[2:]))
    except Exception as error:
        # HTTP errors can embed credentials; do not dump exceptions or tracebacks.
        message = (
            str(error) if isinstance(error, PublicationError) else type(error).__name__
        )
        print(
            "::error::"
            + message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
