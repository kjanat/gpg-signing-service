#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def commentable_lines(files):
    lines = {}
    for changed in files:
        patch = changed.get("patch")
        if not patch:
            continue
        shown = lines.setdefault(changed["filename"], set())
        number = None
        for row in patch.splitlines():
            hunk = HUNK.match(row)
            if hunk:
                number = int(hunk.group(1))
                continue
            if number is None or row.startswith(("-", "\\")):
                continue
            shown.add(number)
            number += 1
    return lines


def comment_body(comment):
    body = comment["body"].strip()
    suggestion = comment.get("suggestion")
    if suggestion is None:
        return body
    return f"{body}\n\n```suggestion\n{suggestion.rstrip(chr(10))}\n```"


def build_review(output, files, head):
    summary = (output.get("summary") or "").strip()
    if not summary:
        raise ValueError("the structured output has no summary")

    shown = commentable_lines(files)
    comments, dropped = [], []
    for comment in output.get("comments") or []:
        path, line, start = comment["path"], comment["line"], comment.get("start_line")
        valid = shown.get(path, set())
        if line not in valid or (
            start is not None and (start >= line or start not in valid)
        ):
            dropped.append(comment)
            continue
        entry = {
            "path": path,
            "line": line,
            "side": "RIGHT",
            "body": comment_body(comment),
        }
        if start is not None:
            entry.update(start_line=start, start_side="RIGHT")
        comments.append(entry)

    review = {
        "commit_id": head,
        "event": "COMMENT",
        "body": summary,
        "comments": comments,
    }
    return review, dropped


def gh(*args, payload=None):
    return subprocess.run(
        ["gh", *args], input=payload, capture_output=True, text=True, check=True
    ).stdout


def main():
    repo, pr = os.environ["GITHUB_REPOSITORY"], os.environ["PR"]
    try:
        output = json.loads(os.environ.get("OUTPUT") or "{}")
        head = gh("api", f"repos/{repo}/pulls/{pr}", "--jq", ".head.sha").strip()
        files = [
            json.loads(row)
            for row in gh(
                "api", "--paginate", f"repos/{repo}/pulls/{pr}/files", "--jq", ".[]"
            ).splitlines()
            if row
        ]
        review, dropped = build_review(output, files, head)
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        json.JSONDecodeError,
    ) as error:
        print(f"::error::Claude finished without a usable review for #{pr}: {error}")
        return 1
    except subprocess.CalledProcessError as error:
        print(f"::error::could not read #{pr} from GitHub: {error.stderr.strip()}")
        return 1

    for comment in dropped:
        print(
            f"::warning::dropped a comment on {comment['path']}:{comment['line']}, a line outside the diff"
        )
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as summary:
            summary.write(review["body"] + "\n")
            for comment in dropped:
                summary.write(
                    f"\n- dropped `{comment['path']}:{comment['line']}`: {comment['body']}\n"
                )

    try:
        posted = gh(
            "api",
            "--method",
            "POST",
            f"repos/{repo}/pulls/{pr}/reviews",
            "--input",
            "-",
            "--jq",
            ".html_url",
            payload=json.dumps(review),
        )
    except subprocess.CalledProcessError as error:
        print(f"::error::GitHub refused the review for #{pr}: {error.stderr.strip()}")
        return 1
    print(posted.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
