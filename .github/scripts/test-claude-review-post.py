#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "claude_review_post", HERE / "claude-review-post.py"
)
if spec is None or spec.loader is None:
    raise ImportError(f"cannot load {HERE / 'claude-review-post.py'}")
post = importlib.util.module_from_spec(spec)
spec.loader.exec_module(post)

PATCH = "\n".join([
    "@@ -1,3 +1,4 @@",
    " kept",
    "-removed",
    "+added one",
    "+added two",
    " kept after",
    "\\ No newline at end of file",
    "@@ -20,2 +21,2 @@ func later() {",
    " context",
    "+changed",
])
FILES = [
    {"filename": "src/a.ts", "patch": PATCH},
    {"filename": "image.png"},
]


class CommentableLines(unittest.TestCase):
    def test_new_side_lines_of_every_hunk(self):
        self.assertEqual(
            post.commentable_lines(FILES), {"src/a.ts": {1, 2, 3, 4, 21, 22}}
        )


class BuildReview(unittest.TestCase):
    def build(self, output):
        return post.build_review(output, FILES, "abc123")

    def test_summary_only(self):
        review, dropped = self.build({"summary": " Fine. "})
        self.assertEqual(
            review,
            {
                "commit_id": "abc123",
                "event": "COMMENT",
                "body": "Fine.",
                "comments": [],
            },
        )
        self.assertEqual(dropped, [])

    def test_missing_or_blank_summary_is_refused(self):
        for output in ({}, {"summary": ""}, {"summary": "   "}, {"comments": []}):
            with self.assertRaises(ValueError):
                self.build(output)

    def test_inline_comment_with_suggestion(self):
        review, _ = self.build({
            "summary": "One fix.",
            "comments": [
                {
                    "path": "src/a.ts",
                    "line": 3,
                    "body": "Typo.",
                    "suggestion": "added too\n",
                }
            ],
        })
        self.assertEqual(
            review["comments"],
            [
                {
                    "path": "src/a.ts",
                    "line": 3,
                    "side": "RIGHT",
                    "body": "Typo.\n\n```suggestion\nadded too\n```",
                }
            ],
        )

    def test_multi_line_range(self):
        review, _ = self.build({
            "summary": "Range.",
            "comments": [
                {"path": "src/a.ts", "start_line": 2, "line": 4, "body": "Merge these."}
            ],
        })
        self.assertEqual(review["comments"][0]["start_line"], 2)
        self.assertEqual(review["comments"][0]["start_side"], "RIGHT")

    def test_comments_outside_the_diff_are_dropped(self):
        outside = [
            {"path": "src/a.ts", "line": 10, "body": "between hunks"},
            {"path": "src/b.ts", "line": 1, "body": "unchanged file"},
            {"path": "image.png", "line": 1, "body": "binary"},
            {
                "path": "src/a.ts",
                "start_line": 10,
                "line": 21,
                "body": "range starts outside",
            },
            {"path": "src/a.ts", "start_line": 4, "line": 4, "body": "empty range"},
        ]
        review, dropped = self.build({
            "summary": "S.",
            "comments": outside + [{"path": "src/a.ts", "line": 22, "body": "ok"}],
        })
        self.assertEqual(dropped, outside)
        self.assertEqual([c["line"] for c in review["comments"]], [22])


class Main(unittest.TestCase):
    def run_main(self, output, refuse=False):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            log = tmp / "gh.log"
            stub = tmp / "gh"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "payload = sys.stdin.read() if '--input' in args else None\n"
                "with open(os.environ['GH_LOG'], 'a') as log:\n"
                "    log.write(json.dumps({'args': args, 'payload': payload}) + '\\n')\n"
                "if args[-3:] == ['repos/o/r/pulls/7', '--jq', '.head.sha']:\n"
                "    print('headsha')\n"
                "elif 'repos/o/r/pulls/7/files' in args:\n"
                f"    print({json.dumps(json.dumps(FILES[0]))})\n"
                + (
                    "elif '--input' in args:\n    sys.stderr.write('HTTP 422: line must be part of the diff')\n    sys.exit(1)\n"
                    if refuse
                    else ""
                )
                + "elif '--input' in args:\n"
                "    print('https://github.com/o/r/pull/7#pullrequestreview-1')\n"
            )
            stub.chmod(0o755)
            summary = tmp / "summary"
            env = {
                **os.environ,
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "GH_LOG": str(log),
                "OUTPUT": output,
                "PR": "7",
                "GITHUB_REPOSITORY": "o/r",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
            done = subprocess.run(
                [sys.executable, str(HERE / "claude-review-post.py")],
                env=env,
                capture_output=True,
                text=True,
            )
            calls = (
                [json.loads(row) for row in log.read_text().splitlines()]
                if log.exists()
                else []
            )
            return done, calls, summary.read_text() if summary.exists() else ""

    def test_posts_one_review_at_the_head_commit(self):
        output = json.dumps({
            "summary": "Two notes.",
            "comments": [
                {"path": "src/a.ts", "line": 3, "body": "Rename."},
                {"path": "src/a.ts", "line": 10, "body": "Outside."},
            ],
        })
        done, calls, summary = self.run_main(output)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        posts = [c for c in calls if "--input" in c["args"]]
        self.assertEqual(len(posts), 1)
        self.assertIn("repos/o/r/pulls/7/reviews", posts[0]["args"])
        review = json.loads(posts[0]["payload"])
        self.assertEqual(review["commit_id"], "headsha")
        self.assertEqual(review["event"], "COMMENT")
        self.assertEqual([c["line"] for c in review["comments"]], [3])
        self.assertIn("::warning::dropped a comment on src/a.ts:10", done.stdout)
        self.assertIn("dropped `src/a.ts:10`", summary)

    def test_a_refused_review_fails_with_githubs_reason(self):
        done, _, _ = self.run_main(json.dumps({"summary": "S."}), refuse=True)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn(
            "::error::GitHub refused the review for #7: HTTP 422: line must be part of the diff",
            done.stdout,
        )

    def test_no_review_fails_without_posting(self):
        for output in ("", "{}", '{"summary": ""}', "not json", "[]", '"text"'):
            done, calls, _ = self.run_main(output)
            self.assertNotEqual(done.returncode, 0, output)
            self.assertIn(
                "::error::Claude finished without a usable review for #7", done.stdout
            )
            self.assertFalse([c for c in calls if "--input" in c["args"]], output)


if __name__ == "__main__":
    unittest.main()
