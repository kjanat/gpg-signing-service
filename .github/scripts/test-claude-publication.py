#!/usr/bin/env python3
"""Publication regressions: real Git, mocked GitHub transport, no signing keys."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "publication", Path(__file__).with_name("claude-publication.py")
)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.previous = Path.cwd()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.chdir, self.previous)
        self.directory = Path(self.temp.name)
        self.repo = self.directory / "repo"
        self.repo.mkdir()
        os.chdir(self.repo)
        # Isolate identities, signing, hooks and system config from the operator.
        self.environment = patch.dict(
            os.environ,
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_COUNT": "0",
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.org",
                "GIT_COMMITTER_EMAIL": "fixture@example.org",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        guard.git("init", "--initial-branch=master")
        Path("file.txt").write_text("base\n")
        guard.git("add", "file.txt")
        guard.git("commit", "-m", "base")
        self.base = guard.git("rev-parse", "HEAD")
        guard.git("switch", "-c", "fix/issue-163")
        self.policy = {
            "repository": "owner/repo",
            "base": "master",
            "mode": "pull-request",
            "reason": "",
            "workspace": str(self.repo),
        }
        (self.directory / "policy.json").write_text(json.dumps(self.policy))
        guard.snapshot(self.directory)
        self.calls = []
        self.failure = ""
        self.remote_sha = None
        self.compare_status = "ahead"
        self.ahead = 1
        self.pr_overrides = None
        self.no_pr = False
        self.api_patch = patch.object(guard, "api", self.api)
        self.api_patch.start()
        self.addCleanup(self.api_patch.stop)

    def commit(self):
        Path("file.txt").write_text("implementation\n")
        guard.git("add", "file.txt")
        guard.git("commit", "-m", "implementation")
        return guard.git("rev-parse", "HEAD")

    def api(self, endpoint, *, pages=False):
        self.calls.append(endpoint)
        if self.failure and self.failure in endpoint:
            # Exercise the real transport wrapper's non-zero/404 handling.
            with patch.object(
                guard, "run", side_effect=guard.PublicationError("HTTP 404")
            ):
                return ORIGINAL_API(endpoint, pages=pages)
        head = guard.git("rev-parse", "HEAD")
        if "/git/ref/" in endpoint:
            return {
                "ref": "refs/heads/fix/issue-163",
                "object": {"type": "commit", "sha": self.remote_sha or head},
            }
        if "/compare/" in endpoint:
            self.assertTrue(endpoint.endswith(f"...{head}"))
            return {"status": self.compare_status, "ahead_by": self.ahead}
        if "/pulls?" in endpoint:
            self.assertTrue(pages)
            pr = {
                "state": "open",
                "head": {
                    "ref": "fix/issue-163",
                    "sha": head,
                    "repo": {"full_name": "owner/repo"},
                },
                "base": {"ref": "master", "repo": {"full_name": "owner/repo"}},
                "html_url": "https://github.com/owner/repo/pull/7",
            }
            if self.pr_overrides:
                pr = self.pr_overrides(pr)
            return [[]] if self.no_pr else [[pr]]
        self.fail(f"Unexpected API endpoint {endpoint}")

    def verify(self):
        return guard.verify(self.directory, self.policy)

    def test_local_commit_missing_remote_branch_fails(self):
        self.commit()
        self.failure = "/git/ref/"
        with self.assertRaisesRegex(
            guard.PublicationError, "lookup failed.*never no-change"
        ):
            self.verify()

    def test_compare_404_after_implementation_fails(self):
        self.commit()
        self.failure = "/compare/"
        with self.assertRaisesRegex(guard.PublicationError, "lookup failed.*compare"):
            self.verify()

    def test_no_change_issue_question_needs_no_branch(self):
        self.assertIn("No implementation changes", self.verify())
        self.assertEqual(self.calls, [])

    def test_no_change_pr_review_with_restored_config(self):
        # Baseline is deliberately AFTER PR checkout and upstream config restore.
        self.commit()
        Path("file.txt").write_text("upstream restored base config\n")
        (self.directory / "baseline.json").unlink()
        guard.snapshot(self.directory)
        self.assertIn("No implementation changes", self.verify())
        Path("file.txt").write_text("model edits restored config\n")
        with self.assertRaisesRegex(guard.PublicationError, "working-tree"):
            self.verify()

    def test_worktree_index_and_untracked_changes_fail(self):
        for kind in ("unstaged", "staged", "cancelled-index", "untracked"):
            with self.subTest(kind=kind):
                if kind == "untracked":
                    Path("new.txt").write_text("lost work")
                else:
                    Path("file.txt").write_text("lost work")
                    if kind != "unstaged":
                        guard.git("add", "file.txt")
                    if kind == "cancelled-index":
                        Path("file.txt").write_text("base\n")
                with self.assertRaisesRegex(guard.PublicationError, "working-tree"):
                    self.verify()
                if kind == "untracked":
                    Path("new.txt").unlink()
                Path("file.txt").write_text("base\n")
                guard.git("add", "file.txt")

    def test_remote_tip_must_match_local_commit(self):
        self.commit()
        self.remote_sha = self.base
        with self.assertRaisesRegex(guard.PublicationError, "does not point"):
            self.verify()

    def test_compare_must_prove_head_and_changes(self):
        self.commit()
        self.compare_status = "behind"
        with self.assertRaisesRegex(guard.PublicationError, "comparison"):
            self.verify()
        self.compare_status = "ahead"
        self.ahead = 0
        with self.assertRaisesRegex(guard.PublicationError, "comparison"):
            self.verify()

    def test_pr_absence_and_lookup_error_fail(self):
        self.commit()
        self.no_pr = True
        with self.assertRaisesRegex(guard.PublicationError, "open PR"):
            self.verify()
        self.failure = "/pulls?"
        with self.assertRaisesRegex(guard.PublicationError, "lookup failed"):
            self.verify()

    def test_pr_must_match_full_identity(self):
        self.commit()
        for field in (
            "state",
            "head.sha",
            "head.ref",
            "head.repo.full_name",
            "base.ref",
            "base.repo.full_name",
        ):
            with self.subTest(field=field):

                def corrupt(pr):
                    changed = copy.deepcopy(pr)
                    parent = changed
                    keys = field.split(".")
                    for key in keys[:-1]:
                        parent = parent[key]
                    parent[keys[-1]] = "wrong"
                    return changed

                self.pr_overrides = corrupt
                with self.assertRaisesRegex(guard.PublicationError, "open PR"):
                    self.verify()

    def test_success_verifies_remote_commit_compare_and_pr(self):
        head = self.commit()
        self.assertIn(head, self.verify())
        self.assertEqual(len(self.calls), 3)
        self.assertIn("fix%2Fissue-163", self.calls[0])

    def test_explicit_branch_only_still_requires_publication(self):
        self.commit()
        self.policy.update(
            mode="branch-only", reason="Maintainer requested a published patch branch"
        )
        self.assertIn("explicit no-PR mode", self.verify())
        self.assertEqual(len(self.calls), 2)
        self.failure = "/git/ref/"
        with self.assertRaises(guard.PublicationError):
            self.verify()

    def test_missing_baseline_fails(self):
        (self.directory / "baseline.json").unlink()
        with self.assertRaisesRegex(guard.PublicationError, "baseline missing"):
            self.verify()

    def test_second_session_cannot_rebaseline_local_commit(self):
        self.commit()
        guard.snapshot(self.directory)
        self.failure = "/git/ref/"
        with self.assertRaises(guard.PublicationError):
            self.verify()

    def test_switching_away_cannot_hide_local_commit(self):
        self.commit()
        guard.git("switch", "-c", "other", self.base)
        with self.assertRaisesRegex(guard.PublicationError, "another local branch"):
            self.verify()

    def test_amended_commit_does_not_require_abandoned_reflog_commit(self):
        self.commit()
        guard.git("commit", "--amend", "-m", "corrected implementation")
        self.assertIn("verified PR", self.verify())

    def test_preparation_preserves_signing_and_hooks(self):
        settings = {
            "env": {"GPG_SIGN_URL": "https://example.org"},
            "hooks": {
                "SessionStart": [
                    {
                        "matcher": "startup",
                        "hooks": [{"type": "command", "command": "echo existing"}],
                    }
                ]
            },
        }
        settings_file = self.directory / "signing.json"
        settings_file.write_text(json.dumps(settings))
        event = self.directory / "event.json"
        event.write_text(json.dumps({"repository": {"default_branch": "master"}}))
        output = self.directory / "output"
        with patch.dict(
            os.environ,
            {
                "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_WORKSPACE": str(self.repo),
                "RUNNER_TEMP": str(self.directory),
                "GITHUB_OUTPUT": str(output),
                "CLAUDE_PUBLICATION_MODE": "pull-request",
            },
        ):
            guard.prepare(str(settings_file))
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
        prepared = json.loads(Path(outputs["settings-file"]).read_text())
        self.assertEqual(prepared["env"], settings["env"])
        self.assertEqual(
            prepared["hooks"]["SessionStart"][0], settings["hooks"]["SessionStart"][0]
        )
        hook = prepared["hooks"]["SessionStart"][1]["hooks"][0]
        # Execute the actual generated hook with this interpreter (portable on Windows).
        command = shlex.split(hook["command"])
        subprocess.run([sys.executable, *command[1:]], check=True, capture_output=True)
        self.assertTrue((Path(outputs["directory"]) / "baseline.json").exists())
        self.assertFalse(Path(outputs["directory"]).is_relative_to(self.repo))


ORIGINAL_API = guard.api


class WorkflowTests(unittest.TestCase):
    def test_both_workflows_enforce_postconditions_outside_action(self):
        # Parse YAML, including folded scalars/aliases. Comments or an echo of a
        # script path cannot satisfy this wiring check.
        program = "import {parse} from 'yaml'; console.log(JSON.stringify(parse(await Bun.file(process.argv[1]).text())))"
        for relative in (
            ".github/workflows/claude.yml",
            ".github/workflows-pending/claude.yml",
        ):
            with self.subTest(workflow=relative):
                result = subprocess.run(
                    ["bun", "-e", program, relative],
                    cwd=ROOT,
                    capture_output=True,
                    check=True,
                )
                steps = json.loads(result.stdout)["jobs"]["claude"]["steps"]
                prepare = next(
                    step for step in steps if step.get("id") == "publication"
                )
                action = next(step for step in steps if step.get("id") == "claude")
                verify = next(
                    step
                    for step in steps
                    if step.get("name") == "Verify Claude publication"
                )
                self.assertLess(steps.index(prepare), steps.index(action))
                self.assertLess(steps.index(action), steps.index(verify))
                self.assertEqual(
                    prepare["run"],
                    'python3 .github/scripts/claude-publication.py prepare "$SIGNING_SETTINGS"',
                )
                self.assertEqual(
                    prepare["env"]["SIGNING_SETTINGS"],
                    "${{ steps.signing.outputs.settings-file }}",
                )
                self.assertEqual(
                    action["with"]["settings"],
                    "${{ steps.publication.outputs.settings-file }}",
                )
                self.assertEqual(
                    verify["run"],
                    'python3 "$PUBLICATION_DIR/guard.py" verify "$PUBLICATION_DIR"',
                )
                self.assertEqual(
                    verify["env"]["PUBLICATION_DIR"],
                    "${{ steps.publication.outputs.directory }}",
                )
                self.assertEqual(verify["env"]["GH_TOKEN"], "${{ github.token }}")
                self.assertEqual(
                    verify["if"],
                    "${{ !cancelled() && steps.publication.outcome == 'success' }}",
                )
                self.assertEqual(verify["timeout-minutes"], 3)
                self.assertFalse(verify.get("continue-on-error", False))
                self.assertFalse(prepare.get("continue-on-error", False))
                if "pending" in relative:
                    self.assertNotIn("GH_TOKEN", action["env"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
