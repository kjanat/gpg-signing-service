#!/usr/bin/env python3
"""Real Git lifecycle regressions; only external GitHub/signing calls are mocked."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "publication", Path(__file__).with_name("claude-publication.py")
)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
ORIGINAL_RUN = guard.run


class PublicationTests(unittest.TestCase):
    def setUp(self):
        previous = Path.cwd()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(os.chdir, previous)
        self.root = Path(temporary.name)
        self.repo = self.root / "editor"
        self.repo.mkdir()
        os.chdir(self.repo)
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.org",
            "GIT_COMMITTER_EMAIL": "fixture@example.org",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_OUTPUT": str(self.root / "outputs"),
            "CLAUDE_WORK_BRANCH": "fix/issue-163",
            "CLAUDE_BASE_BRANCH": "master",
            "CLAUDE_ENTITY_KIND": "issue",
            "CLAUDE_ENTITY_NUMBER": "163",
            "CLAUDE_BRANCH_IS_NEW": "true",
            "CLAUDE_PUBLICATION_MODE": "pull-request",
            "CLAUDE_NO_PR_REASON": "",
            "CLAUDE_CONTEXT_FILE": str(self.root / "context.md"),
            "CLAUDE_RESPONSE_FILE": str(self.root / "response.md"),
            "CLAUDE_OUTCOME": "success",
            "CLAUDE_EXECUTION_FILE": "",
            "GH_TOKEN": "fixture-app-token",
            "WORKFLOW_GITHUB_TOKEN": "fixture-workflow-token",
            "SIGNING_ENABLED": "true",
        }
        env_patch = patch.dict(os.environ, environment)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        guard.git("init", "--initial-branch=master")
        Path("file.txt").write_text("base\n")
        guard.git("add", "file.txt")
        guard.git("commit", "-m", "base")
        self.start = guard.git("rev-parse", "HEAD")
        self.remote = self.root / "remote.git"
        guard.git("init", "--bare", str(self.remote))
        guard.git("remote", "add", "origin", str(self.remote))
        guard.git("push", "origin", "master")
        guard.git("switch", "-c", "fix/issue-163")
        (self.root / "context.md").write_text("Maintainer request\n")
        (self.root / "response.md").write_text("Implemented requested behavior.\n")
        self.inputs = self.root / "input"
        self.candidate = self.root / "candidate"
        self.verified = self.root / "verified"
        guard.prepare(self.inputs)
        self.calls = []
        self.fail = ""
        self.pr_override = {}
        self.created_pr = False
        self.no_pr = False
        self.existing_pr = False
        self.transport_patch = patch.object(guard, "run", self.transport)
        self.transport_patch.start()
        self.addCleanup(self.transport_patch.stop)

    def transport(self, *args, data=None, env=None):
        self.calls.append(args)
        if args[0] == "bash":
            return b""
        if args[0] == "gpg-sign":
            if self.fail == "signing":
                raise guard.PublicationError("Signing service unavailable")
            return b"fixture public key"
        if args[0] == "gpg":
            return b""
        if args[0] == "git":
            if "verify-commit" in args:
                return b""
            if "commit-tree" in args and "-S" in args:
                args = tuple(value for value in args if value != "-S")
                args = tuple(
                    "commit.gpgsign=false" if value == "commit.gpgsign=true" else value
                    for value in args
                )
            if "push" in args and self.fail == "push":
                raise guard.PublicationError("Push rejected")
            result = ORIGINAL_RUN(*args, data=data, env=env)
            if "push" in args and self.fail == "missing-remote":
                ORIGINAL_RUN(
                    "git",
                    "--git-dir=" + str(self.remote),
                    "update-ref",
                    "-d",
                    "refs/heads/fix/issue-163",
                )
            return result
        if args[0] != "gh":
            raise AssertionError("Unexpected external tool: " + str(args))
        if args[1:3] == ("auth", "setup-git"):
            return b""
        endpoint = args[2]
        if endpoint == "--method":
            return b""
        if "/comments" in endpoint:
            return b'{"id":1}'
        if "/git/ref/" in endpoint:
            sha = "0" * 40 if self.fail == "ref-mismatch" else self.remote_head()
            return json.dumps({"object": {"sha": sha}}).encode()
        if "/compare/" in endpoint:
            if self.fail == "compare":
                raise guard.PublicationError("HTTP 404")
            self.assertTrue(endpoint.endswith("..." + self.remote_head()))
            return b'{"status":"ahead","ahead_by":1}'
        if "/pulls?" in endpoint:
            return b'[{"number":164}]' if self.existing_pr else b"[]"
        if endpoint.endswith("/pulls"):
            if self.fail == "create-pr":
                raise guard.PublicationError("HTTP 403")
            self.created_pr = True
            return b'{"number":164}'
        if "/pulls/" in endpoint:
            if self.no_pr:
                raise guard.PublicationError("HTTP 404")
            value = {
                "state": "open",
                "head": {
                    "sha": self.remote_head(),
                    "ref": "fix/issue-163",
                    "repo": {"full_name": "owner/repo"},
                },
                "base": {"ref": "master", "repo": {"full_name": "owner/repo"}},
            }
            value.update(self.pr_override)
            return json.dumps(value).encode()
        raise AssertionError("Unexpected GitHub call: " + str(args))

    def remote_head(self):
        return guard.remote_sha("fix/issue-163")

    def edit(self):
        Path("file.txt").write_text("implementation\n")

    def exported(self):
        guard.export(self.inputs, self.candidate)

    def checkout(self, name):
        target = self.root / name
        guard.git("clone", "--no-local", str(self.remote), str(target))
        os.chdir(target)
        self.assertEqual(guard.git("rev-parse", "HEAD"), self.start)
        return target

    def verified_candidate(self, changed=True):
        if changed:
            self.edit()
        self.exported()
        self.checkout("verifier")
        guard.verify(self.inputs, self.candidate, self.verified)
        guard.seal(self.inputs, self.verified)

    def publish(self):
        self.checkout("publisher")
        return guard.publish(self.inputs, self.verified)

    def comments(self):
        return [
            call
            for call in self.calls
            if call[0] == "gh" and any("/comments" in value for value in call)
        ]

    def test_export_preserves_local_commit_index_worktree_and_new_files(self):
        Path("committed.txt").write_text("local commit\n")
        guard.git("add", "committed.txt")
        guard.git("commit", "-m", "model local work")
        local = guard.git("rev-parse", "HEAD")
        Path("staged.txt").write_text("staged content\n")
        guard.git("add", "staged.txt")
        self.edit()
        Path("new.txt").write_text("new content\n")
        original_index = guard.git("write-tree")
        self.exported()
        self.assertEqual(guard.git("write-tree"), original_index)
        self.assertEqual(guard.git("rev-parse", "HEAD"), local)
        patch_text = (self.candidate / "checkout.patch").read_text()
        for filename in ("committed.txt", "staged.txt", "file.txt", "new.txt"):
            self.assertIn(filename, patch_text)
        recovery = guard.git(
            "bundle", "list-heads", str(self.candidate / "recovery.bundle")
        )
        self.assertIn(local, recovery)
        self.checkout("verifier")
        guard.verify(self.inputs, self.candidate, self.verified)
        for filename in ("committed.txt", "staged.txt", "new.txt"):
            self.assertTrue(Path(filename).is_file())
        self.assertEqual(Path("file.txt").read_text(), "implementation\n")
        guard.seal(self.inputs, self.verified)

    def test_local_commit_then_rejected_push_fails_and_retains_recovery(self):
        self.edit()
        guard.git("add", "file.txt")
        guard.git("commit", "-m", "implementation")
        self.verified_candidate(changed=False)
        self.assertEqual(self.remote_head(), "")
        self.fail = "push"
        with self.assertRaisesRegex(guard.PublicationError, "Push rejected"):
            self.publish()
        self.assertEqual(self.remote_head(), "")
        self.assertTrue((self.candidate / "recovery.bundle").is_file())
        self.assertTrue((self.verified / "verified.bundle").is_file())
        self.assertEqual(self.comments(), [])

    def test_compare_404_after_push_is_fatal(self):
        self.verified_candidate()
        self.fail = "compare"
        with self.assertRaisesRegex(guard.PublicationError, "GitHub lookup failed"):
            self.publish()
        self.assertNotEqual(self.remote_head(), "")
        self.assertFalse(self.created_pr)
        self.assertEqual(self.comments(), [])

    def test_missing_remote_after_push_is_fatal(self):
        self.verified_candidate()
        self.fail = "missing-remote"
        with self.assertRaisesRegex(guard.PublicationError, "Remote branch"):
            self.publish()
        self.assertEqual(self.comments(), [])

    def test_github_ref_must_match_actual_pushed_sha(self):
        self.verified_candidate()
        self.fail = "ref-mismatch"
        with self.assertRaisesRegex(guard.PublicationError, "GitHub branch SHA"):
            self.publish()
        self.assertEqual(self.comments(), [])

    def test_genuine_nochange_question_succeeds_without_remote_branch(self):
        self.verified_candidate(changed=False)
        self.publish()
        self.assertEqual(self.remote_head(), "")
        self.assertEqual(len(self.comments()), 1)
        self.assertFalse(
            any(call[0] == "git" and "push" in call for call in self.calls)
        )
        self.assertFalse(any(call[0] == "gpg-sign" for call in self.calls))
        self.assertIn("status=no-change", (self.root / "outputs").read_text())

    def test_failed_action_nochange_cannot_succeed(self):
        self.exported()
        self.checkout("verifier")
        os.environ["CLAUDE_OUTCOME"] = "failure"
        with self.assertRaisesRegex(guard.PublicationError, "Editing did not complete"):
            guard.verify(self.inputs, self.candidate, self.verified)
        self.assertFalse((self.verified / "verified.bundle").exists())

    def test_success_verifies_exact_branch_pr_and_kaj_identity_without_checkout(self):
        self.verified_candidate()
        self.publish()
        signed = self.remote_head()
        self.assertTrue(signed)
        self.assertTrue(self.created_pr)
        self.assertEqual(guard.git("rev-parse", "HEAD"), self.start)
        self.assertEqual(Path("file.txt").read_text(), "base\n")
        self.assertEqual(guard.git("show", signed + ":file.txt"), "implementation")
        self.assertEqual(
            guard.git("show", "-s", "--format=%an <%ae>|%cn <%ce>", signed),
            "Kaj Kowalski <info@kajkowalski.nl>|Kaj Kowalski <info@kajkowalski.nl>",
        )
        self.assertEqual(guard.git("show", "-s", "--format=%P", signed), self.start)
        self.assertTrue(any("verify-commit" in call for call in self.calls))
        self.assertTrue(
            any("commit-tree" in call and "-S" in call for call in self.calls)
        )
        self.assertEqual(len(self.comments()), 1)
        self.assertTrue(
            any("/pulls/164" in value for call in self.calls for value in call)
        )
        self.assertIn("status=changed", (self.root / "outputs").read_text())

    def test_missing_pr_after_creation_is_fatal(self):
        self.verified_candidate()
        self.no_pr = True
        with self.assertRaisesRegex(guard.PublicationError, "GitHub lookup failed"):
            self.publish()
        self.assertEqual(self.comments(), [])

    def test_wrong_pr_head_is_fatal(self):
        self.verified_candidate()
        self.pr_override = {
            "head": {
                "sha": self.start,
                "ref": "fix/issue-163",
                "repo": {"full_name": "owner/repo"},
            }
        }
        with self.assertRaisesRegex(guard.PublicationError, "PR does not point"):
            self.publish()
        self.assertEqual(self.comments(), [])

    def test_failed_pr_creation_is_fatal(self):
        self.verified_candidate()
        self.fail = "create-pr"
        with self.assertRaisesRegex(guard.PublicationError, "GitHub lookup failed"):
            self.publish()
        self.assertEqual(self.comments(), [])

    def test_branch_only_requires_reason_and_still_verifies_remote(self):
        request = guard.read_json(self.inputs / "request.json")
        request["mode"] = "branch-only"
        guard.write_json(self.inputs / "request.json", request)
        with self.assertRaisesRegex(
            guard.PublicationError, "explicit maintainer reason"
        ):
            guard.policy(self.inputs)
        request["reason"] = "Maintainer requested a branch for downstream testing"
        guard.write_json(self.inputs / "request.json", request)
        self.verified_candidate()
        self.publish()
        self.assertTrue(self.remote_head())
        self.assertFalse(
            any("/pulls" in value for call in self.calls for value in call)
        )
        self.assertEqual(len(self.comments()), 1)

    def test_forged_candidate_parent_rejected(self):
        self.edit()
        guard.git("add", "file.txt")
        guard.git("commit", "-m", "extra parent")
        extra = guard.git("rev-parse", "HEAD")
        self.exported()
        candidate = guard.git(
            "-c",
            "commit.gpgsign=false",
            "commit-tree",
            guard.git("rev-parse", "HEAD^{tree}"),
            "-p",
            extra,
            data=b"forged\n",
        )
        guard.make_bundle(self.candidate / "candidate.bundle", candidate, self.start)
        self.checkout("verifier")
        with self.assertRaisesRegex(guard.PublicationError, "exactly the trusted"):
            guard.verify(self.inputs, self.candidate, self.verified)

    def test_input_for_another_repository_rejected(self):
        request = guard.read_json(self.inputs / "request.json")
        request["repository"] = "attacker/repo"
        guard.write_json(self.inputs / "request.json", request)
        with self.assertRaisesRegex(guard.PublicationError, "Input repository"):
            guard.export(self.inputs, self.candidate)

    def test_changes_during_checks_cannot_be_sealed(self):
        self.edit()
        self.exported()
        self.checkout("verifier")
        guard.verify(self.inputs, self.candidate, self.verified)
        Path("file.txt").write_text("changed by tests\n")
        with self.assertRaisesRegex(guard.PublicationError, "unverified file changes"):
            guard.seal(self.inputs, self.verified)
        self.assertFalse((self.verified / "verified.bundle").exists())

    def test_signing_unavailable_never_pushes(self):
        self.verified_candidate()
        self.fail = "signing"
        with self.assertRaisesRegex(
            guard.PublicationError, "Signing service unavailable"
        ):
            self.publish()
        self.assertEqual(self.remote_head(), "")
        self.assertEqual(self.comments(), [])

    def test_missing_signing_policy_never_pushes(self):
        self.verified_candidate()
        os.environ.pop("SIGNING_ENABLED")
        with self.assertRaisesRegex(
            guard.PublicationError, "Signing policy unavailable"
        ):
            self.publish()
        self.assertEqual(self.remote_head(), "")

    def test_execution_tail_redacts_known_credentials(self):
        execution = self.root / "execution.json"
        execution.write_text("token=fixture-app-token\n")
        os.environ["CLAUDE_EXECUTION_FILE"] = str(execution)
        self.exported()
        text = (self.candidate / "execution-tail.txt").read_text()
        self.assertNotIn("fixture-app-token", text)
        self.assertIn("[REDACTED]", text)

    def test_staged_only_work_cannot_be_misclassified_as_nochange(self):
        Path("file.txt").write_text("staged implementation\n")
        guard.git("add", "file.txt")
        Path("file.txt").write_text("base\n")
        with self.assertRaisesRegex(guard.PublicationError, "cannot be classified"):
            self.exported()
        self.assertIn(
            "staged implementation", (self.candidate / "staged.patch").read_text()
        )
        self.assertIn(
            "staged implementation", (self.candidate / "unstaged.patch").read_text()
        )
        self.assertTrue((self.candidate / "recovery.bundle").is_file())
        self.assertFalse((self.candidate / "response.md").exists())

    def test_hidden_branch_commit_is_preserved_and_export_fails(self):
        guard.git("switch", "-c", "hidden-work")
        self.edit()
        guard.git("add", "file.txt")
        guard.git("commit", "-m", "hidden implementation")
        hidden = guard.git("rev-parse", "HEAD")
        guard.git("switch", "fix/issue-163")
        with self.assertRaisesRegex(guard.PublicationError, "another local branch"):
            self.exported()
        recovery = guard.git(
            "bundle", "list-heads", str(self.candidate / "recovery.bundle")
        )
        self.assertIn(hidden, recovery)

    def test_closed_existing_pr_fails_before_pushing(self):
        guard.git("push", "origin", "fix/issue-163")
        request = guard.read_json(self.inputs / "request.json")
        request.update({"kind": "pull_request", "new": False})
        guard.write_json(self.inputs / "request.json", request)
        self.verified_candidate()
        self.pr_override = {"state": "closed"}
        with self.assertRaisesRegex(guard.PublicationError, "PR does not point"):
            self.publish()
        self.assertEqual(self.remote_head(), self.start)
        self.assertEqual(self.comments(), [])

    def test_retargeted_existing_pr_fails_before_pushing(self):
        guard.git("push", "origin", "fix/issue-163")
        request = guard.read_json(self.inputs / "request.json")
        request.update({"kind": "pull_request", "new": False})
        guard.write_json(self.inputs / "request.json", request)
        self.verified_candidate()
        self.pr_override = {
            "base": {"ref": "different-base", "repo": {"full_name": "owner/repo"}}
        }
        with self.assertRaisesRegex(guard.PublicationError, "PR does not point"):
            self.publish()
        self.assertEqual(self.remote_head(), self.start)
        self.assertEqual(self.comments(), [])

    def test_existing_pr_is_verified_before_and_after_fast_forward(self):
        guard.git("push", "origin", "fix/issue-163")
        request = guard.read_json(self.inputs / "request.json")
        request.update({"kind": "pull_request", "new": False})
        guard.write_json(self.inputs / "request.json", request)
        self.verified_candidate()
        self.publish()
        self.assertNotEqual(self.remote_head(), self.start)
        self.assertFalse(self.created_pr)
        reads = [
            i
            for i, call in enumerate(self.calls)
            if "repos/owner/repo/pulls/163" in call
        ]
        push = next(
            i
            for i, call in enumerate(self.calls)
            if call[0] == "git"
            and "push" in call
            and "--force-with-lease=refs/heads/fix/issue-163:" + self.start in call
        )
        self.assertEqual(len(reads), 2)
        self.assertLess(reads[0], push)
        self.assertGreater(reads[1], push)


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        files = [".github/workflows/claude.yml", ".github/workflows-pending/claude.yml"]
        result = subprocess.run(
            [
                "bun",
                "-e",
                "import {parse} from 'yaml'; "
                "console.log(JSON.stringify(await Promise.all(process.argv.slice(1).map(async p => "
                "parse(await Bun.file(p).text())))));",
                *files,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
        )
        cls.workflows = json.loads(result.stdout)

    def test_editor_and_verifier_cannot_publish_or_request_signing_oidc(self):
        for workflow in self.workflows:
            with self.subTest(workflow=workflow["name"]):
                jobs = workflow["jobs"]
                self.assertEqual(set(jobs), {"edit", "verify", "publish"})
                for name in ("edit", "verify"):
                    self.assertNotIn("write", jobs[name]["permissions"].values())
                    self.assertNotIn("id-token", jobs[name]["permissions"])
                    self.assertNotIn("setup-claude-signing", json.dumps(jobs[name]))
                self.assertEqual(jobs["publish"]["permissions"]["contents"], "write")
                self.assertEqual(jobs["publish"]["permissions"]["id-token"], "write")

    def test_input_is_immutable_before_editing_and_recovery_always_runs(self):
        for workflow in self.workflows:
            edit = workflow["jobs"]["edit"]
            steps = edit["steps"]
            agent_index = next(
                i for i, step in enumerate(steps) if step.get("id") == "claude"
            )
            input_index = next(
                i for i, step in enumerate(steps) if step.get("id") == "input"
            )
            self.assertLess(input_index, agent_index)
            agent = steps[agent_index]
            self.assertIn("/base-action@", agent["uses"])
            self.assertRegex(agent["uses"].split("@")[1], r"^[0-9a-f]{40}$")
            self.assertTrue(agent["continue-on-error"])
            self.assertLess(agent["timeout-minutes"], edit["timeout-minutes"])
            self.assertIn("Do not commit, push", agent["with"]["prompt"])
            self.assertNotIn("SIGNING", agent.get("env", {}))
            export = next(step for step in steps if " export " in step.get("run", ""))
            recovery = next(
                step
                for step in steps
                if step.get("with", {}).get("name") == "claude-candidate"
            )
            self.assertIn("always()", export["if"])
            self.assertIn("always()", recovery["if"])
            self.assertEqual(recovery["with"]["if-no-files-found"], "error")

    def test_only_successful_independent_verification_can_reach_publisher(self):
        for workflow in self.workflows:
            verify = workflow["jobs"]["verify"]
            publish = workflow["jobs"]["publish"]
            self.assertIn("needs.verify.result == 'success'", publish["if"])
            self.assertIn("needs.edit.result == 'success'", publish["if"])
            self.assertIn("always()", verify["if"])
            checks = next(
                step
                for step in verify["steps"]
                if "task test:coverage" in step.get("run", "")
            )
            self.assertNotIn("continue-on-error", checks)
            self.assertIn("changed", checks["if"])
            commands = [step.get("run", "") for step in verify["steps"]]
            self.assertLess(
                next(
                    i
                    for i, command in enumerate(commands)
                    if "task test:coverage" in command
                ),
                next(i for i, command in enumerate(commands) if " seal " in command),
            )
            for job in workflow["jobs"].values():
                checkout = next(
                    step
                    for step in job["steps"]
                    if step.get("uses", "").startswith("actions/checkout@")
                )
                self.assertEqual(checkout["with"]["ref"], "${{ github.workflow_sha }}")
                self.assertFalse(checkout["with"]["persist-credentials"])
            self.assertNotIn("task ", json.dumps(publish))
            self.assertNotIn(
                " checkout ",
                "\n".join(step.get("run", "") for step in publish["steps"]),
            )


class PublisherTokenTests(unittest.TestCase):
    def test_workflow_token_is_refused(self):
        with patch.dict(
            os.environ, {"GH_TOKEN": "workflow", "WORKFLOW_GITHUB_TOKEN": "workflow"}
        ):
            with self.assertRaisesRegex(guard.PublicationError, "suppress PR CI"):
                guard.publisher_token()

    def test_explicit_app_token_needs_no_exchange(self):
        with patch.dict(
            os.environ, {"GH_TOKEN": "app", "WORKFLOW_GITHUB_TOKEN": "workflow"}
        ):
            with patch.object(guard, "http_json") as exchange:
                self.assertEqual(guard.publisher_token(), ("app", False))
                exchange.assert_not_called()

    def test_oidc_app_exchange_requests_only_publication_permissions(self):
        environment = {
            "GH_TOKEN": "",
            "WORKFLOW_GITHUB_TOKEN": "workflow",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid/token?run=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-request-secret",
        }
        with patch.dict(os.environ, environment):
            with patch.object(
                guard,
                "http_json",
                side_effect=[{"value": "oidc-jwt"}, {"token": "app-token"}],
            ) as exchange:
                self.assertEqual(guard.publisher_token(), ("app-token", True))
                self.assertEqual(exchange.call_count, 2)
                self.assertIn(
                    "audience=claude-code-github-action",
                    exchange.call_args_list[0].args[0],
                )
                self.assertEqual(exchange.call_args_list[1].kwargs["token"], "oidc-jwt")
                self.assertEqual(
                    exchange.call_args_list[1].kwargs["body"]["permissions"],
                    {"contents": "write", "pull_requests": "write", "issues": "write"},
                )

    def test_exchange_without_token_is_fatal(self):
        environment = {
            "GH_TOKEN": "",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret",
        }
        with patch.dict(os.environ, environment):
            with patch.object(guard, "http_json", side_effect=[{"value": "jwt"}, {}]):
                with self.assertRaisesRegex(guard.PublicationError, "no token"):
                    guard.publisher_token()

    def test_exchange_token_revoked_even_after_publication_failure(self):
        with patch.object(
            guard, "publisher_token", return_value=("temporary-app-token", True)
        ):
            with patch.object(
                guard,
                "publish_result",
                side_effect=guard.PublicationError("publication failed"),
            ):
                with patch.object(guard, "run") as transport:
                    with self.assertRaisesRegex(
                        guard.PublicationError, "publication failed"
                    ):
                        guard.publish(Path("input"), Path("verified"))
                    transport.assert_called_once_with(
                        "gh", "api", "--method", "DELETE", "/installation/token"
                    )


if __name__ == "__main__":
    unittest.main()
