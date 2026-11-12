"""Offline tests of trusted workflow scripts; no Copilot calls or fixture code execution.

Run locally with Python, PyYAML, Git, Bash, jq, and GNU timeout.
Unsafe source strings below are non-executable review evidence in temporary repos.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.load(
    (ROOT / ".github" / "workflows" / "security-snapshot.yml").read_text(encoding="utf-8"),
    Loader=yaml.BaseLoader,
)
STEPS = WORKFLOW["jobs"]["audit"]["steps"]
SCRIPTS = ROOT / ".github" / "scripts"
PR_WORKFLOW = yaml.load(
    (ROOT / ".github" / "workflows" / "security-compliance.yml").read_text(encoding="utf-8"),
    Loader=yaml.BaseLoader,
)
PR_STEPS = PR_WORKFLOW["jobs"]["review"]["steps"]
POLICY_PATH = "security/organization-standards.md"
BASH = shutil.which("bash")
SAFE_SOURCE = 'connection.execute("SELECT id FROM accounts WHERE email = ?", (email,))\n'
UNSAFE_SOURCE = 'connection.execute("SELECT id FROM accounts WHERE email = \'" + email + "\'")\n'


class SnapshotAuditTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="snapshot-audit-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "repo"
        self.temp = self.root / "runner"
        self.repo.mkdir()
        self.temp.mkdir()
        self.env = {
            **os.environ,
            "RUNNER_TEMP": str(self.temp),
            "GITHUB_WORKSPACE": str(ROOT),
            "GITHUB_STEP_SUMMARY": str(self.temp / "summary.md"),
            "COPILOT_GITHUB_TOKEN": "nonfunctional-offline-placeholder",
            **{f"{stage}_OUTCOME": "success" for stage in ("TRUST", "CHECKOUT", "PREPARE", "INSTALL", "REVIEW")},
        }
        self.env.pop("COPILOT_MODEL", None)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "core.autocrlf", "false")
        self.write(POLICY_PATH, (ROOT / POLICY_PATH).read_text(encoding="utf-8"))
        self.write("src/query.py", SAFE_SOURCE)
        self.write("README.md", "Example repository.\n")
        self.commit()

    def git(self, *args, input=None):
        return subprocess.run(
            ["git", *args], cwd=self.repo, input=input, text=True,
            encoding="utf-8", capture_output=True, check=True,
        ).stdout.strip()

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def commit(self):
        self.git("add", "--all")
        self.git("-c", "user.name=Offline test", "-c", "user.email=offline@example.invalid",
                 "commit", "--quiet", "--allow-empty", "-m", "Offline fixture")
        return self.git("rev-parse", "HEAD")

    def run_step(self, command):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "security-snapshot.py"), command],
            cwd=self.repo, env=self.env,
            capture_output=True, text=True, encoding="utf-8",
        )

    def run_shell(self, command, **env):
        prefix = ""
        if os.name == "nt":
            for name in ("RUNNER_TEMP", "GITHUB_STEP_SUMMARY", "GITHUB_WORKSPACE"):
                prefix += f'export {name}="$(cygpath -u "${name}")"\n'
        return subprocess.run(
            [BASH, "-e", "-o", "pipefail", "-c", prefix + command],
            cwd=self.repo, env={**self.env, **env},
            capture_output=True, text=True, encoding="utf-8",
        )

    def prepare(self, success=True):
        for name in ("prompt.txt", "snapshot.json"):
            (self.temp / name).unlink(missing_ok=True)
        result = self.run_step("prepare")
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        self.manifest = json.loads((self.temp / "snapshot.json").read_text(encoding="utf-8"))
        self.assertEqual(self.manifest["prepared"], success)
        if success:
            prompt = (self.temp / "prompt.txt").read_text(encoding="utf-8")
            return json.loads(prompt.split("Review input:\n", 1)[1])
        self.assertFalse((self.temp / "prompt.txt").exists())
        self.env["PREPARE_OUTCOME"] = "failure"

    def report(self, **overrides):
        return {
            "snapshot_commit": self.manifest["commit"],
            "policy_blob": self.manifest["policy_blob"],
            "reviewed_paths": [f["path"] for f in self.manifest["files"]],
            "complete": True, "summary": "Offline fixture assessment.", "violations": [],
            **overrides,
        }

    def events(self, report):
        return [
            {"type": "assistant.message", "data": {"content": json.dumps(report)}},
            {"type": "result", "exitCode": 0},
        ]

    def publish(self, events, status):
        summary_path = Path(self.env["GITHUB_STEP_SUMMARY"])
        summary_path.unlink(missing_ok=True)
        raw = events if isinstance(events, str) else "\n".join(json.dumps(e) for e in events)
        (self.temp / "events.jsonl").write_text(raw, encoding="utf-8")
        result = self.run_step("report")
        self.assertEqual(result.returncode, 0 if status == "PASS" else 1, result.stderr)
        summary = summary_path.read_text(encoding="utf-8")
        self.assertIn(f"**{status}**", summary)
        self.assertNotIn("do-not-publish-this-diagnostic", summary)
        return summary

    def violation(self):
        return {
            "rule_id": "SEC-001", "severity": "high", "path": "src/query.py", "line": 1,
            "explanation": "Untrusted email is concatenated into executed SQL.",
            "remediation": "Use a placeholder and a separate parameter collection.",
        }

    def mock_cli(self, command, **env):
        mock_bin = self.temp / "bin"
        mock_bin.mkdir(exist_ok=True)
        cli = mock_bin / "copilot"
        cli.write_text(
            '#!/usr/bin/env bash\n'
            'printf "%s\\0" "$@" > "$RUNNER_TEMP/args.bin"\n'
            'pwd > "$RUNNER_TEMP/cli-cwd.txt"\n'
            'printf "%s" "$COPILOT_HOME" > "$RUNNER_TEMP/cli-home.txt"\n'
            'cat > "$RUNNER_TEMP/received-prompt.txt"\n'
            'printf "%s\\n" "$MOCK_EVENTS"\n'
            'exit "$MOCK_EXIT_CODE"\n',
            encoding="utf-8", newline="\n",
        )
        cli.chmod(0o755)
        prefix = 'export PATH="$MOCK_BIN:$PATH"\n'
        if os.name == "nt":
            prefix = 'MOCK_BIN="$(cygpath -u "$MOCK_BIN")"\n' + prefix
        prefix += '[[ "$(command -v copilot)" == "$MOCK_BIN/copilot" ]] || exit 99\n'
        return self.run_shell(
            prefix + command, MOCK_BIN=str(mock_bin),
            **{"MOCK_EVENTS": "", "MOCK_EXIT_CODE": "0", **env},
        )

    def test_shared_cli_default_configured_model_and_isolation(self):
        (self.temp / "prompt.txt").write_text("Offline evidence only.", encoding="utf-8")
        # This model-like string must remain one argument, never shell code or flags.
        literal_model = 'model with spaces; touch MODEL_EXECUTED; $(touch MODEL_EXECUTED) --allow-all'
        for mode in ("pr", "snapshot"):
            for value in (None, "", "another-supported-model", literal_model):
                with self.subTest(mode=mode, model=value):
                    result = self.mock_cli(
                        f'bash "$GITHUB_WORKSPACE/.github/scripts/copilot-review.sh" {mode}',
                        **({} if value is None else {"COPILOT_MODEL": value}),
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = (self.temp / "args.bin").read_bytes().decode().rstrip("\0").split("\0")
                    self.assertEqual(args, [
                        "--model", value or "claude-haiku-5.5", "--context", "long_context",
                        "--silent", "--output-format", "json", "--available-tools=none",
                        "--disable-builtin-mcps", "--no-custom-instructions",
                        "--no-auto-update", "--max-ai-credits", "30",
                    ])
                    cwd = (self.temp / "cli-cwd.txt").read_text().strip()
                    home = (self.temp / "cli-home.txt").read_text().strip()
                    self.assertTrue(cwd.endswith("/" + self.temp.name), cwd)
                    self.assertEqual(home, cwd + "/copilot-home")
                    self.assertEqual((self.temp / "received-prompt.txt").read_text(), "Offline evidence only.")
                    self.assertFalse((self.temp / "MODEL_EXECUTED").exists())
                    self.assertFalse((self.repo / "MODEL_EXECUTED").exists())

    def test_pr_prepare_uses_base_policy_and_never_executes_head_files(self):
        base = self.git("rev-parse", "HEAD")
        trusted_policy = (self.repo / POLICY_PATH).read_text(encoding="utf-8")
        self.write(POLICY_PATH, "Proposed weaker policy; do not use for this review.\n")
        self.write("src/query.py", UNSAFE_SOURCE)
        self.write("doc/example.sql", "Non-executable fixture: unsafe SQL example remains in scope.\n")
        self.write(".github/scripts/security-pr.sh", "touch PR_CODE_EXECUTED\n")
        head = self.commit()
        self.git("switch", "--detach", base)
        self.git("remote", "add", "origin", str(self.repo))
        result = self.run_shell(
            'bash "$GITHUB_WORKSPACE/.github/scripts/security-pr.sh" prepare',
            BASE_SHA=base, HEAD_SHA=head,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        prompt = (self.temp / "prompt.txt").read_text(encoding="utf-8")
        evidence = json.loads(prompt.split("Review input:\n", 1)[1])
        self.assertEqual(evidence["policy"], trusted_policy)
        for text in ("doc/example.sql", ".github/scripts/security-pr.sh", "Proposed weaker policy", UNSAFE_SOURCE.strip()):
            self.assertIn(text, evidence["changes"])
        self.assertEqual(self.git("rev-parse", "HEAD"), base)
        self.assertFalse((self.repo / "PR_CODE_EXECUTED").exists())
        self.assertFalse((self.repo / ".github/scripts/security-pr.sh").exists())

    def test_pr_report_fails_closed_for_incomplete_invalid_and_error_events(self):
        report = {"complete": True, "summary": "Offline fixture.", "violations": []}
        valid = self.events(report)
        cases = [
            (valid, True),
            (self.events({**report, "violations": [self.violation()]}), False),
            (self.events({**report, "complete": False}), False),
            (self.events({**report, "complete": "true"}), False),
            (self.events({**report, "summary": " "}), False),
            (self.events({**report, "violations": [{"line": 0}]}), False),
            ("", False), ("not JSON", False), ("[]", False),
            (valid[:-1], False), (valid + [valid[0]], False),
            (valid + [valid[-1]], False),
            ([valid[0], {"type": "result", "exitCode": 1}], False),
            (valid + [{"type": "session.error", "data": {"message": "offline failure"}}], False),
        ]
        for events, passes in cases:
            with self.subTest(events=events):
                raw = events if isinstance(events, str) else "\n".join(json.dumps(e) for e in events)
                (self.temp / "events.jsonl").write_text(raw, encoding="utf-8")
                Path(self.env["GITHUB_STEP_SUMMARY"]).unlink(missing_ok=True)
                result = self.run_shell('bash "$GITHUB_WORKSPACE/.github/scripts/security-pr.sh" report')
                self.assertEqual(result.returncode == 0, passes, result.stderr)
                summary = Path(self.env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
                self.assertEqual("PASS:" in summary, passes)
        (self.temp / "events.jsonl").unlink()
        result = self.run_shell('bash "$GITHUB_WORKSPACE/.github/scripts/security-pr.sh" report')
        self.assertNotEqual(result.returncode, 0)

    def test_pr_cli_failure_rejects_success_shaped_output(self):
        (self.temp / "prompt.txt").write_text("Offline evidence only.", encoding="utf-8")
        events = self.events({"complete": True, "summary": "Not accepted.", "violations": []})
        result = self.mock_cli(
            'bash "$GITHUB_WORKSPACE/.github/scripts/copilot-review.sh" pr',
            MOCK_EXIT_CODE="1", MOCK_EVENTS="\n".join(json.dumps(e) for e in events),
            COPILOT_MODEL="unavailable-model",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no compliance verdict was accepted", result.stdout)
        self.assertIn(b"unavailable-model\0", (self.temp / "args.bin").read_bytes())

    def test_snapshot_timeout_is_nonzero_and_does_not_run_cli(self):
        (self.temp / "prompt.txt").write_text("Offline evidence only.", encoding="utf-8")
        mock_bin = self.temp / "bin"
        mock_bin.mkdir()
        timer = mock_bin / "timeout"
        timer.write_text(
            '#!/usr/bin/env bash\n'
            'printf "%s\\0" "$@" > "$RUNNER_TEMP/timeout-args.bin"\nexit 124\n',
            encoding="utf-8", newline="\n",
        )
        timer.chmod(0o755)
        result = self.mock_cli('bash "$GITHUB_WORKSPACE/.github/scripts/copilot-review.sh" snapshot')
        self.assertEqual(result.returncode, 124, result.stderr)
        args = (self.temp / "timeout-args.bin").read_bytes().split(b"\0")
        self.assertEqual(args[:2], [b"5m", b"copilot"])
        self.assertFalse((self.temp / "args.bin").exists())

    def test_snapshot_early_summary_never_runs_repository_script(self):
        self.write(".github/scripts/security-snapshot.py", 'raise RuntimeError("UNTRUSTED_SCRIPT_RAN")\n')
        for stage in ("TRUST", "CHECKOUT"):
            with self.subTest(stage=stage):
                result = self.run_shell(STEPS[-1]["run"], **{f"{stage}_OUTCOME": "failure"})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn("UNTRUSTED_SCRIPT_RAN", result.stdout + result.stderr)
                summary = Path(self.env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
                self.assertIn("**ERROR**", summary)

    def test_pr_admission_and_trusted_script_wiring(self):
        self.assertEqual(list(PR_WORKFLOW["jobs"]), ["review"])
        self.assertEqual(PR_WORKFLOW["on"], {"pull_request_target": {
            "branches": ["main"],
            "types": ["opened", "reopened", "synchronize", "ready_for_review", "edited"],
        }})
        self.assertEqual(PR_STEPS[1]["with"]["ref"], "${{ github.event.pull_request.base.sha }}")
        self.assertEqual(PR_STEPS[1]["with"]["persist-credentials"], "false")
        self.assertEqual(PR_STEPS[2]["run"], "bash .github/scripts/security-pr.sh prepare")
        self.assertEqual(PR_STEPS[4]["run"], 'bash "$GITHUB_WORKSPACE/.github/scripts/copilot-review.sh" pr')
        self.assertEqual(PR_STEPS[5]["run"], 'bash "$GITHUB_WORKSPACE/.github/scripts/security-pr.sh" report')
        for workflow in (PR_WORKFLOW, WORKFLOW):
            self.assertEqual(workflow["env"]["COPILOT_MODEL"], "${{ vars.COPILOT_MODEL }}")
            for job in workflow["jobs"].values():
                self.assertEqual(job["timeout-minutes"], "10")
                for step in job["steps"]:
                    if "run" in step:
                        subprocess.run([BASH, "-n"], input=step["run"].encode(), check=True)
        for head, expected in (("owner/repo", 0), ("outsider/repo", 1), ("", 1)):
            result = self.run_shell(
                PR_STEPS[0]["run"], GITHUB_REPOSITORY="owner/repo", HEAD_REPOSITORY=head,
            )
            self.assertEqual(result.returncode, expected, result.stderr)
        ruleset = json.loads((ROOT / ".github/rulesets/protected-main.json").read_text())
        check = next(rule for rule in ruleset["rules"] if rule["type"] == "required_status_checks")
        self.assertEqual(check["parameters"]["required_status_checks"], [{
            "context": PR_WORKFLOW["jobs"]["review"]["name"], "integration_id": 15368,
        }])

    def test_clean_snapshot_and_uncommitted_policy_are_pinned_to_one_commit(self):
        commit = self.git("rev-parse", "HEAD")
        committed_policy = self.git("show", f"HEAD:{POLICY_PATH}") + "\n"
        self.write(POLICY_PATH, "Uncommitted replacement must not become the trusted policy.\n")
        evidence = self.prepare()
        self.assertEqual(evidence["snapshot_commit"], commit)
        self.assertEqual(evidence["policy"]["content"], committed_policy)
        self.assertEqual(evidence["policy"]["blob"], self.git("rev-parse", f"HEAD:{POLICY_PATH}"))
        source = next(f for f in evidence["files"] if f["path"] == "src/query.py")
        self.assertEqual(source["content"], f"1: {SAFE_SOURCE.rstrip()}")
        summary = self.publish(self.events(self.report()), "PASS")
        self.assertIn(commit, summary)
        self.assertIn("3/3", summary)

    def test_existing_violation_outside_latest_diff_is_reviewed_and_reported(self):
        self.write("src/query.py", UNSAFE_SOURCE)
        self.commit()
        self.write("README.md", "Unrelated latest change.\n")
        self.commit()
        self.assertNotIn("src/query.py", self.git("diff", "--name-only", "HEAD~1", "HEAD"))
        evidence = self.prepare()
        source = next(f for f in evidence["files"] if f["path"] == "src/query.py")
        self.assertIn(UNSAFE_SOURCE.rstrip(), source["content"])
        summary = self.publish(self.events(self.report(violations=[self.violation()])), "FAIL")
        self.assertIn("SEC-001", summary)
        self.assertIn("src/query.py:1", summary)
        self.assertIn("Use a placeholder", summary)

    def test_updated_policy_applies_to_unchanged_snapshot_code(self):
        self.write(POLICY_PATH, "# Old policy fixture\nDo not log secrets.\n")
        self.write("src/query.py", UNSAFE_SOURCE)
        self.commit()
        source_blob = self.git("rev-parse", "HEAD:src/query.py")
        updated = (ROOT / POLICY_PATH).read_text(encoding="utf-8")
        self.write(POLICY_PATH, updated)
        self.commit()
        self.assertEqual(self.git("diff", "--name-only", "HEAD~1", "HEAD"), POLICY_PATH)
        evidence = self.prepare()
        self.assertEqual(evidence["policy"]["content"], updated)
        source = next(f for f in evidence["files"] if f["path"] == "src/query.py")
        self.assertEqual(source["blob"], source_blob)
        self.assertIn("all existing behavior", (self.temp / "prompt.txt").read_text(encoding="utf-8"))
        self.publish(self.events(self.report(violations=[self.violation()])), "FAIL")

    def test_incomplete_coverage_never_passes_and_preserves_findings(self):
        self.prepare()
        for changes in (
            {"complete": False},
            {"reviewed_paths": ["README.md"]},
            {"complete": False, "reviewed_paths": [], "violations": [self.violation()]},
        ):
            with self.subTest(changes=changes):
                summary = self.publish(self.events(self.report(**changes)), "INCOMPLETE")
                if changes.get("violations"):
                    self.assertIn("SEC-001", summary)

    def test_malformed_reports_and_unclean_cli_events_never_pass(self):
        self.prepare()
        valid = self.events(self.report())
        cases = [
            "", "not JSON", '[]', json.dumps({"type": "result", "exitCode": 0}),
            [{"type": "assistant.message", "data": {"content": "not JSON"}}, valid[-1]],
            valid + [valid[0]],
            valid + [{"type": "session.error", "data": {"message": "do-not-publish-this-diagnostic"}}],
            [valid[0], {"type": "result", "exitCode": 1}],
            [valid[0], {"type": "result", "exitCode": False}],
            self.events(self.report(snapshot_commit="wrong")),
            self.events(self.report(policy_blob="wrong")),
            self.events(self.report(complete="true")),
            self.events(self.report(reviewed_paths=["README.md", "README.md"])),
            self.events(self.report(reviewed_paths=["unknown.py"])),
            self.events(self.report(violations=[{**self.violation(), "line": 999}])),
        ]
        for index, events in enumerate(cases):
            with self.subTest(case=index):
                self.publish(events, "ERROR")

    def test_early_failures_still_produce_summary_and_reject_success_shaped_output(self):
        self.prepare()
        for stage in ("TRUST", "CHECKOUT", "INSTALL", "REVIEW"):
            with self.subTest(stage=stage):
                self.env[f"{stage}_OUTCOME"] = "failure"
                self.publish(self.events(self.report()), "ERROR")
                self.env[f"{stage}_OUTCOME"] = "success"
        (self.temp / "snapshot.json").unlink()
        self.env["CHECKOUT_OUTCOME"] = "failure"
        self.publish("", "ERROR")

    def test_cli_shell_failure_preserves_summary_without_publishing_raw_output(self):
        self.prepare()
        mock_bin = self.temp / "bin"
        mock_bin.mkdir()
        mock_cli = mock_bin / "copilot"
        mock_cli.write_text(
            '#!/usr/bin/env bash\nprintf "%s\\n" "$MOCK_EVENTS"\n'
            'echo do-not-publish-this-diagnostic >&2\nexit 1\n',
            encoding="utf-8", newline="\n",
        )
        mock_cli.chmod(0o755)
        review = next(step["run"] for step in STEPS if step.get("id") == "review")
        prefix = 'export PATH="$MOCK_BIN:$PATH"\n'
        if os.name == "nt":
            prefix = 'MOCK_BIN="$(cygpath -u "$MOCK_BIN")"\n' + prefix
        prefix += '[[ "$(command -v copilot)" == "$MOCK_BIN/copilot" ]] || exit 99\n'
        result = self.run_shell(
            prefix + review, MOCK_BIN=str(mock_bin),
            COPILOT_GITHUB_TOKEN="nonfunctional-offline-placeholder",
            MOCK_EVENTS="\n".join(json.dumps(e) for e in self.events(self.report())),
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.env["REVIEW_OUTCOME"] = "failure"
        summary = self.publish((self.temp / "events.jsonl").read_text(encoding="utf-8"), "ERROR")
        self.assertIn("CLI installation/review failed", summary)

    def test_binary_non_utf8_lfs_and_oversized_input_are_rejected_without_truncation(self):
        for data in (
            b"binary\0content", b"\xff\xfe",
            b"version https://git-lfs.github.com/spec/v1\noid sha256:nonfunctional-fixture\n",
            b"a" * (128 * 1024 + 1),
            b"\n" * 30000,
        ):
            with self.subTest(size=len(data)):
                (self.repo / "unsupported").write_bytes(data)
                self.commit()
                self.prepare(success=False)
                summary = self.publish("", "INCOMPLETE")
                self.assertIn("Input prepared in full: no", summary)
                if data == b"\n" * 30000:
                    self.assertIn("256 KiB", self.manifest["error"])

    def test_symlinks_submodules_and_file_count_limit_are_rejected(self):
        blob = self.git("hash-object", "-w", "--stdin", input="src/query.py")
        for mode, object_id in (("120000", blob), ("160000", self.git("rev-parse", "HEAD"))):
            with self.subTest(mode=mode):
                self.git("update-index", "--add", "--cacheinfo", f"{mode},{object_id},unsupported")
                self.git("-c", "user.name=Offline test", "-c", "user.email=offline@example.invalid",
                         "commit", "--quiet", "-m", "Unsupported fixture")
                self.prepare(success=False)
                self.assertIn("Unsupported tracked entry", self.manifest["error"])
                self.git("update-index", "--force-remove", "unsupported")
        for index in range(198):
            self.write(f"many/{index}.txt", "")
        self.commit()
        self.prepare(success=False)
        self.assertIn("200 files", self.manifest["error"])

    def test_trusted_ref_guard_and_workflow_contract(self):
        self.assertEqual(WORKFLOW["on"], {"schedule": [{"cron": "17 9 * * 1"}], "workflow_dispatch": ""})
        self.assertEqual(WORKFLOW["permissions"], {"contents": "read"})
        self.assertEqual(STEPS[-1]["if"], "always()")
        self.assertEqual(STEPS[1]["with"], {"ref": "refs/heads/main", "persist-credentials": "false"})
        self.assertEqual(STEPS[2]["run"], "python3 .github/scripts/security-snapshot.py prepare")
        self.assertEqual(STEPS[4]["run"], 'bash "$GITHUB_WORKSPACE/.github/scripts/copilot-review.sh" snapshot')
        self.assertTrue(STEPS[-1]["run"].endswith("python3 .github/scripts/security-snapshot.py report\n"))
        base_env = {
            **os.environ, "GITHUB_REPOSITORY": "owner/repo", "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "WORKFLOW_REF": "owner/repo/.github/workflows/security-snapshot.yml@refs/heads/main",
        }
        for change, expected in (
            ({}, 0), ({"GITHUB_EVENT_NAME": "schedule"}, 0),
            ({"GITHUB_REF": "refs/heads/feature"}, 1),
            ({"WORKFLOW_REF": "owner/repo/.github/workflows/security-snapshot.yml@refs/heads/feature"}, 1),
            ({"GITHUB_EVENT_NAME": "pull_request"}, 1),
        ):
            with self.subTest(change=change):
                result = subprocess.run([BASH, "-c", STEPS[0]["run"]], env={**base_env, **change}, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr)
        for step in STEPS:
            if step.get("shell") == "python":
                compile(step["run"], step["name"], "exec")
            elif "run" in step:
                subprocess.run([BASH, "-n"], input=step["run"].encode("utf-8"), check=True)

    def test_actual_repository_snapshot_fits_limits_and_includes_every_file(self):
        paths = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT,
        ).decode("utf-8").strip("\0").split("\0")
        for path in paths:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / path).read_bytes())
        self.commit()
        evidence = self.prepare()
        self.assertTrue(set(paths) <= {file["path"] for file in evidence["files"]})
        self.publish(self.events(self.report()), "PASS")


if __name__ == "__main__":
    unittest.main()
