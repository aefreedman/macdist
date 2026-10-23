"""Installation identity is offline and must never expose credential-bearing URLs."""

from contextlib import redirect_stdout
from importlib import metadata
import io
import json
from pathlib import Path
import tomllib
import unittest
from unittest.mock import Mock, patch

from macdist import __version__, build_info, cli


class BuildInfoTests(unittest.TestCase):
    def distribution(self, origin):
        distribution = Mock()
        distribution.version = __version__
        distribution.read_text.return_value = json.dumps(origin) if origin is not None else None
        return patch.object(build_info.metadata, "distribution", return_value=distribution)

    def test_vcs_commit_is_reported_without_private_url_or_revision(self):
        origin = {"url": "https://user:fixture-password@example.invalid/private.git",
                  "vcs_info": {"vcs": "git", "commit_id": "a" * 40, "requested_revision": "private-branch"}}
        with self.distribution(origin), patch("subprocess.run", side_effect=AssertionError("must not invoke git")):
            report = build_info.info()
        self.assertEqual(report["version"], __version__)
        self.assertEqual(report["source_commit"], "a" * 40)
        self.assertFalse(report["editable"])
        self.assertNotIn("fixture-password", json.dumps(report))
        self.assertNotIn("private-branch", json.dumps(report))
        self.assertNotIn("url", report)

    def test_editable_checkout_does_not_claim_to_be_its_current_git_head(self):
        with self.distribution({"url": "file:///fixture/checkout", "dir_info": {"editable": True}}):
            report = build_info.info()
        self.assertTrue(report["editable"])
        self.assertIsNone(report["source_commit"])

    def test_unknown_wheel_origin_and_missing_distribution(self):
        with self.distribution(None):
            self.assertIsNone(build_info.info()["source_commit"])
        with patch.object(build_info.metadata, "distribution", side_effect=metadata.PackageNotFoundError):
            self.assertIsNone(build_info.info()["installed_distribution_version"])

    def test_invalid_metadata_never_becomes_a_claimed_commit(self):
        for origin in ([], {"vcs_info": {"vcs": "git", "commit_id": "not-a-commit"}}, {"vcs_info": {"vcs": "git", "commit_id": ["a" * 40]}}):
            with self.distribution(origin):
                self.assertIsNone(build_info.info()["source_commit"])
        with self.distribution(None) as source:
            source.return_value.read_text.return_value = "malformed JSON"
            self.assertIsNone(build_info.info()["source_commit"])

    def test_jsonl_command_and_start_event_report_installation_identity(self):
        stream = io.StringIO()
        with self.distribution({"vcs_info": {"vcs": "git", "commit_id": "b" * 40}}), redirect_stdout(stream):
            code = cli.main(["build-info", "--output", "jsonl"])
        events = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(code, 0)
        self.assertEqual(events[0]["tool_version"], __version__)
        self.assertEqual(events[0]["source_commit"], "b" * 40)
        self.assertEqual(events[1]["event"], "build.info")
        self.assertEqual(events[1]["report"]["source_commit"], "b" * 40)
        self.assertEqual(events[-1]["status"], "succeeded")

    def test_project_and_runtime_versions_match(self):
        with (Path(__file__).resolve().parent.parent / "pyproject.toml").open("rb") as stream:
            self.assertEqual(tomllib.load(stream)["project"]["version"], __version__)
        self.assertEqual(__version__, "0.3.0")


if __name__ == "__main__":
    unittest.main()
