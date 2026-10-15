"""Public adapter commands use fictional configuration and mocked dispatch only."""

from contextlib import redirect_stdout, redirect_stderr
import io
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from macdist import cli, config, publish
from macdist.setup import save_profile

SIGNING = {"team_id": "AB12345678", "signing_identity": "Developer ID Application: Example Corporation (AB12345678)", "keychain_profile": "example-notary"}
PUBLISHING = {"api_key_ref": "op://publishing-vault/itch/credential", "token_env": "MACDIST_GAME_OP_SERVICE_ACCOUNT_TOKEN", "keychain_service": "example-publishing-token", "keychain_account": "example-publisher"}
PROJECT = '''[app]
bundle_id = "com.example.game"
team_id = "AB12345678"
[signing]
profile = "game"
entitlements = "macos.entitlements"
[output]
runs_dir = "releases"
[publishing.itch]
target = "example/game"
channel = "MacOS"
profile = "itch"
'''


class AdapterCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.user = self.root / "user.toml"
        self.project = self.root / "macdist.toml"
        save_profile(self.user, "game", SIGNING)
        save_profile(self.user, "itch", PUBLISHING, group="publishing_profiles")
        self.project.write_text(PROJECT)
        (self.root / "macos.entitlements").write_bytes(plistlib.dumps({}))

    def invoke(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return cli.main(["--user-config", str(self.user), *args])

    def test_destination_is_project_owned_credentials_are_local(self):
        project = config.load_project(self.project, self.user)
        self.assertEqual(project.publishing["itch"], {"target": "example/game", "channel": "MacOS", "api_key_ref": PUBLISHING["api_key_ref"]})
        self.assertEqual(project.publishing["release"], {"bundle_id": "com.example.game", "team_id": "AB12345678"})
        self.assertNotIn("keychain_service", self.project.read_text())

    def test_profile_writes_preserve_both_kinds(self):
        save_profile(self.user, "second", SIGNING)
        save_profile(self.user, "second", PUBLISHING, group="publishing_profiles")
        data = config.load_user(self.user)
        self.assertEqual(data["profiles"]["game"], SIGNING)
        self.assertEqual(data["publishing_profiles"]["itch"], PUBLISHING)

    def test_missing_publishing_profile_is_not_replaced_by_personal_login(self):
        self.project.write_text(PROJECT.replace('profile = "itch"', 'profile = "missing"'))
        with patch.object(publish, "service_token") as token:
            self.assertEqual(self.invoke("publish", "--project", str(self.project), "--run", "run", "--upload"), 1)
            token.assert_not_called()

    def test_no_implicit_upload_or_retry_modes(self):
        for args in (("publish", "--run", "run"), ("publish", "--run", "run", "--dry-run", "--retry-upload"), ("pick-itch", "--dry-run", "--retry-upload")):
            with self.assertRaises(SystemExit) as stopped:
                self.invoke(*args)
            self.assertEqual(stopped.exception.code, 2)

    def test_publish_and_status_dispatch_explicit_modes(self):
        with patch.object(publish, "publish") as dispatch:
            for mode, command in (("upload", ["publish", "--upload"]), ("dry_run", ["publish", "--dry-run"]), ("status", ["publish-status"])):
                self.assertEqual(self.invoke(*command, "--project", str(self.project), "--run", str(self.root / "run")), 0)
                self.assertEqual(dispatch.call_args.args[2], mode)
                self.assertEqual(dispatch.call_args.args[1]["itch"]["target"], "example/game")
                self.assertEqual(dispatch.call_args.args[1]["release"]["team_id"], "AB12345678")

    def test_picker_requires_terminal_and_uses_project_runs(self):
        with patch("macdist.cli.sys.stdin.isatty", return_value=False), patch.object(publish, "interactive_publish") as dispatch:
            self.assertEqual(self.invoke("pick-itch", "--project", str(self.project)), 1)
            dispatch.assert_not_called()
        with patch("macdist.cli.sys.stdin.isatty", return_value=True), patch.object(publish, "interactive_publish") as dispatch:
            self.assertEqual(self.invoke("pick-itch", "--project", str(self.project)), 0)
            self.assertEqual(dispatch.call_args.args[0], self.root / "releases")

    def test_dashboard_has_no_publishing_dependency(self):
        self.project.write_text(PROJECT[:PROJECT.index("[publishing.itch]")])
        with patch("macdist.dashboard.serve", return_value=0) as serve, patch.object(publish, "service_token") as token:
            self.assertEqual(self.invoke("dashboard", "--project", str(self.project), "--port", "0"), 0)
            self.assertIsNone(serve.call_args.args[2])
            token.assert_not_called()

    def test_setup_publishing_is_reference_only_and_preserves_signing(self):
        with patch.object(publish, "service_token", side_effect=AssertionError("must not access credentials")):
            self.assertEqual(self.invoke("setup-publishing", "--profile", "new", "--api-key-ref", PUBLISHING["api_key_ref"], "--keychain-service", "new-service", "--keychain-account", "new-account"), 0)
        data = config.load_user(self.user)
        self.assertEqual(data["profiles"]["game"], SIGNING)
        self.assertEqual(data["publishing_profiles"]["new"]["api_key_ref"], PUBLISHING["api_key_ref"])

    def test_raw_keys_generic_op_variables_and_extra_secret_fields_rejected(self):
        for bad in ({"api_key_ref": "raw-secret"}, {"token_env": "OP_SERVICE_ACCOUNT_TOKEN"}, {"token_env": "PERSONAL_TOKEN"}, {"password": "not-real"}):
            with self.assertRaises((publish.PublishingError, config.DistributionError)):
                save_profile(self.user, "bad", dict(PUBLISHING, **bad), group="publishing_profiles")

    def test_profile_specific_env_is_honored_without_fallback(self):
        project = config.load_project(self.project, self.user)
        with patch.object(publish.subprocess, "run") as run:
            self.assertEqual(publish.service_token(project.publishing, {PUBLISHING["token_env"]: "fixture-token"}), "fixture-token")
            with self.assertRaises(publish.PublishingError):
                publish.service_token(project.publishing, {PUBLISHING["token_env"]: ""})
            run.assert_not_called()

    def test_isolated_worker_module_runs_without_current_directory_imports(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, "-I", "-m", "macdist.butler_worker", "/fake/butler", "status"],
                                cwd=self.root, env=publish.base_environment(), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Worker rejected", result.stdout)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
