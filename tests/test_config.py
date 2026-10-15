"""Offline tests for portability, team boundaries, and setup. No credentials used."""

from contextlib import redirect_stdout, redirect_stderr
import io
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from macdist import cli, config
from macdist.engine import DistributionError
from macdist.setup import save_profile

PROFILE = {
    "team_id": "AB12345678",
    "signing_identity": "Developer ID Application: Example Corporation (AB12345678)",
    "keychain_profile": "example-notary",
}
PROJECT = '''[app]
bundle_id = "com.example.game"
team_id = "AB12345678"
[signing]
profile = "example"
entitlements = "distribution/macos.entitlements"
[output]
runs_dir = "Releases/macos"
'''


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.user = self.root / "user/config.toml"
        save_profile(self.user, "example", PROFILE)
        self.project = self.root / "game/macdist.toml"
        self.project.parent.mkdir()
        self.project.write_text(PROJECT)
        self.entitlements = self.project.parent / "distribution/macos.entitlements"
        self.entitlements.parent.mkdir()
        self.entitlements.write_bytes(plistlib.dumps({}))

    def invoke(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return cli.main(["--user-config", str(self.user), *args])

    def test_paths_are_project_relative_not_cwd(self):
        result = config.load_project(self.project, self.user)
        self.assertEqual(result.entitlements, self.entitlements)
        self.assertEqual(result.runs_dir, self.project.parent / "Releases/macos")
        self.assertEqual(result.config, {"bundle_id": "com.example.game", **PROFILE})

    def test_team_mismatch_fails_closed(self):
        self.project.write_text(PROJECT.replace('team_id = "AB12345678"', 'team_id = "ZZ12345678"'))
        with self.assertRaisesRegex(DistributionError, "different Apple team"):
            config.load_project(self.project, self.user)

    def test_unknown_profile_does_not_fallback(self):
        self.project.write_text(PROJECT.replace('profile = "example"', 'profile = "missing"'))
        with self.assertRaisesRegex(DistributionError, "Unknown local profile"):
            config.load_project(self.project, self.user)

    def test_secret_fields_are_rejected(self):
        with self.user.open("a") as stream:
            stream.write('password = "not-a-real-password"\n')
        with self.assertRaises(DistributionError):
            config.load_project(self.project, self.user)

    def test_no_implicit_entitlements(self):
        self.entitlements.unlink()
        self.assertEqual(self.invoke("prepare", "--project", str(self.project), "--app", "Game.app", "--name", "one"), 1)

    def test_unsafe_entitlements_rejected(self):
        for name in ("com.apple.security.get-task-allow", "com.apple.security.app-sandbox"):
            self.entitlements.write_bytes(plistlib.dumps({name: True}))
            with self.assertRaises(DistributionError):
                config.load_project(self.project, self.user)

    def test_entitlements_must_be_dictionary(self):
        self.entitlements.write_bytes(plistlib.dumps([]))
        with self.assertRaises(DistributionError):
            config.load_project(self.project, self.user)

    def test_profiles_preserved_and_replacement_explicit(self):
        save_profile(self.user, "second", PROFILE)
        with self.assertRaises(DistributionError):
            save_profile(self.user, "example", PROFILE)
        save_profile(self.user, "example", dict(PROFILE, keychain_profile="different"), replace=True)
        profiles = config.load_user(self.user)["profiles"]
        self.assertEqual(profiles["second"], PROFILE)
        self.assertEqual(profiles["example"]["keychain_profile"], "different")
        self.assertEqual(self.user.stat().st_mode & 0o777, 0o600)

    def test_setup_rejects_symlinked_config(self):
        link = self.root / "linked.toml"
        link.symlink_to(self.user)
        with self.assertRaises(DistributionError):
            save_profile(link, "new", PROFILE)
        self.assertNotIn("new", config.load_user(self.user)["profiles"])

    def test_doctor_offline_and_online_are_explicit(self):
        with patch("macdist.cli.sys.platform", "darwin"), patch("macdist.cli.identities", return_value=[("a" * 40, PROFILE["signing_identity"])]), patch("macdist.cli.engine.Runner") as runner:
            self.assertEqual(self.invoke("doctor", "--project", str(self.project)), 0)
            runner.return_value.json.assert_not_called()
            self.assertEqual(self.invoke("doctor", "--project", str(self.project), "--check-credentials"), 0)
            argv = runner.return_value.json.call_args.args[0]
            self.assertEqual(argv[1:3], ["notarytool", "history"])

    def test_doctor_missing_key_fails(self):
        with patch("macdist.cli.sys.platform", "darwin"), patch("macdist.cli.identities", return_value=[]), patch("macdist.cli.engine.Runner"):
            self.assertEqual(self.invoke("doctor", "--project", str(self.project)), 1)

    def test_named_run_uses_project_output_and_resolved_policy(self):
        with patch("macdist.cli.engine.execute", return_value=0) as execute:
            self.assertEqual(self.invoke("prepare", "--project", str(self.project), "--app", "Game.app", "--name", "one"), 0)
            args, resolved = execute.call_args.args
            self.assertEqual(args.run, self.project.parent / "Releases/macos/one")
            self.assertEqual(args.entitlements, self.entitlements)
            self.assertEqual(resolved["team_id"], PROFILE["team_id"])
        self.assertEqual(self.invoke("prepare", "--project", str(self.project), "--app", "Game.app", "--name", "../escape"), 1)

    def test_setup_never_contacts_apple_by_default(self):
        with patch("macdist.setup.sys.platform", "darwin"), patch("macdist.setup.identities", return_value=[("a" * 40, PROFILE["signing_identity"])]), patch("macdist.setup.subprocess.run") as run:
            self.assertEqual(self.invoke("setup", "--profile", "new", "--identity", PROFILE["signing_identity"], "--keychain-profile", "new-notary"), 0)
            run.assert_not_called()
        self.assertEqual(config.load_user(self.user)["profiles"]["new"]["team_id"], "AB12345678")

    def test_setup_rejects_ambiguous_identity(self):
        duplicate = [("a" * 40, PROFILE["signing_identity"]), ("b" * 40, PROFILE["signing_identity"])]
        with patch("macdist.setup.sys.platform", "darwin"), patch("macdist.setup.identities", return_value=duplicate):
            self.assertEqual(self.invoke("setup", "--profile", "new", "--identity", PROFILE["signing_identity"], "--keychain-profile", "new-notary"), 1)
        self.assertNotIn("new", config.load_user(self.user)["profiles"])

    def test_xdg_config_root(self):
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.root)}):
            self.assertEqual(config.user_config_path(), self.root / "macdist/config.toml")

    def test_cli_subprocess_errors_are_readable(self):
        with patch("macdist.setup.sys.platform", "darwin"), patch("macdist.setup.identities", side_effect=subprocess.TimeoutExpired("security", 30)):
            self.assertEqual(self.invoke("setup"), 1)


if __name__ == "__main__":
    unittest.main()
