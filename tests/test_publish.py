"""Offline publishing tests: fixture ZIPs, mocked credentials/commands, and loopback-free workers."""

from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from macdist import butler_worker
from macdist import engine as distribute
from macdist import publish


class PublishingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.run = self.root / "run"
        self.run.mkdir()
        (self.run / "final").mkdir()
        self.archive = self.run / "final/Example-macos.zip"
        self.archive.write_bytes(b"verified fixture ZIP")
        self.identifier = str(uuid.uuid4())
        self.config = publish.load_config(Path(__file__).parent / "fixtures/publishing.json")
        self.state = {"schema": 1, "config": self.config["release"], "stage": "packaged", "app_name": "Example.app",
                      "source": {"version": "alpha-4458-261009"}, "notary_status": "Accepted",
                      "submission_id": self.identifier, "archive_sha256": "a" * 64,
                      "final_archive": str(self.archive), "final_sha256": distribute.sha256(self.archive)}
        self.save()
        distribute.save_json(self.run / "notarization-log.json",
                             {"status": "Accepted", "jobId": self.identifier, "sha256": "a" * 64})
        self.calls = []
        self.code = 0

    def save(self):
        distribute.save_json(self.run / "state.json", self.state)

    def invoke(self, command, arguments, config, executables, emit, timeout):
        self.calls.append((command, arguments, timeout))
        emit("fixture Butler progress")
        return self.code

    def execute(self, mode="dry_run", **kwargs):
        with redirect_stdout(io.StringIO()):
            return publish.publish(self.run, self.config, mode, invoke_command=self.invoke,
                                   resolve_tools=lambda: {"op": "/fake/op", "butler": "/fake/butler"}, **kwargs)

    def test_config_has_only_reference_and_preserves_requested_channel(self):
        self.assertEqual(self.config["itch"]["target"], "example/example")
        self.assertEqual(self.config["itch"]["channel"], "MacOS")
        for field, bad in (("api_key_ref", "raw-secret"), ("target", "--danger"), ("channel", "../bad")):
            config = json.loads(json.dumps(self.config))
            config["itch"][field] = bad
            path = self.root / "bad.json"
            distribute.save_json(path, config)
            with self.assertRaises(publish.PublishingError):
                publish.load_config(path)

    def test_dry_run_is_explicit_versioned_and_never_changes_notarization(self):
        before = (self.run / "state.json").read_bytes()
        receipt = self.execute()
        command, args, _ = self.calls[0]
        self.assertEqual(command, "push")
        self.assertEqual(args, [str(self.archive), "example/example:MacOS", "--userversion", "alpha-4458-261009", "--dry-run"])
        self.assertEqual(receipt["status"], "dry_run_passed")
        self.assertFalse(receipt["delivery_verified"])
        self.assertIsNone(receipt["remote_build_id"])
        self.assertEqual((self.run / "state.json").read_bytes(), before)
        self.assertTrue((self.run / receipt["log"]).is_file())
        self.assertFalse((self.run / ".operation-lock").exists())

    def test_upload_receipt_is_saved_before_dispatch(self):
        original = self.invoke
        def invoke(*args):
            self.assertEqual(publish.read_receipt(self.run)["status"], "uploading")
            return original(*args)
        self.invoke = invoke
        receipt = self.execute("upload")
        self.assertEqual(receipt["status"], "uploaded")
        self.assertNotIn("--dry-run", self.calls[0][1])
        self.assertEqual(receipt["artifact_sha256"], self.state["final_sha256"])

    def test_status_is_read_only_and_does_not_erase_upload_record(self):
        uploaded = self.execute("upload")
        self.execute("status")
        self.assertEqual(self.calls[-1][0:2], ("status", ["example/example"]))
        self.assertEqual(publish.read_receipt(self.run), uploaded)
        self.assertEqual(distribute.read_json(self.run / "publishing/itch-status.json")["status"], "status_checked")
        with self.assertRaises(publish.PublishingError):
            self.execute("upload")

    def test_dry_run_does_not_enable_repeating_successful_or_uncertain_upload(self):
        for result in (0, 1):
            self.code = result
            try:
                self.execute("upload", retry_upload=True)
            except publish.PublishingError:
                pass
            before = publish.read_receipt(self.run)
            self.code = 0
            self.execute()
            self.assertEqual(publish.read_receipt(self.run), before)
            with self.assertRaises(publish.PublishingError):
                self.execute("upload")
        self.execute("upload", retry_upload=True)

    def test_nonzero_timeout_and_interruption_are_uncertain_without_retry(self):
        self.code = 7
        with self.assertRaises(publish.PublishingError):
            self.execute("upload")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(publish.read_receipt(self.run)["status"], "uncertain")
        for error in (publish.PublishingError("timeout"), KeyboardInterrupt()):
            def fail(*args):
                raise error
            self.invoke = fail
            with self.assertRaises(type(error)):
                self.execute("upload", retry_upload=True)
            self.assertEqual(publish.read_receipt(self.run)["status"], "uncertain")

    def test_failed_read_only_check_does_not_require_upload_retry_override(self):
        self.code = 1
        with self.assertRaises(publish.PublishingError):
            self.execute()
        self.code = 0
        self.assertEqual(self.execute("upload")["status"], "uploaded")

    def test_corrupt_upload_receipt_blocks_dispatch_instead_of_enabling_replay(self):
        self.execute("upload")
        before = len(self.calls)
        receipt = publish.read_receipt(self.run)
        receipt["status"] = "dry_run_passed"
        distribute.save_json(self.run / "publishing/itch.json", receipt)
        with self.assertRaises(publish.PublishingError):
            self.execute("upload", retry_upload=True)
        self.assertEqual(len(self.calls), before)

    def test_changed_input_after_command_is_uncertain(self):
        def mutate(*args):
            self.archive.write_bytes(b"changed")
            return 0
        self.invoke = mutate
        with self.assertRaises(publish.PublishingError):
            self.execute("upload")
        self.assertEqual(publish.read_receipt(self.run)["status"], "uncertain")

    def test_incomplete_tampered_and_wrong_evidence_never_dispatch(self):
        self.state["stage"] = "accepted"
        self.save()
        with self.assertRaises(distribute.DistributionError):
            self.execute()
        self.state["stage"] = "packaged"
        self.save()
        self.archive.write_bytes(b"tampered")
        with self.assertRaises(distribute.DistributionError):
            self.execute()
        self.state["final_sha256"] = distribute.sha256(self.archive)
        self.save()
        distribute.save_json(self.run / "notarization-log.json", {"status": "Accepted", "jobId": str(uuid.uuid4()), "sha256": "a" * 64})
        with self.assertRaises(publish.PublishingError):
            self.execute()
        self.assertEqual(self.calls, [])

    def test_symlinked_output_input_or_state_rejected(self):
        (self.run / "publishing").symlink_to(self.root)
        with self.assertRaises(distribute.DistributionError):
            self.execute()
        (self.run / "publishing").unlink()
        (self.run / "state.json").rename(self.run / "real-state.json")
        (self.run / "state.json").symlink_to("real-state.json")
        with self.assertRaises(distribute.DistributionError):
            self.execute()
        self.assertEqual(self.calls, [])

    def test_lock_blocks_concurrent_publish(self):
        (self.run / ".operation-lock").write_text("pid=unknown")
        with self.assertRaises(distribute.DistributionError):
            self.execute()
        self.assertEqual(self.calls, [])

    def test_missing_tools_stop_before_attempt(self):
        with patch.object(publish.shutil, "which", return_value=None):
            with self.assertRaises(publish.PublishingError):
                publish.tools()

    def test_tool_versions_accept_butler_stderr_on_success(self):
        responses = [subprocess.CompletedProcess([], 0, "2.38.1\n", ""),
                     subprocess.CompletedProcess([], 0, "", "v15.32.0\n")]
        with patch.object(publish.shutil, "which", side_effect=lambda name: "/fake/" + name), \
                patch.object(publish.subprocess, "run", side_effect=responses):
            versions = publish.tools()["versions"]
        self.assertEqual(versions, {"op": "2.38.1", "butler": "v15.32.0"})

    def test_picker_lists_versions_and_requires_explicit_selection_and_confirmation(self):
        dispatched = []
        answers = iter(["1", "yes"])
        output = io.StringIO()
        with redirect_stdout(output):
            publish.interactive_publish(self.root, self.config, input_fn=lambda prompt: next(answers),
                                        execute=lambda *args, **kwargs: dispatched.append((args, kwargs)))
        self.assertIn("alpha-4458-261009", output.getvalue())
        self.assertIn("example/example:MacOS", output.getvalue())
        self.assertEqual(dispatched[0][0], (self.run, self.config, "upload"))
        self.assertEqual(dispatched[0][1]["expected_artifact"], self.state["final_sha256"])
        self.assertEqual(dispatched[0][1]["expected_version"], "alpha-4458-261009")

    def test_picker_cancellation_invalid_selection_and_default_no_never_dispatch(self):
        for answers in ([""], ["0"], ["bogus"], ["2"], ["1", ""], ["1", "no"]):
            values = iter(answers)
            with redirect_stdout(io.StringIO()), patch.object(publish, "service_token") as token:
                dispatched = []
                try:
                    publish.interactive_publish(self.root, self.config, input_fn=lambda prompt: next(values),
                                                execute=lambda *args, **kwargs: dispatched.append(args))
                except publish.PublishingError:
                    pass
                self.assertEqual(dispatched, [])
                token.assert_not_called()

    def test_picker_dry_run_and_prior_upload_guard(self):
        dispatched = []
        with redirect_stdout(io.StringIO()):
            publish.interactive_publish(self.root, self.config, dry_run=True, input_fn=lambda prompt: "1",
                                        execute=lambda *args, **kwargs: dispatched.append(args))
        self.assertEqual(dispatched[0][2], "dry_run")
        self.execute("upload")
        with redirect_stdout(io.StringIO()), self.assertRaises(publish.PublishingError):
            publish.interactive_publish(self.root, self.config, input_fn=lambda prompt: "1")

    def test_picker_excludes_nonpackaged_malformed_and_symlinked_runs(self):
        (self.root / "linked").symlink_to(self.run)
        (self.root / "not-a-build").mkdir()
        self.assertEqual(publish.packaged_runs(self.root), [(self.run, "alpha-4458-261009")])
        self.state["stage"] = "accepted"
        self.save()
        self.assertEqual(publish.packaged_runs(self.root), [])
        with self.assertRaises(publish.PublishingError):
            publish.interactive_publish(self.root, self.config)

    def test_confirmed_version_or_artifact_change_blocks_dispatch_under_lock(self):
        for expected in ({"expected_version": "another-version"}, {"expected_artifact": "0" * 64}):
            with self.assertRaises(publish.PublishingError):
                self.execute("upload", **expected)
        self.assertEqual(self.calls, [])


    def test_cross_project_or_team_never_dispatches(self):
        for wrong in ({"bundle_id": "com.other.game"}, {"team_id": "ZZ12345678"}):
            self.state["config"] = dict(self.config["release"], **wrong)
            self.save()
            with self.assertRaisesRegex(publish.PublishingError, "different project"):
                self.execute("upload")
        self.assertEqual(self.calls, [])

    def test_destination_change_cannot_retarget_existing_run(self):
        self.execute("upload")
        self.config["itch"]["target"] = "other/game"
        with self.assertRaisesRegex(publish.PublishingError, "different destination"):
            self.execute("upload", retry_upload=True)
        self.assertEqual(len(self.calls), 1)

    def test_picker_filters_foreign_project(self):
        self.state["config"] = {"bundle_id": "com.other.game", "team_id": "AB12345678"}
        self.save()
        self.assertEqual(publish.packaged_runs(self.root, self.config["release"]), [])
        with self.assertRaises(publish.PublishingError):
            publish.interactive_publish(self.root, self.config)


class CredentialAndWorkerTests(unittest.TestCase):
    def setUp(self):
        self.config = publish.load_config(Path(__file__).parent / "fixtures/publishing.json")

    def test_allowlist_excludes_other_references_sessions_and_generic_token(self):
        source = {"PATH": "/bin", "HOME": "/home/test", "CODECKS_TOKEN": "op://[REDACTED]/[REDACTED]/[REDACTED]",
                  "OP_CONNECT_TOKEN": "other", "OP_SESSION_main": "other", "OP_SERVICE_ACCOUNT_TOKEN": "other",
                  "BUTLER_API_KEY": "saved", publish.TOKEN_ENV: "publishing-only"}
        self.assertEqual(publish.base_environment(source), {"PATH": "/bin", "HOME": "/home/test"})
        with patch.object(publish.subprocess, "run") as run:
            self.assertEqual(publish.service_token(self.config, source), "publishing-only")
            run.assert_not_called()

    def test_invalid_explicit_token_never_falls_back_to_keychain(self):
        for value in ("", "op://[REDACTED]/[REDACTED]/[REDACTED]", " padded ", "two\nlines"):
            with patch.object(publish.subprocess, "run") as run:
                with self.assertRaises(publish.PublishingError):
                    publish.service_token(self.config, {publish.TOKEN_ENV: value})
                run.assert_not_called()

    def test_keychain_query_is_fixed_and_errors_do_not_echo_credentials(self):
        result = subprocess.CompletedProcess([], 0, "fixture-service-token\n", "")
        with patch.object(publish.subprocess, "run", return_value=result) as run:
            self.assertEqual(publish.service_token(self.config, {}), "fixture-service-token")
            self.assertEqual(run.call_args.args[0], ["/usr/bin/security", "find-generic-password", "-s",
                                                   "example-publishing-op-service-account-token", "-a", "example-publishing", "-w"])
        result.returncode = 1
        result.stderr = "SECRET"
        with patch.object(publish.subprocess, "run", return_value=result):
            with self.assertRaises(publish.PublishingError) as error:
                publish.service_token(self.config, {})
            self.assertNotIn("SECRET", str(error.exception))

    def test_op_environment_is_isolated_and_no_secrets_are_arguments(self):
        source = {"PATH": "/bin", "HOME": "/tmp", publish.TOKEN_ENV: "fixture-service-token",
                  "CODECKS_TOKEN": "op://[REDACTED]/[REDACTED]/[REDACTED]", "OP_ACCOUNT": "personal"}
        with patch.dict(os.environ, source, clear=True), patch.object(publish, "stream_process", return_value=0) as stream:
            publish.invoke("status", ["example/example"], self.config, {"op": "/fake/op", "butler": "/fake/butler"}, print, 10)
            argv, env = stream.call_args.args[:2]
            self.assertNotIn("fixture-service-token", argv)
            self.assertEqual(set(env), {"PATH", "HOME", "OP_SERVICE_ACCOUNT_TOKEN", "BUTLER_API_KEY"})
            self.assertEqual(env["OP_SERVICE_ACCOUNT_TOKEN"], "fixture-service-token")
            self.assertEqual(env["BUTLER_API_KEY"], self.config["itch"]["api_key_ref"])

    def test_worker_removes_service_token_and_personal_identity_from_butler(self):
        source = {"PATH": "/bin", "OP_SERVICE_ACCOUNT_TOKEN": "fixture-sa", "BUTLER_API_KEY": "fixture-api",
                  "CODECKS_TOKEN": "op://[REDACTED]/[REDACTED]/[REDACTED]"}
        with patch.object(publish, "stream_process", return_value=0) as stream:
            self.assertEqual(butler_worker.run(["/fake/butler", "status", "example/example"], source), 0)
            argv, env = stream.call_args.args[:2]
            self.assertEqual(argv[:3], ["/fake/butler", "--identity", "/dev/null"])
            self.assertEqual(env, {"PATH": "/bin", "BUTLER_API_KEY": "fixture-api"})
            self.assertEqual(stream.call_args.kwargs["secrets"], ("fixture-api", "fixture-sa"))
            self.assertFalse(stream.call_args.kwargs["own_group"])

    def test_worker_rejects_unresolved_key_or_login(self):
        with redirect_stdout(io.StringIO()), patch.object(publish, "stream_process") as stream:
            self.assertEqual(butler_worker.run(["/fake/butler", "status"], {"BUTLER_API_KEY": "op://[REDACTED]/[REDACTED]/[REDACTED]", "OP_SERVICE_ACCOUNT_TOKEN": "fixture"}), 1)
            self.assertEqual(butler_worker.run(["/fake/butler", "login"], {"BUTLER_API_KEY": "fixture-api", "OP_SERVICE_ACCOUNT_TOKEN": "fixture"}), 1)
            stream.assert_not_called()

    def test_stream_redacts_secrets_across_chunks_and_suppresses_oversized_lines(self):
        lines = []
        code = ('import sys,time; sys.stdout.write("fixt"); sys.stdout.flush(); time.sleep(.01); '
                'print("ure-api fixture-sa"); print("x"*70000); print("safe progress")')
        result = publish.stream_process([sys.executable, "-c", code], publish.base_environment(), lines.append,
                                        secrets=("fixture-api", "fixture-sa"), timeout=5)
        self.assertEqual(result, 0)
        self.assertIn("[REDACTED] [REDACTED]", lines)
        self.assertIn("[Oversized output line suppressed]", lines)
        self.assertIn("safe progress", lines)
        self.assertNotIn("fixture", "\n".join(lines))

    def test_worker_push_gets_terminal_progress_and_redacts_decorated_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / "fake-butler"
            executable.write_text(
                '#!' + sys.executable + '\n'
                'import os,sys,time\n'
                'assert os.isatty(1) and os.isatty(2) and not os.isatty(0)\n'
                'assert "OP_SERVICE_ACCOUNT_TOKEN" not in os.environ\n'
                'assert "CODECKS_TOKEN" not in os.environ\n'
                'print("scan 10%\\r", end="", flush=True)\n'
                'time.sleep(.02)\n'
                'print("upload 50% 2 MiB/s ETA 5s\\r", end="", flush=True)\n'
                'print("fixture-\\x1b[31mapi\\x1b[0m fixture-sa")\n'
                'print("upload 100%")\n'
            )
            executable.chmod(0o755)
            output = io.StringIO()
            source = dict(publish.base_environment(), BUTLER_API_KEY="fixture-api")
            source["OP_SERVICE_ACCOUNT_TOKEN"] = "fixture-sa"
            source["CODECKS_TOKEN"] = "op://other-vault/item/field"
            with redirect_stdout(output):
                result = butler_worker.run([str(executable), "push", "fixture.zip", "example/example:MacOS"], source, timeout=5)
            self.assertEqual(result, 0)
            text = output.getvalue()
            self.assertIn("scan 10%", text)
            self.assertIn("upload 50%", text)
            self.assertIn("upload 100%", text)
            self.assertIn("[REDACTED] [REDACTED]", text)
            self.assertNotIn("fixture-api", text)
            self.assertNotIn("fixture-sa", text)
            self.assertNotIn(chr(27), text)

    def test_pty_nonzero_exit_and_timeout_are_not_success(self):
        lines = []
        code = publish.stream_process([sys.executable, "-c", 'print("50%\\r", end="", flush=True); exit(7)'],
                                      publish.base_environment(), lines.append, terminal=True, timeout=5)
        self.assertEqual(code, 7)
        self.assertIn("50%", lines)
        with self.assertRaises(publish.PublishingError):
            publish.stream_process([sys.executable, "-c", "import time; time.sleep(5)"],
                                   publish.base_environment(), lines.append, terminal=True, timeout=.05)

    def test_live_console_redraws_only_interactive_progress_and_finishes_cleanly(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        terminal = Terminal()
        console = publish.LiveConsole(terminal)
        console.emit("upload 10%")
        console.emit("upload 50% 2 MiB/s ETA 5s")
        console.emit("Completed")
        self.assertEqual(terminal.getvalue().count(chr(13) + chr(27) + "[2K"), 2)
        self.assertTrue(terminal.getvalue().endswith("\nCompleted\n"))
        redirected = io.StringIO()
        console = publish.LiveConsole(redirected)
        console.emit("upload 10%")
        console.emit("upload 50%")
        console.finish()
        self.assertEqual(redirected.getvalue(), "upload 10%\nupload 50%\n")

    def test_stream_timeout_stops_owned_process_without_retry(self):
        with self.assertRaises(publish.PublishingError):
            publish.stream_process([sys.executable, "-c", "import time; time.sleep(5)"],
                                   publish.base_environment(), lambda line: None, timeout=.05)


if __name__ == "__main__":
    unittest.main()
