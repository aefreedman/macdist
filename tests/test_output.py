"""Offline presentation tests: never contact Apple, Keychain, or a publisher."""

from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from macdist import cli, engine, output, publish
from macdist.inspection import MAX_STATE, snapshot


def records(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()]


class OutputTests(unittest.TestCase):
    def test_auto_terminal_and_pipe_modes(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        tty = Terminal()
        reporter = output.Reporter(stream=tty)
        self.assertEqual(reporter.mode, "human")
        with output.reporting(reporter):
            reporter.progress("upload", 20)
            reporter.emit("next", "Waiting for Apple")
        self.assertIn("\r\x1b[2K", tty.getvalue())
        self.assertIn("\nWaiting for Apple\n", tty.getvalue())
        pipe = io.StringIO()
        reporter = output.Reporter(stream=pipe)
        self.assertEqual(reporter.mode, "plain")
        reporter.progress("upload", 20)
        reporter.emit("next", "Waiting\r\x1b[2K for Apple")
        self.assertNotIn("\r", pipe.getvalue())
        self.assertNotIn("\x1b", pipe.getvalue())

    def test_progress_is_throttled_but_completion_immediate(self):
        stream = io.StringIO()
        clock = [0.0]
        reporter = output.Reporter("jsonl", stream, clock=lambda: clock[0])
        for percent, when in ((0, 0), (1, .1), (5, .2), (6, 1), (5, 2), (7, 11), (100, 11.1), (100, 12), (101, 13)):
            clock[0] = when
            reporter.progress("upload", percent)
        events = records(stream)
        self.assertEqual([event["percent"] for event in events], [0, 6, 7, 100])
        self.assertEqual([event["sequence"] for event in events], [1, 2, 3, 4])
        self.assertTrue(all(event["schema"] == 1 and event["timestamp"] for event in events))

    def test_incremental_parser_handles_ansi_utf8_and_final_frame(self):
        stream = io.StringIO()
        with output.reporting(output.Reporter("jsonl", stream)):
            parser = output.UploadProgress()
            data = 'Ignored diagnostic 👋\r\x1b[2KUpload progress: 12.50%\rUpload progress: 100.00%'.encode()
            for byte in data:
                parser.feed(bytes([byte]))
            parser.feed(b"", final=True)
        self.assertEqual([record["percent"] for record in records(stream)], [12.5, 100])
        self.assertNotIn("Ignored diagnostic", stream.getvalue())
        self.assertNotIn("\x1b", stream.getvalue())
        self.assertNotIn("\r", stream.getvalue())

    def test_dec_cursor_progress_is_live_without_newlines_or_eof(self):
        stream = io.StringIO()
        clock = [0.0]
        with output.reporting(output.Reporter("jsonl", stream, clock=lambda: clock[0])):
            parser = output.UploadProgress()
            for percent in (0, 25, 50, 100):
                clock[0] += 5
                parser.feed(f"\x1b7Upload progress: {percent:.2f}% (fixture bytes)   \x1b8".encode())
                self.assertEqual(records(stream)[-1]["percent"], percent)
                self.assertEqual(parser.pending, "")
        self.assertEqual([event["percent"] for event in records(stream)], [0, 25, 50, 100])

    def test_dec_cursor_frames_handle_every_chunk_split(self):
        data = b"\x1b7Upload progress: 0.00% (Zero KB of 900 MB)   \x1b8\x1b7Upload progress: 100.00% (900 MB of 900 MB)   \x1b8"
        for split in range(len(data) + 1):
            stream = io.StringIO()
            with output.reporting(output.Reporter("jsonl", stream)):
                parser = output.UploadProgress()
                parser.feed(data[:split])
                parser.feed(data[split:])
            self.assertEqual([event["percent"] for event in records(stream)], [0, 100], split)
            self.assertNotIn("\x1b", stream.getvalue())

    def test_cursor_frames_recover_after_oversized_diagnostic(self):
        stream = io.StringIO()
        with output.reporting(output.Reporter("jsonl", stream)):
            parser = output.UploadProgress()
            parser.feed(b"x" * 100000 + b"\x1b7Upload progress: 100%\x1b8")
        self.assertEqual(records(stream)[0]["percent"], 100)

    def test_jsonl_messages_preserve_word_boundaries(self):
        stream = io.StringIO()
        reporter = output.Reporter("jsonl", stream)
        reporter.emit("test", "ZIP: fixture.zip\r\nSHA-256: value\nInput:\tfixture")
        self.assertEqual(records(stream)[0]["message"], "ZIP: fixture.zip SHA-256: value Input: fixture")
        self.assertEqual(output.clean("\x1b7one\x1b8\nnext"), "one next")

    def test_parser_bounds_unterminated_frames_and_recovers(self):
        stream = io.StringIO()
        with output.reporting(output.Reporter("jsonl", stream)):
            parser = output.UploadProgress()
            parser.feed(b"x" * 100000)
            self.assertLessEqual(len(parser.pending), 65536)
            parser.feed(b"\rUpload progress: 100%\n", final=True)
        self.assertEqual(records(stream)[0]["percent"], 100)

    def test_publishing_machine_output_does_not_echo_raw_worker_text(self):
        stream = io.StringIO()
        with output.reporting(output.Reporter("jsonl", stream)):
            console = publish.LiveConsole()
            console.emit("fixture scan diagnostic")
            console.emit("upload 10% 2 MiB/s ETA 5s")
            console.emit("upload 100%")
        self.assertEqual([record["percent"] for record in records(stream)], [10, 100])
        self.assertNotIn("fixture", stream.getvalue())

    def test_context_is_reset_between_invocations(self):
        with output.reporting(output.Reporter("jsonl", io.StringIO())):
            self.assertIsNotNone(output.current())
        self.assertIsNone(output.current())


class WorkflowOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run = Path(self.tmp.name).resolve() / "release"
        self.run.mkdir()
        self.state = {"schema": 1, "config": {}, "stage": "signed", "app_name": "Game.app", "submission_id": None}
        engine.save_json(self.run / "state.json", self.state)

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(["--output", "jsonl", *args])
        return code, records(stdout), stderr.getvalue()

    def test_inspect_recognizes_historical_cursor_progress(self):
        (self.run / "upload-progress.log").write_bytes(b"\x1b7Upload progress: 25.00% (fixture)\x1b8\x1b7Upload progress: 100.00% (fixture)\x1b8")
        self.assertEqual(snapshot(self.run)["last_upload_percent"], 100)

    def test_inspect_is_local_read_only_and_allowlists_fields(self):
        self.state["private_extra"] = "must-not-appear"
        engine.save_json(self.run / "state.json", self.state)
        (self.run / "upload-progress.log").write_bytes(b"ignored\rUpload progress: 25.00%\r")
        (self.run / ".operation-lock").write_text("pid=unknown")
        before = {str(p): p.read_bytes() for p in self.run.rglob("*") if p.is_file()}
        with patch.object(engine.subprocess, "run", side_effect=AssertionError("no child commands")), patch.object(engine, "locked", side_effect=AssertionError("no lock mutations")):
            code, events, stderr = self.invoke("inspect", "--run", str(self.run))
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        report = next(e["snapshot"] for e in events if e["event"] == "run.snapshot")
        self.assertEqual(report["last_upload_percent"], 25)
        self.assertTrue(report["progress_is_historical"])
        self.assertTrue(report["operation_lock_present"])
        self.assertNotIn("must-not-appear", json.dumps(events))
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.run.rglob("*") if p.is_file()})
        self.assertEqual(events[-1]["status"], "succeeded")
        self.assertFalse(events[-1]["ready"])

    def test_inspect_does_not_claim_packaged_zip_is_currently_verified(self):
        archive = self.run / "final/Game-macos.zip"
        archive.parent.mkdir()
        archive.write_bytes(b"fixture")
        self.state.update(stage="packaged", final_archive=str(archive), final_sha256="a" * 64)
        engine.save_json(self.run / "state.json", self.state)
        report = snapshot(self.run)
        self.assertTrue(report["artifact"]["present"])
        self.assertFalse(report["artifact"]["checksum_verified"])

    def test_snapshot_rejects_oversize_metadata_and_symlinked_logs(self):
        (self.run / "state.json").write_bytes(b" " * (MAX_STATE + 1))
        with self.assertRaises(engine.DistributionError):
            snapshot(self.run)
        engine.save_json(self.run / "state.json", self.state)
        (self.run / "upload-progress.log").symlink_to(self.run / "state.json")
        with self.assertRaises(engine.DistributionError):
            snapshot(self.run)

    def test_output_option_also_works_after_subcommand(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = cli.main(["inspect", "--run", str(self.run), "--output", "jsonl"])
        self.assertEqual(code, 0)
        self.assertEqual(records(stream)[-1]["event"], "workflow.result")

    def test_missing_run_produces_structured_error_and_final_result(self):
        code, events, _ = self.invoke("inspect", "--run", str(self.run / "missing"))
        self.assertEqual(code, 1)
        self.assertEqual(events[-1]["status"], "failed")
        self.assertEqual(events[-2]["event"], "workflow.error")

    def test_jsonl_never_enters_interactive_or_credential_setup(self):
        with patch.object(cli, "setup", side_effect=AssertionError("no credential prompt")):
            code, events, _ = self.invoke("setup", "--store-credentials")
        self.assertEqual(code, 1)
        self.assertEqual(events[-1]["status"], "failed")

    def test_pending_and_uncertain_are_distinct_and_never_retried(self):
        self.state["stage"] = "uploading"
        self.state["submission_id"] = str(uuid.uuid4())
        engine.save_json(self.run / "state.json", self.state)
        with patch.object(cli, "_dispatch", return_value=1) as dispatch:
            code, events, _ = self.invoke("submit", "--run", str(self.run))
            dispatch.assert_called_once()
        self.assertEqual(code, 1)
        self.assertEqual(events[-1]["status"], "uncertain")
        with patch.object(cli, "_dispatch", return_value=2):
            code, events, _ = self.invoke("status", "--run", str(self.run))
        self.assertEqual(events[-1]["status"], "pending")
        self.assertEqual(code, 2)

    def test_submission_event_is_emitted_only_after_id_is_persisted(self):
        identifier = str(uuid.uuid4())
        self.state["config"]["keychain_profile"] = "fixture-notary"
        run = self.run
        class CheckedStream(io.StringIO):
            def write(self, text):
                if '"event": "submission.recorded"' in text:
                    assert engine.read_json(run / "state.json")["submission_id"] == identifier
                return super().write(text)
        class FakeRunner:
            def stream(self, argv, on_output, timeout):
                on_output("id: " + identifier)
        stream = CheckedStream()
        with patch.object(engine, "assert_unchanged"), output.reporting(output.Reporter("jsonl", stream)):
            engine.submit(self.run, self.state, FakeRunner(), progress=True)
        self.assertEqual([e["event"] for e in records(stream)], ["upload.started", "submission.recorded", "upload.completed"])
        self.assertEqual(self.state["stage"], "submitted")

    def test_publishing_jsonl_retains_redacted_details_in_log_only(self):
        config = publish.load_config(Path(__file__).parent / "fixtures/publishing.json")
        archive = self.run / "final/Game-macos.zip"
        archive.parent.mkdir()
        archive.write_bytes(b"fixture ZIP")
        self.state.update(stage="packaged", config=config["release"], source={"version": "test-1"},
                          final_archive=str(archive), final_sha256=engine.sha256(archive),
                          submission_id=str(uuid.uuid4()), archive_sha256="a" * 64, notary_status="Accepted")
        engine.save_json(self.run / "state.json", self.state)
        engine.save_json(self.run / "notarization-log.json", {"status": "Accepted", "jobId": self.state["submission_id"], "sha256": "a" * 64})
        def invoke(command, args, config, tools, emit, timeout):
            emit("fixture detail [REDACTED]")
            emit("upload 100%")
            return 0
        stream = io.StringIO()
        with output.reporting(output.Reporter("jsonl", stream)):
            receipt = publish.publish(self.run, config, "upload", invoke_command=invoke, resolve_tools=lambda: {})
        self.assertNotIn("fixture detail", stream.getvalue())
        self.assertIn("fixture detail [REDACTED]", (self.run / receipt["log"]).read_text())
        self.assertEqual(records(stream)[-1]["event"], "publishing.completed")
        self.assertFalse(records(stream)[-1]["delivery_verified"])
        with output.reporting(output.Reporter("jsonl", io.StringIO())), self.assertRaises(publish.PublishingError):
            publish.publish(self.run, config, "upload", invoke_command=invoke, resolve_tools=lambda: {})

    def test_refused_symlink_is_not_followed_by_final_result_inspection(self):
        link = self.run.parent / "linked"
        link.symlink_to(self.run)
        code, events, _ = self.invoke("inspect", "--run", str(link))
        self.assertEqual(code, 1)
        self.assertNotIn("stage", events[-1])
        self.assertNotIn("evidence", events[-1])

    def test_pty_transcript_is_retained_without_leaking_raw_output(self):
        logs = self.run / "logs"
        logs.mkdir()
        stream = io.StringIO()
        code = 'import os; assert os.isatty(1); print("raw diagnostic\\r\\x1b[2KUpload progress: 100%", flush=True)'
        seen = []
        with output.reporting(output.Reporter("jsonl", stream)):
            engine.Runner(logs).stream([sys.executable, "-c", code], seen.append, timeout=10)
        self.assertIn("raw diagnostic", seen[-1])
        self.assertIn(b"\x1b", (self.run / "upload-progress.log").read_bytes())
        self.assertNotIn("raw diagnostic", stream.getvalue())
        self.assertEqual(records(stream)[0]["event"], "upload.progress")
        evidence = engine.read_json(next(logs.glob("*.json")))
        self.assertEqual(evidence["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
