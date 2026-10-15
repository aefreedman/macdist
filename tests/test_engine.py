"""Offline safety tests. No Apple requests, Keychain mutations, or real signing."""

import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest.mock import patch
import uuid

from macdist import engine as tool


CONFIG = {
    "bundle_id": "com.example.example", "team_id": "AB12345678",
    "signing_identity": "Developer ID Application: Example Corporation (AB12345678)",
    "keychain_profile": "example-notary",
}


class EvidenceWriteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def test_existing_temporary_links_cannot_overwrite_outside_files(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                destination = self.root / (kind + ".json")
                sentinel = self.root / (kind + "-sentinel")
                sentinel.write_text("preserve me")
                temporary = destination.with_name(destination.name + ".tmp")
                if kind == "symlink":
                    temporary.symlink_to(sentinel)
                else:
                    os.link(sentinel, temporary)
                tool.save_json(destination, {"status": "saved"})
                self.assertEqual(sentinel.read_text(), "preserve me")
                self.assertEqual(tool.read_json(destination), {"status": "saved"})

    def test_destination_links_are_replaced_without_overwriting_their_targets(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                destination = self.root / (kind + ".json")
                sentinel = self.root / (kind + "-sentinel")
                sentinel.write_text("preserve me")
                if kind == "symlink":
                    destination.symlink_to(sentinel)
                else:
                    os.link(sentinel, destination)
                tool.save_json(destination, {"status": "saved"})
                self.assertEqual(sentinel.read_text(), "preserve me")
                self.assertEqual(tool.read_json(destination), {"status": "saved"})
                self.assertFalse(destination.is_symlink())

    def test_failed_serialization_preserves_destination_and_removes_new_temporary(self):
        destination = self.root / "state.json"
        destination.write_text("original")
        with self.assertRaises(TypeError):
            tool.save_json(destination, {"invalid": object()})
        self.assertEqual(destination.read_text(), "original")
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_symlinked_parent_is_rejected(self):
        directory = self.root / "outside"
        directory.mkdir()
        linked = self.root / "linked"
        linked.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(tool.DistributionError):
            tool.save_json(linked / "state.json", {"status": "saved"})
        self.assertEqual(list(directory.iterdir()), [])


class FakeRunner:
    def __init__(self, responses=()):
        self.responses = iter(responses)
        self.commands = []

    def json(self, argv, timeout=300):
        self.commands.append([str(a) for a in argv])
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response

    def run(self, argv, timeout=300):
        self.commands.append([str(a) for a in argv])
        return "", ""


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.app = self.root / "Example.app"
        (self.app / "Contents/MacOS").mkdir(parents=True)
        self.executable = self.app / "Contents/MacOS/Example"
        self.executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 32)
        self.executable.chmod(0o755)
        with (self.app / "Contents/Info.plist").open("wb") as stream:
            plistlib.dump({"CFBundleIdentifier": CONFIG["bundle_id"], "CFBundleExecutable": "Example",
                          "CFBundlePackageType": "APPL"}, stream)
        self.run = self.root / "release"
        self.run.mkdir()
        (self.run / "staged").mkdir()
        os.rename(self.app, self.run / "staged" / self.app.name)
        self.app = self.run / "staged" / self.app.name
        (self.run / "submission.zip").write_bytes(b"signed archive placeholder")
        self.state = {"schema": 1, "stage": "signed", "config": CONFIG,
                      "app_name": self.app.name, "submission_id": None,
                      "signed_hash": tool.tree_hash(self.app),
                      "archive_sha256": tool.sha256(self.run / "submission.zip")}
        tool.save_json(self.run / "state.json", self.state)

    def completed_responses(self, status="Accepted", archive_hash=None):
        identifier = str(uuid.uuid4())
        self.state["submission_id"] = identifier
        self.state["stage"] = "submitted"
        return [
            {"id": identifier, "status": status},
            {"jobId": identifier, "status": status,
             "sha256": archive_hash or self.state["archive_sha256"]},
        ]

    def test_inspection_checks_bundle_identifier(self):
        config = dict(CONFIG, bundle_id="com.wrong.app")
        with self.assertRaisesRegex(tool.DistributionError, "Bundle ID mismatch"):
            tool.inspect_app(self.app, config)

    def test_reject_external_link(self):
        outside = self.root / "outside"
        outside.write_text("private data")
        (self.app / "escape").symlink_to(outside)
        with self.assertRaisesRegex(tool.DistributionError, "escapes"):
            tool.tree_hash(self.app)

    def test_internal_links_are_preserved_in_inventory(self):
        (self.app / "linked-executable").symlink_to("Contents/MacOS/Example")
        self.assertEqual(tool.inventory(self.app)["linked-executable"][0], "link")

    def test_inventory_detects_content_and_mode_changes(self):
        before = tool.tree_hash(self.app)
        self.executable = self.app / "Contents/MacOS/Example"
        self.executable.chmod(0o644)
        self.assertNotEqual(before, tool.tree_hash(self.app))
        self.executable.chmod(0o755)
        self.executable.write_bytes(self.executable.read_bytes() + b"changed")
        self.assertNotEqual(before, tool.tree_hash(self.app))

    def test_signing_order_includes_unusual_locations_and_no_symlink_duplicates(self):
        framework = self.app / "Contents/Frameworks/Example.framework"
        (framework / "Versions/A").mkdir(parents=True)
        binary = framework / "Versions/A/Example"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 32)
        (framework / "Versions/Current").symlink_to("A")
        (framework / "Example").symlink_to("Versions/Current/Example")
        burst = self.app / "Contents/Plugins/lib_burst_generated.bundle"
        burst.parent.mkdir()
        burst.write_bytes(b"\xca\xfe\xba\xbe" + b"\0" * 32)
        resource = self.app / "Contents/Resources/Images.bundle"
        resource.mkdir(parents=True)
        (resource / "image.png").write_bytes(b"not code")
        targets = tool.signing_targets(self.app)
        self.assertLess(targets.index(binary), targets.index(framework))
        self.assertIn(burst, targets)
        self.assertNotIn(resource, targets)
        self.assertEqual(targets[-1], self.app)
        self.assertEqual(targets.count(binary), 1)

    def test_config_rejects_secrets_and_wrong_certificate_type(self):
        path = self.root / "config.json"
        tool.save_json(path, dict(CONFIG, password="not allowed"))
        with self.assertRaises(tool.DistributionError):
            tool.load_config(path)
        tool.save_json(path, dict(CONFIG, signing_identity="Apple Distribution: Wrong"))
        with self.assertRaises(tool.DistributionError):
            tool.load_config(path)
        tool.save_json(path, CONFIG)
        self.assertEqual(tool.load_config(path), CONFIG)

    def test_lock_rejects_concurrent_operation(self):
        with tool.locked(self.run):
            with self.assertRaises(tool.DistributionError):
                with tool.locked(self.run):
                    self.fail("Lock should not be acquired")
        self.assertFalse((self.run / ".operation-lock").exists())

    def test_existing_run_never_overwritten(self):
        existing = self.root / "existing-output"
        existing.mkdir()
        with self.assertRaisesRegex(tool.DistributionError, "already exists"):
            tool.prepare(self.app, existing, CONFIG, Path(__file__).parent / "fixtures/unity-mono.entitlements")

    def test_reject_run_containing_source(self):
        with self.assertRaisesRegex(tool.DistributionError, "must not contain"):
            tool.prepare(self.app, self.run, CONFIG, Path(__file__).parent / "fixtures/unity-mono.entitlements")

    def test_signed_tree_change_blocks_upload(self):
        (self.app / "changed.txt").write_text("changed")
        runner = FakeRunner()
        with self.assertRaisesRegex(tool.DistributionError, "changed after signing"):
            tool.submit(self.run, self.state, runner)
        self.assertEqual(runner.commands, [])

    def test_archive_change_blocks_upload(self):
        (self.run / "submission.zip").write_bytes(b"changed")
        runner = FakeRunner()
        with self.assertRaisesRegex(tool.DistributionError, "archive changed"):
            tool.submit(self.run, self.state, runner)
        self.assertEqual(runner.commands, [])

    def test_failed_upload_cannot_be_replayed(self):
        runner = FakeRunner([tool.DistributionError("uncertain")])
        with self.assertRaises(tool.DistributionError):
            tool.submit(self.run, self.state, runner)
        saved = tool.load_state(self.run)
        self.assertEqual(saved["stage"], "submission_attempted")
        with self.assertRaisesRegex(tool.DistributionError, "Never replay"):
            tool.submit(self.run, saved, runner)
        self.assertEqual(len(runner.commands), 1)

    def test_missing_response_id_blocks_replay(self):
        runner = FakeRunner([{"status": "Uploaded"}])
        with self.assertRaises(tool.DistributionError):
            tool.submit(self.run, self.state, runner)
        self.assertEqual(tool.load_state(self.run)["stage"], "submission_attempted")

    def test_submission_id_is_saved_before_any_wait(self):
        identifier = str(uuid.uuid4())
        runner = FakeRunner([{"id": identifier}])
        tool.submit(self.run, self.state, runner)
        self.assertEqual(tool.load_state(self.run)["submission_id"], identifier)
        self.assertIn("--no-wait", runner.commands[0])

    def test_progress_records_id_before_upload_finishes(self):
        identifier = str(uuid.uuid4())
        runner = FakeRunner()

        def stream(argv, on_output, timeout=900):
            runner.commands.append([str(a) for a in argv])
            on_output(f"Submission ID received\n  id: {identifier}\nUpload progress: 10%\r")
            self.assertEqual(tool.load_state(self.run)["submission_id"], identifier)
            self.assertEqual(tool.load_state(self.run)["stage"], "uploading")

        runner.stream = stream
        tool.submit(self.run, self.state, runner, progress=True)
        self.assertEqual(tool.load_state(self.run)["stage"], "submitted")
        self.assertIn("--progress", runner.commands[0])

    def test_progress_failure_keeps_id_and_prevents_replay(self):
        identifier = str(uuid.uuid4())
        runner = FakeRunner()

        def stream(argv, on_output, timeout=900):
            on_output(f"id: {identifier}\nUpload progress: 10%")
            raise tool.DistributionError("connection lost")

        runner.stream = stream
        with self.assertRaises(tool.DistributionError):
            tool.submit(self.run, self.state, runner, progress=True)
        saved = tool.load_state(self.run)
        self.assertEqual(saved["submission_id"], identifier)
        with self.assertRaisesRegex(tool.DistributionError, "Never replay"):
            tool.submit(self.run, saved, runner, progress=True)

    def test_progress_rejects_conflicting_ids(self):
        runner = FakeRunner()
        def stream(argv, on_output, timeout=900):
            on_output(f"id: {uuid.uuid4()}\nid: {uuid.uuid4()}")
        runner.stream = stream
        with self.assertRaisesRegex(tool.DistributionError, "conflicting"):
            tool.submit(self.run, self.state, runner, progress=True)

    def test_acceptance_requires_matching_archive_hash(self):
        runner = FakeRunner(self.completed_responses(archive_hash="wrong"))
        with self.assertRaisesRegex(tool.DistributionError, "does not match"):
            tool.check_submission(self.run, self.state, runner)
        self.assertNotEqual(self.state["stage"], "accepted")

    def test_acceptance_requires_matching_submission_id(self):
        responses = self.completed_responses()
        responses[0]["id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(tool.DistributionError, "different submission"):
            tool.check_submission(self.run, self.state, FakeRunner(responses))

    def test_matching_acceptance_allows_packaging_stage(self):
        runner = FakeRunner(self.completed_responses())
        self.assertTrue(tool.check_submission(self.run, self.state, runner))
        self.assertEqual(tool.load_state(self.run)["stage"], "accepted")

    def test_invalid_notarization_never_allows_packaging(self):
        with self.assertRaisesRegex(tool.DistributionError, "rejected"):
            tool.check_submission(self.run, self.state, FakeRunner(self.completed_responses("Invalid")))
        self.assertNotEqual(self.state["stage"], "accepted")

    def test_in_progress_is_not_accepted_and_does_not_fetch_log(self):
        identifier = str(uuid.uuid4())
        self.state["submission_id"] = identifier
        runner = FakeRunner([{"id": identifier, "status": "In Progress"}])
        self.assertFalse(tool.check_submission(self.run, self.state, runner))
        self.assertEqual(len(runner.commands), 1)

    def test_wait_timeout_retains_submission_without_upload(self):
        self.state["submission_id"] = str(uuid.uuid4())
        self.state["stage"] = "submitted"
        tool.save_json(self.run / "state.json", self.state)
        runner = FakeRunner([tool.DistributionError("timeout")])
        with self.assertRaises(tool.DistributionError):
            tool.check_submission(self.run, self.state, runner, wait=True)
        self.assertEqual(tool.load_state(self.run)["submission_id"], self.state["submission_id"])
        self.assertEqual(runner.commands[0][2], "wait")

    def test_package_without_acceptance_is_rejected(self):
        runner = FakeRunner()
        with self.assertRaisesRegex(tool.DistributionError, "Accepted"):
            tool.package(self.run, self.state, runner)
        self.assertEqual(runner.commands, [])

    def test_packaging_does_not_overwrite_partial_final_output(self):
        self.state["stage"] = "accepted"
        (self.run / "final").mkdir()
        with self.assertRaisesRegex(tool.DistributionError, "already exists"):
            tool.package(self.run, self.state, FakeRunner())

    def test_prepare_changes_only_staged_copy_and_excludes_siblings(self):
        source = self.root / "source" / "Example.app"
        source.parent.mkdir()
        shutil.copytree(self.app, source)
        sibling = source.parent / "Example_BurstDebugInformation_DoNotShip"
        sibling.mkdir()
        (sibling / "debug.txt").write_text("do not distribute")
        before = tool.tree_hash(source)
        output = self.root / "new-release"
        report = {"source_hash": before, "identity_sha1": "A" * 40}
        runner = FakeRunner()

        def execute(argv, timeout=300):
            runner.commands.append([str(a) for a in argv])
            if argv[0] == "/usr/bin/ditto" and argv[1] == source:
                shutil.copytree(source, Path(argv[2]))
            elif argv[0] == "/usr/bin/codesign" and argv[-1] == output / "staged/Example.app":
                (Path(argv[-1]) / "signature-fixture").write_text("signed copy")
            elif argv[0] == "/usr/bin/ditto" and "-c" in argv:
                Path(argv[-1]).write_bytes(b"submission fixture")
            return "", ""

        runner.run = execute
        with patch.object(tool, "preflight", return_value=report), patch.object(tool, "verify_signatures"):
            tool.prepare(source, output, CONFIG, Path(__file__).parent / "fixtures/unity-mono.entitlements", runner)
        self.assertEqual(tool.tree_hash(source), before)
        self.assertFalse((output / "staged" / sibling.name).exists())
        self.assertEqual(tool.load_state(output)["stage"], "signed")
        self.assertFalse(any("notarytool" in command for command in runner.commands))
        signing = [command for command in runner.commands if command[0] == "/usr/bin/codesign"]
        self.assertTrue(signing)
        self.assertTrue(all("--deep" not in command for command in signing))
        self.assertEqual(signing[-1][-1], str(output / "staged/Example.app"))

    def test_package_staples_before_zip_and_preserves_submitted_tree(self):
        self.state["stage"] = "accepted"
        signed_hash = tool.tree_hash(self.app)
        runner = FakeRunner()
        final = self.run / "final/Example.app"

        def execute(argv, timeout=300):
            runner.commands.append([str(a) for a in argv])
            if argv[0] == "/usr/bin/ditto" and argv[1] == self.app:
                shutil.copytree(self.app, final)
            elif argv[0] == "/usr/bin/xcrun" and argv[2] == "staple":
                (Path(argv[-1]) / "ticket-fixture").write_text("stapled")
            elif argv[0] == "/usr/bin/ditto" and "-c" in argv:
                self.assertTrue((final / "ticket-fixture").exists())
                Path(argv[-1]).write_bytes(b"final fixture ZIP")
            elif argv[0] == "/usr/bin/ditto" and "-x" in argv:
                shutil.copytree(final, Path(argv[-1]) / final.name)
            return "", ""

        runner.run = execute
        with patch.object(tool, "verify_signatures"):
            tool.package(self.run, self.state, runner, keep_working_artifacts=True)
        self.assertEqual(tool.tree_hash(self.app), signed_hash)
        self.assertEqual(tool.load_state(self.run)["stage"], "packaged")
        self.assertEqual(sum("--assess" in command for command in runner.commands), 2)
        self.assertEqual(sum("validate" in command for command in runner.commands), 2)

    def test_package_automatically_cleans_only_after_final_verification(self):
        original = self.root / "original/Example.app"
        original.parent.mkdir()
        shutil.copytree(self.app, original)
        self.state["source"] = {"app": str(original)}
        tool.check_submission(self.run, self.state, FakeRunner(self.completed_responses()))
        final = self.run / "final/Example.app"
        runner = FakeRunner()
        def execute(argv, timeout=300):
            runner.commands.append([str(a) for a in argv])
            if argv[0] == "/usr/bin/ditto" and argv[1] == self.app:
                shutil.copytree(self.app, final)
            elif argv[0] == "/usr/bin/ditto" and "-c" in argv:
                Path(argv[-1]).write_bytes(b"verified final fixture ZIP")
            elif argv[0] == "/usr/bin/ditto" and "-x" in argv:
                shutil.copytree(final, Path(argv[-1]) / final.name)
            return "", ""
        runner.run = execute
        with patch.object(tool, "verify_signatures"):
            tool.package(self.run, self.state, runner)
        self.assertEqual(tool.load_state(self.run)["cleanup"]["status"], "complete")
        self.assertFalse(self.app.exists())
        self.assertFalse((self.run / "submission.zip").exists())
        self.assertFalse(final.exists())
        self.assertTrue((self.run / "final/Example-macos.zip").exists())
        self.assertTrue(original.is_dir())

    def test_package_gatekeeper_failure_never_marks_packaged(self):
        self.state["stage"] = "accepted"
        runner = FakeRunner()

        def execute(argv, timeout=300):
            if argv[0] == "/usr/bin/ditto":
                shutil.copytree(self.app, Path(argv[-1]))
            if argv[0] == "/usr/sbin/spctl":
                raise tool.DistributionError("Gatekeeper rejected")
            return "", ""

        runner.run = execute
        with patch.object(tool, "verify_signatures"), patch.object(tool, "cleanup") as clean:
            with self.assertRaisesRegex(tool.DistributionError, "Gatekeeper rejected"):
                tool.package(self.run, self.state, runner)
        clean.assert_not_called()
        self.assertNotEqual(self.state["stage"], "packaged")
        self.assertFalse((self.run / "final/Example-macos.zip").exists())

    def test_prepare_rejects_symlink_app(self):
        link = self.root / "linked.app"
        link.symlink_to(self.app)
        with self.assertRaisesRegex(tool.DistributionError, "not a symlink"):
            tool.prepare(link, self.root / "output", CONFIG, Path(__file__).parent / "fixtures/unity-mono.entitlements")

    def test_stream_uses_terminal_and_retains_progress_without_cloud_access(self):
        logs = self.run / "logs"
        logs.mkdir()
        observed = []
        script = 'import os; assert os.isatty(1); print("Upload progress: 50.00%")'
        tool.Runner(logs).stream([tool.sys.executable, "-c", script], observed.append, timeout=10)
        self.assertIn("50.00%", observed[-1])
        self.assertIn("50.00%", (self.run / "upload-progress.log").read_text())
        evidence = list(logs.glob("*.json"))
        self.assertEqual(len(evidence), 1)
        self.assertEqual(tool.read_json(evidence[0])["exit_code"], 0)

    def test_runner_rejects_malformed_json_without_retry(self):
        completed = type("Result", (), {"returncode": 0, "stdout": "not JSON", "stderr": ""})()
        with patch.object(tool.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(tool.DistributionError, "Malformed JSON"):
                tool.Runner().json(["fake-tool"])
            self.assertEqual(run.call_count, 1)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.original = self.root / "original/Example.app"
        self.original.mkdir(parents=True)
        (self.original / "original-data").write_text("preserve original")
        self.run = self.root / "run"
        self.run.mkdir()
        for relative in ("staged/Example.app", "archive-check/Example.app", "final/Example.app"):
            directory = self.run / relative
            directory.mkdir(parents=True)
            (directory / "generated-data").write_text("working copy")
        (self.run / "submission.zip").write_bytes(b"submission")
        self.archive = self.run / "final/Example-macos.zip"
        self.archive.write_bytes(b"verified final ZIP")
        (self.run / "logs").mkdir()
        (self.run / "logs/evidence.json").write_text('{"exit_code": 0}')
        (self.run / "entitlements.plist").write_text("preserve policy")
        self.state = {"schema": 1, "stage": "packaged", "app_name": "Example.app", "config": CONFIG,
                      "source": {"app": str(self.original)}, "submission_id": str(uuid.uuid4()),
                      "notary_status": "Accepted", "archive_sha256": tool.sha256(self.run / "submission.zip"),
                      "final_archive": str(self.archive), "final_sha256": tool.sha256(self.archive)}
        self.log = {"jobId": self.state["submission_id"], "status": "Accepted",
                    "sha256": self.state["archive_sha256"]}
        self.save()

    def save(self):
        tool.save_json(self.run / "state.json", self.state)
        tool.save_json(self.run / "notarization-log.json", self.log)

    def clean(self, keep_app=False):
        with tool.locked(self.run):
            tool.cleanup(self.run, self.state, keep_app=keep_app)

    def test_cleanup_preserves_outside_sentinel_linked_from_state_temporary(self):
        sentinel = self.root / "outside-sentinel"
        sentinel.write_text("preserve me")
        (self.run / "state.json.tmp").symlink_to(sentinel)
        self.clean()
        self.assertEqual(sentinel.read_text(), "preserve me")
        self.assertEqual(tool.read_json(self.run / "state.json")["cleanup"]["status"], "complete")

    def test_cleanup_preserves_outside_sentinel_hardlinked_from_state_temporary(self):
        sentinel = self.root / "outside-sentinel"
        sentinel.write_text("preserve me")
        os.link(sentinel, self.run / "state.json.tmp")
        self.clean()
        self.assertEqual(sentinel.read_text(), "preserve me")
        self.assertEqual(tool.read_json(self.run / "state.json")["cleanup"]["status"], "complete")

    def test_cleanup_preserves_zip_evidence_and_original(self):
        original_hash = tool.tree_hash(self.original)
        self.clean()
        self.assertEqual(tool.sha256(self.archive), self.state["final_sha256"])
        self.assertEqual(tool.tree_hash(self.original), original_hash)
        self.assertTrue((self.run / "logs/evidence.json").exists())
        self.assertTrue((self.run / "notarization-log.json").exists())
        self.assertTrue((self.run / "entitlements.plist").exists())
        self.assertFalse((self.run / "staged").exists())
        self.assertFalse((self.run / "archive-check").exists())
        self.assertFalse((self.run / "submission.zip").exists())
        self.assertFalse((self.run / "final/Example.app").exists())
        receipt = tool.load_state(self.run)["cleanup"]
        self.assertEqual(receipt["status"], "complete")
        self.assertEqual(len(receipt["removed"]), 4)

    def test_cleanup_is_idempotent_and_completed_status_still_works(self):
        self.clean()
        removed = list(self.state["cleanup"]["removed"])
        self.clean()
        self.assertEqual(self.state["cleanup"]["removed"], removed)
        self.assertEqual(tool.completed_archive(self.run, self.state), self.archive)
        with patch.object(tool.sys, "platform", "darwin"), patch.object(tool, "check_submission") as query:
            from macdist.cli import main
            self.assertEqual(main(["status", "--run", str(self.run)]), 0)
        query.assert_not_called()

    def test_keep_app_retains_final_app_but_not_temporary_copies(self):
        self.clean(keep_app=True)
        self.assertTrue((self.run / "final/Example.app").is_dir())
        self.assertTrue(self.state["cleanup"]["final_app_retained"])
        self.assertFalse((self.run / "staged").exists())
        self.assertFalse((self.run / "submission.zip").exists())
        self.clean()
        self.assertFalse((self.run / "final/Example.app").exists())

    def test_cleanup_refuses_pending_and_failed_runs(self):
        for stage in ("preparing", "signed", "submission_attempted", "uploading", "submitted", "accepted", "failed"):
            self.state["stage"] = stage
            with self.assertRaisesRegex(tool.DistributionError, "successfully packaged"):
                self.clean()
        self.assertTrue((self.run / "submission.zip").exists())

    def test_cleanup_refuses_changed_or_missing_final_zip(self):
        self.archive.write_bytes(b"tampered")
        with self.assertRaisesRegex(tool.DistributionError, "Final ZIP changed"):
            self.clean()
        self.assertTrue((self.run / "staged/Example.app").exists())
        self.archive.unlink()
        with self.assertRaisesRegex(tool.DistributionError, "missing"):
            self.clean()

    def test_cleanup_refuses_wrong_archive_path_and_unsafe_app_name(self):
        self.state["final_archive"] = str(self.root / "outside.zip")
        with self.assertRaisesRegex(tool.DistributionError, "expected run-local ZIP"):
            self.clean()
        self.state["final_archive"] = str(self.archive)
        self.state["app_name"] = "../Example.app"
        with self.assertRaisesRegex(tool.DistributionError, "Invalid app name"):
            self.clean()
        self.assertTrue((self.run / "submission.zip").exists())

    def test_cleanup_requires_matching_apple_evidence(self):
        for field, value in (("status", "Invalid"), ("jobId", str(uuid.uuid4())), ("sha256", "wrong")):
            original = self.log[field]
            self.log[field] = value
            self.save()
            with self.assertRaisesRegex(tool.DistributionError, "matching Accepted"):
                self.clean()
            self.log[field] = original
        self.assertTrue((self.run / "submission.zip").exists())

    def test_cleanup_requires_original_path_and_rejects_overlap(self):
        self.state["source"] = {}
        with self.assertRaisesRegex(tool.DistributionError, "Original build path"):
            self.clean()
        self.state["source"] = {"app": str(self.run / "staged/Example.app")}
        with self.assertRaisesRegex(tool.DistributionError, "overlap"):
            self.clean()
        self.assertTrue((self.run / "submission.zip").exists())

    def test_cleanup_prevalidates_all_targets_and_refuses_symlinked_parent(self):
        shutil.rmtree(self.run / "archive-check")
        (self.run / "archive-check").symlink_to(self.original.parent)
        with self.assertRaisesRegex(tool.DistributionError, "symlinked artifact"):
            self.clean()
        self.assertTrue((self.run / "staged/Example.app").exists())
        self.assertTrue((self.original / "original-data").exists())

    def test_cleanup_does_not_follow_nested_links_or_delete_unknown_files(self):
        (self.run / "staged/Example.app/linked-original").symlink_to(self.original)
        (self.run / "staged/unrelated.txt").write_text("preserve unrelated")
        self.clean()
        self.assertTrue((self.original / "original-data").exists())
        self.assertTrue((self.run / "staged/unrelated.txt").exists())

    def test_cleanup_does_not_bypass_existing_operation_lock(self):
        with tool.locked(self.run):
            with self.assertRaises(tool.DistributionError):
                self.clean()
        self.assertTrue((self.run / "submission.zip").exists())

    def test_partial_cleanup_retains_zip_and_can_be_explicitly_resumed(self):
        real_remove = tool.shutil.rmtree
        def remove(path):
            if path.parent.name == "archive-check":
                raise OSError("simulated deletion failure")
            real_remove(path)
        with patch.object(tool.shutil, "rmtree", side_effect=remove):
            with self.assertRaises(OSError):
                self.clean()
        self.assertEqual(tool.load_state(self.run)["cleanup"]["status"], "in_progress")
        self.assertTrue(self.archive.exists())
        self.clean()
        self.assertEqual(tool.load_state(self.run)["cleanup"]["status"], "complete")


if __name__ == "__main__":
    unittest.main()
