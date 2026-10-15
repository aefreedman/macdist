"""Dashboard tests use temporary fixtures, loopback HTTP, and fake Apple responses."""

import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from macdist import dashboard
from macdist import engine as distribute
from macdist import publish


CONFIG = {"bundle_id": "com.example.example", "team_id": "AB12345678",
          "signing_identity": "Developer ID Application: Example Corporation (AB12345678)",
          "keychain_profile": "example-notary"}


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.run = self.root / "playtest-001"
        self.run.mkdir()
        self.identifier = str(uuid.uuid4())
        self.state = {"schema": 1, "stage": "accepted", "source": {"version": "alpha-test"},
                      "config": CONFIG, "submission_id": self.identifier,
                      "app_name": "Example.app", "notary_status": "Accepted"}
        self.save()
        self.calls = []

        def query(argv):
            self.calls.append(argv)
            if argv[2] == "info":
                return {"id": self.identifier, "status": "Accepted"}
            return {"jobId": self.identifier, "status": "Accepted", "issues": []}

        self.revealed = []
        self.monitor = dashboard.Monitor(self.root, CONFIG, query, reveal=self.revealed.append,
                                         publishing_config=publish.load_config(Path(__file__).parent / "fixtures/publishing.json"))
        self.server = dashboard.DashboardServer(0, self.monitor)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.monitor.executor.shutdown(wait=True)
        self.monitor.close()
        self.temporary.cleanup()

    def save(self):
        distribute.save_json(self.run / "state.json", self.state)

    def request(self, method, path, authorized=True, headers=None, body=None):
        values = {"X-Dashboard-Token": self.server.token} if authorized else {}
        values.update(headers or {})
        connection = HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=values)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def make_archive(self):
        (self.run / "final").mkdir()
        archive = self.run / "final/Example-macos.zip"
        archive.write_bytes(b"small fixture ZIP")
        self.state.update(stage="packaged", final_archive=str(archive),
                          final_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
        self.save()
        return archive

    def test_loopback_only_and_root_security_headers(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        code, headers, body = self.request("GET", "/", authorized=False)
        self.assertEqual(code, 200)
        self.assertIn(b"macOS distribution", body)
        self.assertNotIn(b"__SESSION_TOKEN__", body)
        self.assertNotIn("Set-Cookie", headers)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_api_requires_session_token(self):
        self.assertEqual(self.request("GET", "/api/runs", authorized=False)[0], 403)
        self.assertEqual(self.request("GET", "/api/runs")[0], 200)

    def test_dns_rebinding_host_and_cross_origin_blocked(self):
        self.assertEqual(self.request("GET", "/api/runs", headers={"Host": "attacker.example"})[0], 403)
        self.assertEqual(self.request("POST", "/api/runs/playtest-001/refresh",
                                      headers={"Origin": "https://attacker.example"})[0], 403)
        self.assertEqual(self.calls, [])

    def test_no_submit_retry_package_actions(self):
        for action in ("submit", "retry", "package", "sign", "resume", "publish", "itch", "upload", "itch-refresh"):
            self.assertEqual(self.request("POST", f"/api/runs/playtest-001/{action}")[0], 404)
        self.assertEqual(self.calls, [])

    def test_upload_request_bodies_rejected(self):
        code, _, _ = self.request("POST", "/api/runs/playtest-001/refresh", body=b"file")
        self.assertEqual(code, 400)
        self.assertEqual(self.calls, [])

    def test_listing_and_log_polling_never_query_apple(self):
        (self.run / "upload-progress.log").write_text("Upload progress: 12.50%\r\x1b[2KUpload progress: 25.00%")
        code, _, body = self.request("GET", "/api/runs")
        row = json.loads(body)["runs"][0]
        self.assertEqual(code, 200)
        self.assertEqual(row["upload_percent"], 25)
        self.assertFalse(row["ready"])
        _, _, log = self.request("GET", "/api/runs/playtest-001/logs/upload")
        self.assertNotIn(b"\x1b", log)
        self.assertEqual(self.calls, [])

    def test_accepted_is_not_ready_until_packaging(self):
        self.assertFalse(self.monitor.rows()[0]["ready"])
        self.make_archive()
        self.assertTrue(self.monitor.rows()[0]["ready"])

    def test_refresh_is_read_only_and_keeps_credentials_in_keychain(self):
        before = (self.run / "state.json").read_bytes()
        code, _, _ = self.request("POST", "/api/runs/playtest-001/refresh")
        self.assertEqual(code, 202)
        self.monitor.executor.shutdown(wait=True)
        self.assertEqual((self.run / "state.json").read_bytes(), before)
        self.assertEqual(self.monitor.rows()[0]["apple"]["status"], "Accepted")
        self.assertEqual([call[2] for call in self.calls], ["info", "log"])
        self.assertTrue(all("--keychain-profile" in call for call in self.calls))
        self.assertFalse(any("--password" in call for call in self.calls))
        self.assertIn('"issues": []', self.monitor.log("playtest-001", "apple"))

    def test_refresh_wrong_team_profile_or_uuid_blocked(self):
        self.state["config"] = dict(CONFIG, keychain_profile="untrusted-profile")
        self.save()
        self.assertEqual(self.request("POST", "/api/runs/playtest-001/refresh")[0], 400)
        self.state["config"] = CONFIG
        self.state["submission_id"] = "not a UUID"
        self.save()
        self.assertEqual(self.request("POST", "/api/runs/playtest-001/refresh")[0], 400)
        self.assertEqual(self.calls, [])

    def test_refresh_mismatched_apple_id_is_not_success(self):
        self.monitor.query = lambda argv: {"id": str(uuid.uuid4()), "status": "Accepted"}
        self.monitor.refresh("playtest-001")
        self.monitor.executor.shutdown(wait=True)
        cache = self.monitor.rows()[0]["apple"]
        self.assertIn("different submission", cache["error"])
        self.assertNotIn("status", cache)

    def test_refresh_is_coalesced_and_throttled(self):
        release = threading.Event()
        def query(argv):
            release.wait(timeout=3)
            self.calls.append(argv)
            return {"id": self.identifier, "status": "In Progress"}
        self.monitor.query = query
        self.monitor.refresh("playtest-001")
        self.monitor.refresh("playtest-001")
        release.set()
        self.monitor.executor.shutdown(wait=True)
        self.monitor.refresh("playtest-001")
        self.assertEqual(len(self.calls), 1)

    def test_path_traversal_and_symlink_escape_blocked(self):
        self.assertEqual(self.request("GET", "/api/runs/%2E%2E/logs/upload")[0], 400)
        self.assertEqual(self.request("GET", "/api/runs/%2Ftmp/logs/upload")[0], 400)
        (self.root / "linked-run").symlink_to(self.run)
        self.assertFalse(any(row["id"] == "linked-run" for row in self.monitor.rows()))
        outside = self.root / "private.txt"
        outside.write_text("secret fixture")
        (self.run / "upload-progress.log").symlink_to(outside)
        self.assertEqual(self.request("GET", "/api/runs/playtest-001/logs/upload")[0], 400)

    def test_malformed_state_is_reported_not_crashing_listing(self):
        (self.run / "state.json").write_text("not JSON")
        rows = self.monitor.rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("error", rows[0])
        self.assertFalse(rows[0]["ready"])

    def test_log_reads_are_bounded(self):
        (self.run / "upload-progress.log").write_bytes(b"x" * (dashboard.MAX_TEXT * 2))
        text = self.monitor.log("playtest-001", "upload")
        self.assertTrue(text.startswith("[Showing the latest log tail]"))
        self.assertLess(len(text), dashboard.MAX_TEXT + 100)

    def test_download_endpoint_removed_even_for_completed_zip(self):
        archive = self.make_archive()
        for authorized in (True, False):
            code, headers, body = self.request("GET", "/download/playtest-001", authorized=authorized)
            self.assertEqual(code, 404)
            self.assertNotIn("Content-Disposition", headers)
            self.assertNotEqual(body, archive.read_bytes())
        self.assertEqual(self.revealed, [])

    def test_copy_path_available_only_for_ready_run_without_gui_side_effects(self):
        self.assertIsNone(self.monitor.rows()[0]["archive_path"])
        archive = self.make_archive()
        code, _, body = self.request("GET", "/api/runs")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["runs"][0]["archive_path"], str(archive.resolve()))
        self.assertEqual(self.revealed, [])
        script = (dashboard.HERE / "dashboard.js").read_text()
        self.assertIn("navigator.clipboard.writeText(run.archive_path)", script)
        self.assertNotIn("/download/", script)

    def test_reveal_requires_post_session_completed_run_and_matching_checksum(self):
        endpoint = "/api/runs/playtest-001/reveal"
        self.assertEqual(self.request("POST", endpoint, authorized=False)[0], 403)
        self.assertEqual(self.request("GET", endpoint)[0], 404)
        self.assertEqual(self.request("POST", endpoint)[0], 400)
        self.assertEqual(self.revealed, [])
        archive = self.make_archive()
        before = (self.run / "state.json").read_bytes()
        self.assertEqual(self.request("POST", endpoint)[0], 200)
        self.assertEqual(self.revealed, [archive])
        self.assertEqual((self.run / "state.json").read_bytes(), before)
        archive.write_bytes(b"tampered")
        self.assertEqual(self.request("POST", endpoint)[0], 400)
        self.assertEqual(self.revealed, [archive])

    def test_reveal_cannot_open_arbitrary_file_cross_origin_or_body_path(self):
        self.make_archive()
        endpoint = "/api/runs/playtest-001/reveal"
        self.assertEqual(self.request("POST", endpoint, headers={"Origin": "https://attacker.example"})[0], 403)
        self.assertEqual(self.request("POST", endpoint, body=b"/etc/passwd")[0], 400)
        self.assertEqual(self.request("POST", "/api/runs/%2E%2E/reveal")[0], 400)
        self.state["final_archive"] = str(self.root / "outside.zip")
        self.save()
        self.assertEqual(self.request("POST", endpoint)[0], 400)
        self.assertEqual(self.revealed, [])

    def test_reveal_rejects_symlinked_final_parent(self):
        self.make_archive()
        (self.run / "final").rename(self.run / "renamed-final")
        (self.run / "final").symlink_to("renamed-final")
        self.assertEqual(self.request("POST", "/api/runs/playtest-001/reveal")[0], 400)
        self.assertEqual(self.revealed, [])

    def test_finder_uses_fixed_argv_without_shell_and_reports_failure(self):
        archive = self.make_archive()
        success = type("Result", (), {"returncode": 0, "stderr": ""})()
        with patch.object(dashboard.subprocess, "run", return_value=success) as run:
            dashboard.show_in_finder(archive)
            self.assertEqual(run.call_args.args[0], ["/usr/bin/open", "-R", str(archive)])
            self.assertNotIn("shell", run.call_args.kwargs)
        self.monitor.reveal = lambda path: (_ for _ in ()).throw(ValueError("Finder unavailable"))
        code, _, body = self.request("POST", "/api/runs/playtest-001/reveal")
        self.assertEqual(code, 400)
        self.assertIn(b"Finder unavailable", body)

    def publishing_fixture(self, status="uploaded"):
        archive = self.make_archive()
        identifier = str(uuid.uuid4())
        attempt = self.run / "publishing/itch" / identifier
        attempt.mkdir(parents=True)
        (attempt / "publish.log").write_text("Upload complete [REDACTED]")
        receipt = {"schema": 1, "provider": "itch", "attempt_id": identifier, "target": "example/example", "channel": "MacOS",
                   "status": status, "artifact_sha256": distribute.sha256(archive), "version": "alpha-test",
                   "finished_at": "2026-10-12T12:00:00+00:00", "log": str((attempt / "publish.log").relative_to(self.run)),
                   "page_url": "javascript:untrusted", "api_key": "[REDACTED]"}
        distribute.save_json(self.run / "publishing/itch.json", receipt)
        return receipt

    def test_publishing_monitor_reads_only_local_allowlisted_evidence(self):
        receipt = self.publishing_fixture()
        with patch.object(publish, "service_token", side_effect=AssertionError("must not access credentials")), \
                patch.object(publish, "invoke", side_effect=AssertionError("must not run Butler")):
            code, _, body = self.request("GET", "/api/runs")
            self.assertEqual(code, 200)
            publication = json.loads(body)["runs"][0]["publishing"]
            self.assertEqual(publication["status"], "uploaded")
            self.assertEqual(publication["page_url"], "https://example.itch.io/example")
            self.assertNotIn(b"not-for-api-output", body)
            self.assertNotIn(b"javascript:", body)
            code, _, log = self.request("GET", "/api/runs/playtest-001/logs/itch")
            self.assertEqual(code, 200)
            self.assertIn(b"[REDACTED]", log)
            receipt["status"] = "status_checked"
            distribute.save_json(self.run / "publishing/itch-status.json", receipt)
            self.assertIsNotNone(self.monitor.rows()[0]["publishing"]["remote_checked_at"])
        self.assertEqual(self.calls, [])

    def test_publishing_log_traversal_symlinks_and_wrong_destinations_rejected(self):
        receipt = self.publishing_fixture()
        for field, value in (("log", "../private.txt"), ("target", "attacker/other"), ("channel", "other")):
            bad = dict(receipt, **{field: value})
            distribute.save_json(self.run / "publishing/itch.json", bad)
            self.assertEqual(self.request("GET", "/api/runs/playtest-001/logs/itch")[0], 400)
            self.assertIn("error", self.monitor.rows()[0]["publishing"])
        distribute.save_json(self.run / "publishing/itch.json", receipt)
        log = self.run / receipt["log"]
        log.unlink()
        log.symlink_to(self.run / "state.json")
        self.assertEqual(self.request("GET", "/api/runs/playtest-001/logs/itch")[0], 400)

    def test_malformed_publishing_receipt_does_not_hide_run_and_artifact_mismatch_warns(self):
        receipt = self.publishing_fixture()
        receipt["artifact_sha256"] = "0" * 64
        distribute.save_json(self.run / "publishing/itch.json", receipt)
        self.assertIn("different artifact", self.monitor.rows()[0]["publishing"]["error"])
        (self.run / "publishing/itch.json").write_text("not JSON")
        row = self.monitor.rows()[0]
        self.assertTrue(row["ready"])
        self.assertIn("error", row["publishing"])

    def test_dashboard_without_publishing_never_loads_credentials(self):
        self.monitor.publishing_config = None
        with patch.object(publish, "service_token", side_effect=AssertionError("credentials forbidden")):
            self.assertEqual(self.monitor.rows()[0]["publishing"], {"status": "not_configured"})
            self.assertEqual(self.request("GET", "/api/runs/playtest-001/logs/itch")[0], 200)

    def test_foreign_project_logs_reveal_and_refresh_are_blocked(self):
        self.state["config"] = dict(CONFIG, bundle_id="com.other.game")
        self.save()
        for endpoint in ("logs/upload", "reveal", "refresh"):
            method = "GET" if endpoint.startswith("logs") else "POST"
            self.assertEqual(self.request(method, "/api/runs/playtest-001/" + endpoint)[0], 400)
        self.assertIn("different project", self.monitor.rows()[0]["error"])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.revealed, [])

    def test_same_run_symlinked_log_parent_is_rejected(self):
        directory = self.run / "logs"
        directory.mkdir()
        (directory / "file.log").write_text("fixture")
        (self.run / "linked").symlink_to(directory)
        with self.assertRaises(ValueError):
            dashboard.safe_file(self.run, "linked/file.log")

    def test_frontend_uses_text_nodes_not_raw_html(self):
        script = (dashboard.HERE / "dashboard.js").read_text()
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("eval(", script)
        self.assertIn("textContent", script)
        self.assertIn("encodeURIComponent", script)


if __name__ == "__main__":
    unittest.main()
