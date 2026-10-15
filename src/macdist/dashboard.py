#!/usr/bin/env python3
"""Local read-only monitor for macOS distribution runs; never signs/submits/packages."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
from socketserver import TCPServer
import subprocess
import threading
import time
from urllib.parse import unquote, urlsplit

from . import engine as distribute
from . import publish


HERE = Path(__file__).resolve().parent
MAX_TEXT = 128 * 1024
MAX_STATE = 1024 * 1024
LOG_NAMES = {"upload": "upload-progress.log", "pipeline": "finalize-task.log", "apple": "notarization-log.json"}
PUBLISH_LOGS = {"itch": "itch.json", "itch-preview": "itch-preview.json", "itch-status": "itch-status.json"}
PUBLISH_STATES = {"running", "upload_attempted", "uploading", "uploaded", "uncertain", "failed", "dry_run_passed", "status_checked"}


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def bounded_text(path, limit=MAX_TEXT, tail=False):
    with path.open("rb") as stream:
        if tail:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size - limit))
        else:
            size = path.stat().st_size
            if size > limit:
                raise ValueError("File exceeds the dashboard's display limit.")
        data = stream.read(limit)
    value = data.decode("utf-8", errors="replace")
    # Terminal progress uses carriage returns and ANSI control sequences.
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "\n")
    return ("[Showing the latest log tail]\n" if tail and size > limit else "") + value


def safe_file(run, relative):
    try:
        return distribute.owned_path(run, relative)
    except distribute.DistributionError as error:
        raise ValueError(str(error)) from error


def apple_json(argv):
    """Read-only Apple calls, fixed executable, Keychain profile only, no shell."""
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError(f"Apple query failed ({result.returncode}): {(result.stderr or result.stdout)[-1200:]}")
    if len(result.stdout.encode()) > MAX_STATE:
        raise ValueError("Apple response exceeds the display limit.")
    response = json.loads(result.stdout)
    if not isinstance(response, dict):
        raise ValueError("Apple returned an unexpected response.")
    return response


def show_in_finder(path):
    """Reveal a validated ZIP on this Mac only after an explicit dashboard action."""
    result = subprocess.run(["/usr/bin/open", "-R", str(path)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError(f"Finder reveal failed ({result.returncode}): {result.stderr[-1200:]}")


class Monitor:
    def __init__(self, root, config, query=apple_json, reveal=show_in_finder, publishing_config=None):
        self.root = root.expanduser().resolve()
        self.config = config
        self.query = query
        self.reveal = reveal
        self.publishing_config = publish.validate_config(publishing_config) if publishing_config is not None else None
        self.cache = {}
        self.mutex = threading.Lock()
        self.slots = threading.BoundedSemaphore(2)
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notary-status")

    def close(self):
        self.executor.shutdown(wait=False, cancel_futures=True)

    def run_path(self, name):
        if not name or name in (".", "..") or Path(name).name != name or "\\" in name or len(name) > 200:
            raise ValueError("Invalid run name.")
        path = self.root / name
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise ValueError("Run is outside the selected root or is a symlink.")
        if not path.is_dir():
            raise FileNotFoundError("Run not found.")
        return path

    def state(self, name):
        path = self.run_path(name)
        state = json.loads(bounded_text(safe_file(path, "state.json"), MAX_STATE))
        if not isinstance(state, dict) or state.get("schema") != 1:
            raise ValueError("Unsupported or malformed run state.")
        configuration = state.get("config", {})
        if not isinstance(configuration, dict) or any(configuration.get(k) != self.config[k] for k in ("team_id", "bundle_id")):
            raise ValueError("Run belongs to a different project or release team.")
        return path, state

    def archive(self, run, state):
        app_name = state.get("app_name", "")
        if not isinstance(app_name, str) or Path(app_name).name != app_name or not app_name.endswith(".app"):
            raise ValueError("Invalid app name.")
        if state.get("stage") != "packaged" or not re.fullmatch(r"[a-fA-F0-9]{64}", str(state.get("final_sha256", ""))):
            raise ValueError("This run is not ready to distribute.")
        archive = safe_file(run, "final/" + Path(app_name).stem + "-macos.zip")
        if Path(state.get("final_archive", "")).resolve() != archive.resolve() or not archive.is_file():
            raise ValueError("Final ZIP is missing or does not match the recorded path.")
        return archive

    def rows(self):
        if not self.root.exists():
            return []
        rows = []
        candidates = sorted(self.root.iterdir(), key=lambda p: p.name, reverse=True)[:200]
        for candidate in candidates:
            if not candidate.is_dir() or candidate.is_symlink():
                continue
            try:
                run, state = self.state(candidate.name)
                source = state.get("source", {})
                if not isinstance(source, dict):
                    source = {}
                ready = False
                archive_path = None
                archive_error = None
                if state.get("stage") == "packaged":
                    try:
                        archive_path = str(self.archive(run, state).resolve())
                        ready = True
                    except (ValueError, OSError) as error:
                        archive_error = str(error)
                with self.mutex:
                    cached = dict(self.cache.get(candidate.name, {}))
                cached.pop("log", None)
                cached.pop("last_attempt", None)
                row = {"id": candidate.name, "version": source.get("version"),
                       "app": state.get("app_name"), "stage": state.get("stage"),
                       "apple_local_status": state.get("notary_status"),
                       "submission_id": state.get("submission_id"), "apple": cached,
                       "ready": ready, "archive_error": archive_error, "archive_path": archive_path,
                       "sha256": state.get("final_sha256") if ready else None,
                       "updated": datetime.fromtimestamp(safe_file(run, "state.json").stat().st_mtime,
                                                         timezone.utc).isoformat(timespec="seconds"),
                       "operation_locked": safe_file(run, ".operation-lock").exists(),
                       "publishing": self.publication(run, state)}
                # Lock presence is not proof that its process is still alive.
                log_path = safe_file(run, "upload-progress.log")
                if log_path.is_file():
                    log = bounded_text(log_path, tail=True)
                    percentages = re.findall(r"Upload progress:\s*([0-9]+(?:\.[0-9]+)?)%", log)
                    percent = float(percentages[-1]) if percentages else None
                    row["upload_percent"] = percent if percent is not None and 0 <= percent <= 100 else None
                rows.append(row)
            except (OSError, ValueError, TypeError) as error:
                rows.append({"id": candidate.name, "error": str(error), "ready": False})
        return rows

    def publishing_receipt(self, run, filename):
        path = distribute.owned_path(run, "publishing/" + filename)
        if not path.exists():
            return None
        receipt = json.loads(bounded_text(path, publish.MAX_RECEIPT))
        if self.publishing_config is None:
            raise ValueError("Publishing is not configured for this project.")
        itch = self.publishing_config["itch"]
        if (not isinstance(receipt, dict) or receipt.get("schema") != 1 or receipt.get("provider") != "itch"
                or receipt.get("target") != itch["target"] or receipt.get("channel") != itch["channel"]
                or receipt.get("status") not in PUBLISH_STATES):
            raise ValueError("Publishing receipt is malformed or differs from the configured itch destination.")
        identifier = str(distribute.submission_id(receipt.get("attempt_id")))
        expected = "publishing/itch/" + identifier + "/publish.log"
        if receipt.get("log") != expected:
            raise ValueError("Publishing log is not the expected attempt-local path.")
        distribute.owned_path(run, expected)
        return receipt

    def publication(self, run, state):
        if self.publishing_config is None:
            return {"status": "not_configured"}
        itch = self.publishing_config["itch"]
        owner, game = itch["target"].split("/")
        result = {"status": "not_published", "target": itch["target"], "channel": itch["channel"],
                  "page_url": f"https://{owner}.itch.io/{game}"}
        try:
            receipt = self.publishing_receipt(run, "itch.json")
            if receipt:
                result.update({key: receipt.get(key) for key in ("status", "version", "started_at", "finished_at", "note")})
                if receipt.get("artifact_sha256") != state.get("final_sha256"):
                    result["error"] = "Publishing receipt refers to a different artifact; do not treat it as this build's upload."
            checked = self.publishing_receipt(run, "itch-status.json")
            if checked:
                result["remote_checked_at"] = checked.get("finished_at") if checked.get("status") == "status_checked" else None
                result["remote_check_failed"] = checked.get("status") == "failed"
        except (OSError, ValueError, TypeError, distribute.DistributionError) as error:
            result["error"] = str(error)
        return result

    def reveal_archive(self, name):
        run, state = self.state(name)
        self.archive(run, state)
        # Verify the retained ZIP checksum and reject symlinked parent paths before GUI access.
        archive = distribute.completed_archive(run, state)
        self.reveal(archive)

    def refresh(self, name):
        _, state = self.state(name)
        identifier = distribute.submission_id(state.get("submission_id"))
        configuration = state.get("config", {})
        if not isinstance(configuration, dict) or any(configuration.get(key) != self.config[key]
                                                     for key in ("team_id", "bundle_id", "keychain_profile")):
            raise ValueError("Run configuration differs from this dashboard's trusted config.")
        with self.mutex:
            cached = self.cache.get(name, {})
            if cached.get("refreshing") or time.monotonic() - cached.get("last_attempt", -100) < 15:
                return
            if not self.slots.acquire(blocking=False):
                raise ValueError("Two Apple queries are already active; try again shortly.")
            self.cache[name] = dict(cached, refreshing=True, error=None, last_attempt=time.monotonic())
        try:
            self.executor.submit(self._refresh, name, identifier)
        except BaseException:
            with self.mutex:
                self.cache[name]["refreshing"] = False
            self.slots.release()
            raise

    def _refresh(self, name, identifier):
        try:
            options = ["--keychain-profile", self.config["keychain_profile"], "--output-format", "json"]
            response = self.query(["/usr/bin/xcrun", "notarytool", "info", identifier] + options)
            if distribute.submission_id(response.get("id")) != identifier:
                raise ValueError("Apple returned a different submission ID.")
            status = response.get("status")
            if status not in ("In Progress", "Accepted", "Invalid", "Rejected"):
                raise ValueError("Apple returned an unrecognized status.")
            with self.mutex:
                self.cache[name].update(status=status, checked_at=timestamp(), error=None)
            if status in ("Accepted", "Invalid", "Rejected"):
                log = self.query(["/usr/bin/xcrun", "notarytool", "log", identifier] + options)
                if distribute.submission_id(log.get("jobId")) != identifier:
                    raise ValueError("Apple log refers to a different submission.")
                with self.mutex:
                    self.cache[name]["log"] = json.dumps(log, indent=2)
        except (OSError, ValueError, subprocess.TimeoutExpired, distribute.DistributionError) as error:
            with self.mutex:
                self.cache[name]["error"] = str(error)
        finally:
            with self.mutex:
                self.cache[name]["refreshing"] = False
            self.slots.release()

    def log(self, name, kind):
        run, _ = self.state(name)
        if kind in PUBLISH_LOGS:
            receipt = self.publishing_receipt(run, PUBLISH_LOGS[kind])
            if not receipt:
                return "No publishing log available yet."
            return bounded_text(distribute.owned_path(run, receipt["log"]), tail=True)
        if kind not in LOG_NAMES:
            raise ValueError("Unknown log type.")
        if kind == "apple":
            with self.mutex:
                cached = self.cache.get(name, {}).get("log")
            if cached:
                return cached
        path = safe_file(run, LOG_NAMES[kind])
        if kind == "upload" and not path.exists():
            path = safe_file(run, "upload-task.log")
        if not path.is_file():
            return "No log available yet."
        return bounded_text(path, tail=True)


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer's reverse-DNS lookup is unnecessary and can stall local startup.
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def __init__(self, port, monitor):
        super().__init__(("127.0.0.1", port), Handler)
        self.monitor = monitor
        self.token = secrets.token_urlsafe(32)
        self.port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Do not log URLs, session tokens, cookies, or request headers.
        print(f"Dashboard request: {self.command}", flush=True)

    def headers_for(self, status, content_type, length=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if length is not None:
            self.send_header("Content-Length", str(length))

    def respond(self, status, value, content_type="application/json; charset=utf-8"):
        if content_type.startswith("application/json"):
            value = json.dumps(value)
        data = value.encode("utf-8")
        self.headers_for(status, content_type, len(data))
        self.end_headers()
        self.wfile.write(data)

    def guard(self, api=False):
        if self.headers.get("Host") not in self.server.allowed_hosts:
            raise PermissionError("Unexpected Host header.")
        origin = self.headers.get("Origin")
        if origin and origin not in {f"http://{host}" for host in self.server.allowed_hosts}:
            raise PermissionError("Cross-origin requests are not allowed.")
        if api and not hmac.compare_digest(self.headers.get("X-Dashboard-Token", "").encode(), self.server.token.encode()):
            raise PermissionError("Missing dashboard session token.")

    def do_GET(self):
        try:
            parsed = urlsplit(self.path)
            self.guard(api=parsed.path.startswith("/api/"))
            if parsed.query:
                raise ValueError("Query parameters are not supported.")
            if parsed.path in ("/", "/dashboard.js", "/dashboard.css"):
                if parsed.path == "/":
                    value = (HERE / "dashboard.html").read_text(encoding="utf-8").replace("__SESSION_TOKEN__", self.server.token)
                    self.respond(200, value, "text/html; charset=utf-8")
                else:
                    mime = "text/javascript; charset=utf-8" if parsed.path.endswith(".js") else "text/css; charset=utf-8"
                    self.respond(200, (HERE / parsed.path[1:]).read_text(encoding="utf-8"), mime)
                return
            if parsed.path == "/api/runs":
                self.respond(200, {"runs": self.server.monitor.rows(), "checked_at": timestamp()})
                return
            parts = parsed.path.split("/")
            if len(parts) == 6 and parts[1:3] == ["api", "runs"] and parts[4] == "logs":
                self.respond(200, self.server.monitor.log(unquote(parts[3]), parts[5]), "text/plain; charset=utf-8")
                return
            self.respond(404, {"error": "Not found."})
        except (BrokenPipeError, ConnectionResetError):
            return  # Browser cancelled a response; do not send a second response.
        except PermissionError as error:
            self.respond(403, {"error": str(error)})
        except FileNotFoundError:
            self.respond(404, {"error": "Run or file not found."})
        except (ValueError, TypeError, OSError, distribute.DistributionError) as error:
            self.respond(400, {"error": str(error)})

    def do_POST(self):
        try:
            self.guard(api=True)
            # Actions identify only a known run in the URL, never a caller-supplied file path.
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
                raise ValueError("Request bodies are not supported.")
            parsed = urlsplit(self.path)
            parts = parsed.path.split("/")
            if not parsed.query and len(parts) == 5 and parts[1:3] == ["api", "runs"] and parts[4] == "refresh":
                self.server.monitor.refresh(unquote(parts[3]))
                self.respond(202, {"message": "Status refresh requested; local run state is unchanged."})
                return
            if not parsed.query and len(parts) == 5 and parts[1:3] == ["api", "runs"] and parts[4] == "reveal":
                self.server.monitor.reveal_archive(unquote(parts[3]))
                self.respond(200, {"message": "ZIP revealed in Finder on this Mac."})
                return
            self.respond(404, {"error": "No such action. This dashboard cannot submit, retry, sign, or package."})
        except (BrokenPipeError, ConnectionResetError):
            return
        except PermissionError as error:
            self.respond(403, {"error": str(error)})
        except FileNotFoundError:
            self.respond(404, {"error": "Run not found."})
        except (ValueError, TypeError, OSError, subprocess.TimeoutExpired, distribute.DistributionError) as error:
            self.respond(400, {"error": str(error)})



def serve(project, port=8765, publishing_config=None):
    monitor = Monitor(project.runs_dir, project.config, publishing_config=publishing_config)
    try:
        server = DashboardServer(port, monitor)
        print(f"Dashboard: http://127.0.0.1:{server.port}/", flush=True)
        print(f"Run root: {monitor.root}\\nApple is queried only on request. Publishing is CLI-only.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    finally:
        monitor.close()
    return 0
