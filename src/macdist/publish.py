#!/usr/bin/env python3
"""Explicit itch publishing of verified macOS runs; never builds, signs, or changes access restrictions."""

import errno
import fcntl
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pty
import re
import selectors
import shutil
import signal
import subprocess
import struct
import sys
import termios
import time
import uuid

from . import engine as distribute, output


TOKEN_ENV = "MACDIST_PUBLISHING_OP_SERVICE_ACCOUNT_TOKEN"
BASE_ENV = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE")
MAX_LINE = 64 * 1024
MAX_RECEIPT = 128 * 1024
UPLOAD_STATES = {"upload_attempted", "uploading", "uploaded", "failed", "uncertain"}
RECEIPT_STATES = UPLOAD_STATES | {"running", "dry_run_passed", "status_checked"}


class PublishingError(RuntimeError):
    """A publishing failure that must not trigger a credential fallback or automatic retry."""


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def base_environment(source=None):
    source = os.environ if source is None else source
    return {name: source[name] for name in BASE_ENV if name in source}


def load_config(path):
    return validate_config(distribute.read_json(path))


def validate_config(config):
    if not isinstance(config, dict) or set(config) != {"schema", "itch", "credentials", "release"} or config["schema"] != 1:
        raise PublishingError("Unsupported publishing configuration.")
    itch, credentials = config["itch"], config["credentials"]
    if not isinstance(itch, dict) or set(itch) != {"target", "channel", "api_key_ref"}:
        raise PublishingError("Invalid itch configuration.")
    if not isinstance(credentials, dict) or set(credentials) != {"token_env", "keychain_service", "keychain_account"}:
        raise PublishingError("Invalid publishing credential configuration.")
    if any(not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value)
           for value in [*itch.values(), *credentials.values()]):
        raise PublishingError("Publishing configuration requires nonempty single-line strings.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*", itch["target"]):
        raise PublishingError("Itch target must be an account/game slug.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", itch["channel"]):
        raise PublishingError("Invalid itch channel.")
    if not re.fullmatch(r"op://[^/]+/[^/]+/(?:[^/]+/)?[^/]+", itch["api_key_ref"]):
        raise PublishingError("Butler credentials must be an op:// secret reference, never a raw API key.")
    if not re.fullmatch(r"MACDIST_[A-Z0-9_]*OP_SERVICE_ACCOUNT_TOKEN", credentials["token_env"]):
        raise PublishingError("Use a publishing-specific MACDIST_*OP_SERVICE_ACCOUNT_TOKEN variable.")
    release_config = config["release"]
    if (not isinstance(release_config, dict) or set(release_config) != {"bundle_id", "team_id"}
            or any(not isinstance(v, str) or not v for v in release_config.values())):
        raise PublishingError("Publishing requires the project's bundle ID and release team.")
    return config


def service_token(config, source=None):
    source = os.environ if source is None else source
    token_env = config["credentials"]["token_env"]
    if token_env in source:
        token = source[token_env]
        # An explicitly supplied empty/invalid token must not fall through to another credential source.
        if not token or any(c.isspace() for c in token) or token.startswith("op://"):
            raise PublishingError("The publishing-specific token must contain a raw service-account token.")
        return token
    credentials = config["credentials"]
    try:
        result = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", credentials["keychain_service"],
             "-a", credentials["keychain_account"], "-w"],
            env=base_environment(source), capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublishingError("Publishing Keychain retrieval failed or timed out; no fallback attempted.") from error
    token = result.stdout.rstrip("\r\n")
    if result.returncode or not token or any(c.isspace() for c in token) or token.startswith("op://"):
        raise PublishingError("Publishing Keychain token is missing or invalid; no fallback attempted.")
    return token


def tools():
    result = {}
    for name in ("op", "butler"):
        executable = shutil.which(name)
        if not executable:
            raise PublishingError(f"Required executable is not on PATH: {name}")
        result[name] = str(Path(executable).resolve())
    versions = {}
    for name in ("op", "butler"):
        try:
            inspected = subprocess.run([result[name], "--version"], env=base_environment(),
                                       capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PublishingError("Could not inspect publishing executable versions.") from error
        # Butler v15 reports its version on stderr even when it exits successfully.
        version = (inspected.stdout + inspected.stderr).strip()
        if inspected.returncode or not version or len(version) > 4096:
            raise PublishingError("Publishing executable returned invalid version evidence.")
        versions[name] = version
    result["versions"] = versions
    return result


def stream_process(argv, env, emit, secrets=(), timeout=3600, own_group=True, terminal=False):
    """Stream complete bounded lines, redacting known secrets before any logging.

    An owned process group includes op, the worker, and Butler. Timeout/interruption
    terminates that group, but cannot prove an upload was not accepted remotely.
    """
    if terminal:
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
            process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=slave,
                                       stderr=subprocess.STDOUT, start_new_session=own_group)
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        reader = os.fdopen(master, "rb", buffering=0)
    else:
        process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=own_group)
        reader = process.stdout
    pending = b""
    dropping = False
    deadline = time.monotonic() + timeout

    def output(line):
        value = line.decode("utf-8", errors="replace")
        # Remove terminal decoration before redaction, including escapes inside a secret.
        value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
        value = "".join(c for c in value if c == "\t" or (ord(c) >= 32 and not 127 <= ord(c) < 160))
        for secret in sorted((value for value in secrets if value), key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        emit(value)

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(reader, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise PublishingError("Command timed out; inspect remote status before another upload.")
                for key, _ in selector.select(min(.2, max(0, deadline - time.monotonic()))):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 8192)
                    except OSError as error:
                        if terminal and error.errno == errno.EIO:
                            chunk = b""  # macOS/Linux PTYs can report EIO when their slave closes.
                        else:
                            raise
                    if not chunk:
                        selector.unregister(key.fileobj)
                        if pending and not dropping:
                            output(pending)
                        pending = b""
                        break
                    # Treat carriage-return progress updates as complete lines too.
                    for part in re.split(b"([\r\n])", chunk):
                        if part in (b"\r", b"\n"):
                            if dropping:
                                emit("[Oversized output line suppressed]")
                            elif pending:
                                output(pending)
                            pending, dropping = b"", False
                        elif not dropping:
                            pending += part
                            if len(pending) > MAX_LINE:
                                pending, dropping = b"", True
            return process.wait(timeout=max(.1, deadline - time.monotonic()))
    finally:
        # Even if op exits early, any remaining descendants belong only to this invocation.
        if own_group:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.wait()
        reader.close()


class LiveConsole:
    """Redraw progress in interactive terminals; keep redirected output line-oriented."""

    def __init__(self, stream=None):
        self.stream = sys.stdout if stream is None else stream
        self.active = False

    def emit(self, line):
        reporter = output.current()
        if reporter is not None and reporter.mode != "human":
            percentages = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s*%", line)
            if percentages:
                reporter.progress("publishing.upload", float(percentages[-1]))
            return  # Full, already-redacted output is retained in the attempt log.
        progress = re.search(r"\d+(?:\.\d+)?\s*%|(?:[KMGT]?i?B|bytes)/s|\bETA\b", line, re.IGNORECASE)
        if self.stream.isatty() and progress:
            self.stream.write("\r\x1b[2K" + line)
            self.stream.flush()
            self.active = True
        else:
            self.finish()
            print(line, file=self.stream, flush=True)

    def finish(self):
        if self.active:
            self.stream.write("\n")
            self.stream.flush()
            self.active = False


def invoke(command, arguments, config, executables, emit, timeout):
    token = service_token(config)
    env = base_environment()
    env["OP_SERVICE_ACCOUNT_TOKEN"] = token
    env["BUTLER_API_KEY"] = config["itch"]["api_key_ref"]
    # The worker scrubs the resolved Butler key before returning any output to op or us.
    argv = [executables["op"], "run", "--", sys.executable, "-I", "-m", "macdist.butler_worker",
            "--timeout", str(timeout), executables["butler"], command, *arguments]
    try:
        return stream_process(argv, env, emit, secrets=(token,), timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise PublishingError("Publishing process failed; inspect its receipt before another upload.") from error


def release(run, expected=None):
    distribute.owned_path(run, "state.json")
    state = distribute.load_state(run)
    if expected is not None and any(state["config"].get(k) != v for k, v in expected.items()):
        raise PublishingError("Run belongs to a different project or release team.")
    archive = distribute.completed_archive(run, state)
    source = state.get("source")
    version = source.get("version") if isinstance(source, dict) else None
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version):
        raise PublishingError("Run needs a valid recorded build version; version overrides are not supported.")
    log = distribute.read_json(distribute.owned_path(run, "notarization-log.json"))
    identifier = distribute.submission_id(state.get("submission_id"))
    recorded_hash = state.get("archive_sha256", "")
    if (not isinstance(log, dict) or state.get("notary_status") != "Accepted" or log.get("status") != "Accepted"
            or log.get("jobId") != identifier or not isinstance(recorded_hash, str)
            or not re.fullmatch(r"[a-fA-F0-9]{64}", recorded_hash) or log.get("sha256") != recorded_hash):
        raise PublishingError("Publishing requires matching Accepted notarization evidence.")
    # Reject symlinked state/evidence and lock files before entering the operation lock.
    distribute.owned_path(run, "state.json")
    distribute.owned_path(run, ".operation-lock")
    return state, archive, version


def read_receipt(run):
    path = distribute.owned_path(run, "publishing/itch.json")
    if not path.exists():
        return None
    if path.stat().st_size > MAX_RECEIPT:
        raise PublishingError("Publishing receipt exceeds its size limit.")
    receipt = distribute.read_json(path)
    if (not isinstance(receipt, dict) or receipt.get("schema") != 1 or receipt.get("provider") != "itch"
            or receipt.get("mode") not in ("upload", "dry_run", "status")
            or receipt.get("status") not in RECEIPT_STATES
            or (receipt.get("mode") == "upload" and receipt.get("status") not in UPLOAD_STATES)):
        raise PublishingError("Malformed publishing receipt; inspect it before any new upload.")
    return receipt


def publish(run, config, mode, retry_upload=False, timeout=3600, invoke_command=invoke, resolve_tools=tools,
            expected_artifact=None, expected_version=None):
    validate_config(config)
    if mode not in ("dry_run", "upload", "status"):
        raise PublishingError("Unknown publishing mode.")
    if run.is_symlink():
        raise PublishingError("Symlinked run directories are not supported.")
    run = run.expanduser().resolve(strict=True)
    # Prevalidate output paths; never write through a run-local symlink.
    root = distribute.owned_path(run, "publishing")
    summary = distribute.owned_path(run, "publishing/itch.json")
    inspection_name = "itch-status.json" if mode == "status" else "itch-preview.json"
    inspection = distribute.owned_path(run, "publishing/" + inspection_name)
    distribute.owned_path(run, "publishing/" + inspection_name + ".tmp")
    distribute.owned_path(run, "publishing/itch.json.tmp")
    distribute.owned_path(run, ".operation-lock")
    with distribute.locked(run):
        state, archive, version = release(run, config["release"])
        if ((expected_artifact is not None and state["final_sha256"] != expected_artifact)
                or (expected_version is not None and version != expected_version)):
            raise PublishingError("The confirmed build changed; select and confirm it again.")
        previous = read_receipt(run)
        if previous and any(previous.get(k) != config["itch"][k] for k in ("target", "channel")):
            raise PublishingError("Existing publishing receipt has a different destination; refusing to retarget this run.")
        had_upload = previous and previous.get("mode") == "upload"
        if mode == "upload" and had_upload and not retry_upload:
            raise PublishingError("This run already has an upload attempt. Inspect status/logs, then explicitly use --retry-upload if intended.")
        executables = resolve_tools()
        root.mkdir(exist_ok=True)
        attempts = distribute.owned_path(run, "publishing/itch")
        attempts.mkdir(exist_ok=True)
        attempt_id = str(uuid.uuid4())
        attempt = distribute.owned_path(run, "publishing/itch/" + attempt_id)
        attempt.mkdir()
        receipt_path = attempt / "receipt.json"
        log_path = attempt / "publish.log"
        itch = config["itch"]
        owner, game = itch["target"].split("/")
        receipt = {"schema": 1, "provider": "itch", "attempt_id": attempt_id, "mode": mode,
                   "target": itch["target"], "channel": itch["channel"], "version": version,
                   "artifact": str(archive.relative_to(run)), "artifact_sha256": state["final_sha256"],
                   "page_url": f"https://{owner}.itch.io/{game}", "started_at": timestamp(),
                   "log": str(log_path.relative_to(run)), "status": "upload_attempted" if mode == "upload" else "running",
                   "remote_build_id": None, "delivery_verified": False,
                   "tool_versions": executables.get("versions", {})}
        # Dry-run and status attempts cannot erase the blocking record of a previous upload.
        update_summary = mode == "upload" or not had_upload

        def save():
            distribute.save_json(receipt_path, receipt)
            if update_summary:
                distribute.save_json(summary, receipt)
            if mode != "upload":
                distribute.save_json(inspection, receipt)

        save()
        output.result(receipt=str(receipt_path), delivery_verified=False)
        destination = itch["target"] + ":" + itch["channel"]
        output.event("publishing.started", f"{mode}: {destination} · {version}\nInput: {archive}\nSHA-256: {state['final_sha256']}", mode=mode, destination=destination, version=version, archive=str(archive), receipt=str(receipt_path), log=str(log_path))
        arguments = [str(archive), destination, "--userversion", version]
        if mode == "dry_run":
            arguments.append("--dry-run")
        elif mode == "status":
            arguments = [itch["target"]]
        try:
            with log_path.open("x", encoding="utf-8") as stream:
                console = LiveConsole()
                def emit(line):
                    stream.write(line + "\n")
                    stream.flush()
                    console.emit(line)
                if mode == "upload":
                    receipt["status"] = "uploading"
                    save()
                try:
                    code = invoke_command("status" if mode == "status" else "push", arguments,
                                          config, executables, emit, timeout)
                finally:
                    console.finish()
                receipt["exit_code"] = code
                if distribute.sha256(archive) != state["final_sha256"]:
                    raise PublishingError("Input ZIP changed during publishing; delivery is uncertain.")
                if code:
                    receipt["status"] = "uncertain" if mode == "upload" else "failed"
                    raise PublishingError(f"Butler/op returned exit code {code}. Inspect the retained log; no retry attempted.")
                receipt["status"] = {"upload": "uploaded", "dry_run": "dry_run_passed", "status": "status_checked"}[mode]
                receipt["note"] = ("Butler exited successfully; remote delivery/runtime is not verified. Remote build ID is not parsed from human output."
                                   if mode == "upload" else "Read-only Butler command completed; does not prove upload or delivery.")
        except (Exception, KeyboardInterrupt) as error:
            receipt["status"] = "uncertain" if mode == "upload" else "failed"
            receipt["note"] = (str(error) if isinstance(error, PublishingError) else
                               "Operation failed or was interrupted. No automatic retry or credential fallback.")
            raise
        finally:
            receipt["finished_at"] = timestamp()
            save()
        output.event("publishing.completed", "Receipt: " + str(receipt_path), status=receipt["status"], receipt=str(receipt_path), delivery_verified=False)
        output.result(publishing_status=receipt["status"], receipt=str(receipt_path), delivery_verified=False)
        return receipt


def packaged_runs(root, expected=None):
    """Discover only immediate packaged runs; hash the selected ZIP later, not every build."""
    if not root.is_dir() or root.is_symlink():
        raise PublishingError("The workspace's distribution run directory is missing or symlinked.")
    result = []
    for run in sorted(root.iterdir(), key=lambda path: path.name):
        if not run.is_dir() or run.is_symlink():
            continue
        try:
            state_path = distribute.owned_path(run, "state.json")
            if state_path.stat().st_size > 1024 * 1024:
                continue
            state = distribute.load_state(run)
            if expected is not None and any(state["config"].get(k) != v for k, v in expected.items()):
                continue
            source = state.get("source")
            version = source.get("version") if isinstance(source, dict) else None
            app_name = state.get("app_name", "")
            if (state.get("stage") != "packaged" or not isinstance(version, str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version)
                    or "\\" in app_name):
                continue
            archive = distribute.owned_path(run, "final/" + Path(app_name).stem + "-macos.zip")
            if not archive.is_file() or Path(state.get("final_archive", "")).resolve() != archive.resolve():
                continue
            result.append((run, version))
        except (OSError, ValueError, TypeError, AttributeError, distribute.DistributionError):
            continue
    return result


def interactive_publish(root, config, dry_run=False, retry_upload=False, timeout=3600,
                        input_fn=input, execute=publish):
    """Pick a build and explicitly confirm uploads; cancellation never accesses credentials."""
    validate_config(config)
    candidates = packaged_runs(root, config["release"])
    if not candidates:
        raise PublishingError("No packaged builds found in this workspace. Package a build first.")
    print("Packaged builds (the selected ZIP will be verified):")
    for index, (run, version) in enumerate(candidates, 1):
        name = "".join(c for c in run.name if 32 <= ord(c) < 127)
        print(f"  {index}. {version}  [{name}]")
    answer = input_fn("Select a build number (Enter or 0 to cancel): ").strip()
    if not answer or answer == "0":
        print("Cancelled; nothing uploaded.")
        return None
    if not answer.isascii() or not answer.isdecimal() or not 1 <= int(answer) <= len(candidates):
        raise PublishingError("Invalid build selection; nothing uploaded.")
    run, listed_version = candidates[int(answer) - 1]
    state, archive, version = release(run, config["release"])
    if version != listed_version:
        raise PublishingError("Selected build changed during selection; run the picker again.")
    previous = read_receipt(run)
    if not dry_run and previous and previous.get("mode") == "upload" and not retry_upload:
        raise PublishingError("This build already has an upload attempt. Inspect its logs/status before explicitly using --retry-upload.")
    destination = config["itch"]["target"] + ":" + config["itch"]["channel"]
    print(f"\nBuild: {version}\nDestination: {destination}\nZIP: {archive}\nSHA-256: {state['final_sha256']}")
    if dry_run:
        print("Dry run only; nothing will be uploaded.")
    else:
        if previous and previous.get("mode") == "upload":
            print("WARNING: this is an explicitly requested repeat upload.")
        answer = input_fn("Upload this build to itch.io? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled; nothing uploaded.")
            return None
    # Backend rechecks the source and repeat guard under the existing run lock.
    return execute(run, config, "dry_run" if dry_run else "upload",
                   retry_upload=retry_upload, timeout=timeout,
                   expected_artifact=state["final_sha256"], expected_version=version)
