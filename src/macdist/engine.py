#!/usr/bin/env python3
"""Sign and notarize an existing Unity macOS app; never build or launch Unity."""

import errno
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pty
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from . import __version__


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}
BUNDLE_SUFFIXES = {".app", ".framework", ".bundle", ".xpc"}
CONFIG_KEYS = {"bundle_id", "team_id", "signing_identity", "keychain_profile"}


class DistributionError(RuntimeError):
    """A failed or uncertain operation requiring operator attention."""


def save_json(path, value):
    """Publish evidence atomically without opening existing temporary-file links."""
    path = Path(path).absolute()
    for directory in (path.parent, *path.parent.parents):
        if directory.is_symlink():
            raise DistributionError("Refusing symlinked evidence directory.")
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def read_json(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inventory(app):
    """Hash files, permissions, directories, and links without following links."""
    result = {}
    for root, directories, files in os.walk(app, followlinks=False):
        for name in sorted(directories + files):
            path = Path(root) / name
            relative = str(path.relative_to(app))
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                if not path.resolve(strict=True).is_relative_to(app.resolve()):
                    raise DistributionError(f"Link escapes the app: {relative}")
                result[relative] = ["link", os.readlink(path), mode]
            elif path.is_file():
                result[relative] = ["file", sha256(path), mode]
            elif path.is_dir():
                result[relative] = ["directory", mode]
            else:
                raise DistributionError(f"Unsupported filesystem entry: {relative}")
    return result


def tree_hash(app):
    return hashlib.sha256(json.dumps(inventory(app), sort_keys=True).encode()).hexdigest()


def macho(path):
    with path.open("rb") as stream:
        return stream.read(4) in MACHO_MAGICS


def signing_targets(app):
    """Leaves first, then real code bundles deepest-first, outer app last."""
    leaves = []
    bundles = []
    for root, directories, files in os.walk(app, followlinks=False):
        directories[:] = sorted(d for d in directories if not (Path(root) / d).is_symlink())
        directory = Path(root)
        if directory != app and directory.suffix.lower() in BUNDLE_SUFFIXES:
            # Resource-only .bundles are not code bundles.
            if any(macho(p) for p in directory.rglob("*") if p.is_file() and not p.is_symlink()):
                bundles.append(directory)
        for name in sorted(files):
            path = directory / name
            if not path.is_symlink() and macho(path):
                leaves.append(path)
    return sorted(leaves) + sorted(bundles, key=lambda p: (-len(p.parts), str(p))) + [app]


def load_config(path):
    config = read_json(path)
    if set(config) != CONFIG_KEYS or any(not isinstance(v, str) or not v.strip() for v in config.values()):
        raise DistributionError("Config must contain only bundle_id, team_id, signing_identity, keychain_profile.")
    if not re.fullmatch(r"[A-Z0-9]{10}", config["team_id"]):
        raise DistributionError("Expected a 10-character Apple Team ID.")
    if not config["signing_identity"].startswith("Developer ID Application:"):
        raise DistributionError("Use a Developer ID Application identity, not Apple Distribution/Development.")
    if not config["signing_identity"].endswith(f'({config["team_id"]})'):
        raise DistributionError("Signing identity and Team ID disagree.")
    return config


def inspect_app(app, config):
    if app.is_symlink():
        raise DistributionError("Pass the real .app, not a symlink.")
    app = app.resolve(strict=True)
    if app.suffix != ".app" or not app.is_dir():
        raise DistributionError("Input must be an existing .app directory.")
    with (app / "Contents/Info.plist").open("rb") as stream:
        info = plistlib.load(stream)
    if info.get("CFBundleIdentifier") != config["bundle_id"]:
        raise DistributionError(f'Bundle ID mismatch: {info.get("CFBundleIdentifier")!r}; expected {config["bundle_id"]}.')
    executable_name = info.get("CFBundleExecutable", "")
    if not executable_name or Path(executable_name).name != executable_name:
        raise DistributionError("Invalid CFBundleExecutable.")
    executable = app / "Contents/MacOS" / executable_name
    if not executable.is_file() or not os.access(executable, os.X_OK) or not macho(executable):
        raise DistributionError("Main executable is missing, not executable, or not Mach-O.")
    if info.get("CFBundlePackageType") != "APPL":
        raise DistributionError("Expected an APPL bundle.")
    # Validate every link and entry before staging, including unusual code locations.
    source_hash = tree_hash(app)
    return app, executable, info, source_hash


class Runner:
    """Run argv without a shell; retain bounded-stage evidence, never credentials."""

    def __init__(self, directory=None):
        self.directory = directory
        self.sequence = 0

    def run(self, argv, timeout=300):
        self.sequence += 1
        print("Running:", " ".join(str(arg) for arg in argv), flush=True)
        try:
            completed = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout)
            evidence = {"argv": [str(a) for a in argv], "exit_code": completed.returncode,
                        "stdout": completed.stdout, "stderr": completed.stderr}
        except subprocess.TimeoutExpired as error:
            evidence = {"argv": [str(a) for a in argv], "timeout": timeout}
            for field in ("stdout", "stderr"):
                value = getattr(error, field) or ""
                evidence[field] = value.decode(errors="replace") if isinstance(value, bytes) else value
            self.record(evidence)
            raise DistributionError("Command timed out; no automatic retry. Inspect retained evidence.") from error
        self.record(evidence)
        if completed.returncode:
            raise DistributionError(f'Command failed ({completed.returncode}): {(completed.stderr or completed.stdout)[-2000:]}')
        return completed.stdout, completed.stderr

    def stream(self, argv, on_output, timeout=900):
        """Stream normal notarytool progress while persisting submission identity early."""
        self.sequence += 1
        print("Running:", " ".join(str(arg) for arg in argv), flush=True)
        transcript = ""
        deadline = time.monotonic() + timeout
        evidence = {"argv": [str(a) for a in argv]}
        progress_path = self.directory.parent / "upload-progress.log"
        # notarytool suppresses its progress display when stdout is not a terminal.
        # A PTY preserves that display even when our own output is redirected to a log.
        master, slave = pty.openpty()
        try:
            with progress_path.open("xb", buffering=0) as log:
                with subprocess.Popen([str(a) for a in argv], stdout=slave, stderr=slave,
                                      stdin=subprocess.DEVNULL) as process:
                    os.close(slave)
                    slave = None
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(master, selectors.EVENT_READ)
                            while selector.get_map():
                                if time.monotonic() >= deadline:
                                    raise DistributionError("Upload timed out; inspect state/logs, never replay submit.")
                                for key, _ in selector.select(timeout=1):
                                    try:
                                        chunk = os.read(key.fd, 65536)
                                    except OSError as error:
                                        if error.errno != errno.EIO:
                                            raise
                                        chunk = b""  # PTY EOF on platforms that return EIO.
                                    if not chunk:
                                        selector.unregister(key.fd)
                                        continue
                                    log.write(chunk)
                                    decoded = chunk.decode("utf-8", errors="replace")
                                    transcript += decoded
                                    print(decoded, end="", flush=True)
                                    on_output(transcript)
                        code = process.wait(timeout=max(1, deadline - time.monotonic()))
                        evidence["exit_code"] = code
                        if code:
                            raise DistributionError(f"Upload command failed ({code}); inspect upload-progress.log.")
                    except BaseException:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                        evidence["uncertain"] = True
                        raise
                    finally:
                        evidence["stdout"] = transcript
                        self.record(evidence)
        finally:
            os.close(master)
            if slave is not None:
                os.close(slave)

    def record(self, evidence):
        if self.directory:
            save_json(self.directory / f"{self.sequence:03d}-{uuid.uuid4().hex[:8]}.json", evidence)

    def json(self, argv, timeout=300):
        stdout, _ = self.run(argv, timeout)
        try:
            value = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise DistributionError("Malformed JSON response; inspect evidence, do not replay a submission.") from error
        if not isinstance(value, dict):
            raise DistributionError("Expected a JSON object response.")
        return value


def preflight(app, config, runner, check_credentials=False):
    if sys.platform != "darwin":
        raise DistributionError("Distribution operations require macOS.")
    app, executable, info, source_hash = inspect_app(app, config)
    for tool in ("notarytool", "stapler"):
        runner.run(["/usr/bin/xcrun", "--find", tool])
    identities, _ = runner.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"])
    matches = re.findall(r'\b([A-Fa-f0-9]{40})\s+"' + re.escape(config["signing_identity"]) + '"', identities)
    if len(matches) != 1:
        raise DistributionError("Expected exactly one valid matching signing identity in Keychain.")
    architecture, _ = runner.run(["/usr/bin/lipo", "-archs", executable])
    if check_credentials:
        runner.json(["/usr/bin/xcrun", "notarytool", "history", "--keychain-profile",
                     config["keychain_profile"], "--output-format", "json"], timeout=60)
    return {"app": str(app), "bundle_id": info["CFBundleIdentifier"],
            "version": info.get("CFBundleShortVersionString"),
            "minimum_macos": info.get("LSMinimumSystemVersion"),
            "architectures": architecture.strip(), "source_hash": source_hash,
            "identity_sha1": matches[0], "credentials_checked": check_credentials}


@contextmanager
def locked(run):
    """Reject concurrent operations; never remove a crashed process's lock silently."""
    lock = run / ".operation-lock"
    try:
        with lock.open("x", encoding="utf-8") as stream:
            stream.write(f"pid={os.getpid()}\n")
    except FileExistsError as error:
        raise DistributionError("Run is locked. Inspect its process/state before manually removing a stale lock.") from error
    try:
        yield
    finally:
        lock.unlink()


def load_state(run):
    state = read_json(run / "state.json")
    if state.get("schema") != 1 or not isinstance(state.get("config"), dict):
        raise DistributionError("Unsupported run state.")
    app_name = state.get("app_name", "")
    if not isinstance(app_name, str) or not app_name.endswith(".app") or Path(app_name).name != app_name:
        raise DistributionError("Invalid staged app name.")
    return state


def staged_app(run, state):
    return run / "staged" / state["app_name"]


def assert_unchanged(run, state):
    if tree_hash(staged_app(run, state)) != state["signed_hash"]:
        raise DistributionError("Staged app changed after signing; do not notarize/package it.")
    if sha256(run / "submission.zip") != state["archive_sha256"]:
        raise DistributionError("Submission archive changed; cannot associate it with this run.")


def verify_signatures(app, config, runner):
    for target in signing_targets(app):
        runner.run(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", target])
    runner.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", app])
    # Verify each slice, not just codesign's default architecture.
    with (app / "Contents/Info.plist").open("rb") as stream:
        executable = app / "Contents/MacOS" / plistlib.load(stream)["CFBundleExecutable"]
    architectures, _ = runner.run(["/usr/bin/lipo", "-archs", executable])
    for architecture in architectures.split():
        _, details = runner.run(["/usr/bin/codesign", "--display", "--verbose=4", "--arch", architecture, app])
        if f'TeamIdentifier={config["team_id"]}' not in details:
            raise DistributionError("Signed app has the wrong Team ID.")
        if "(runtime)" not in details or "Timestamp=" not in details or "Signature=adhoc" in details:
            raise DistributionError("Missing hardened runtime, secure timestamp, or Developer ID signature.")


def prepare(app, run, config, entitlements, runner=None):
    app = app.expanduser()
    if app.is_symlink():
        raise DistributionError("Pass the real .app, not a symlink.")
    app = app.resolve(strict=True)
    run = run.expanduser().resolve()
    if run.is_relative_to(app) or app.is_relative_to(run):
        raise DistributionError("Run output and original app must not contain each other.")
    if run.exists():
        raise DistributionError("Run directory already exists. Use resume, or choose a new directory.")
    report = preflight(app, config, runner or Runner())
    entitlement_bytes = entitlements.read_bytes()
    permissions = plistlib.loads(entitlement_bytes)
    if permissions.get("com.apple.security.get-task-allow") or permissions.get("com.apple.security.app-sandbox"):
        raise DistributionError("This workflow does not support debug get-task-allow or App Sandbox entitlements.")
    run.mkdir(parents=True, mode=0o700)
    (run / "logs").mkdir()
    runner = runner or Runner(run / "logs")
    state = {"schema": 1, "tool_version": __version__, "stage": "preparing", "config": config, "source": report,
             "app_name": app.name, "submission_id": None}
    save_json(run / "state.json", state)
    with locked(run):
        (run / "staged").mkdir()
        staged = staged_app(run, state)
        runner.run(["/usr/bin/ditto", app, staged], timeout=900)
        if tree_hash(staged) != report["source_hash"] or tree_hash(app) != report["source_hash"]:
            raise DistributionError("Build changed during staging, or copy differs; stop and create a fresh run.")
        (run / "entitlements.plist").write_bytes(entitlement_bytes)
        with (staged / "Contents/Info.plist").open("rb") as stream:
            main_executable = staged / "Contents/MacOS" / plistlib.load(stream)["CFBundleExecutable"]
        for target in signing_targets(staged):
            command = ["/usr/bin/codesign", "--force", "--sign", report["identity_sha1"],
                       "--timestamp", "--options", "runtime"]
            if target in (staged, main_executable) or target.suffix.lower() in (".app", ".xpc"):
                command += ["--entitlements", run / "entitlements.plist"]
            runner.run(command + [target])
        verify_signatures(staged, config, runner)
        state["signed_hash"] = tree_hash(staged)
        runner.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                    staged, run / "submission.zip"], timeout=900)
        state["archive_sha256"] = sha256(run / "submission.zip")
        state["stage"] = "signed"
        save_json(run / "state.json", state)
    return run


def notary_arguments(state):
    return ["--keychain-profile", state["config"]["keychain_profile"], "--output-format", "json"]


def submission_id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as error:
        raise DistributionError("Missing or invalid submission UUID. Do not submit again.") from error


def submit(run, state, runner, progress=False):
    if state["stage"] != "signed" or state["submission_id"]:
        raise DistributionError("This run has already attempted submission, or is not signed. Never replay submit.")
    assert_unchanged(run, state)
    # Write before dispatch: even a crash or lost response must not permit a second upload.
    state["stage"] = "submission_attempted"
    save_json(run / "state.json", state)
    if progress:
        def remember_identifier(output):
            identifiers = re.findall(r"\bid:\s*([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})", output)
            for value in identifiers:
                identifier = submission_id(value)
                if state["submission_id"] and state["submission_id"] != identifier:
                    raise DistributionError("Upload output contains conflicting submission IDs; inspect evidence.")
                if not state["submission_id"]:
                    state["submission_id"] = identifier
                    state["stage"] = "uploading"
                    save_json(run / "state.json", state)
        runner.stream(["/usr/bin/xcrun", "notarytool", "submit", run / "submission.zip", "--no-wait",
                       "--keychain-profile", state["config"]["keychain_profile"],
                       "--output-format", "normal", "--progress"], remember_identifier, timeout=900)
        if not state["submission_id"]:
            raise DistributionError("Upload returned no submission ID; inspect progress log, do not replay submit.")
    else:
        response = runner.json(["/usr/bin/xcrun", "notarytool", "submit", run / "submission.zip",
                                "--no-wait"] + notary_arguments(state), timeout=900)
        state["submission_id"] = submission_id(response.get("id"))
    state["stage"] = "submitted"
    save_json(run / "state.json", state)
    print("Submission ID:", state["submission_id"])


def check_submission(run, state, runner, wait=False):
    identifier = submission_id(state.get("submission_id"))
    assert_unchanged(run, state)
    if wait:
        # Wait on the known ID only. A wait timeout leaves that ID available for resume.
        runner.json(["/usr/bin/xcrun", "notarytool", "wait", identifier, "--timeout", "20m"]
                    + notary_arguments(state), timeout=1230)
    response = runner.json(["/usr/bin/xcrun", "notarytool", "info", identifier] + notary_arguments(state))
    if submission_id(response.get("id")) != identifier:
        raise DistributionError("Status response refers to a different submission.")
    status = response.get("status")
    state["notary_status"] = status
    save_json(run / "state.json", state)
    print("Notarization:", status)
    if status == "In Progress":
        return False
    if status not in ("Accepted", "Invalid", "Rejected"):
        raise DistributionError(f"Unrecognized notarization status: {status!r}")
    # Apple log includes the archive's sha256, independently binding acceptance to our upload.
    log = runner.json(["/usr/bin/xcrun", "notarytool", "log", identifier] + notary_arguments(state))
    save_json(run / "notarization-log.json", log)
    if log.get("jobId") != identifier or log.get("sha256", "").lower() != state["archive_sha256"]:
        raise DistributionError("Notarization log does not match this submission/archive.")
    if log.get("status") != status or status != "Accepted":
        raise DistributionError("Notarization rejected or conflicting evidence; inspect notarization-log.json.")
    state["stage"] = "accepted"
    save_json(run / "state.json", state)
    return True


def owned_path(run, relative):
    """Resolve a fixed artifact path without accepting symlinked parents/targets."""
    path = run
    for part in Path(relative).parts:
        if part in (".", "..") or Path(relative).is_absolute():
            raise DistributionError("Unsafe artifact path.")
        path = path / part
        if path.is_symlink():
            raise DistributionError(f"Refusing symlinked artifact path: {relative}")
    if not path.resolve().is_relative_to(run.resolve()):
        raise DistributionError("Artifact escapes the run directory.")
    return path


def completed_archive(run, state):
    """Require a packaged run and its exact unchanged final ZIP."""
    if state.get("stage") != "packaged":
        raise DistributionError("Only successfully packaged runs can be cleaned.")
    app_name = state.get("app_name", "")
    if not isinstance(app_name, str) or not app_name.endswith(".app") or Path(app_name).name != app_name or "\\" in app_name:
        raise DistributionError("Invalid app name in completed run.")
    archive = owned_path(run, Path("final") / (Path(app_name).stem + "-macos.zip"))
    expected_hash = state.get("final_sha256", "")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected_hash) or not archive.is_file():
        raise DistributionError("Final ZIP or its recorded checksum is missing.")
    if Path(state.get("final_archive", "")).resolve() != archive.resolve():
        raise DistributionError("Recorded final archive is not the expected run-local ZIP.")
    if sha256(archive) != expected_hash.lower():
        raise DistributionError("Final ZIP changed since packaging; working artifacts will not be removed.")
    return archive


def cleanup(run, state, keep_app=False):
    """Remove only known generated copies after revalidating the retained evidence."""
    archive = completed_archive(run, state)
    log = read_json(owned_path(run, "notarization-log.json"))
    identifier = submission_id(state.get("submission_id"))
    recorded_hash = state.get("archive_sha256", "")
    if (not isinstance(log, dict) or not isinstance(recorded_hash, str)
            or not re.fullmatch(r"[a-fA-F0-9]{64}", recorded_hash)
            or state.get("notary_status") != "Accepted" or log.get("status") != "Accepted"
            or submission_id(log.get("jobId")) != identifier
            or log.get("sha256") != recorded_hash):
        raise DistributionError("Cleanup requires matching Accepted notarization evidence.")
    metadata = state.get("source", {})
    source = metadata.get("app") if isinstance(metadata, dict) else None
    if not isinstance(source, str) or not source:
        raise DistributionError("Original build path is missing; cleanup cannot prove safe scope.")
    original = Path(source).resolve()
    if original.is_relative_to(run.resolve()) or run.resolve().is_relative_to(original):
        raise DistributionError("Original build and run overlap; cleanup is unsafe.")
    names = [Path("staged") / state["app_name"], Path("archive-check") / state["app_name"],
             Path("submission.zip")]
    if not keep_app:
        names.append(Path("final") / state["app_name"])
    # Validate the entire deletion scope before removing anything. Nested app links
    # are never followed by shutil.rmtree; top-level/parent links are rejected.
    targets = [(name, owned_path(run, name)) for name in names]
    for name, path in targets:
        if path.exists() and (path.resolve() == archive.resolve() or original.is_relative_to(path.resolve())):
            raise DistributionError(f"Artifact overlaps retained ZIP/original build: {name}")
        if path.exists() and not (path.is_dir() or path.is_file()):
            raise DistributionError(f"Unsupported artifact: {name}")
    removed = list(state.get("cleanup", {}).get("removed", []))
    receipt = {"status": "in_progress", "removed": removed, "keep_app_requested": keep_app}
    state["cleanup"] = receipt
    save_json(run / "state.json", state)
    for name, path in targets:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
        else:
            continue
        if str(name) not in removed:
            removed.append(str(name))
        save_json(run / "state.json", state)
    # Remove empty generated containers, but never discard unknown extra files.
    for name in ("staged", "archive-check"):
        directory = owned_path(run, name)
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    receipt.update(status="complete", completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   final_app_retained=owned_path(run, Path("final") / state["app_name"]).exists())
    save_json(run / "state.json", state)
    print("Working artifacts cleaned; final ZIP and evidence retained:", archive)


def package(run, state, runner, keep_working_artifacts=False):
    if state["stage"] != "accepted":
        raise DistributionError("Packaging requires matched Accepted notarization evidence.")
    assert_unchanged(run, state)
    final_directory = run / "final"
    if final_directory.exists():
        raise DistributionError("Final directory already exists; inspect it, do not overwrite/retry automatically.")
    # Keep the submitted, signed app immutable; staple a separate final copy.
    final_directory.mkdir()
    final_app = final_directory / state["app_name"]
    runner.run(["/usr/bin/ditto", staged_app(run, state), final_app], timeout=900)
    if tree_hash(final_app) != state["signed_hash"]:
        raise DistributionError("Final copy differs from the submitted app.")
    runner.run(["/usr/bin/xcrun", "stapler", "staple", final_app])
    runner.run(["/usr/bin/xcrun", "stapler", "validate", final_app])
    verify_signatures(final_app, state["config"], runner)
    runner.run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", final_app])
    archive = final_directory / (Path(state["app_name"]).stem + "-macos.zip")
    runner.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", final_app, archive], timeout=900)
    # Assess the extracted shipping ZIP too, not only the pre-archive app.
    unpacked = run / "archive-check"
    unpacked.mkdir()
    runner.run(["/usr/bin/ditto", "-x", "-k", archive, unpacked], timeout=900)
    extracted = unpacked / state["app_name"]
    if tree_hash(extracted) != tree_hash(final_app):
        raise DistributionError("Final ZIP round trip changed the app.")
    runner.run(["/usr/bin/xcrun", "stapler", "validate", extracted])
    runner.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", extracted])
    runner.run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", extracted])
    state["stage"] = "packaged"
    state["final_archive"] = str(archive)
    state["final_sha256"] = sha256(archive)
    save_json(run / "state.json", state)
    print("Distribution ZIP:", archive)
    print("SHA-256:", state["final_sha256"])
    if not keep_working_artifacts:
        cleanup(run, state)


def execute(args, config=None):
    if sys.platform != "darwin":
        raise DistributionError("Distribution operations require macOS.")
    if args.command in ("preflight", "prepare", "distribute"):
        if config is None:
            raise DistributionError("Resolved project configuration is required.")
        if args.command == "preflight":
            print(json.dumps(preflight(args.app.expanduser(), config, Runner(), args.check_credentials), indent=2))
            return 0
        # A release validates authentication before making any new run.
        if args.command == "distribute":
            preflight(args.app.expanduser(), config, Runner(), check_credentials=True)
        run = prepare(args.app, args.run, config, args.entitlements)
        if args.command == "prepare":
            print("Signed, not submitted:", run)
            return 0
    else:
        run = args.run.expanduser().resolve(strict=True)
    with locked(run):
        state = load_state(run)
        runner = Runner(run / "logs")
        if args.command == "cleanup":
            cleanup(run, state, keep_app=args.keep_app)
            return 0
        if state["stage"] == "packaged":
            if args.command == "submit":
                raise DistributionError("Packaged run cannot be resubmitted.")
            completed_archive(run, state)
            print("Already packaged:", state["final_archive"])
            return 0
        if args.command in ("submit", "distribute"):
            submit(run, state, runner, progress=getattr(args, "progress", False))
            if args.command == "submit":
                return 0
        if args.command == "reconcile":
            if state["stage"] != "submission_attempted" or state["submission_id"]:
                raise DistributionError("Reconcile is only for a lost submit response with no recorded ID.")
            state["submission_id"] = submission_id(args.submission_id)
            state["stage"] = "submitted"
            save_json(run / "state.json", state)
        if args.command == "package":
            # Recheck Apple's evidence before the local packaging mutation.
            if not check_submission(run, state, runner):
                return 2
            package(run, state, runner, keep_working_artifacts=args.keep_working_artifacts)
            return 0
        accepted = check_submission(run, state, runner,
                                    wait=args.command == "distribute" or getattr(args, "wait", False))
        if accepted and args.command in ("distribute", "resume"):
            package(run, state, runner, keep_working_artifacts=args.keep_working_artifacts)
        return 0 if accepted else 2
