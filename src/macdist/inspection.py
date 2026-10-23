"""Bounded, read-only local snapshots; never query Apple, sign, or take a lock."""

import json
from pathlib import Path
import re

from . import engine
from .output import clean

MAX_STATE = 1024 * 1024
MAX_TAIL = 64 * 1024


def read_json(run, relative, limit=MAX_STATE):
    path = engine.owned_path(run, relative)
    if not path.is_file():
        raise engine.DistributionError("Inspection metadata must be a regular file.")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise engine.DistributionError("Inspection metadata exceeds its size limit.")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise engine.DistributionError("Inspection metadata must be an object.")
    return value


def snapshot(path):
    path = Path(path).expanduser()
    if path.is_symlink():
        raise engine.DistributionError("Refusing a symlinked run directory.")
    run = path.resolve(strict=True)
    state = read_json(run, "state.json")
    if state.get("schema") != 1 or not isinstance(state.get("config"), dict):
        raise engine.DistributionError("Unsupported run state.")
    app_name = state.get("app_name")
    if not isinstance(app_name, str) or Path(app_name).name != app_name or "\\" in app_name or not app_name.endswith(".app"):
        raise engine.DistributionError("Invalid app name in run state.")
    stage = state.get("stage")
    if stage not in {"preparing", "signed", "submission_attempted", "uploading", "submitted", "accepted", "packaged"}:
        raise engine.DistributionError("Unknown run stage.")
    identifier = state.get("submission_id")
    if identifier is not None:
        identifier = engine.submission_id(identifier)
    notary_status = state.get("notary_status")
    if notary_status not in (None, "In Progress", "Accepted", "Invalid", "Rejected"):
        raise engine.DistributionError("Unknown notarization status in run state.")
    result = {"run": str(run), "stage": stage, "submission_id": identifier,
              "notary_status": notary_status,
              "operation_lock_present": engine.owned_path(run, ".operation-lock").exists(),
              "snapshot_consistency": "best_effort",
              "paths": {"state": str(run / "state.json"), "command_logs": str(run / "logs"),
                        "upload_log": str(run / "upload-progress.log"),
                        "notarization_log": str(run / "notarization-log.json"),
                        "publishing_receipt": str(run / "publishing/itch.json")}}
    progress = engine.owned_path(run, "upload-progress.log")
    if progress.exists():
        if not progress.is_file():
            raise engine.DistributionError("Upload log must be a regular file.")
        with progress.open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - MAX_TAIL))
            tail = stream.read(MAX_TAIL).decode("utf-8", errors="replace")
        matches = re.findall(r"Upload progress:\s*([0-9]+(?:\.[0-9]+)?)%", clean(tail))
        if matches and 0 <= float(matches[-1]) <= 100:
            result["last_upload_percent"] = float(matches[-1])
            result["progress_is_historical"] = True
    if stage == "packaged":
        archive = engine.owned_path(run, "final/" + Path(app_name).stem + "-macos.zip")
        if Path(state.get("final_archive", "")).resolve() != archive:
            raise engine.DistributionError("Recorded archive is not the expected run-local ZIP.")
        checksum = state.get("final_sha256", "")
        if not isinstance(checksum, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", checksum):
            raise engine.DistributionError("Invalid recorded archive checksum.")
        result["artifact"] = {"path": str(archive), "present": archive.is_file(),
                              "recorded_sha256": checksum, "checksum_verified": False}
    receipt_path = engine.owned_path(run, "publishing/itch.json")
    if receipt_path.exists():
        receipt = read_json(run, "publishing/itch.json", 128 * 1024)
        selected = {}
        for key in ("status", "attempt_id", "target", "channel", "version"):
            value = receipt.get(key)
            if value is not None and (not isinstance(value, str) or len(value) > 256):
                raise engine.DistributionError("Invalid publishing metadata.")
            selected[key] = value
        selected["delivery_verified"] = receipt.get("delivery_verified") is True
        result["publishing"] = selected
    return result
