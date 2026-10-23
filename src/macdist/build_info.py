"""Offline installation identity; never expose direct-URL credentials or invoke Git."""

from importlib import metadata
import json
import re
import sys

from . import __version__


def info():
    result = {"version": __version__, "installed_distribution_version": None,
              "source_commit": None, "editable": None, "executable": sys.executable}
    try:
        distribution = metadata.distribution("macdist")
        result["installed_distribution_version"] = distribution.version
        raw = distribution.read_text("direct_url.json")
        if raw is None:
            return result
        origin = json.loads(raw)
        if not isinstance(origin, dict):
            return result
        directory = origin.get("dir_info")
        result["editable"] = bool(directory.get("editable", False)) if isinstance(directory, dict) else False
        vcs = origin.get("vcs_info")
        if isinstance(vcs, dict) and vcs.get("vcs") == "git":
            commit = vcs.get("commit_id")
            if isinstance(commit, str) and re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", commit):
                result["source_commit"] = commit.lower()
    except (metadata.PackageNotFoundError, OSError, ValueError, UnicodeError):
        pass  # An unavailable source commit is unknown, not the checkout's HEAD.
    return result
