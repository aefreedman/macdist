"""Nonsecret configuration. Project paths are relative to the project file."""

from dataclasses import dataclass
import os
from pathlib import Path
import plistlib
import re
import tomllib

from .engine import DistributionError

PROFILE_KEYS = {"team_id", "signing_identity", "keychain_profile"}


def user_config_path():
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "macdist/config.toml"


def table(value, required, optional=()):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - set(optional):
        raise DistributionError(f"Expected keys {sorted(required)}; optional {sorted(optional)}. No secret fields are supported.")
    return value


def string(value, name):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise DistributionError(f"{name} must be a nonempty, single-line string.")
    return value


def validate_profile(profile):
    table(profile, PROFILE_KEYS)
    for key, value in profile.items():
        string(value, key)
    if not re.fullmatch(r"[A-Z0-9]{10}", profile["team_id"]):
        raise DistributionError("Expected a 10-character Apple Team ID.")
    identity = profile["signing_identity"]
    if not identity.startswith("Developer ID Application:") or not identity.endswith(f'({profile["team_id"]})'):
        raise DistributionError("Expected a Developer ID Application identity for the configured team.")
    return profile


def read_toml(path):
    with path.open("rb") as stream:
        return tomllib.load(stream)


def load_user(path):
    data = table(read_toml(path), {"profiles"}, {"publishing_profiles"})
    if not isinstance(data["profiles"], dict):
        raise DistributionError("profiles must be a table.")
    for name, profile in data["profiles"].items():
        string(name, "profile name")
        validate_profile(profile)
    publishing_profiles = data.get("publishing_profiles", {})
    if not isinstance(publishing_profiles, dict):
        raise DistributionError("publishing_profiles must be a table.")
    for name, profile in publishing_profiles.items():
        string(name, "publishing profile name")
        validate_publishing_profile(profile)
    return data


def validate_publishing_profile(profile):
    from .publish import validate_config
    table(profile, {"api_key_ref", "token_env", "keychain_service", "keychain_account"})
    for key, value in profile.items():
        string(value, key)
    validate_config({"schema": 1,
                     "itch": {"target": "example/game", "channel": "MacOS", "api_key_ref": profile["api_key_ref"]},
                     "credentials": {k: profile[k] for k in ("token_env", "keychain_service", "keychain_account")},
                     "release": {"bundle_id": "com.example.game", "team_id": "AB12345678"}})
    return profile


def validate_entitlements(path):
    with path.open("rb") as stream:
        permissions = plistlib.load(stream)
    if not isinstance(permissions, dict):
        raise DistributionError("Entitlements must be a plist dictionary.")
    if permissions.get("com.apple.security.get-task-allow") or permissions.get("com.apple.security.app-sandbox"):
        raise DistributionError("Debug and App Sandbox entitlements are unsupported.")
    return path


@dataclass(frozen=True)
class Project:
    path: Path
    config: dict
    entitlements: Path
    runs_dir: Path
    publishing: dict | None = None


def load_project(path, user_path):
    path = path.expanduser().resolve(strict=True)
    data = table(read_toml(path), {"app", "signing", "output"}, {"publishing"})
    app = table(data["app"], {"bundle_id", "team_id"})
    signing = table(data["signing"], {"profile", "entitlements"})
    output = table(data["output"], {"runs_dir"})
    for section in (app, signing, output):
        for key, value in section.items():
            string(value, key)
    if not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", app["bundle_id"]):
        raise DistributionError("Expected a reverse-DNS bundle identifier.")
    user = load_user(user_path.expanduser())
    profiles = user["profiles"]
    if signing["profile"] not in profiles:
        raise DistributionError(f'Unknown local profile {signing["profile"]!r}; run macdist setup.')
    profile = profiles[signing["profile"]]
    if app["team_id"] != profile["team_id"]:
        raise DistributionError("Project requires a different Apple team; refusing to sign.")
    def relative(value):
        candidate = Path(value).expanduser()
        return (path.parent / candidate).resolve()
    entitlements = validate_entitlements(relative(signing["entitlements"]))
    publishing = None
    if "publishing" in data:
        from .publish import validate_config
        settings = table(data["publishing"], {"itch"})
        itch = table(settings["itch"], {"target", "channel", "profile"})
        for key, value in itch.items():
            string(value, key)
        local = user.get("publishing_profiles", {}).get(itch["profile"])
        if local is None:
            raise DistributionError("Unknown publishing profile; run macdist setup-publishing.")
        publishing = validate_config({
            "schema": 1,
            "itch": {"target": itch["target"], "channel": itch["channel"], "api_key_ref": local["api_key_ref"]},
            "credentials": {k: local[k] for k in ("token_env", "keychain_service", "keychain_account")},
            "release": {"bundle_id": app["bundle_id"], "team_id": app["team_id"]},
        })
    return Project(path, {"bundle_id": app["bundle_id"], **profile}, entitlements,
                   relative(output["runs_dir"]), publishing)
