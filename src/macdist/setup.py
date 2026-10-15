"""Interactive local identity selection; credentials are entered only into notarytool."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from .config import load_user, validate_profile
from .engine import DistributionError


def identities():
    result = subprocess.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
                            capture_output=True, text=True, check=True, timeout=30)
    return re.findall(r'\b([A-Fa-f0-9]{40})\s+"(Developer ID Application:[^"\n]+)"', result.stdout)


def save_profile(path, name, profile, replace=False):
    validate_profile(profile)
    data = load_user(path) if path.exists() else {"profiles": {}}
    if name in data["profiles"] and not replace:
        raise DistributionError("Profile exists; use --replace-profile deliberately to replace it.")
    data["profiles"][name] = profile
    # JSON quoted basic strings are valid TOML for the supported single-line fields.
    lines = ["# Nonsecret machine-local configuration. Credentials live in Keychain.\n"]
    for key, values in data["profiles"].items():
        lines.append(f"[profiles.{json.dumps(key, ensure_ascii=False)}]")
        lines.extend(f"{k} = {json.dumps(v, ensure_ascii=False)}" for k, v in values.items())
        lines.append("")
    for directory in (path.parent, *path.parent.parents):
        if directory.is_symlink():
            raise DistributionError("Refusing symlinked configuration directory.")
    if path.is_symlink():
        raise DistributionError("Refusing symlinked configuration file.")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix="config-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines))
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def setup(args):
    if sys.platform != "darwin":
        raise DistributionError("Setup requires macOS.")
    available = identities()
    if not available:
        raise DistributionError("No valid Developer ID Application identity/private key found. See certificate setup in README.")
    name = args.profile
    identity = args.identity
    keychain = args.keychain_profile
    if not name or not identity or not keychain:
        if not sys.stdin.isatty():
            raise DistributionError("Noninteractive setup requires --profile, --identity and --keychain-profile.")
        name = name or input("Local profile name: ").strip()
        if not identity:
            for index, (fingerprint, label) in enumerate(available, 1):
                print(f"{index}. {label} [{fingerprint}]")
            selection = input("Identity number: ").strip()
            if not selection.isdigit() or not 1 <= int(selection) <= len(available):
                raise DistributionError("Invalid selection.")
            identity = available[int(selection) - 1][1]
        keychain = keychain or input(f"Notary Keychain profile [{name}-notary]: ").strip() or f"{name}-notary"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise DistributionError("Profile name may contain only letters, digits, underscores and hyphens.")
    if sum(label == identity for _, label in available) != 1:
        raise DistributionError("Expected exactly one matching valid signing identity.")
    match = re.search(r"\(([A-Z0-9]{10})\)$", identity)
    if not match:
        raise DistributionError("Could not derive identity's Apple Team ID.")
    profile = {"team_id": match[1], "signing_identity": identity, "keychain_profile": keychain}
    save_profile(args.user_config.expanduser().absolute(), name, profile, args.replace_profile)
    print(f"Saved profile {name!r} to {args.user_config} (no credentials stored in this file).")
    command = ["/usr/bin/xcrun", "notarytool", "store-credentials", keychain, "--team-id", match[1]]
    if args.store_credentials:
        if not sys.stdin.isatty():
            raise DistributionError("Run --store-credentials from an interactive Terminal.")
        # Inherit the terminal: macdist never reads, captures, or logs passwords.
        subprocess.run(command, check=True)
    else:
        import shlex
        print("Credentials have NOT been validated. Run interactively:\n" + shlex.join(command))
