"""Public command line. No implicit uploads, identity fallback, or build invocation."""

import argparse
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tomllib

from . import __version__, engine
from .config import load_project, user_config_path
from .setup import identities, setup


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--user-config", type=Path, default=user_config_path())
    commands = root.add_subparsers(dest="command", required=True)
    command = commands.add_parser("setup", help="Configure a machine-local signing profile")
    command.add_argument("--profile")
    command.add_argument("--identity", help="Exact Developer ID Application certificate name")
    command.add_argument("--keychain-profile")
    command.add_argument("--replace-profile", action="store_true")
    command.add_argument("--store-credentials", action="store_true", help="Launch Apple's interactive secure credential prompt")
    for name in ("doctor", "preflight", "prepare", "distribute"):
        command = commands.add_parser(name)
        command.add_argument("--project", type=Path, default=Path("macdist.toml"))
        command.add_argument("--app", type=Path, required=name != "doctor")
        if name in ("doctor", "preflight"):
            command.add_argument("--check-credentials", action="store_true", help="Read-only request to Apple")
        else:
            output = command.add_mutually_exclusive_group(required=True)
            output.add_argument("--run", type=Path, help="Explicit new run path, relative to current directory")
            output.add_argument("--name", help="New run name beneath project's output.runs_dir")
            if name == "distribute":
                command.add_argument("--progress", action="store_true")
                command.add_argument("--keep-working-artifacts", action="store_true")
    for name in ("submit", "status", "resume", "package", "reconcile", "cleanup"):
        command = commands.add_parser(name)
        command.add_argument("--run", required=True, type=Path)
        if name == "submit":
            command.add_argument("--progress", action="store_true")
        if name in ("resume", "package"):
            command.add_argument("--keep-working-artifacts", action="store_true")
        if name == "resume":
            command.add_argument("--wait", action="store_true")
        if name == "reconcile":
            command.add_argument("--submission-id", required=True)
        if name == "cleanup":
            command.add_argument("--keep-app", action="store_true")
    return root


def doctor(project, args):
    if sys.platform != "darwin":
        raise engine.DistributionError("Signing and notarization require macOS.")
    runner = engine.Runner()
    for tool in ("notarytool", "stapler"):
        runner.run(["/usr/bin/xcrun", "--find", tool])
    matches = [fingerprint for fingerprint, label in identities() if label == project.config["signing_identity"]]
    if len(matches) != 1:
        raise engine.DistributionError("Expected exactly one valid matching certificate/private key in Keychain.")
    if args.app:
        report = engine.preflight(args.app.expanduser(), project.config, runner, args.check_credentials)
    else:
        if args.check_credentials:
            runner.json(["/usr/bin/xcrun", "notarytool", "history", "--keychain-profile",
                         project.config["keychain_profile"], "--output-format", "json"], timeout=60)
        report = {"identity_sha1": matches[0], "credentials_checked": args.check_credentials}
    print(json.dumps({"project": str(project.path), "config": project.config,
                      "entitlements": str(project.entitlements), **report}, indent=2))
    if not args.check_credentials:
        print("Notarization credentials were NOT checked; add --check-credentials to contact Apple.")
    return 0


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "setup":
            setup(args)
            return 0
        config = None
        if args.command in ("doctor", "preflight", "prepare", "distribute"):
            project = load_project(args.project, args.user_config)
            config = project.config
            if args.command == "doctor":
                return doctor(project, args)
            args.entitlements = project.entitlements
            if args.command in ("prepare", "distribute") and args.name is not None:
                if not args.name.strip() or any(ord(c) < 32 for c in args.name) or args.name in (".", "..") or Path(args.name).name != args.name or "\\" in args.name:
                    raise engine.DistributionError("Run name must be a single directory name.")
                args.run = project.runs_dir / args.name
        return engine.execute(args, config)
    except (engine.DistributionError, OSError, ValueError, TypeError, KeyError,
            plistlib.InvalidFileException, tomllib.TOMLDecodeError, subprocess.SubprocessError) as error:
        print(f"STOP: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Stopped. Inspect run evidence before retrying an interrupted operation.", file=sys.stderr)
        return 130
