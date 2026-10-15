"""Public command line. No implicit uploads, identity fallback, or build invocation."""

import argparse
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tomllib

from . import __version__, engine, publish
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
    command = commands.add_parser("setup-publishing", help="Configure nonsecret publishing references; never reads credentials")
    for name in ("profile", "api-key-ref", "keychain-service", "keychain-account", "token-env"):
        command.add_argument("--" + name)
    command.add_argument("--replace-profile", action="store_true")
    for name in ("dashboard", "publish", "publish-status", "pick-itch"):
        command = commands.add_parser(name)
        command.add_argument("--project", type=Path, default=Path("macdist.toml"))
        if name == "dashboard":
            command.add_argument("--port", type=int, default=8765, help="Loopback port; 0 chooses a free port")
        else:
            command.add_argument("--timeout", type=int, default=3600)
            if name in ("publish", "publish-status"):
                command.add_argument("--run", type=Path, required=True)
            if name == "publish":
                mode = command.add_mutually_exclusive_group(required=True)
                mode.add_argument("--dry-run", action="store_true", help="Read-only Butler file preview; accesses publishing credentials")
                mode.add_argument("--upload", action="store_true", help="Explicitly upload the verified ZIP")
            if name == "pick-itch":
                command.add_argument("--dry-run", action="store_true")
            if name in ("publish", "pick-itch"):
                command.add_argument("--retry-upload", action="store_true")
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
    root = parser()
    args = root.parse_args(argv)
    if args.command in ("publish", "publish-status", "pick-itch"):
        if not 1 <= args.timeout <= 14400:
            root.error("Timeout must be between 1 and 14400 seconds.")
        if getattr(args, "retry_upload", False) and getattr(args, "dry_run", False):
            root.error("--retry-upload cannot be combined with --dry-run.")
    if args.command == "dashboard" and not 0 <= args.port <= 65535:
        root.error("Port must be between 0 and 65535.")
    try:
        if args.command == "setup":
            setup(args)
            return 0
        if args.command == "setup-publishing":
            from .publishing_setup import setup_publishing
            return setup_publishing(args)
        if args.command in ("dashboard", "publish", "publish-status", "pick-itch"):
            project = load_project(args.project, args.user_config)
            if args.command == "dashboard":
                from .dashboard import serve
                return serve(project, args.port, project.publishing)
            if project.publishing is None:
                raise publish.PublishingError("No publishing destination configured for this project.")
            if args.command == "pick-itch":
                if not sys.stdin.isatty():
                    raise publish.PublishingError("The build picker requires an interactive Terminal; use publish --run for automation.")
                publish.interactive_publish(project.runs_dir, project.publishing, args.dry_run,
                                            args.retry_upload, args.timeout)
            else:
                mode = "status" if args.command == "publish-status" else "upload" if args.upload else "dry_run"
                publish.publish(args.run, project.publishing, mode, getattr(args, "retry_upload", False), args.timeout)
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
    except publish.PublishingError as error:
        print(f"Publishing stopped: {error}", file=sys.stderr)
        return 1
    except (engine.DistributionError, OSError, ValueError, TypeError, KeyError,
            plistlib.InvalidFileException, tomllib.TOMLDecodeError, subprocess.SubprocessError) as error:
        if args.command in ("publish", "publish-status", "pick-itch"):
            print("Publishing stopped. Inspect configuration and retained evidence; no retry or credential fallback attempted.", file=sys.stderr)
        else:
            print(f"STOP: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Stopped. Inspect run evidence before retrying an interrupted operation.", file=sys.stderr)
        return 130
