#!/usr/bin/env python3
"""Offline release gates and manifests. Never create tags or publish anything."""

import argparse
import ast
from datetime import date
from email.parser import Parser
import hashlib
import json
from pathlib import Path
import re
import tarfile
import tomllib
import zipfile

VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
ASSETS = ("dashboard.html", "dashboard.js", "dashboard.css")


class ReleaseError(ValueError):
    pass


def runtime_version(source):
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise ReleaseError("Missing literal runtime version.")


def candidate(root, tag=None, allow_unreleased=False):
    with (root / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    version = project["version"]
    if project["name"] != "macdist" or not re.fullmatch(VERSION, version):
        raise ReleaseError("Release requires macdist and a stable X.Y.Z version.")
    if runtime_version((root / "src/macdist/__init__.py").read_text()) != version:
        raise ReleaseError("Package and runtime versions disagree.")
    if tag is not None and tag != "v" + version:
        raise ReleaseError("Tag must exactly match v<package version>.")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    sections = list(re.finditer(r"^## (.+)$", changelog, re.MULTILINE))
    matches = []
    for index, heading in enumerate(sections):
        title = heading[1].strip()
        if title == version or title.startswith(version + " "):
            end = sections[index + 1].start() if index + 1 < len(sections) else len(changelog)
            matches.append((title, changelog[heading.end():end].strip()))
    if len(matches) != 1:
        raise ReleaseError("Changelog must have exactly one section for the version.")
    title, notes = matches[0]
    if title == version + " (unreleased)" and allow_unreleased:
        pass
    else:
        match = re.fullmatch(re.escape(version) + r" - (\d{4}-\d{2}-\d{2})", title)
        if not match:
            raise ReleaseError("Finalize the changelog heading as '## X.Y.Z - YYYY-MM-DD' before tagging.")
        date.fromisoformat(match[1])
    if not notes or not any(line.startswith("- ") for line in notes.splitlines()):
        raise ReleaseError("Release notes must contain changelog entries.")
    return version, notes


def check_archives(dist, version):
    wheel = dist / f"macdist-{version}-py3-none-any.whl"
    sdist = dist / f"macdist-{version}.tar.gz"
    if sorted(p.name for p in dist.iterdir()) != sorted([wheel.name, sdist.name]):
        raise ReleaseError("Expected exactly the matching wheel and source archive in a fresh dist directory.")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ReleaseError("Wheel has duplicate entries.")
        required = ["macdist/__init__.py", "macdist/cli.py", "macdist/build_info.py", "macdist/butler_worker.py",
                    *("macdist/" + asset for asset in ASSETS)]
        if not set(required) <= set(names):
            raise ReleaseError("Wheel is missing runtime files or dashboard assets.")
        metadata = Parser().parsestr(archive.read(f"macdist-{version}.dist-info/METADATA").decode())
        if metadata["Name"] != "macdist" or metadata["Version"] != version:
            raise ReleaseError("Wheel metadata disagrees with the release.")
        if runtime_version(archive.read("macdist/__init__.py").decode()) != version:
            raise ReleaseError("Wheel runtime version disagrees with the release.")
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        prefix = f"macdist-{version}/"
        names = set()
        for member in members:
            if member.name == prefix.rstrip("/") and member.isdir():
                continue
            if not member.name.startswith(prefix) or ".." in Path(member.name).parts or not (member.isfile() or member.isdir()):
                raise ReleaseError("Source archive has an unsafe path or unsupported entry.")
            if member.name in names:
                raise ReleaseError("Source archive has duplicate entries.")
            names.add(member.name)
        required = {"pyproject.toml", "LICENSE", "README.md", "CHANGELOG.md", "SECURITY.md", "src/macdist/__init__.py",
                    "scripts/release.py", "tests/test_release.py", "tests/test_dashboard_ui.js",
                    "tests/fixtures/publishing.json", "tests/fixtures/unity-mono.entitlements",
                    *("src/macdist/" + asset for asset in ASSETS)}
        if not {prefix + name for name in required} <= names:
            raise ReleaseError("Source archive is missing docs, tests, fixtures, release tooling, or assets.")
        stream = archive.extractfile(prefix + "pyproject.toml")
        project = tomllib.loads(stream.read().decode())["project"]
        if project["name"] != "macdist" or project["version"] != version:
            raise ReleaseError("Source archive metadata disagrees with the release.")
        stream = archive.extractfile(prefix + "src/macdist/__init__.py")
        if runtime_version(stream.read().decode()) != version:
            raise ReleaseError("Source archive runtime version disagrees with the release.")
    return wheel, sdist


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(root, tag, commit, dist):
    version, notes = candidate(root, tag)
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ReleaseError("Expected the full validated Git commit SHA.")
    archives = check_archives(dist, version)
    manifest = {"schema": 1, "project": "macdist", "version": version, "tag": tag, "commit": commit,
                "artifacts": [{"name": p.name, "bytes": p.stat().st_size, "sha256": digest(p)} for p in archives]}
    (dist / "release.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (dist / "release-notes.md").write_text(f"# macdist {version}\n\n{notes}\n\nSource commit: `{commit}`\n", encoding="utf-8")
    files = sorted(dist.iterdir(), key=lambda p: p.name)
    (dist / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in files), encoding="utf-8")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--tag")
    check.add_argument("--allow-unreleased", action="store_true")
    archives = commands.add_parser("check-archives")
    archives.add_argument("--dist", type=Path, default=Path("dist"))
    release = commands.add_parser("prepare")
    release.add_argument("--tag", required=True)
    release.add_argument("--commit", required=True)
    release.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            version, _ = candidate(args.root, args.tag, args.allow_unreleased)
            print(version)
        elif args.command == "check-archives":
            version, _ = candidate(args.root, allow_unreleased=True)
            check_archives(args.dist, version)
            print(f"Validated wheel and source archive for {version}")
        else:
            print(json.dumps(prepare(args.root, args.tag, args.commit, args.dist), indent=2))
        return 0
    except (ReleaseError, OSError, ValueError, KeyError, SyntaxError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, f"Release validation failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
