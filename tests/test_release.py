"""Offline release gates: no tags, credentials, network, or publication."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("release_tools", Path(__file__).resolve().parents[1] / "scripts/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        (self.root / "src/macdist").mkdir(parents=True)
        self.project = '[project]\nname = "macdist"\nversion = "1.2.3"\n'
        (self.root / "pyproject.toml").write_text(self.project)
        (self.root / "src/macdist/__init__.py").write_text('__version__ = "1.2.3"\n')
        (self.root / "CHANGELOG.md").write_text('# Changelog\n\n## 1.2.3 - 2026-10-23\n\n- New feature.\n\n## 1.2.2\n\n- Older feature.\n')
        self.wheel = self.dist / "macdist-1.2.3-py3-none-any.whl"
        self.sdist = self.dist / "macdist-1.2.3.tar.gz"

    def archives(self, missing_wheel=None, missing_sdist=None, extra_tar=None):
        with zipfile.ZipFile(self.wheel, "w") as archive:
            files = {"macdist/__init__.py": '__version__ = "1.2.3"\n',
                     "macdist/cli.py": "", "macdist/build_info.py": "", "macdist/butler_worker.py": "",
                     "macdist-1.2.3.dist-info/METADATA": "Name: macdist\nVersion: 1.2.3\n"}
            files.update({"macdist/" + asset: "fixture" for asset in release.ASSETS})
            for name, content in files.items():
                if name != missing_wheel:
                    archive.writestr(name, content)
        files = {"pyproject.toml": self.project, "src/macdist/__init__.py": '__version__ = "1.2.3"\n',
                 "LICENSE": "fixture", "README.md": "fixture", "CHANGELOG.md": "fixture", "SECURITY.md": "fixture",
                 "scripts/release.py": "fixture", "tests/test_release.py": "fixture", "tests/test_dashboard_ui.js": "fixture",
                 "tests/fixtures/publishing.json": "{}", "tests/fixtures/unity-mono.entitlements": "fixture"}
        files.update({"src/macdist/" + asset: "fixture" for asset in release.ASSETS})
        with tarfile.open(self.sdist, "w:gz") as archive:
            root = tarfile.TarInfo("macdist-1.2.3")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            for name, content in files.items():
                if name != missing_sdist:
                    data = content.encode()
                    member = tarfile.TarInfo("macdist-1.2.3/" + name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            if extra_tar:
                member = tarfile.TarInfo(extra_tar)
                archive.addfile(member, io.BytesIO(b""))

    def test_versions_and_notes_are_matched_without_old_entries(self):
        version, notes = release.candidate(self.root, "v1.2.3")
        self.assertEqual(version, "1.2.3")
        self.assertEqual(notes, "- New feature.")

    def test_wrong_tag_or_runtime_version_blocks_release(self):
        for tag in ("v1.2.4", "1.2.3", "v1.2.3-rc1", "v01.2.3", "main"):
            with self.assertRaises(release.ReleaseError):
                release.candidate(self.root, tag)
        (self.root / "src/macdist/__init__.py").write_text('__version__ = "1.2.4"')
        with self.assertRaises(release.ReleaseError):
            release.candidate(self.root, "v1.2.3")

    def test_unreleased_is_only_allowed_in_candidate_checks(self):
        path = self.root / "CHANGELOG.md"
        path.write_text("# Changelog\n\n## 1.2.3 (unreleased)\n\n- New feature.\n")
        self.assertEqual(release.candidate(self.root, allow_unreleased=True)[0], "1.2.3")
        with self.assertRaises(release.ReleaseError):
            release.candidate(self.root, "v1.2.3")
        self.archives()
        with self.assertRaises(release.ReleaseError):
            release.prepare(self.root, "v1.2.3", "a" * 40, self.dist)

    def test_missing_empty_duplicate_or_invalid_date_notes_block_release(self):
        path = self.root / "CHANGELOG.md"
        for content in ("## 1.2.2\n- Old", "## 1.2.3 - 2026-10-23\n", "## 1.2.3 - 2026-02-31\n- Bad date", "## 1.2.3 - 2026-10-23\n- One\n## 1.2.3 - 2026-10-23\n- Two"):
            path.write_text(content)
            with self.assertRaises(ValueError):
                release.candidate(self.root, "v1.2.3")

    def test_complete_archives_produce_checksums_and_commit_manifest(self):
        self.archives()
        manifest = release.prepare(self.root, "v1.2.3", "a" * 40, self.dist)
        self.assertEqual(manifest["commit"], "a" * 40)
        self.assertEqual(len(manifest["artifacts"]), 2)
        for line in (self.dist / "SHA256SUMS").read_text().splitlines():
            checksum, name = line.split("  ")
            self.assertEqual(checksum, hashlib.sha256((self.dist / name).read_bytes()).hexdigest())
        self.assertIn("- New feature.", (self.dist / "release-notes.md").read_text())
        self.assertNotIn("Older feature", (self.dist / "release-notes.md").read_text())
        self.assertEqual(json.loads((self.dist / "release.json").read_text()), manifest)
        with self.assertRaises(release.ReleaseError):
            release.prepare(self.root, "v1.2.3", "a" * 40, self.dist)  # Never overwrite a prepared bundle.

    def test_missing_assets_fixtures_or_release_tooling_are_rejected(self):
        for missing in ("macdist/dashboard.js", "macdist/butler_worker.py"):
            self.archives(missing_wheel=missing)
            with self.assertRaises(release.ReleaseError):
                release.check_archives(self.dist, "1.2.3")
        for missing in ("tests/fixtures/publishing.json", "scripts/release.py", "src/macdist/dashboard.html"):
            self.archives(missing_sdist=missing)
            with self.assertRaises(release.ReleaseError):
                release.check_archives(self.dist, "1.2.3")

    def test_unexpected_artifacts_or_unsafe_source_paths_block_release(self):
        self.archives(extra_tar="macdist-1.2.3/../outside")
        with self.assertRaises(release.ReleaseError):
            release.check_archives(self.dist, "1.2.3")
        self.archives()
        (self.dist / "unexpected.p12").write_bytes(b"fixture only")
        with self.assertRaises(release.ReleaseError):
            release.check_archives(self.dist, "1.2.3")

    def test_commit_must_be_full_hex_before_writing_metadata(self):
        self.archives()
        with self.assertRaises(release.ReleaseError):
            release.prepare(self.root, "v1.2.3", "main", self.dist)
        self.assertFalse((self.dist / "release.json").exists())


if __name__ == "__main__":
    unittest.main()
