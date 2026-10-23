# Releasing macdist

The package version for this release is **0.3.0**, with tag **v0.3.0**. The workflow
publishes a GitHub Release, not to PyPI. No Apple, signing, notarization, itch,
1Password, or user Keychain credentials are involved. All release tests are offline
with respect to those services.

## Release contract

- Only stable `vX.Y.Z` tags are supported initially; no abbreviated `v0.3` tags or
  prerelease suffixes. The tag must already exist and point to a commit reachable
  from `main`.
- `pyproject.toml` and `src/macdist/__init__.py` must agree on `X.Y.Z`.
- Finalize exactly one changelog section as `## X.Y.Z - YYYY-MM-DD`, with nonempty
  release notes. `X.Y.Z (unreleased)` is permitted for development checks only,
  never for publishing. Do not regenerate old release notes from Git history.
- Build the wheel and source archive in a fresh directory. Check metadata, runtime
  versions, packaged dashboard assets, docs, tests, fixtures, and release scripts.
  `twine check --strict` checks package metadata without uploading to PyPI.
- Test the built wheel and an isolated source-archive installation on Linux/macOS
  with Python 3.11/3.14; run the frontend checks too. Publication requires every
  matrix job to pass.
- The publishing job downloads only the verified bundle. It does not check out or
  execute package code. Only that job has `contents: write`; build/test jobs have
  read-only repository permissions and no persisted checkout credentials.
- Recheck remote tag identity and main ancestry before creating the release. Make
  a draft, upload all assets, then publish it. Never overwrite an existing release,
  replace its assets, move a released tag, or automatically recover a partial draft.

## Maintainer procedure

1. Update both version strings and the changelog in a reviewed branch. Ensure
   intended fixes are included; a version bump does not update existing installs.
2. Run local checks:

   ```sh
   .venv/bin/python scripts/release.py check --tag v0.3.0
   .venv/bin/python -m unittest discover -s tests -v
   node tests/test_dashboard_ui.js
   ```

3. Merge to `main`, push over HTTPS, and wait for the Tests workflow to succeed.
   Protect main and release tags through repository rules where appropriate.
   Workflow file changes pushed with GitHub CLI's OAuth token require its
   `workflow` scope in addition to repository access:

   ```sh
   gh auth refresh -h github.com -s workflow
   ```

   Do not work around missing HTTPS permissions by switching transport or embedding
   credentials in remote URLs. Creating/pushing a tag is an explicit publication
   action; do not use it as a workflow smoke test.
4. From clean, up-to-date main, create an annotated tag on the reviewed commit:

   ```sh
   git switch main
   git pull --ff-only origin main
   git status --short  # Must be clean.
   git tag -a v0.3.0 -m 'macdist 0.3.0'
   git push origin v0.3.0
   gh run list --workflow release.yml
   ```

   Use the appropriate new version for each subsequent release. Do not reuse a
   version or retag a prior release.
5. Watch the Release workflow, then inspect the published GitHub Release, its
   source commit manifest, asset checksums, and wheel/source-archive names.
   Ordinary Tests CI also runs release validation and packaging checks, but it
   cannot publish.

## Safe dry runs and recovery

`workflow_dispatch` accepts an **existing tag** and always builds/tests only,
regardless of who dispatches it. It never runs the publish job:

```sh
gh workflow run release.yml -f tag=v0.3.0
```

For an untagged development candidate, use
`python scripts/release.py check --allow-unreleased` and build archives locally;
`python scripts/release.py check-archives --dist /path/to/fresh/dist` validates them
without preparing publication metadata or contacting GitHub. Tests CI performs
these candidate packaging checks automatically.

A failed build/test cannot publish. A failure during asset upload or final release
publication may leave a draft. Inspect the workflow logs, tag identity, and draft
assets before deciding how to recover. Existing releases/drafts deliberately block
rerun publication. If a partial draft must be discarded, a maintainer must inspect
and explicitly remove it before rerunning; no automatic deletion is provided. CI
bundle artifacts may be regenerated on reruns, but published assets are never
clobbered. If the release was already published, do not retry publication; fix any
problem in a new version instead.

## Published assets and installation

Each GitHub Release includes:

- `macdist-X.Y.Z-py3-none-any.whl`
- `macdist-X.Y.Z.tar.gz`
- `release.json`: version, tag, full source commit, archive sizes and SHA-256 hashes
- `release-notes.md`: that version's changelog notes and source commit
- `SHA256SUMS`: checksums for the four files above

After downloading the assets into one directory:

```sh
shasum -a 256 -c SHA256SUMS
/path/to/venv/bin/python -m pip install --no-deps ./macdist-0.3.0-py3-none-any.whl
/path/to/venv/bin/macdist --version
/path/to/venv/bin/macdist build-info --output jsonl
```

A wheel installed from a downloaded file need not retain VCS provenance in pip's
metadata; `source_commit: null` is expected in that case. Match the archive's hash
to `release.json`/`SHA256SUMS` to associate it with the published source commit.
The manifest/checksums identify bytes; they are not an independent signature or
proof that application delivery has been verified. No package is published to
PyPI by this workflow; never assume a similarly named PyPI project is this code.
