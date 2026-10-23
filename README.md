# macdist

Explicit, resumable Developer ID signing and notarization for **plain macOS application bundles**, including Unity players. Build your app first; macdist stages a copy, signs it, submits it to Apple, staples the accepted ticket, and produces a verified ZIP. It never invokes Unity or changes your original build.

Includes a loopback-only monitoring dashboard and an explicit itch.io publishing adapter. No hosted service, certificate issuance, or automatic release uploads. Python 3.11+, macOS, and current selected Xcode command-line tools are required for real operations. The tool has no runtime Python dependencies.

## Install

Using an isolated tool installer:

```sh
pipx install 'git+https://github.com/aefreedman/macdist.git@v0.2.0'
# Or: uv tool install 'git+https://github.com/aefreedman/macdist.git@v0.2.0'
```

For a local checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/macdist --help
```

Pin a tag or commit in automation. This distribution name has not been published to PyPI; do not assume `pip install macdist` installs this project.

## Configuration boundaries

1. **Tool repository:** reusable implementation and offline tests; no machine configuration or credentials.
2. **Game repository:** `macdist.toml` with expected bundle ID, required Apple team, local profile name, reviewed entitlements, and output directory.
3. **User/machine:** `~/.config/macdist/config.toml` (or `$XDG_CONFIG_HOME/macdist/config.toml`) maps profile names to signing identities and Keychain credential profile names. `--user-config PATH`, before the subcommand, selects another file.
4. **Secrets:** certificate private keys and notarization credentials stay in Keychain. CI must provision an isolated Keychain itself; a dedicated CI credential bootstrap is not implemented yet.

Team IDs and identity names are not secrets. The project-required team prevents a local configuration from silently changing the release organization. There is no identity fallback. Different users can map the same logical profile to their own certificates and credential profile names for that team.

## 1. Install a signing identity

You need **Developer ID Application**, not Apple Development or Apple Distribution. Either import an existing password-protected `.p12` containing the certificate **and private key**, or use Keychain Access to create a CSR on this Mac and have the Apple Developer Account Holder issue a Developer ID Application certificate. Install the resulting `.cer` on the Mac holding the matching private key.

```sh
security find-identity -v -p codesigning
```

The exact organization identity must appear among valid identities. Developer ID Installer is only for `.pkg` installers, which this initial tool does not support. Back up private keys securely; never commit certificate exports or keys.

See [Apple's certificate instructions](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/).

## 2. Configure this machine

```sh
macdist setup
```

Select a valid identity, name the local profile, and choose the notarization Keychain profile. Setup writes a mode-0600 nonsecret configuration; replacing an existing profile requires `--replace-profile`. It prints the credential command but **does not contact Apple by default**.

To launch Apple's interactive secure credential prompt as part of setup:

```sh
macdist setup --store-credentials
```

Enter your Apple Account and an [app-specific password](https://support.apple.com/en-us/102654) into Apple's prompt in Terminal, never into chat, source files, or command arguments. macdist does not capture the credential prompt. Follow Apple's prompts for your supported authentication method; existing API-key-backed Keychain profiles can also be referenced.

Noninteractive profile configuration (does not install certificates or store credentials):

```sh
macdist setup --profile example \
  --identity 'Developer ID Application: Example Corporation (AB12345678)' \
  --keychain-profile example-notary
```

See `examples/user-config.toml`. Setup validates the identity/private key but does not prove notarization authentication unless you explicitly store/validate credentials. Profile writing is intended for one local operator at a time.

## 3. Configure each game

Copy `examples/macdist.toml` into the game repository:

```toml
[app]
bundle_id = "com.example.game"
team_id = "AB12345678"

[signing]
profile = "example"
entitlements = "distribution/macos.entitlements"

[output]
runs_dir = "Releases/macos"
```

Entitlement and output paths resolve relative to the project file, **not** the tool installation or current working directory. Absolute paths are supported but are discouraged in committed project files. The `--app` and explicit `--run` CLI paths are relative to your current directory. Add the generated output directory to your game's ignore rules.

**Entitlements must be deliberately reviewed and supplied.** There is no default Unity policy. `examples/empty.entitlements` is a starting point only for apps needing no runtime exceptions; it is not a working recipe for every Unity version/backend. Mono, IL2CPP, native plugins, helpers, and Unity upgrades require review. The Mono entitlement file under `tests/fixtures/` is solely a test fixture, not a recommended release policy.

This initial workflow rejects App Sandbox and debug `get-task-allow`. It is not suitable for independent helper entitlement policies, app extensions, restricted capabilities requiring profiles, arbitrary installers, or App Store releases.

## 4. Inspect before uploading

```sh
macdist doctor --project /path/to/game/macdist.toml
macdist doctor --project /path/to/game/macdist.toml --check-credentials
macdist preflight --project /path/to/game/macdist.toml --app /path/to/Game.app
```

`doctor` validates configuration, entitlement format, Xcode tools, and exactly one valid matching signing identity. With `--app`, it inspects the build too. `--check-credentials` makes an explicit **read-only** notarization-history request to Apple. Offline checks do not prove authentication, runtime compatibility, or successful notarization.

## 5. Sign, notarize, and package

Sign a staged copy and create the submission ZIP **without uploading**:

```sh
macdist prepare --project /path/to/game/macdist.toml \
  --app /path/to/Game.app --name release-001
```

Or explicitly perform the whole workflow, including upload to Apple:

```sh
macdist distribute --project /path/to/game/macdist.toml \
  --app /path/to/Game.app --name release-002 --progress
```

`--name` creates a new run under the configured output directory. Alternatively, supply `--run /explicit/new/run`. Every new run requires a nonexistent directory. Budget peak storage for several app copies and two ZIPs. Successful packaging removes working copies by default; `--keep-working-artifacts` retains them for diagnosis.

Only ship `final/Game-macos.zip` from a **packaged** run. Never ship `submission.zip`: it predates stapling. The final ZIP checksum, resolved nonsecret signing configuration, tool version, entitlement snapshot, submission ID, and Apple evidence are retained with the run. Logs and run state contain local paths and release metadata; they are not intended for public source control.

## Agent-managed and automated output

Output is a presentation layer, independent of the workflow and its safety checks:

- `--output auto` (default): updating progress lines for a TTY, compact plain lines
  for redirected/captured stdout. Raw PTY redraws are never forwarded to captured output.
- `--output human`: explicit terminal rendering.
- `--output plain`: compact lines without ANSI escapes or carriage returns.
- `--output jsonl`: one schema-versioned JSON object per line on stdout. No raw
  command output or terminal decoration is mixed into this stream.

The option works before or after the subcommand. Help/version and initial argparse
usage errors retain normal CLI behavior. JSONL is supported for noninteractive
workflow commands, doctor/preflight, inspection, and explicit publishing.
Interactive setup, the picker, and the long-running dashboard reject JSONL
**before** prompting, accessing credentials, or dispatching work. Output mode
never bypasses confirmations, enables retries, changes authentication, or chooses
an upload target.

For an explicitly authorized release:

```sh
macdist distribute --project /path/to/game/macdist.toml \
  --app /path/to/Game.app --name release-003 --progress --output jsonl
```

`--progress` is still explicit. It enables Apple's existing PTY-based progress
collection, not another upload attempt. Full command evidence and raw Apple
transcripts remain in the run's logs; publishing logs retain their existing
credential redaction. Console progress is coalesced: duplicate/regressing
percentages are dropped, updates are at least one second apart and normally at
least five points or ten seconds apart, and a reported 100% is emitted immediately.
Only percentages actually reported by the tool are displayed. Apple processing
is a named waiting stage, **not** a simulated percentage or inferred completion.

Example events (timestamps, sequence numbers, and paths abbreviated):

```json
{"schema":1,"event":"upload.started","run":"/releases/release-003"}
{"schema":1,"event":"upload.progress","percent":25}
{"schema":1,"event":"submission.recorded","submission_id":"…"}
{"schema":1,"event":"notarization.waiting","submission_id":"…"}
{"schema":1,"event":"package.ready","archive":"…","sha256":"…"}
{"schema":1,"event":"workflow.result","status":"succeeded","exit_code":0,"ready":true}
```

Every event has `schema`, `event`, a per-invocation monotonic `sequence`, UTC
`timestamp`, and `run` (null before a run is known). Other fields are event-specific.
Human-readable `message` text is not a parsing contract. Handled errors produce
`workflow.error` and a final `workflow.result`; argument validation may also
write conventional diagnostics to stderr. Do not parse raw child-process logs
to make workflow decisions.

The final result distinguishes requested-operation success, Apple `pending`
(exit 2), failure, interruption, and an `uncertain` recorded upload attempt.
It includes known stage/submission/artifact/receipt/evidence paths.
A successful `submit` or `prepare` is **not** a ready release. `ready: true`
is emitted only when this invocation observes the packaging verification path;
other commands do not establish readiness. Publishing reports
`delivery_verified: false` even after a successful Butler exit.
A killed process may leave no final event: inspect persisted evidence and never
infer permission to retry from a missing event.

### Bounded local monitoring

```sh
macdist inspect --run /path/to/run --output jsonl
# Unlike inspect, status explicitly contacts Apple:
macdist status --run /path/to/run --output jsonl
```

`inspect` reads only local allowlisted metadata and at most the last 64 KiB of
upload progress. It never contacts Apple/Keychain/Butler, acquires an operation
lock, changes state, hashes a multi-gigabyte archive, signs, submits, or retries.
It returns the recorded stage and submission ID, historical last upload percentage,
lock presence, expected artifact presence, publishing summary, and evidence paths.
Unknown metadata fields and raw log contents are not returned. Oversized metadata
and symlinked artifacts are rejected.

Snapshots are best-effort across atomically updated files, not a transaction
with a running operation. A lock may be stale and an old percentage is not proof
the upload is still active. Artifact `checksum_verified: false` is explicit:
presence and recorded packaging state alone do not reverify the ZIP. Use the
existing verification/recovery workflow rather than editing state or automatically
resubmitting. Agents can poll this small snapshot instead of tailing terminal
transcripts; `resume --wait` remains an explicit operation on the existing ID.

## Recovery

A prepared run can be uploaded and resumed separately:

```sh
macdist submit --run /path/to/run --progress
macdist status --run /path/to/run
macdist resume --run /path/to/run --wait
```

Recovery uses the configuration captured in that run, not today's project or local profile configuration. Its referenced Keychain profile must remain available. Do not edit run evidence to migrate credentials or fake success.

- Exit **0** means the requested operation succeeded; `prepare`/`submit` success does not mean a shipping ZIP is ready.
- Exit **2** means Apple is still processing.
- Exit **1** means failed/uncertain; inspect evidence.
- Exit **130** means interrupted; inspect the run before further operations.

A submission attempt is recorded **before dispatch**. Failed/lost upload responses cannot be blindly replayed. Locate the original submission in Apple's history, then deliberately associate its ID:

```sh
macdist reconcile --run /path/to/run --submission-id ORIGINAL_UUID
macdist resume --run /path/to/run --wait
```

Apple's Accepted log must match both the submission UUID and uploaded archive SHA-256 before packaging. `resume --wait` waits on the existing ID; it never uploads again. There is no automatic retry or backend fallback. Preserve partial final output for investigation; it is not overwritten automatically.

An operation lock blocks concurrent run mutations. After a crash, inspect the PID, logs, and state before manually removing a stale lock. Never remove a live process's lock. Avoid concurrent local configuration edits.

```sh
macdist cleanup --run /path/to/completed/run
# Add --keep-app to retain the final unpacked app.
```

Cleanup revalidates final archive and Accepted evidence, removes only known working artifacts, and preserves the original app, final ZIP, metadata, logs, and unknown files. A failed cleanup can be deliberately resumed after inspection.

## Local dashboard

```sh
macdist dashboard --project /path/to/game/macdist.toml
# --port 0 chooses a free port; default is 8765.
```

Open the printed loopback URL. Only immediate children of that project's configured output directory are inspected. The dashboard works without publishing configuration or `op`/Butler installed.

- Local metadata/log tails refresh every three seconds. Apple queries occur only on an explicit **Refresh Apple** action, are read-only, throttled/coalesced, and never change run state.
- **Accepted is not Ready.** ZIP actions require packaged state and the expected archive. Reveal rechecks its SHA-256 before invoking Finder. The dashboard does not serve archive downloads.
- Publishing status comes from local allowlisted receipts only; the dashboard never retrieves publishing secrets, invokes Butler, or uploads. A successful Butler exit is not proof of remote delivery/playability.
- It binds only `127.0.0.1`, rejects unexpected Host/cross-origin requests, requires a per-process session token for APIs, serves only fixed assets, and renders run data as text rather than HTML.
- There are **no signing, submission, packaging, retry, or publishing buttons**. The only POST actions are read-only Apple refresh and checksum-checked Finder reveal.

This is a local single-user utility. Do not expose it through tunnels, proxies, public interfaces, or a shared hosted service. Foreign project/team evidence and symlinked artifact paths are rejected. Closing the server clears its in-memory Apple cache, not the evidence on disk.

## Optional itch.io publishing

Publishing is separate from notarization and never runs automatically. Install [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) and [itch Butler](https://itch.io/docs/butler/) on PATH. The initial adapter deliberately retains the dedicated 1Password service-account boundary, rather than borrowing personal `op` or Butler sessions. No raw Butler-key option or personal-login fallback is supported.

### Machine configuration

```sh
macdist setup-publishing
```

The wizard asks only for **nonsecret references**. It does not read or validate credentials. Alternatively:

```sh
macdist setup-publishing --profile example-itch \
  --api-key-ref 'op://publishing-vault/itch/credential' \
  --keychain-service example-publishing-token \
  --keychain-account example-publisher
```

Create a generic-password item through Keychain Access with that service/item name and account; the password is the **raw publishing-only 1Password service-account token**, not the Butler API key and not an `op://` reference. Restrict the service account to read-only access to a dedicated publishing vault. Do not put raw tokens in terminal commands, chat, shell profiles, or source files.

For CI, the default input is `MACDIST_PUBLISHING_OP_SERVICE_ACCOUNT_TOKEN` from the CI secret store. `--token-env MACDIST_GAME_OP_SERVICE_ACCOUNT_TOKEN` gives a local publishing profile a distinct input variable. Only `MACDIST_*OP_SERVICE_ACCOUNT_TOKEN` names are accepted. If the configured variable is present but empty/invalid, the command fails; it does not fall back to Keychain.

`setup-publishing` stores this outside game/tool repositories:

```toml
[publishing_profiles.example-itch]
api_key_ref = "op://publishing-vault/itch/credential"
token_env = "MACDIST_PUBLISHING_OP_SERVICE_ACCOUNT_TOKEN"
keychain_service = "example-publishing-token"
keychain_account = "example-publisher"
```

The existing signing and publishing profiles are preserved; replacement requires `--replace-profile`.

### Project destination

Opt in by adding this to the game's `macdist.toml`:

```toml
[publishing.itch]
target = "example/game"
channel = "MacOS"
profile = "example-itch"
```

The target and case-sensitive channel are project-owned and have no CLI override. Secret references and Keychain identifiers stay machine-local. See `examples/publishing-project.toml` and `examples/user-config.toml`. Configured publishing profiles must exist even when opening that project's dashboard, but no credentials are retrieved by the dashboard.

### Preview, select, upload, inspect

```sh
# Read-only Butler file preview. Accesses publishing credentials; never uploads.
macdist publish --project /path/to/game/macdist.toml --run /path/to/run --dry-run

# Explicit automation-friendly upload; may become available immediately on itch.
macdist publish --project /path/to/game/macdist.toml --run /path/to/run --upload

# Interactive selection, exact destination/hash/version display, then [y/N] confirmation.
macdist pick-itch --project /path/to/game/macdist.toml
macdist pick-itch --project /path/to/game/macdist.toml --dry-run

# Read-only remote channel snapshot, not per-attempt reconciliation.
macdist publish-status --project /path/to/game/macdist.toml --run /path/to/run
```

Omitting a publishing mode never uploads. The picker requires selection even with one build; Enter, `0`, EOF, and default-No cancel before credential access. There is no implicit latest-build choice or confirmation bypass. It filters builds by the project's bundle ID and release team, then rechecks the confirmed artifact/version under the same operation lock used by notarization and cleanup.

Uploads require a packaged, unchanged final ZIP, recorded build version, and matching Accepted Apple UUID/archive-hash evidence. The existing run's original app, ZIP, and notarization state remain unchanged. Butler receives the versioned ZIP directly, without permission-fixing, link-dereferencing, visibility/access, or ignore overrides. A second checksum check catches input changes during execution.

Each attempt has an immutable-ID receipt/log under `publishing/itch/`. A summary blocks repeat uploads even after a dry run or status check. `--retry-upload` is required after inspecting a previous attempt; it does not bypass evidence checks. Changing a run's recorded publishing destination is rejected even with that flag. Lost responses, nonzero exits, timeouts, and interruptions remain **uncertain**, never automatically retried. `uploaded` means Butler exited successfully; `delivery_verified` stays false and remote build IDs are not guessed from human-readable output.

The subprocess chain is environment-allowlisted: only the dedicated token and configured Butler reference reach `op run`. An isolated Python worker gives Butler only its resolved API key, disables Butler's saved identity with `--identity /dev/null`, and redacts known credentials before output reaches logs. Personal `OP_SESSION_*`, Connect settings, generic service-account tokens, unrelated references, and normal Butler login are not inherited. Errors never trigger another credential source or login. Credential-bearing processes and descendants are terminated on timeout/interruption.

Download through itch on a separate Mac/user account and verify extraction, Gatekeeper, launch, and gameplay without overrides. Test itch-app install/update separately if you intend to support it. Existing itch visibility/access restrictions determine availability; macdist never changes them.

## Verification and limitations

Code is discovered as Mach-O, signed leaves-first and nested bundles next, then the outer app last. `--deep` is used for verification, **not signing**. Signing enables hardened runtime and secure timestamps. Entitlements are applied to main executables and app/XPC bundles, not every dylib. Each architecture is checked; the final archive is extracted and checked again for signatures, staple, and Gatekeeper acceptance.

Notarization is not a playtest. Download the final ZIP through a browser on another Mac/user account, extract and launch without Gatekeeper overrides, and test architectures, permissions, native plugins, startup, and gameplay. Do not bypass Gatekeeper or strip quarantine as a release fix.

Treat source apps, project files, and run directories as trusted local inputs. Run only as your normal user, never root. This is not a sandbox or a multi-user service. See [SECURITY.md](SECURITY.md).

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Tests use mocks, local subprocess fixtures, and temporary loopback HTTP servers: no real signing, Keychain mutation, Apple requests, or uploads. Run `node tests/test_dashboard_ui.js` for the dependency-free frontend regression checks (Node.js 22+ is a development dependency only). CI tests Python 3.11 and 3.14 on Linux and macOS. A real app signing/notarization smoke test is still required before adopting a release for production.

The engine, dashboard, publishing adapter, and safety tests were extracted from owner-authorized project-local Unity distribution tooling, without importing its project history, credentials, machine-specific configuration, or release artifacts. Examples use fictional destinations; no publishing destination is enabled by default.

References: [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution), [Unity macOS signing](https://docs.unity3d.com/6000.5/Documentation/Manual/macoscodesigning.html). Review documentation for your actual Unity version, not just the linked example.
