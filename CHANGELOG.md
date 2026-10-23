# Changelog

## Unreleased

- Add `--output auto|human|plain|jsonl` before or after workflow subcommands.
  Auto retains terminal progress rendering while captured output uses compact,
  control-character-free lines; JSONL provides schema-versioned events with
  timestamps, sequence numbers, run paths, and structured final results.
- Throttle Apple and publishing progress, preserve submission IDs before emitting
  their events, and identify Apple processing as a waiting stage without inventing
  percentages. Distinguish operation success, pending, failure, interruption, and
  uncertain upload attempts; none of these presentation changes enable retries.
- Keep raw Apple transcripts, redacted publishing logs, and command evidence on
  disk instead of forwarding verbose terminal output to agents.
- Add `inspect --run PATH --output jsonl` for bounded, read-only local snapshots
  of recorded state, historical progress, lock presence, artifact presence, and
  evidence paths. Inspection never contacts services, takes a lock, or claims an
  archive checksum was reverified.
- Reject JSONL for interactive setup, the build picker, and the dashboard before
  dispatch. Preserve upload authorization, credential isolation, confirmation,
  evidence verification, and retry guards; no Pi-specific dependencies.
- Add output, inspection, and safety regressions: 154 Python tests plus frontend
  checks pass locally, from an installed wheel, and in macOS/Linux CI.

## 0.2.0

- Port the existing owner-authorized local dashboard, itch adapter, credential
  isolation worker, interactive build picker, and regression tests.
- Package static dashboard assets for normal wheel installs.
- Separate optional project publishing destinations from user-local credential
  references; add reference-only setup-publishing.
- Enforce project bundle/team boundaries for publishing and dashboard operations.
- Keep publishing explicit and CLI-only; preserve confirmation, immutable
  notarization evidence, per-run locks, no credential fallback, and uncertain
  upload/retry handling. Reject retargeting an existing publishing run.

## 0.1.0

- Extract the signing/notarization engine with project and user-local profiles,
  setup/doctor, explicit entitlements, resumable evidence, and offline tests.
