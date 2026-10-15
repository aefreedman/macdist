# Changelog

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
