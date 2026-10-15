# macdist contributor guidance

- Standalone Python 3.11+ CLI; standard-library runtime only.
- Keep machine configuration, credentials, app builds, and release artifacts out
  of this public repository. Examples and tests use fictional organizations.
- Tests must remain offline: no actual signing, Keychain writes, Apple calls, or
  uploads. Real release operations require explicit operator authorization.
- Preserve immutable submission evidence, inside-out signing, matched Apple
  acceptance, staged copies, and fail-closed recovery/cleanup behavior.
- Per-project entitlements must be explicit. Never introduce permissive defaults.
- Run: python -m unittest discover -s tests -v (with the package installed).
