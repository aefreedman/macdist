# Security

Do not include passwords, private keys, certificate exports, or raw release logs
in issues or pull requests. For a suspected vulnerability, use GitHub's private
vulnerability reporting when available rather than posting exploit details
publicly. No response-time guarantee is offered for this initial release.

## Boundaries

- Run as an ordinary local user, never root. Source applications, project
  configuration, and run directories must be trusted. Configuration selects code
  that will be signed using your organization's authority.
- Local profiles contain only nonsecret team/identity/Keychain profile names.
  macdist never accepts raw passwords as CLI options or reads password values.
  Apple's interactive notarytool owns credential entry and Keychain storage.
- Preserve and restrict access to release evidence. It includes local filesystem
  paths, signed app metadata, hashes, and Apple submission reports.
- macdist is not a sandbox and does not defend against a hostile process running
  as the same user. Directory validation does not eliminate filesystem races.
- No automatic submission retry, credential fallback, key export, Keychain ACL
  changes, quarantine removal, or Gatekeeper bypass is performed.
- Notarization and local Gatekeeper acceptance do not establish application
  safety or runtime compatibility. Perform an independent download/launch test.
- CI credentials and isolated Keychain provisioning are the operator's
  responsibility. Do not use untrusted pull-request code with signing secrets.
