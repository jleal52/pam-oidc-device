# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-09

### Added

- PAM module `pam_oidc_device.so` (C) plus helper process
  `pam-oidc-device-helper` (Go) authenticating logins with the OAuth 2.0
  Device Authorization Grant (RFC 8628) against any OpenID Connect provider.
  The helper runs as a separate process per login so the module works under
  OpenSSH's fork-based PAM child.
- The device code is shown as a "press Enter after approving" prompt so that
  sshd relays it to the client before the wait starts.
- Mapping of "users carrying group *G*" to a fixed local account
  (`users:` in the configuration); unmapped accounts get `PAM_IGNORE` without
  any network traffic.
- ID token verification via the provider's JWKS (`RS256`/`ES256` only),
  issuer, audience, `exp`/`iat` with configurable clock skew, non-empty `sub`.
- `https://` enforced for the issuer and every discovered endpoint; redirects
  refused; per-request HTTP timeout.
- Session environment `OIDC_USER` (configurable name) and `OIDC_SUB`; values
  with control characters are rejected.
- One sanitised audit line per attempt to syslog `authpriv`, with severity by
  outcome; never logs tokens or codes.
- Fail-closed behaviour throughout, including a panic guard in the helper and a strict line protocol at the module
  boundary and `PAM_IGNORE` from the account stack.
- YAML configuration with defaults, strict unknown-key rejection and
  validation; `{{hostname}}` expansion for `device_name`.
- Debian/Ubuntu (`.deb`) and Fedora/RHEL (`.rpm`) packages for amd64 and
  arm64, built with nfpm; releases signed with cosign (keyless) and shipped
  with an SBOM and checksums.
- In-memory test provider and `mock-provider` binary; pamtester integration
  suite running in a stock Debian container, and the same scenarios through
  a real OpenSSH server and client.
