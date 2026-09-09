# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `docs/PROVIDER-CONTRACT.md`: the provider contract (v1) for key-based SSH
  access — host identity and EdDSA host assertions, `POST /hosts/enroll`,
  `GET /authorized-keys`, device-flow extensions (`host_assertion`,
  `account`, `intent`) and `ssh_access_endpoint` discovery.
- Configuration keys `api_base`, `host_id`, `identity_key` (default
  `/etc/oidc-ssh/host.key`), `cache_dir` (default `/var/cache/oidc-ssh`) and
  `cache_ttl` (default `24h`, `0s` disables the cache). Paths must be
  absolute; `api_base` must be `https://` unless `allow_insecure_http` and is
  kept verbatim.

### Changed

- The default configuration path is now `/etc/oidc-ssh/config.yaml`, shared
  by the PAM helper and `oidc-ssh`. `config.LoadDefault` still reads
  `/etc/security/pam_oidc_device.yaml` when the new path does not exist, so
  existing installations keep working unchanged.
- The `sshd_config` block printed at the end of an enrolment now separates
  `publickey` and `keyboard-interactive:pam` with a space, not a comma:
  space-separated alternatives mean "a key is enough, and a login without
  one falls back to the device flow", while the comma demands both.

### Fixed

- A successful authentication could be reported to PAM as
  `PAM_AUTHINFO_UNAVAIL` ("helper reported success but exited abnormally").
  The module reaped the helper with `WNOHANG` the instant its result line
  arrived, which normally finds it still unwinding, and killed it; the
  signal in the exit status then invalidated the result. The helper now gets
  a bounded grace period to exit on its own. Caught by the sshd integration
  test, where it failed roughly four logins in five.

## [0.1.1] - 2026-09-09

### Fixed

- The 0.1.0 module was built on a glibc 2.39 system with `_GNU_SOURCE`, which
  made it reference `__isoc23_strtol` (GLIBC_2.38) and fail to load on Debian
  12 / glibc 2.36 (`PAM unable to dlopen`). The module now uses POSIX feature
  macros only, release builds compile it inside Debian 12, and CI enforces a
  glibc 2.36 symbol ceiling (`make check-glibc`).

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
