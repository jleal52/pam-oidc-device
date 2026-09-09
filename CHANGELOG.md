# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Releases never carried the SBOM they advertised. The pinned
  `anchore/sbom-action` predated the `output-file` input, warned "Unexpected
  input(s)" and wrote nothing, so 0.1.0 through 0.2.0 shipped without one and
  nothing failed. The action is updated and the workflow now asserts the file
  exists before checksumming and signing it.

## [0.2.0] - 2026-09-09

### Added

- `oidc-ssh`, a second binary next to the PAM module, with three
  subcommands. `enroll` gives the host an Ed25519 identity and registers it
  with the provider through a device flow that a person approves.
  `authorized-keys` is what sshd runs as its `AuthorizedKeysCommand`: it asks
  the provider which keys may open the requested account and prints them.
  `status` reports what the host knows and whether it can reach the provider.
- Last-known-good cache for `authorized-keys`. A provider that is unreachable
  or answering 5xx falls back to the last successful answer while it is
  younger than `cache_ttl`, and says so in syslog. Denials are never cached,
  so revoking access still takes effect during an outage.
- The packages create an unprivileged `oidc-ssh` system account with no shell
  and no home, and lay down `/etc/oidc-ssh` (2750 root:oidc-ssh, setgid so
  that what enrolment writes is readable by that account) and
  `/var/cache/oidc-ssh` (0700). CI installs both packages on stock Debian 12
  and Fedora 41 and checks all of it.
- Integration scenarios against a real OpenSSH server for key-based login:
  enrolment, a key login carrying `OIDC_USER` through `sudo`, an
  unauthorized key falling back to the device flow, a provider outage served
  from a warm cache and refused with a cold one, and `PermitUserEnvironment`
  dropping an `environment=` option the server was not told to accept.
- `docs/PROVIDER-CONTRACT.md`: the provider contract (v1) for key-based SSH
  access — host identity and EdDSA host assertions, `POST /hosts/enroll`,
  `GET /authorized-keys`, device-flow extensions (`host_assertion`,
  `account`, `intent`, `groups`) and `ssh_access_endpoint` discovery.
- Configuration keys `api_base`, `host_id`, `identity_key` (default
  `/etc/oidc-ssh/host.key`), `cache_dir` (default `/var/cache/oidc-ssh`) and
  `cache_ttl` (default `24h`, `0s` disables the cache). Paths must be
  absolute; `api_base` must be `https://` unless `allow_insecure_http` and is
  kept verbatim.

### Changed

- The device authorization request now carries `host_assertion`, `account`
  and `intent=login` when the host is enrolled, so a provider can identify
  the machine and the account instead of trusting the unsigned `device_name`
  hint. Without an identity the request is byte-for-byte the 0.1.1 one.
- `enroll` announces the host groups it claims (`groups`) in the same
  request, so the person approving sees what the machine is asking for.
  Those groups decide who may log into it afterwards, and the enrolment body
  that carries them is only sent after the approval.
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
- The module always passed `--config /etc/security/pam_oidc_device.yaml` to
  the helper, so the search order above never ran on the PAM path: a host
  enrolled with `oidc-ssh` wrote its identity to one file while logins read
  the other, and both files looked right. `config=` now defaults to unset.

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
