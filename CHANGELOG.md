# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-09-12

Two failures from one real enrolment, neither of them the operator's fault.

### Fixed

- `oidc-ssh` is on `PATH`. The command lives under `/usr/libexec`, which is on
  nobody's `PATH`, while the documentation — this package's own postinstall
  message included — tells people to run `oidc-ssh enroll`. A symlink in
  `/usr/sbin` fixes it, and CI now asserts the command is reachable after
  installing: an instruction that does not work is worse than a missing one.
- The provider's reason reaches the operator. An enrolment refused with
  `HTTP 400 (Bad Request)` and nothing else; the provider had said why, but
  under `message`, the field most REST stacks use, while this client only read
  the OAuth pair `error`/`error_description`. The contract (§4.2) fixes status
  codes, not a body shape, so being liberal in what we read costs nothing and
  turns a dead end into an instruction. `error_description` still wins when
  both are present.

[1.0.1]: https://github.com/jleal52/oidc-ssh/releases/tag/v1.0.1

## [1.0.0] - 2026-09-11

First stable release, and a rename: the project is now **oidc-ssh**, after the
command people actually type. The old name, `pam-oidc-device`, described the
device flow and nothing else — by now the module also serves `authorized_keys`
from the provider, enrols hosts and carries the identity into the session, so
the name undersold it.

The 0.x releases have been withdrawn. They were three days of rapid iteration
with two known-bad versions in the middle (0.1.0 would not load on Debian 12;
0.1.1 reported some successful logins as failures), and keeping them published
only invited someone to install one. Start here.

### Changed — everything named after the old project

Upgrading from a 0.x install is a manual migration, not a package upgrade:

| Before | Now |
|---|---|
| `pam_oidc_device.so` | `pam_oidc_ssh.so` |
| `/usr/libexec/pam-oidc-device/pam-oidc-device-helper` | `/usr/libexec/oidc-ssh/oidc-ssh-helper` |
| `/usr/libexec/pam-oidc-device/oidc-ssh` | `/usr/libexec/oidc-ssh/oidc-ssh` |
| `/usr/share/doc/pam-oidc-device/` | `/usr/share/doc/oidc-ssh/` |
| package `pam-oidc-device` | package `oidc-ssh` |
| module `github.com/jleal52/pam-oidc-device` | `github.com/jleal52/oidc-ssh` |

`/etc/oidc-ssh/`, `/var/cache/oidc-ssh` and the `oidc-ssh` system account keep
their names. What has to be edited by hand on an existing host: the module
line in `/etc/pam.d/*` and `AuthorizedKeysCommand` in `sshd_config`.

### Removed

- The pre-0.2.0 configuration fallback under `/etc/security`. The default
  path has been `/etc/oidc-ssh/config.yaml` since 0.2.0; keeping a fallback
  named after the old project would have kept that name alive on disk
  forever. A host still holding its configuration at the old location must
  move it before upgrading, or the module fails closed — which it does
  loudly, naming the path it looked for.

### Fixed

- Releases never carried the SBOM they advertised. The pinned
  `anchore/sbom-action` predated the `output-file` input, warned "Unexpected
  input(s)" and wrote nothing, so nothing failed and no SBOM shipped. The
  action is updated and the workflow now asserts the file exists before
  checksumming and signing it.

### Inherited from the 0.x series

Everything those releases built, now under one version: the PAM module in C
that execs a static Go helper (a cgo `.so` did not survive sshd's fork), the
device flow with a confirmation PIN typed back into the terminal, key-based
login through `AuthorizedKeysCommand` with a last-known-good cache, host
enrolment tied to the approval that authorised it, attribution of shared
accounts through `OIDC_USER`, deb/rpm packaging, and keyless cosign
signatures with an SPDX SBOM.

[1.0.0]: https://github.com/jleal52/oidc-ssh/releases/tag/v1.0.0
