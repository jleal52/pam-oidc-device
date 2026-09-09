# pam-oidc-device

[![CI](https://github.com/jleal52/pam-oidc-device/actions/workflows/ci.yml/badge.svg)](https://github.com/jleal52/pam-oidc-device/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Linux PAM module that authenticates a login, typically SSH, by asking the
person to approve it in a browser at their OpenID Connect provider, using the
OAuth 2.0 Device Authorization Grant (RFC 8628). Anyone whose ID token carries
the required group logs in as a fixed local account, so the server needs no
per-person Unix users, no SSH keys to distribute and no directory sync.

```
$ ssh systems@bastion
Open the following URL in a browser and approve this login:
  https://login.example.com/device?user_code=BCDF-GHJK
Code: BCDF-GHJK. Press Enter after approving in the browser:
```

The person opens the link on any device, signs in with their usual identity
provider flow (SSO, MFA, whatever the provider enforces), approves, presses
Enter, and the SSH session continues (pressing Enter early is fine: the module
keeps polling until the approval arrives or the time runs out). Their identity is exported to the session as
`OIDC_USER` and written to syslog, so a shared account stays attributable.

Status: 0.1.0 — tested against an in-house OpenID Connect provider, on Debian
12 and Fedora 41, amd64 and arm64.

## What it does, and what it does not

- Authenticates PAM logins (`auth` stack) with the RFC 8628 device flow.
- Maps "any user whose groups claim contains *G*" to one local account. Several
  accounts with different groups are fine (`systems` for admins, `ops` for
  read-only staff).
- Exports the identity to the session (`OIDC_USER`, `OIDC_SUB`) and logs one
  audit line per attempt to syslog (`authpriv`).
- Ignores accounts that are not mapped: root, service users and everyone else
  keep authenticating with the rest of the PAM stack.

It does **not** create or sync users, manage SSH keys, or replace `sudo`
policy. Each mapped local account must already exist. It does not cut sessions
that are already open when a permission is revoked at the provider.

## How it works

The module itself (`pam_oidc_device.so`) is a small C shared object. For every
login it starts the helper `pam-oidc-device-helper`, a static Go binary that
does all the work and talks back over a pipe (messages to show, variables to
export, the final result). No Go runtime ever runs inside the application
calling PAM, which is what makes the module safe under OpenSSH's process model
(sshd runs `pam_authenticate` in a child created with `fork()`).

```
 sshd (keyboard-interactive) → PAM → pam_oidc_device.so         Identity provider          Browser
 ───────────────────────────────────────────────────────         ─────────────────          ───────
 1. user mapped? no → PAM_IGNORE (no network)
 2. GET  <issuer>/.well-known/openid-configuration ─────────────▶
 3. POST device_authorization_endpoint (client_id, scope, device_name) ─▶ device_code, user_code, URL
 4. PAM_TEXT_INFO: URL; PAM_PROMPT_ECHO_OFF: "Code: …, press Enter"                     user opens URL,
 5. POST token_endpoint every <interval> s ─────────────────────▶ authorization_pending   signs in, approves,
                                                                 … → id_token             presses Enter
 6. verify id_token: signature (JWKS, RS256/ES256), iss, aud=client_id, exp/iat ± clock_skew
 7. groups claim contains the group mapped to the local account? no → PAM_AUTH_ERR
 8. pam_putenv OIDC_USER=<username claim>, OIDC_SUB=<sub>; syslog; PAM_SUCCESS
```

What is validated in the ID token: the signature against the provider's JWKS
(only `RS256` and `ES256` are accepted), `iss` equal to the configured issuer,
`aud` containing the client id, `exp` and `iat` within `clock_skew`, a
non-empty `sub`, and the required group in the groups claim (exact,
case-sensitive string match). `nonce` does not apply to the device flow: there
is no browser session on the device to bind, the device code itself ties the
token response to the polling client.

What is exported: `<session_env>` (default `OIDC_USER`) with the value of
`username_claim`, and `OIDC_SUB` with the token subject. Values containing
control characters or invalid UTF-8 are rejected and the login fails.

What is logged: one line per attempt to syslog facility `authpriv`, tag
`pam_oidc_device`:

```
user=alice@example.com sub=8d2f… local_user=systems rhost=203.0.113.9 host=bastion result=success reason=- err=-
```

`result` is `success` (INFO), `denied` (NOTICE), `error` (ERR) or `ignore`
(DEBUG, only with the `debug` module argument). `reason` is one of
`not_mapped`, `provider_unavailable`, `denied`, `timeout`, `expired`,
`no_id_token`, `invalid_token`, `missing_group`, `empty_username`,
`invalid_env`, `putenv`, `panic`. Every value is sanitised (control characters
collapsed, length bounded). Tokens, device codes and user codes are never
logged. If syslog is unavailable the line goes to stderr and the login is not
affected.

## Provider requirements

- OpenID Connect discovery at `<issuer>/.well-known/openid-configuration`
  advertising `device_authorization_endpoint`, `token_endpoint` and
  `jwks_uri`, all `https://`. `issuer` must match the configured value byte
  for byte.
- OAuth 2.0 Device Authorization Grant (RFC 8628) for a **public** client (no
  client secret; the module sends `client_id` in the request body).
- ID tokens signed with `RS256` or `ES256` and a groups claim that is a JSON
  array of strings (its name is configurable; default `groups`).
- Optional: the module sends a non-standard `device_name` form parameter in
  the device authorization request (the host name by default). A provider can
  show it on the approval page so the person can check they are approving the
  right server.

The module polls at the interval the provider announces (clamped to 5..60 s),
honours `slow_down`, and treats `access_denied` and `expired_token` as final.

## Install

### From a release (deb / rpm)

Releases ship `.deb` (amd64, arm64; depends on `libpam0g`) and `.rpm`
(x86_64, aarch64; depends on `pam`) packages, the raw shared object, an SBOM,
`SHA256SUMS`, and a keyless [cosign](https://github.com/sigstore/cosign)
signature (`.sig` + `.pem`) for every file. Verify before installing:

```sh
cosign verify-blob \
  --certificate pam-oidc-device_0.1.0_amd64.deb.pem \
  --signature   pam-oidc-device_0.1.0_amd64.deb.sig \
  --certificate-identity-regexp 'https://github.com/jleal52/pam-oidc-device/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  pam-oidc-device_0.1.0_amd64.deb

sudo apt-get install ./pam-oidc-device_0.1.0_amd64.deb   # Debian/Ubuntu
sudo dnf install ./pam-oidc-device-0.1.0-1.x86_64.rpm    # Fedora/RHEL
```

The package installs `pam_oidc_device.so` into the distribution's PAM module
directory, the helper under `/usr/libexec/pam-oidc-device/`, and an annotated
example configuration under
`/usr/share/doc/pam-oidc-device/config.example.yaml`. It changes nothing else:
the module is inert until referenced from `/etc/pam.d`.

### From source

```sh
make so helper   # build/pam_oidc_device.so (C; Docker if libpam0g-dev is missing) and build/pam-oidc-device-helper (Go, static)
make check-so    # the three pam_sm_* symbols must be exported
sudo install -m 0644 build/pam_oidc_device.so /usr/lib/$(gcc -print-multiarch)/security/
sudo install -D -m 0755 build/pam-oidc-device-helper /usr/libexec/pam-oidc-device/pam-oidc-device-helper
make package VERSION=0.1.0 ARCH=amd64   # dist/*.deb and *.rpm via nfpm (Docker)
```

Requirements: Go 1.26, a C compiler and `libpam0g-dev` (or Docker).

## Configuration

Default path `/etc/oidc-ssh/config.yaml`; the pre-0.2.0 path
`/etc/security/pam_oidc_device.yaml` is still read when the default does not
exist, and another path can be given with the `config=` module argument. The
file is read on every attempt.

| Key | Default | Meaning |
|---|---|---|
| `issuer` | required | Provider issuer URL. Must be `https://` (see `allow_insecure_http`), must not carry query, fragment or userinfo, and must equal the discovery document's `issuer` exactly (trailing slash included). |
| `client_id` | required | Public OAuth client registered for the device flow. |
| `scope` | `openid profile email groups` | Scopes requested; the username and groups claims must be released under them. |
| `device_name` | `{{hostname}}` | Hint sent to the provider (`{{hostname}}` → `os.Hostname()`). |
| `username_claim` | `email` | Claim exported as the session identity. Must be a non-empty string in the token. |
| `groups_claim` | `groups` | Claim holding the group list (JSON array of strings). |
| `session_env` | `OIDC_USER` | Environment variable receiving `username_claim`. Must be a valid variable name. `OIDC_SUB` is always exported too. |
| `timeout` | `300s` | Maximum wait for the approval. The provider's `expires_in` applies as well; the shorter wins. |
| `clock_skew` | `60s` | Tolerance when checking `exp` and `iat`. |
| `http_timeout` | `10s` | Bound on every single HTTP request (discovery, device request, each poll, JWKS). |
| `allow_insecure_http` | `false` | Accept `http://` issuer and endpoints. For tests against a local mock only. |
| `users` | required | Map `local account → required group`. Keys and values are trimmed; duplicates after trimming are rejected. |
| `api_base` | discovery or `<issuer>/api/ssh` | Base URL of the provider's SSH access API ([contract](docs/PROVIDER-CONTRACT.md)). Kept verbatim; `https://` unless `allow_insecure_http`. Written by enrolment. |
| `host_id` | unset | Host identifier assigned at enrolment; `iss`/`sub` of host assertions. Written by enrolment. |
| `identity_key` | `/etc/oidc-ssh/host.key` | Absolute path of the host's Ed25519 private key. |
| `cache_dir` | `/var/cache/oidc-ssh` | Absolute path of the last-known-good authorized-keys cache. |
| `cache_ttl` | `24h` | Maximum age of a cached answer served while the provider is unreachable. `0s` disables the cache; negative values are rejected. |

Unknown keys are rejected. Example (also shipped in the package):

```yaml
issuer: https://login.example.com
client_id: ssh-bastion
users:
  systems: ssh:admin
  ops: ssh:ops
```

Module arguments in `/etc/pam.d/*`: `config=<path>` (default
`/etc/oidc-ssh/config.yaml`, falling back to
`/etc/security/pam_oidc_device.yaml`), `helper=<path>` (default
`/usr/libexec/pam-oidc-device/pam-oidc-device-helper`), `timeout=<seconds>`
(wall-clock bound for the whole exchange, default 420; the helper is killed
when it elapses), `debug` (verbose syslog, ignored attempts at DEBUG).

## PAM and sshd setup

Local accounts, once per server (one per entry in `users`):

```sh
useradd -m -s /bin/bash systems && passwd -l systems
useradd -m -s /bin/bash ops     && passwd -l ops
```

No password, no `authorized_keys`. `/etc/pam.d/sshd`, first line of the
`auth` block:

```
auth  [success=done ignore=ignore default=die]  pam_oidc_device.so
```

Why not `required`: the module returns `PAM_IGNORE` for accounts that are not
in `users`, which `required` treats as a failure; the control above lets those
accounts fall through to the next module (`pam_unix`, keys, …). The module
needs no line in the `account` stack (`pam_sm_acct_mgmt` returns `PAM_IGNORE`
so that a stray `account required pam_oidc_device.so` cannot let everyone in).

`/etc/ssh/sshd_config` (check with `sshd -t`, then reload):

```
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
LoginGraceTime 400

Match User systems,ops
    AuthenticationMethods keyboard-interactive:pam
    PubkeyAuthentication no
```

`LoginGraceTime` matters: a login can take up to `timeout + 4 × http_timeout`
(300 s + 40 s = 340 s with the defaults) while sshd's default grace time is
120 s, after which it kills the unauthenticated session mid-flow. Raise it or
lower `timeout`. Keep root (or another break-glass account) on a key, outside
this flow: if the provider is unreachable nobody gets in through the module.

`/etc/sudoers.d/oidc`, so the person behind the shared account is visible in
`sudo` logs:

```
Defaults env_keep += "OIDC_USER OIDC_SUB"
Defaults log_input, log_output
systems ALL=(ALL) NOPASSWD:ALL
```

## Attribution with shared accounts

`last`, `who` and `sudo` see the local account. The person is recoverable from
three places: `OIDC_USER`/`OIDC_SUB` in the session environment (sshd copies
the PAM environment into the session, `env_keep` carries it through `sudo`),
the syslog line written by the module (`user=`, `local_user=`, `rhost=`,
`host=`), and the provider's own audit of the approval. Ship `auth.log` to
your log platform and search by `user=`.

## Security notes

- **The module trusts the provider.** Whoever controls the issuer, or a
  group claim, controls who gets a shell. Treat the provider's group
  assignment as the access list it is.
- **Code phishing.** An attacker who starts a login and tricks the victim
  into approving it would obtain the attacker's session. Mitigations: the
  code is single-use and short-lived, the provider should show the server
  name (`device_name`) and requester address on the approval page, and users
  should approve only right after typing `ssh`.
- **Transport.** Discovery, device, token and JWKS endpoints must be
  `https://`; redirects are refused; TLS is verified with the system CA store.
- **Token validation** as described above; `alg: none` and HMAC algorithms
  are rejected before signature verification.
- **Fail closed.** Every path that is not an explicit success returns a PAM
  failure code; a Go panic inside the module is caught and mapped to
  `PAM_AUTHINFO_UNAVAIL`; invalid session values deny the login instead of
  exporting them.
- **Input hygiene.** Provider-controlled text is sanitised before it reaches
  the terminal (control characters stripped) or syslog (collapsed, bounded).
- **Revocation** at the provider stops new logins immediately (subject to any
  caching in the provider) but does not end sessions already open.
- **No foreign runtime in the PAM host.** The shared object is ~200 lines of
  C; the Go code runs in a separate, freshly exec'ed process per login and
  can only talk back through a strict line protocol (messages, environment
  entries, one result). A helper crash, an early exit or the wall-clock
  `timeout` all fail closed.
- **Messages on failure.** OpenSSH only relays informational PAM text to the
  client together with a prompt, so on a failed login the SSH client shows
  the usual "Permission denied (keyboard-interactive)" and the specific
  reason is in syslog (`reason=`). Interactive PAM applications (login, su,
  pamtester) show the messages directly.

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| Login fails right away; syslog `reason=provider_unavailable` (interactive apps also show "Identity provider unavailable") | No egress to the issuer, DNS, or provider down | `curl -sS <issuer>/.well-known/openid-configuration` from the host. Use the break-glass account. |
| Prompt appears, then "No approval received in time." | Nobody approved within `timeout` | Approve faster or raise `timeout` (and `LoginGraceTime`). |
| "The code expired before approval; try again." | Provider's `expires_in` elapsed, or the code was approved after expiry | Retry. |
| "Login denied." | The person denied, or lacks the provider-side permission to approve | Provider audit log; `reason=denied` in syslog. |
| "Not allowed to log in as systems on this host." | Approved, but the token's groups do not contain the required group | Assign the group at the provider; check `groups_claim` and `scope`. |
| Connection closes after ~2 minutes with no message | sshd `LoginGraceTime` (default 120 s) shorter than the flow | Set `LoginGraceTime 400` or lower `timeout`. |
| syslog `helper ... is not executable` | Helper missing or installed elsewhere | Install the package or pass `helper=<path>`. |
| `reason=invalid_token` | Wrong `client_id` (`aud`), issuer mismatch, clock skew, key rotation | Compare `issuer` with the discovery `issuer`; check NTP; `clock_skew`. |
| Unmapped users are denied instead of falling through | `auth required` used instead of `[success=done ignore=ignore default=die]` | Fix the control field. |
| `slow_down` loops | Provider interval below what it accepts | The module already backs off as the RFC requires; check the provider's own limits. |

Test a service without sshd:

```sh
cat >/etc/pam.d/oidc-test <<'EOF'
auth    required pam_oidc_device.so debug
account required pam_permit.so
EOF
pamtester oidc-test systems authenticate
```

## Development

```sh
make test          # unit tests (pure Go, no PAM headers needed)
make lint          # golangci-lint (config in .golangci.yml)
make so helper check-so   # build the C module (Docker fallback) and the Go helper; check exported symbols
make integration          # pamtester scenarios in a Debian container against a mock provider
make integration-sshd     # the same through a real OpenSSH server and client (fork model)
make package VERSION=0.1.0 ARCH=amd64
```

Layout: `pam/pam_oidc_device.c` (the PAM module: exec the helper, relay the
line protocol), `cmd/pam-oidc-device-helper` (the helper process),
`internal/config` (YAML), `internal/oidc` (discovery, device flow, ID token
verification, on `coreos/go-oidc` + `golang.org/x/oauth2`), `internal/auth`
(the decision logic, testable without PAM), `internal/pamlog` (audit line,
sanitising), `internal/testprovider` + `cmd/mock-provider` (an in-memory
provider for tests), `test/integration` (pamtester scenarios: approved,
denied, wrong group, unmapped user under two stack controls, account stack
ignore, provider down; and the same against a real `sshd`), `packaging`
(nfpm).

Contributions are welcome. Please keep the module provider-agnostic, add a
test for every behaviour change, and run `make test lint integration` before
opening a pull request.

## Compatibility

Linux-PAM only (Linux). Packages for Debian/Ubuntu (`.deb`) and
Fedora/RHEL-family (`.rpm`), amd64 and arm64. Built with Go 1.26.

## License

Apache License 2.0, see [LICENSE](LICENSE).
