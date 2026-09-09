# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories:
open the repository's **Security** tab and choose **Report a vulnerability**.
Do not open a public issue or pull request for a security bug.

You will get an acknowledgement as soon as possible; there is no fixed
response-time commitment. Fixes are released as a new patch version with a
note in the changelog, and the advisory is published once a fix is available.

## Supported versions

Only the latest minor release receives security fixes.

## Scope

This module sits on the authentication path of a host and grants shell access
based on a token issued by a third party. In scope: anything that lets a
login succeed without a valid, approved ID token carrying the required group;
anything that lets provider-controlled data reach the terminal, the session
environment or syslog unsanitised; crashes of the host process triggered by
provider responses; weakening of the transport or token checks.

Out of scope: the security of the identity provider itself, of the
configuration file's permissions, and of the local accounts and `sudo` policy
around the module.

## Security-relevant design decisions

See the "Security notes" section of the README for details. In short:

- Only `RS256` and `ES256` ID tokens are accepted; `alg: none` and HMAC are
  rejected before signature verification.
- Issuer, audience, `exp`, `iat` (with `clock_skew`) and a non-empty `sub`
  are checked; the required group must match exactly.
- `https://` is required for the issuer and all discovered endpoints;
  redirects are refused; the system CA store is used.
- Every non-success path fails closed, including a panic guard in the helper and a strict line protocol at the module
  boundary; the account stack callback returns `PAM_IGNORE`.
- Provider-controlled strings are sanitised before reaching the terminal or
  syslog; session values with control characters deny the login.
- Tokens, device codes and user codes are never logged.
