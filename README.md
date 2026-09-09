# pam-oidc-device

`pam-oidc-device` is a PAM module that authenticates logins (typically SSH) against any OpenID Connect provider using the OAuth 2.0 Device Authorization Grant (RFC 8628). The user is shown a verification URL and a short code at the login prompt, completes the sign-in in a browser on any device, and the module verifies the resulting ID token. Users that carry a required group claim are mapped to a fixed local account, so no per-user local accounts or SSH keys need to be provisioned.

**Status: Work in progress — not yet released.**

## License

Apache-2.0. See [LICENSE](LICENSE).
