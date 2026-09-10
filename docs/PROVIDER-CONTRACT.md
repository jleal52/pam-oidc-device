# Provider contract for key-based SSH access (v1)

This document specifies what an identity provider must implement so that hosts
running `oidc-ssh` can enrol themselves and fetch the SSH public keys allowed
to log in to a local account. It is normative: the reference test provider in
this repository and any production provider implement it, and the client code
in this repository is written against it.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

Throughout, `{base}` is the provider's SSH access API base URL (see
[Discovery](#5-discovery)) and `{issuer}` is its OpenID Connect issuer.
Example: `{issuer} = https://login.example.com`,
`{base} = https://login.example.com/api/ssh`.

## 1. Overview and roles

- **Provider** — the OpenID Connect provider. It authenticates people, stores
  their SSH public keys, keeps the inventory of enrolled hosts and decides,
  by its own policy, who may log in to which local account on which host.
- **Host** — a server running `sshd` and `oidc-ssh`. It holds an Ed25519 key
  pair that identifies it to the provider and asks the provider for the
  authorized keys of a local account at every public-key login attempt.
- **Person** — the human logging in. Their private key never leaves their
  machine; `sshd` verifies the signature locally, the provider only ships
  public keys.

The contract has four parts: host identity (§2), enrolment (§3), authorized
keys (§4) and optional device-flow extensions (§6), plus discovery (§5).

## 2. Host identity

### 2.1 Key pair

At enrolment the host generates an Ed25519 key pair. The private key MUST stay
on the host (recommended location `/etc/oidc-ssh/host.key`, mode `0640`,
owned by root and readable by the unprivileged user that runs the
authorized-keys command). The public key is sent to the provider once, in
OpenSSH format (`ssh-ed25519 AAAA…`).

### 2.2 Host assertion

A host proves its identity with a **host assertion**: a compact JWS (RFC 7515)
with header `alg: EdDSA`, `typ: JWT`, signed with the host's private key. Its
claims MUST be:

| Claim | Value |
|---|---|
| `iss` | the `hostId` returned at enrolment |
| `sub` | equal to `iss` |
| `aud` | `{base}`, verbatim (the string the host was configured with or discovered) |
| `iat` | issue time, seconds since the epoch |
| `exp` | expiry; MUST satisfy `exp <= iat + 60` |
| `jti` | random, at least 128 bits of entropy, unique per assertion |

The host MUST mint a fresh assertion for every request. The assertion is sent
as `Authorization: Bearer <jws>` on the authorized-keys endpoint (§4) and as
the `host_assertion` parameter of the device authorization request (§6).

### 2.3 Verification

On receipt the provider MUST:

1. parse the JWS and reject any `alg` other than `EdDSA`;
2. resolve the host by `iss` and verify the signature with the public key
   enrolled for it;
3. check `sub == iss` and `aud == {base}`;
4. check `iat` and `exp` against its clock with a tolerance of at most
   ±60 s, and reject assertions whose lifetime exceeds 60 s;
5. check that the host is active (not revoked, not deleted);
6. reject a `jti` already seen from that host within the assertion's lifetime
   (a store with an expiry of at least 120 s is sufficient).

Any failure is answered with `401` (bad or unverifiable assertion) or `403`
(valid assertion, but the host is revoked). The provider SHOULD not reveal
which check failed beyond that distinction.

## 3. Enrolment

```
POST {base}/hosts/enroll
Authorization: Bearer <access_token>
Content-Type: application/json
```

The bearer token is an OAuth 2.0 access token obtained by an administrator
through the provider's own device flow with `intent=enroll` (§6). The
provider decides who may enrol hosts.

Request body:

```json
{
  "publicKey":    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… oidc-ssh@host01",
  "name":         "host01",
  "hostname":     "host01.internal.example.com",
  "groups":       ["bastions"],
  "accounts":     ["systems", "ops"],
  "agentVersion": "0.2.0"
}
```

| Field | Required | Meaning |
|---|---|---|
| `publicKey` | yes | The host's Ed25519 public key, OpenSSH format. The provider MUST parse it strictly and reject any other key type. |
| `name` | yes | Stable, human-readable host name; unique per provider. Shown to people approving logins. |
| `hostname` | no | The machine's own hostname, informational only. |
| `groups` | yes (may be empty) | Provider-defined host groups the host claims membership of, in the same order as the `groups` parameter of the device authorization request that obtained the token (§6); the provider MAY restrict which groups an enroller can assign, and MAY refuse a body that does not match what was approved. |
| `accounts` | yes | Local accounts the host will ask keys for. Requests for other accounts are refused (§4). |
| `agentVersion` | no | Version of the client, informational only. |

Responses:

| Status | Meaning |
|---|---|
| `201 Created` | New host. Body: `{"hostId": "…", "name": "…", "groups": [...], "accounts": [...]}`. |
| `200 OK` | Re-enrolment of an existing host: `publicKey` already belongs to a host and `name` matches it. Metadata (`hostname`, `groups`, `accounts`, `agentVersion`) is replaced. Same body as `201`. |
| `401` | Access token missing, invalid or expired. |
| `403` | The token is valid but its owner may not enrol hosts (or not with these groups/accounts). |
| `409` | `publicKey` is already registered under a different `name`, or `name` is taken by a host with a different key. |

`hostId` is an opaque string chosen by the provider, stable for the life of
the host. The client stores it and the `{base}` it enrolled against in its
configuration.

## 4. Authorized keys

```
GET {base}/authorized-keys?account=<local account>[&fingerprint=<fp>][&env=<NAME>]
Authorization: Bearer <host assertion>
```

| Parameter | Required | Meaning |
|---|---|---|
| `account` | yes | Local account being logged in to (sshd's `%u`). |
| `fingerprint` | no | `SHA256:<base64>` of the key offered by the client (sshd's `%f`). When present the provider MUST return only the matching key. |
| `env` | no | Name of the environment variable that carries the person's identity (default `OIDC_USER`). MUST match `^[A-Za-z_][A-Za-z0-9_]*$`. |

### 4.1 Success

`200 OK` with `Content-Type: text/plain; charset=utf-8` and `Cache-Control:
no-store`. The body holds zero or more lines in `authorized_keys` format, one
per key whose owner is allowed, by the provider's policy, to log in to
`account` on **this** host. Each line MUST carry the options

```
environment="<env>=<identity>",environment="OIDC_SUB=<sub>"
```

where `<identity>` is the person's login identity (their e-mail or username,
the same value the device flow exports) and `<sub>` their OIDC subject. The
provider MAY add further options such as `restrict` or `from=`. Values MUST
NOT contain control characters, `"` or newlines. Example:

```
environment="OIDC_USER=alice@example.com",environment="OIDC_SUB=7f3a…" ssh-ed25519 AAAAC3… alice
```

An **empty `200`** means that nobody holding the offered key (or nobody at
all, without `fingerprint`) may log in as `account`. It is an authoritative
denial: the host MUST NOT cache it and MUST NOT fall back to an earlier
answer. The provider SHOULD audit every query.

### 4.2 Errors

| Status | Meaning | Host behaviour |
|---|---|---|
| `401` | Host assertion invalid (signature, `aud`, time window, replayed `jti`, unknown host). | Deny. Never served from cache. |
| `403` | Host revoked, or `account` not among the accounts the host declared at enrolment. | Deny. Never served from cache. |
| `429` | Rate limited. | Deny. Never served from cache; the host SHOULD honour `Retry-After`. |
| `5xx`, timeout, connection or TLS failure | Provider unavailable. | MAY serve the cached last-known-good answer (§4.3). |

### 4.3 Caching

A host MAY keep, per `(account, fingerprint)`, the last non-empty `200`
answer it received. It MUST use that cache only when the provider is
unavailable (§4.2, last row), only while the entry is younger than a
configured TTL (24 h by default), and it MUST log every use of the cache. It
MUST NOT cache empty answers or errors, and MUST replace the cache entry on
every successful answer. Revocations therefore take effect immediately while
the provider is up and within the TTL otherwise; deployments choose the TTL
with that window in mind.

## 5. Discovery

The OpenID configuration document at
`{issuer}/.well-known/openid-configuration` MAY carry

```json
"ssh_access_endpoint": "https://login.example.com/api/ssh",
"ssh_device_confirmation_supported": true
```

A host resolves `{base}` in this order: its configured `api_base`, then
`ssh_access_endpoint` from discovery, then `{issuer}/api/ssh`. `{base}` MUST
be an absolute `https://` URL without query or fragment; it is used verbatim
as the `aud` of host assertions, so provider and host MUST agree on it byte
for byte (trailing slash included).

`ssh_device_confirmation_supported` announces the confirmation PIN of §6.1. A
host MUST read it **before** asking for a device code and MUST NOT ask the
user for a PIN unless it is `true`: prompting for a number no page will ever
show turns a working login into a dead end.

## 6. Device flow extensions

These extensions to the device authorization request of RFC 8628 are
optional. A provider that does not understand them MUST ignore them (RFC 6749
§3.1), in which case the PAM module keeps working in plain device-flow mode.

`POST {device_authorization_endpoint}` MAY carry, in addition to `client_id`,
`scope` and `device_name`:

| Parameter | Meaning |
|---|---|
| `host_assertion` | A host assertion (§2.2). Verified as in §2.3; an invalid one yields the standard `invalid_request` error. |
| `account` | The local account the person is logging in to. |
| `intent` | `login` (default) or `enroll`. |
| `groups` | Only with `intent=enroll`: the host group codes the host is asking to join, comma-separated, in the order they will appear in the enrolment body. Omitted when the host claims none. |
| `confirmation_supported` | `true` when the host will ask the user for the confirmation PIN of §6.1 and send it back. A host MUST NOT send it unless discovery advertises `ssh_device_confirmation_supported`. |

With a valid `host_assertion` the provider knows which enrolled host is
asking and for which account. It SHOULD show the enrolled `name` of the host
(not the unauthenticated `device_name` hint) on the approval page, and it
MUST apply the same access policy as for authorized keys: if the person may
log in to `account` on that host, the ID token's groups claim MUST contain
`ssh:<account>`; otherwise it MUST NOT. The host's configuration maps the
local account to that group (`users: {systems: "ssh:systems"}`).

With `intent=enroll` the provider MUST issue an access token usable at
`{base}/hosts/enroll` (§3) only to people allowed to enrol hosts. A provider
MAY require `host_assertion` for `intent=login` on managed hosts.

`groups` exists because the host groups decide, from then on, who may log in
to the machine, and the enrolment body that carries them (§3) is only sent
*after* the approval: without the parameter the person approving would be
authorising a claim they cannot see. A provider SHOULD therefore show the
codes on the approval page. It is an **unsigned hint**, exactly like
`device_name`: a host being enrolled has no identity the provider knows yet,
so nothing about it is verified, and the page MUST present the codes as
requested by the machine rather than as an established fact. A provider that
takes the parameter into account SHOULD compare it with the `groups` of the
enrolment body and refuse a mismatch; a host therefore MUST send both lists
with the same codes in the same order, trimmed, lowercased and without
repeats.

### 6.1 Confirmation PIN

The `user_code` proves nothing about who approves. A device flow prints a
verification URI that usually embeds it, so approving is one click, and an
attacker who starts the flow can simply pass their own link to someone with
access: that person sees an ordinary-looking approval and grants the
attacker's session.

The PIN closes that by carrying a secret **the other way**, from the browser
to the terminal:

1. The host sends `confirmation_supported=true` (only if discovery advertises
   support).
2. On approval — never before — the provider generates a PIN, shows it on the
   result page and remembers it with the device code.
3. The user types it at the terminal, and the host sends it as
   `user_confirmation` in the token request (RFC 8628 §3.4).

Requirements for a provider that implements it:

- The PIN MUST NOT appear anywhere before the approval, or anyone who opens
  the link has it without approving.
- A wrong PIN MUST invalidate the device code. There is **no retry**: the
  person at the terminal is exactly who this defends against, and with retries
  they enumerate the whole space.
- The PIN SHOULD be at least 4 digits, generated with a cryptographic random
  source, and compared in constant time.
- A confirmation window SHOULD bound how long an approval stays usable
  (2 minutes is a reasonable default). **Expiry MUST be checked before the
  PIN**: otherwise a correct PIN out of time and a wrong one give different
  errors, which tells an attacker whether the PIN was right.
- A token request with no `user_confirmation` for a code awaiting one MUST
  answer `authorization_pending` and MUST NOT consume the code.
- A rejected PIN is reported as `access_denied`, like any other refusal.

Note what this does not do: if the user reads the PIN out to whoever asks,
it falls. What it buys is turning "click this link" into "have a phone
conversation", which is far more expensive to mount and far more likely to
raise suspicion.

The same applies to `intent=enroll`, where it matters more: enrolment picks
the host groups, and those groups decide who may log in to that machine from
then on.

## 7. Security considerations

- **Host key compromise.** Whoever holds a host's private key can list the
  public keys allowed on the accounts that host declared and open device
  flows "as" that host. It cannot obtain private keys or tokens. Mitigations:
  revoke the host at the provider (immediate effect), the 60 s assertion
  lifetime and `jti` replay check, accounts fixed at enrolment, audit of
  every query.
- **Provider compromise** is equivalent to compromise of the managed
  accounts, exactly as with the plain device flow. Deployments SHOULD keep an
  out-of-band break-glass account and set `AuthorizedKeysFile none` for
  managed accounts so that the provider is the only source of keys.
- **Environment injection.** `sshd` honours `environment=` options only with
  `PermitUserEnvironment`; deployments SHOULD limit it to
  `PermitUserEnvironment <env>,OIDC_SUB` and providers MUST sanitise the
  values they emit (§4.1).
- **Key validation.** Providers MUST parse submitted user keys strictly,
  enforce minimum sizes for RSA, and keep fingerprints globally unique so a
  key cannot belong to two people.
- **Transport.** Everything travels over TLS; hosts MUST refuse plain HTTP
  outside test setups and MUST NOT follow redirects on these endpoints.
- **Denials are not cached** (§4.3); the cache only papers over provider
  downtime, never over a decision.

## 8. Versioning

This is version 1 of the contract. Changes that add optional request
parameters, response fields or discovery keys are backwards compatible and
do not bump the version. Anything that changes the meaning of an existing
element, removes one, or alters the assertion format is a new version
served under a different `{base}` (for example `…/api/ssh/v2`) and announced
under a new discovery key.
