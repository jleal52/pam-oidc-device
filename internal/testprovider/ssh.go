package testprovider

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"
)

// This file implements the provider side of docs/PROVIDER-CONTRACT.md: host
// enrolment, host assertions and the authorized-keys endpoint.

// SSHBasePath is the path of the SSH access API relative to the issuer, so
// that SSHBase() == URL() + SSHBasePath. Discovery advertises it as
// ssh_access_endpoint.
const SSHBasePath = "/api/ssh"

// assertionSkew is the clock tolerance applied to iat and exp, and
// assertionMaxLifetime the longest exp-iat a host assertion may declare.
const (
	assertionSkew        = 60 * time.Second
	assertionMaxLifetime = 60 * time.Second
	// accessTokenLifetime matches the expires_in advertised by /token.
	accessTokenLifetime = 300 * time.Second
	// keysTimeoutDelay is how long KeysTimeout stalls a request before
	// answering, long enough for any sane client timeout to fire first.
	keysTimeoutDelay = 10 * time.Second
	// maxEnrollBody bounds the JSON body accepted by /hosts/enroll.
	maxEnrollBody = 64 << 10
)

// envNameRe is the syntax the contract imposes on the env query parameter.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// KeysOutcome programs how the authorized-keys endpoint answers requests
// that pass authentication.
type KeysOutcome int

const (
	// KeysOK serves the programmed lines (default).
	KeysOK KeysOutcome = iota
	// KeysServerError answers 500 with a text/plain body, simulating a
	// broken backend.
	KeysServerError
	// KeysTimeout stalls until the client gives up (or 10 s pass),
	// simulating an unreachable provider. The stall ends early when the
	// request context is cancelled.
	KeysTimeout
)

// Host is an enrolled host as stored by the provider.
type Host struct {
	// ID is the opaque hostId returned at enrolment.
	ID string
	// Name is the unique, human-readable name given at enrolment.
	Name string
	// Hostname is the informational machine hostname, if sent.
	Hostname string
	// PublicKey is the host's Ed25519 public key.
	PublicKey ssh.PublicKey
	// Fingerprint is ssh.FingerprintSHA256(PublicKey).
	Fingerprint string
	// Groups and Accounts are the values from the last (re-)enrolment.
	Groups   []string
	Accounts []string
	// AgentVersion is the informational client version, if sent.
	AgentVersion string
	// Active is false once RevokeHost has been called.
	Active bool
}

func (h Host) clone() Host {
	h.Groups = append([]string(nil), h.Groups...)
	h.Accounts = append([]string(nil), h.Accounts...)
	return h
}

// sshState is the SSH-contract part of the provider's state. It is guarded
// by Provider.mu like everything else.
type sshState struct {
	hosts        map[string]*Host     // by hostId
	accessTokens map[string]issuedAT  // access_token -> flow it was issued for
	seenJTI      map[string]time.Time // hostId + "\x00" + jti -> expiry
	keys         map[string][]string  // account -> authorized_keys lines
	keysOutcome  KeysOutcome
	requireHost  bool
	policyDeny   bool

	// per device flow, reset at every /device_authorization
	hostAssertion string
	account       string
	intent        string
	flowHost      *Host // resolved from a valid host_assertion, or nil

	// recorded authorized-keys traffic
	keysAccount     string
	keysFingerprint string
	keysEnv         string
	keysRequests    int
}

type issuedAT struct {
	intent string
	exp    time.Time
}

func newSSHState() sshState {
	return sshState{
		hosts:        map[string]*Host{},
		accessTokens: map[string]issuedAT{},
		seenJTI:      map[string]time.Time{},
		keys:         map[string][]string{},
	}
}

// SSHBase returns the SSH access API base URL, URL() + SSHBasePath. It is
// the audience host assertions must carry.
func (p *Provider) SSHBase() string { return p.URL() + SSHBasePath }

// AddHost registers an active host directly, bypassing enrolment. It
// returns the new hostId. Tests that only exercise authorized-keys use it
// instead of running a device flow plus /hosts/enroll.
func (p *Provider) AddHost(name string, pub ssh.PublicKey, accounts, groups []string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.addHostLocked(name, pub)
	h.Accounts = append([]string(nil), accounts...)
	h.Groups = append([]string(nil), groups...)
	return h.ID
}

// addHostLocked creates and stores a new active host. p.mu must be held.
func (p *Provider) addHostLocked(name string, pub ssh.PublicKey) *Host {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand failing is not a condition tests can recover from.
		panic(fmt.Sprintf("testprovider: random host id: %v", err))
	}
	h := &Host{
		ID:          hex.EncodeToString(raw[:]),
		Name:        name,
		PublicKey:   pub,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Active:      true,
	}
	p.ssh.hosts[h.ID] = h
	return h
}

// Hosts returns a snapshot of the enrolled hosts keyed by hostId.
func (p *Provider) Hosts() map[string]Host {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]Host, len(p.ssh.hosts))
	for id, h := range p.ssh.hosts {
		out[id] = h.clone()
	}
	return out
}

// RevokeHost marks a host inactive: its assertions are still verifiable but
// answered with 403. Unknown ids are ignored.
func (p *Provider) RevokeHost(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h, ok := p.ssh.hosts[id]; ok {
		h.Active = false
	}
}

// SetAuthorizedKeys programs the authorized_keys lines served for account
// (to any active host that declared it). Lines are served verbatim, one per
// line; a fingerprint query filters them by the key each line carries.
func (p *Provider) SetAuthorizedKeys(account string, lines []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ssh.keys[account] = append([]string(nil), lines...)
}

// SetKeysOutcome programs how authorized-keys answers authenticated
// requests (default KeysOK).
func (p *Provider) SetKeysOutcome(o KeysOutcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ssh.keysOutcome = o
}

// SetRequireHost makes /device_authorization refuse requests without a
// host_assertion with invalid_request, modelling a provider that only
// serves managed hosts.
func (p *Provider) SetRequireHost(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ssh.requireHost = on
}

// SetPolicyDeny flips the provider's access policy from "everyone may log
// in everywhere" to "nobody may": device flows that carried a valid
// host_assertion end in access_denied and authorized-keys answers an empty
// 200. Flows without a host assertion are outside host policy and are not
// affected.
func (p *Provider) SetPolicyDeny(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ssh.policyDeny = on
}

// LastHostAssertion returns the host_assertion form field of the last
// /device_authorization request ("" when absent).
func (p *Provider) LastHostAssertion() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ssh.hostAssertion
}

// LastAccount returns the account form field of the last
// /device_authorization request ("" when absent).
func (p *Provider) LastAccount() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ssh.account
}

// LastIntent returns the intent of the last /device_authorization request,
// "login" when the field was absent, and "" before any request.
func (p *Provider) LastIntent() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ssh.intent
}

// LastKeysAccount returns the account query parameter of the last
// authorized-keys request.
func (p *Provider) LastKeysAccount() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ssh.keysAccount
}

// LastKeysFingerprint returns the fingerprint query parameter of the last
// authorized-keys request ("" when absent).
func (p *Provider) LastKeysFingerprint() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ssh.keysFingerprint
}

// LastKeysEnv returns the env query parameter of the last authorized-keys
// request ("" when absent).
func (p *Provider) LastKeysEnv() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ssh.keysEnv
}

// KeysRequests returns how many requests the authorized-keys endpoint has
// received, whatever their outcome.
func (p *Provider) KeysRequests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ssh.keysRequests
}

// --- host assertions ---

// assertionError is the outcome of a failed host assertion check. Status is
// 401 for anything unverifiable and 403 for a valid assertion of a revoked
// host, as the contract prescribes.
type assertionError struct {
	status int
	reason string
}

func (e *assertionError) Error() string { return e.reason }

func unverifiable(reason string) *assertionError {
	return &assertionError{status: http.StatusUnauthorized, reason: reason}
}

// assertionClaims mirrors hostid's payload; aud is decoded loosely because
// RFC 7519 allows either a string or an array.
type assertionClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience any    `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	ID       string `json:"jti"`
}

// audienceMatches reports whether aud is want, either as a plain string or
// as a single-element array.
func audienceMatches(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		return len(a) == 1 && a[0] == want
	}
	return false
}

// verifyHostAssertionLocked verifies tok per contract §2.3 and returns the
// host it names. It consumes the jti, so a second call with the same token
// fails. p.mu must be held.
func (p *Provider) verifyHostAssertionLocked(tok string, now time.Time) (*Host, *assertionError) {
	if tok == "" {
		return nil, unverifiable("missing host assertion")
	}
	jws, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, unverifiable("malformed assertion: " + err.Error())
	}
	var unverified assertionClaims
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &unverified); err != nil {
		return nil, unverifiable("malformed claims")
	}
	host, ok := p.ssh.hosts[unverified.Issuer]
	if !ok {
		return nil, unverifiable("unknown host")
	}
	cryptoPub, ok := host.PublicKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, unverifiable("host key is not usable")
	}
	edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, unverifiable("host key is not ed25519")
	}
	payload, err := jws.Verify(edPub)
	if err != nil {
		return nil, unverifiable("bad signature")
	}
	var c assertionClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, unverifiable("malformed claims")
	}
	switch {
	case c.Subject != c.Issuer:
		return nil, unverifiable("sub != iss")
	case !audienceMatches(c.Audience, p.SSHBase()):
		return nil, unverifiable("wrong audience")
	case c.IssuedAt == 0 || c.Expiry == 0:
		return nil, unverifiable("missing iat or exp")
	case c.Expiry <= c.IssuedAt:
		return nil, unverifiable("exp before iat")
	case c.Expiry-c.IssuedAt > int64(assertionMaxLifetime/time.Second):
		return nil, unverifiable("lifetime exceeds 60 s")
	case time.Unix(c.IssuedAt, 0).After(now.Add(assertionSkew)):
		return nil, unverifiable("issued in the future")
	case time.Unix(c.Expiry, 0).Before(now.Add(-assertionSkew)):
		return nil, unverifiable("expired")
	case c.ID == "":
		return nil, unverifiable("missing jti")
	}
	if !host.Active {
		return nil, &assertionError{status: http.StatusForbidden, reason: "host revoked"}
	}

	// Replay protection: prune expired entries, then record this jti until
	// the assertion (plus skew) could no longer be accepted anyway.
	for k, exp := range p.ssh.seenJTI {
		if exp.Before(now) {
			delete(p.ssh.seenJTI, k)
		}
	}
	key := host.ID + "\x00" + c.ID
	if _, seen := p.ssh.seenJTI[key]; seen {
		return nil, unverifiable("replayed jti")
	}
	p.ssh.seenJTI[key] = time.Unix(c.Expiry, 0).Add(assertionSkew)
	return host, nil
}

// bearerToken extracts the token of an "Authorization: Bearer ..." header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// --- enrolment ---

type enrollPayload struct {
	PublicKey    string    `json:"publicKey"`
	Name         string    `json:"name"`
	Hostname     string    `json:"hostname"`
	Groups       *[]string `json:"groups"`
	Accounts     *[]string `json:"accounts"`
	AgentVersion string    `json:"agentVersion"`
}

func (p *Provider) handleEnroll(w http.ResponseWriter, r *http.Request) {
	tok := bearerToken(r)
	if tok == "" {
		writeStatusError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnrollBody))
	if err != nil {
		writeStatusError(w, http.StatusBadRequest, "invalid_request", "cannot read body")
		return
	}
	var req enrollPayload
	if err := json.Unmarshal(body, &req); err != nil {
		writeStatusError(w, http.StatusBadRequest, "invalid_request", "body is not valid JSON")
		return
	}
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	issued, ok := p.ssh.accessTokens[tok]
	if !ok || issued.exp.Before(now) {
		writeStatusError(w, http.StatusUnauthorized, "invalid_token", "unknown or expired access token")
		return
	}
	if issued.intent != "enroll" {
		writeStatusError(w, http.StatusForbidden, "insufficient_scope", "access token was not issued with intent=enroll")
		return
	}

	pub, err := parseEd25519AuthorizedKey(req.PublicKey)
	if err != nil {
		writeStatusError(w, http.StatusBadRequest, "invalid_request", "publicKey: "+err.Error())
		return
	}
	switch {
	case req.Name == "":
		writeStatusError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	case req.Groups == nil:
		writeStatusError(w, http.StatusBadRequest, "invalid_request", "groups is required (may be empty)")
		return
	case req.Accounts == nil || len(*req.Accounts) == 0:
		writeStatusError(w, http.StatusBadRequest, "invalid_request", "accounts is required and must not be empty")
		return
	}

	fp := ssh.FingerprintSHA256(pub)
	var byKey, byName *Host
	for _, h := range p.ssh.hosts {
		if h.Fingerprint == fp {
			byKey = h
		}
		if h.Name == req.Name {
			byName = h
		}
	}
	status := http.StatusCreated
	var host *Host
	switch {
	case byKey != nil && byKey != byName:
		// Either the key is registered under another name, or (byName ==
		// nil) the caller wants to rename a known key: both are conflicts.
		writeStatusError(w, http.StatusConflict, "conflict", "publicKey is already registered under name "+byKey.Name)
		return
	case byName != nil && byKey == nil:
		writeStatusError(w, http.StatusConflict, "conflict", "name is taken by a host with a different key")
		return
	case byKey != nil:
		host, status = byKey, http.StatusOK
	default:
		host = p.addHostLocked(req.Name, pub)
	}
	host.Hostname = req.Hostname
	host.Groups = append([]string{}, *req.Groups...)
	host.Accounts = append([]string{}, *req.Accounts...)
	host.AgentVersion = req.AgentVersion

	writeJSON(w, status, map[string]any{
		"hostId":   host.ID,
		"name":     host.Name,
		"groups":   host.Groups,
		"accounts": host.Accounts,
	})
}

// parseEd25519AuthorizedKey parses a single OpenSSH public key line and
// insists on ssh-ed25519.
func parseEd25519AuthorizedKey(line string) (ssh.PublicKey, error) {
	if strings.TrimSpace(line) == "" {
		return nil, errors.New("required")
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("not an OpenSSH public key: %w", err)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("must hold exactly one key")
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("key type %s is not ssh-ed25519", pub.Type())
	}
	return pub, nil
}

// --- authorized keys ---

func (p *Provider) handleAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	account, fingerprint, env := q.Get("account"), q.Get("fingerprint"), q.Get("env")
	now := time.Now()

	p.mu.Lock()
	p.ssh.keysRequests++
	p.ssh.keysAccount, p.ssh.keysFingerprint, p.ssh.keysEnv = account, fingerprint, env
	outcome := p.ssh.keysOutcome
	p.mu.Unlock()

	// Simulated outages apply before authentication: a dead provider does
	// not get as far as checking who is asking.
	switch outcome {
	case KeysServerError:
		writeText(w, http.StatusInternalServerError, "internal server error\n")
		return
	case KeysTimeout:
		select {
		case <-r.Context().Done():
		case <-time.After(keysTimeoutDelay):
		}
		writeText(w, http.StatusGatewayTimeout, "timed out\n")
		return
	case KeysOK:
	}

	p.mu.Lock()
	host, aerr := p.verifyHostAssertionLocked(bearerToken(r), now)
	if aerr != nil {
		p.mu.Unlock()
		writeText(w, aerr.status, aerr.reason+"\n")
		return
	}
	if account == "" {
		p.mu.Unlock()
		writeText(w, http.StatusBadRequest, "account is required\n")
		return
	}
	if env != "" && !envNameRe.MatchString(env) {
		p.mu.Unlock()
		writeText(w, http.StatusBadRequest, "env is not a valid variable name\n")
		return
	}
	declared := false
	for _, a := range host.Accounts {
		if a == account {
			declared = true
			break
		}
	}
	if !declared {
		p.mu.Unlock()
		writeText(w, http.StatusForbidden, "account not declared at enrolment\n")
		return
	}
	var lines []string
	if !p.ssh.policyDeny {
		lines = append(lines, p.ssh.keys[account]...)
	}
	p.mu.Unlock()

	if fingerprint != "" {
		lines = filterByFingerprint(lines, fingerprint)
	}
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	writeText(w, http.StatusOK, sb.String())
}

// filterByFingerprint keeps the authorized_keys lines whose key has the
// given SHA256 fingerprint. Unparsable lines never match.
func filterByFingerprint(lines []string, fingerprint string) []string {
	var out []string
	for _, l := range lines {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil && ssh.FingerprintSHA256(pub) == fingerprint {
			out = append(out, l)
		}
	}
	return out
}

// --- helpers ---

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// writeStatusError emits a JSON error body with an explicit status, for the
// enrolment endpoint whose failures are not RFC 6749 400s.
func writeStatusError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}
