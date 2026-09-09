// Package testprovider implements an in-memory OpenID Connect provider that
// speaks the OAuth 2.0 Device Authorization Grant (RFC 8628). It is intended
// for unit and integration tests: the outcome of the device flow, the number
// of "authorization_pending" responses, and the claims of the issued ID token
// are all programmable, and every request is recorded for later inspection.
//
// The provider is not a complete or secure OIDC implementation and must never
// be used outside of tests.
package testprovider

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// DeviceGrantType is the grant_type value of RFC 8628 §3.4.
const DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// KeyID is the "kid" of the single signing key published at /jwks.
const KeyID = "test-key-1"

// DefaultClientID is the audience used by SignIDToken when no
// device_authorization request has been received yet.
const DefaultClientID = "test-client"

// Outcome is the final answer the token endpoint gives once no
// "authorization_pending" responses remain.
type Outcome int

const (
	// Approved issues an access token and a signed ID token.
	Approved Outcome = iota
	// Denied answers "access_denied": the user rejected the request.
	Denied
	// Expired answers "expired_token": the device code is no longer valid.
	Expired
)

// Option configures a Provider at construction time.
type Option func(*Provider)

// WithOutcome sets the initial outcome (default Approved).
func WithOutcome(o Outcome) Option { return func(p *Provider) { p.outcome = o } }

// WithClaims sets the initial extra ID token claims.
func WithClaims(c map[string]any) Option { return func(p *Provider) { p.claims = cloneClaims(c) } }

// WithPendingPolls sets the initial number of "authorization_pending" replies.
func WithPendingPolls(n int) Option { return func(p *Provider) { p.pending = n } }

// WithInterval sets the advertised polling interval in seconds (default 1).
func WithInterval(sec int) Option { return func(p *Provider) { p.interval = sec } }

// WithExpiresIn sets the advertised device code lifetime in seconds (default 600).
func WithExpiresIn(sec int) Option { return func(p *Provider) { p.expiresIn = sec } }

// WithListenAddr binds the server to a fixed "host:port" instead of an
// ephemeral loopback port, so that a process outside the test (a PAM
// module under pamtester, for instance) can reach it at a known issuer
// URL. New fails when the address cannot be bound.
func WithListenAddr(addr string) Option { return func(p *Provider) { p.listenAddr = addr } }

// WithRequestLog writes one "METHOD PATH" line per request to w. It lets a
// test that only sees the provider from the outside assert which
// endpoints were (or were not) called.
func WithRequestLog(w io.Writer) Option { return func(p *Provider) { p.requestLog = w } }

// Provider is an in-memory OIDC provider backed by an httptest.Server.
// All methods are safe for concurrent use.
type Provider struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	listenAddr string
	requestLog io.Writer

	mu sync.Mutex
	// programmable behaviour
	outcome   Outcome
	claims    map[string]any
	pending   int
	slowDown  bool
	interval  int
	expiresIn int
	// recorded state
	deviceCode string
	userCode   string
	clientID   string
	scope      string
	deviceName string
	pollCount  int
	// SSH provider contract (ssh.go)
	ssh sshState
}

// New generates an RSA-2048 signing key and starts the HTTP server.
// Call Close when done.
func New(opts ...Option) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("testprovider: generate key: %w", err)
	}
	p := &Provider{
		key:       key,
		outcome:   Approved,
		interval:  1,
		expiresIn: 600,
		ssh:       newSSHState(),
	}
	for _, o := range opts {
		o(p)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("GET /jwks", p.handleJWKS)
	mux.HandleFunc("POST /device_authorization", p.handleDeviceAuthorization)
	mux.HandleFunc("POST /token", p.handleToken)
	mux.HandleFunc("GET /device", p.handleVerificationPage)
	mux.HandleFunc("POST "+SSHBasePath+"/hosts/enroll", p.handleEnroll)
	mux.HandleFunc("GET "+SSHBasePath+"/authorized-keys", p.handleAuthorizedKeys)

	var handler http.Handler = mux
	if p.requestLog != nil {
		handler = p.logRequests(mux)
	}
	if p.listenAddr == "" {
		p.server = httptest.NewServer(handler)
		return p, nil
	}
	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("testprovider: listen on %s: %w", p.listenAddr, err)
	}
	p.server = httptest.NewUnstartedServer(handler)
	// NewUnstartedServer already holds an ephemeral loopback listener;
	// release it before swapping in the requested one.
	_ = p.server.Listener.Close()
	p.server.Listener = ln
	p.server.Start()
	return p, nil
}

// Addr returns the "host:port" the server is listening on.
func (p *Provider) Addr() string { return p.server.Listener.Addr().String() }

func (p *Provider) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(p.requestLog, "%s %s\n", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// Close shuts down the HTTP server.
func (p *Provider) Close() { p.server.Close() }

// URL returns the base URL of the server, without a trailing slash.
func (p *Provider) URL() string { return strings.TrimSuffix(p.server.URL, "/") }

// Issuer returns the OIDC issuer identifier, which equals URL().
func (p *Provider) Issuer() string { return p.URL() }

// SetOutcome programs the final answer of the token endpoint.
func (p *Provider) SetOutcome(o Outcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outcome = o
}

// SetClaims programs extra claims to embed in the ID token when Approved,
// for example "email" or "groups". A "sub" claim overrides the default "user-1".
func (p *Provider) SetClaims(c map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims = cloneClaims(c)
}

// SetPendingPolls programs n "authorization_pending" responses before the
// outcome is delivered.
func (p *Provider) SetPendingPolls(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = n
}

// SetSlowDownOnce arms a single "slow_down" response for the next poll.
func (p *Provider) SetSlowDownOnce() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slowDown = true
}

// SetInterval sets the polling interval (seconds) advertised by
// /device_authorization. The default of 1 keeps tests fast.
func (p *Provider) SetInterval(sec int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.interval = sec
}

// SetExpiresIn sets the device code lifetime (seconds) advertised by
// /device_authorization. The default is 600.
func (p *Provider) SetExpiresIn(sec int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expiresIn = sec
}

// PollCount returns how many requests the token endpoint has received.
func (p *Provider) PollCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pollCount
}

// LastDeviceName returns the device_name form field of the last
// /device_authorization request.
func (p *Provider) LastDeviceName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deviceName
}

// LastClientID returns the client_id of the last /device_authorization request.
func (p *Provider) LastClientID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clientID
}

// LastScope returns the scope of the last /device_authorization request.
func (p *Provider) LastScope() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.scope
}

// SignIDToken returns an RS256-signed JWT with the given claims. Unless the
// caller overrides them, iss is Issuer(), aud is LastClientID() (or
// DefaultClientID), iat is now and exp is now+5m.
func (p *Provider) SignIDToken(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": KeyID}
	signingInput, err := encodeJWT(header, p.withDefaultClaims(claims))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("testprovider: sign: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignHS256 returns a JWT signed with HMAC-SHA256 over secret, carrying the
// same default claims as SignIDToken and a header of "alg":"HS256" with the
// provider's KeyID as "kid". It exists for algorithm-confusion tests: a
// verifier that trusts the "alg" header could accept such a token when the
// secret is the RSA public key material. A correct verifier must reject it.
func (p *Provider) SignHS256(claims map[string]any, secret []byte) (string, error) {
	header := map[string]any{"alg": "HS256", "typ": "JWT", "kid": KeyID}
	signingInput, err := encodeJWT(header, p.withDefaultClaims(claims))
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// SignWithAlgNone returns an unsigned JWT ("alg":"none", empty signature)
// with the same default claims as SignIDToken. Intended for negative tests.
func (p *Provider) SignWithAlgNone(claims map[string]any) string {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	signingInput, err := encodeJWT(header, p.withDefaultClaims(claims))
	if err != nil {
		// Only unmarshalable claim values can fail here; that is a test bug.
		panic(err)
	}
	return signingInput + "."
}

// CorruptSignature returns token with the last bytes of its signature
// flipped, so that it no longer verifies while remaining well-formed.
func (p *Provider) CorruptSignature(token string) string {
	i := strings.LastIndex(token, ".")
	if i < 0 {
		return token
	}
	sig, err := base64.RawURLEncoding.DecodeString(token[i+1:])
	if err != nil || len(sig) == 0 {
		return token[:i+1] + "AAAA"
	}
	for j := len(sig) - 1; j >= 0 && j >= len(sig)-4; j-- {
		sig[j] ^= 0xFF
	}
	return token[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
}

func (p *Provider) withDefaultClaims(claims map[string]any) map[string]any {
	p.mu.Lock()
	aud := p.clientID
	p.mu.Unlock()
	if aud == "" {
		aud = DefaultClientID
	}
	now := time.Now()
	out := map[string]any{
		"iss": p.Issuer(),
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range claims {
		out[k] = v
	}
	return out
}

func encodeJWT(header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("testprovider: marshal header: %w", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("testprovider: marshal claims: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c), nil
}

// --- HTTP handlers ---

func (p *Provider) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	base := p.URL()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"jwks_uri":                              base + "/jwks",
		"device_authorization_endpoint":         base + "/device_authorization",
		"grant_types_supported":                 []string{"authorization_code", DeviceGrantType},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"ssh_access_endpoint":                   p.SSHBase(),
	})
}

func (p *Provider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := &p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": KeyID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (p *Provider) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "malformed form body")
		return
	}
	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		writeError(w, "invalid_request", "client_id is required")
		return
	}
	intent := r.PostForm.Get("intent")
	switch intent {
	case "":
		intent = "login"
	case "login", "enroll":
	default:
		writeError(w, "invalid_request", "intent must be login or enroll")
		return
	}
	hostAssertion := r.PostForm.Get("host_assertion")
	deviceCode, err := randomToken(32)
	if err != nil {
		writeError(w, "server_error", err.Error())
		return
	}
	userCode, err := randomUserCode()
	if err != nil {
		writeError(w, "server_error", err.Error())
		return
	}

	p.mu.Lock()
	// Record the extension parameters first so a test can inspect what the
	// client sent even when the request is refused below.
	p.ssh.hostAssertion = hostAssertion
	p.ssh.account = r.PostForm.Get("account")
	p.ssh.intent = intent
	p.ssh.flowHost = nil
	if hostAssertion == "" && p.ssh.requireHost {
		p.mu.Unlock()
		writeError(w, "invalid_request", "host_assertion is required")
		return
	}
	if hostAssertion != "" {
		host, aerr := p.verifyHostAssertionLocked(hostAssertion, time.Now())
		if aerr != nil {
			p.mu.Unlock()
			writeError(w, "invalid_request", "host_assertion: "+aerr.reason)
			return
		}
		p.ssh.flowHost = host
	}
	p.clientID = clientID
	p.scope = r.PostForm.Get("scope")
	p.deviceName = r.PostForm.Get("device_name")
	p.deviceCode = deviceCode
	p.userCode = userCode
	interval, expiresIn := p.interval, p.expiresIn
	p.mu.Unlock()

	base := p.URL()
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base + "/device",
		"verification_uri_complete": base + "/device?user_code=" + userCode,
		"expires_in":                expiresIn,
		"interval":                  interval,
	})
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "malformed form body")
		return
	}
	if gt := r.PostForm.Get("grant_type"); gt != DeviceGrantType {
		writeError(w, "unsupported_grant_type", "grant_type must be "+DeviceGrantType)
		return
	}
	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		writeError(w, "invalid_request", "client_id is required")
		return
	}
	deviceCode := r.PostForm.Get("device_code")
	if deviceCode == "" {
		writeError(w, "invalid_request", "device_code is required")
		return
	}

	p.mu.Lock()
	p.pollCount++
	if deviceCode != p.deviceCode {
		p.mu.Unlock()
		writeError(w, "invalid_grant", "unknown device_code")
		return
	}
	if p.slowDown {
		p.slowDown = false
		p.mu.Unlock()
		writeError(w, "slow_down", "polling too fast; increase the interval")
		return
	}
	if p.pending > 0 {
		p.pending--
		p.mu.Unlock()
		writeError(w, "authorization_pending", "the user has not yet completed authorization")
		return
	}
	outcome := p.outcome
	scope := p.scope
	claims := map[string]any{"sub": "user-1"}
	for k, v := range p.claims {
		claims[k] = v
	}
	// Host policy (contract §6): only flows that proved which host is
	// asking are subject to it. The test policy allows everyone unless
	// SetPolicyDeny is on.
	hostFlow := p.ssh.flowHost != nil
	if hostFlow && p.ssh.policyDeny && outcome == Approved {
		outcome = Denied
	}
	if hostFlow && p.ssh.account != "" {
		claims["groups"] = appendGroup(claims["groups"], "ssh:"+p.ssh.account)
	}
	intent := p.ssh.intent
	p.mu.Unlock()

	switch outcome {
	case Denied:
		writeError(w, "access_denied", "the user denied the authorization request")
	case Expired:
		writeError(w, "expired_token", "the device_code has expired")
	case Approved:
		accessToken, err := randomToken(16)
		if err != nil {
			writeError(w, "server_error", err.Error())
			return
		}
		idToken, err := p.SignIDToken(claims)
		if err != nil {
			writeError(w, "server_error", err.Error())
			return
		}
		accessToken = "at-" + accessToken
		p.mu.Lock()
		p.ssh.accessTokens[accessToken] = issuedAT{intent: intent, exp: time.Now().Add(accessTokenLifetime)}
		p.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   300,
			"scope":        scope,
			"id_token":     idToken,
		})
	default:
		writeError(w, "server_error", fmt.Sprintf("unknown outcome %d", outcome))
	}
}

// handleVerificationPage is a placeholder for verification_uri so that a
// browser (or a curious integration test) gets something other than 404.
func (p *Provider) handleVerificationPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "test provider: user_code %q would be verified here\n", r.URL.Query().Get("user_code"))
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits an RFC 6749 §5.2 / RFC 8628 §3.5 error response.
func writeError(w http.ResponseWriter, code, description string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("testprovider: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomUserCode returns a code shaped like "ABCD-EFGH" from an alphabet
// without easily confused characters.
func randomUserCode() (string, error) {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ"
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			sb.WriteByte('-')
		}
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("testprovider: random: %w", err)
		}
		sb.WriteByte(alphabet[idx.Int64()])
	}
	return sb.String(), nil
}

// appendGroup returns the groups claim with g appended, accepting the
// []string a test configures or the []any a decoded JSON document yields.
// The input slice is never mutated.
func appendGroup(groups any, g string) []any {
	var out []any
	switch gs := groups.(type) {
	case []string:
		for _, x := range gs {
			out = append(out, x)
		}
	case []any:
		out = append(out, gs...)
	}
	return append(out, g)
}

func cloneClaims(c map[string]any) map[string]any {
	if c == nil {
		return nil
	}
	out := make(map[string]any, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}
