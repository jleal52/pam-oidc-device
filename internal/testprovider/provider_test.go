package testprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jleal52/pam-oidc-device/internal/hostid"
)

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

func newProvider(t *testing.T, opts ...Option) *Provider {
	t.Helper()
	p, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func postForm(t *testing.T, endpoint string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(endpoint, form) //nolint:gosec // test server URL
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("POST %s: Content-Type = %q, want application/json", endpoint, ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v (body %q)", endpoint, err, body)
	}
	return resp.StatusCode, out
}

func getJSON(t *testing.T, endpoint string) map[string]any {
	t.Helper()
	resp, err := http.Get(endpoint) //nolint:gosec // test server URL
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", endpoint, resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", endpoint, err)
	}
	return out
}

func startDeviceFlow(t *testing.T, p *Provider, deviceName string) string {
	t.Helper()
	status, body := postForm(t, p.URL()+"/device_authorization", url.Values{
		"client_id":   {"ssh-pam"},
		"scope":       {"openid profile email groups"},
		"device_name": {deviceName},
	})
	if status != http.StatusOK {
		t.Fatalf("device_authorization: status %d body %v", status, body)
	}
	code, _ := body["device_code"].(string)
	if code == "" {
		t.Fatalf("device_authorization: missing device_code in %v", body)
	}
	return code
}

func poll(t *testing.T, p *Provider, deviceCode string) (int, map[string]any) {
	t.Helper()
	return postForm(t, p.URL()+"/token", url.Values{
		"grant_type":  {deviceGrant},
		"client_id":   {"ssh-pam"},
		"device_code": {deviceCode},
	})
}

func expectError(t *testing.T, status int, body map[string]any, code string) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %v)", status, body)
	}
	if got := body["error"]; got != code {
		t.Fatalf("error = %v, want %q", got, code)
	}
	if desc, _ := body["error_description"].(string); desc == "" {
		t.Fatalf("missing error_description in %v", body)
	}
}

// publicKeyFromJWKS fetches /jwks and rebuilds the RSA public key for kid.
func publicKeyFromJWKS(t *testing.T, p *Provider, kid string) *rsa.PublicKey {
	t.Helper()
	jwks := getJSON(t, p.URL()+"/jwks")
	keys, _ := jwks["keys"].([]any)
	for _, k := range keys {
		key, _ := k.(map[string]any)
		if key["kid"] != kid {
			continue
		}
		if key["kty"] != "RSA" || key["alg"] != "RS256" || key["use"] != "sig" {
			t.Fatalf("unexpected JWK attributes: %v", key)
		}
		nb, err := base64.RawURLEncoding.DecodeString(key["n"].(string))
		if err != nil {
			t.Fatalf("decode n: %v", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(key["e"].(string))
		if err != nil {
			t.Fatalf("decode e: %v", err)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	}
	t.Fatalf("kid %q not found in JWKS %v", kid, jwks)
	return nil
}

// verifyRS256 checks the JWT signature against pub and returns header and claims.
func verifyRS256(token string, pub *rsa.PublicKey) (map[string]any, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("token must have three segments")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, nil, err
	}
	var header, claims map[string]any
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, nil, err
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, nil, err
	}
	return header, claims, nil
}

func decodeSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func TestDiscovery(t *testing.T) {
	p := newProvider(t)
	doc := getJSON(t, p.URL()+"/.well-known/openid-configuration")

	if doc["issuer"] != p.Issuer() {
		t.Errorf("issuer = %v, want %q", doc["issuer"], p.Issuer())
	}
	if p.Issuer() != p.URL() || strings.HasSuffix(p.Issuer(), "/") {
		t.Errorf("Issuer() = %q, URL() = %q: want equal and without trailing slash", p.Issuer(), p.URL())
	}
	want := map[string]string{
		"device_authorization_endpoint": p.URL() + "/device_authorization",
		"token_endpoint":                p.URL() + "/token",
		"jwks_uri":                      p.URL() + "/jwks",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %q", k, doc[k], v)
		}
	}
	if _, ok := doc["authorization_endpoint"].(string); !ok {
		t.Errorf("missing authorization_endpoint")
	}
	grants, _ := doc["grant_types_supported"].([]any)
	found := false
	for _, g := range grants {
		if g == deviceGrant {
			found = true
		}
	}
	if !found {
		t.Errorf("grant_types_supported = %v, want to include %q", grants, deviceGrant)
	}
	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 1 || algs[0] != "RS256" {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [RS256]", algs)
	}
}

func TestDeviceAuthorizationRecordsRequest(t *testing.T) {
	p := newProvider(t)
	p.SetInterval(7)
	p.SetExpiresIn(120)

	status, body := postForm(t, p.URL()+"/device_authorization", url.Values{
		"client_id":   {"my-client"},
		"scope":       {"openid email"},
		"device_name": {"host42"},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, body %v", status, body)
	}
	if p.LastClientID() != "my-client" {
		t.Errorf("LastClientID = %q", p.LastClientID())
	}
	if p.LastScope() != "openid email" {
		t.Errorf("LastScope = %q", p.LastScope())
	}
	if p.LastDeviceName() != "host42" {
		t.Errorf("LastDeviceName = %q", p.LastDeviceName())
	}
	userCode, _ := body["user_code"].(string)
	if len(userCode) != 9 || userCode[4] != '-' {
		t.Errorf("user_code = %q, want XXXX-XXXX", userCode)
	}
	if body["verification_uri"] != p.URL()+"/device" {
		t.Errorf("verification_uri = %v", body["verification_uri"])
	}
	if vc, _ := body["verification_uri_complete"].(string); !strings.Contains(vc, userCode) {
		t.Errorf("verification_uri_complete = %q, want to contain user_code", vc)
	}
	if body["interval"] != float64(7) {
		t.Errorf("interval = %v, want 7", body["interval"])
	}
	if body["expires_in"] != float64(120) {
		t.Errorf("expires_in = %v, want 120", body["expires_in"])
	}
}

func TestDeviceAuthorizationRequiresClientID(t *testing.T) {
	p := newProvider(t)
	status, body := postForm(t, p.URL()+"/device_authorization", url.Values{})
	expectError(t, status, body, "invalid_request")
}

func TestTokenPendingThenApproved(t *testing.T) {
	p := newProvider(t)
	p.SetOutcome(Approved)
	p.SetPendingPolls(2)
	p.SetClaims(map[string]any{"email": "alice@example.org", "groups": []string{"ssh-admins"}})

	code := startDeviceFlow(t, p, "host1")

	for i := 0; i < 2; i++ {
		status, body := poll(t, p, code)
		expectError(t, status, body, "authorization_pending")
	}
	status, body := poll(t, p, code)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body %v", status, body)
	}
	if p.PollCount() != 3 {
		t.Errorf("PollCount = %d, want 3", p.PollCount())
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}
	if at, _ := body["access_token"].(string); !strings.HasPrefix(at, "at-") {
		t.Errorf("access_token = %q", at)
	}
	if body["scope"] != "openid profile email groups" {
		t.Errorf("scope = %v", body["scope"])
	}
	if body["expires_in"] != float64(300) {
		t.Errorf("expires_in = %v", body["expires_in"])
	}

	idToken, _ := body["id_token"].(string)
	pub := publicKeyFromJWKS(t, p, "test-key-1")
	header, claims, err := verifyRS256(idToken, pub)
	if err != nil {
		t.Fatalf("id_token verification failed: %v", err)
	}
	if header["alg"] != "RS256" || header["kid"] != "test-key-1" || header["typ"] != "JWT" {
		t.Errorf("header = %v", header)
	}
	if claims["iss"] != p.Issuer() {
		t.Errorf("iss = %v, want %q", claims["iss"], p.Issuer())
	}
	if claims["aud"] != "ssh-pam" {
		t.Errorf("aud = %v, want ssh-pam", claims["aud"])
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", claims["sub"])
	}
	if claims["email"] != "alice@example.org" {
		t.Errorf("email = %v", claims["email"])
	}
	groups, _ := claims["groups"].([]any)
	if len(groups) != 1 || groups[0] != "ssh-admins" {
		t.Errorf("groups = %v", claims["groups"])
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if iat == 0 || exp <= iat {
		t.Errorf("iat/exp = %v/%v", iat, exp)
	}
}

func TestTokenSlowDownOnceThenPending(t *testing.T) {
	p := newProvider(t)
	p.SetPendingPolls(1)
	p.SetSlowDownOnce()

	code := startDeviceFlow(t, p, "host1")

	status, body := poll(t, p, code)
	expectError(t, status, body, "slow_down")
	status, body = poll(t, p, code)
	expectError(t, status, body, "authorization_pending")
	status, body = poll(t, p, code)
	if status != http.StatusOK {
		t.Fatalf("third poll: status %d body %v", status, body)
	}
	if p.PollCount() != 3 {
		t.Errorf("PollCount = %d, want 3", p.PollCount())
	}
}

func TestTokenDenied(t *testing.T) {
	p := newProvider(t)
	p.SetOutcome(Denied)
	code := startDeviceFlow(t, p, "host1")
	status, body := poll(t, p, code)
	expectError(t, status, body, "access_denied")
}

func TestTokenExpired(t *testing.T) {
	p := newProvider(t)
	p.SetOutcome(Expired)
	code := startDeviceFlow(t, p, "host1")
	status, body := poll(t, p, code)
	expectError(t, status, body, "expired_token")
}

func TestTokenWrongDeviceCode(t *testing.T) {
	p := newProvider(t)
	startDeviceFlow(t, p, "host1")
	status, body := poll(t, p, "not-the-code")
	expectError(t, status, body, "invalid_grant")
}

func TestTokenUnsupportedGrantType(t *testing.T) {
	p := newProvider(t)
	code := startDeviceFlow(t, p, "host1")
	status, body := postForm(t, p.URL()+"/token", url.Values{
		"grant_type":  {"authorization_code"},
		"client_id":   {"ssh-pam"},
		"device_code": {code},
	})
	expectError(t, status, body, "unsupported_grant_type")
}

func TestSignIDTokenDefaultsAndOverrides(t *testing.T) {
	p := newProvider(t)
	pub := publicKeyFromJWKS(t, p, "test-key-1")

	tok, err := p.SignIDToken(map[string]any{"sub": "bob"})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	_, claims, err := verifyRS256(tok, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["iss"] != p.Issuer() || claims["aud"] != "test-client" || claims["sub"] != "bob" {
		t.Errorf("claims = %v", claims)
	}

	tok, err = p.SignIDToken(map[string]any{"iss": "https://evil.example", "aud": "other"})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	_, claims, err = verifyRS256(tok, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["iss"] != "https://evil.example" || claims["aud"] != "other" {
		t.Errorf("overrides not honoured: %v", claims)
	}
}

func TestSignWithAlgNone(t *testing.T) {
	p := newProvider(t)
	tok := p.SignWithAlgNone(map[string]any{"sub": "mallory"})
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("token = %q, want header.payload. with empty signature", tok)
	}
	var header, claims map[string]any
	if err := decodeSegment(parts[0], &header); err != nil {
		t.Fatalf("header: %v", err)
	}
	if header["alg"] != "none" {
		t.Errorf("alg = %v, want none", header["alg"])
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims["sub"] != "mallory" || claims["iss"] != p.Issuer() {
		t.Errorf("claims = %v", claims)
	}
}

func TestCorruptSignatureFailsVerification(t *testing.T) {
	p := newProvider(t)
	pub := publicKeyFromJWKS(t, p, "test-key-1")
	tok, err := p.SignIDToken(nil)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	if _, _, err := verifyRS256(tok, pub); err != nil {
		t.Fatalf("pristine token must verify: %v", err)
	}
	bad := p.CorruptSignature(tok)
	if bad == tok {
		t.Fatalf("CorruptSignature returned the same token")
	}
	if _, _, err := verifyRS256(bad, pub); err == nil {
		t.Fatalf("corrupted token verified")
	}
}

func TestSignHS256(t *testing.T) {
	p := newProvider(t)
	secret := []byte("shared-secret")
	tok, err := p.SignHS256(map[string]any{"sub": "mallory"}, secret)
	if err != nil {
		t.Fatalf("SignHS256: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["alg"] != "HS256" || hdr["kid"] != KeyID {
		t.Errorf("header = %v, want alg HS256 and kid %q", hdr, KeyID)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parts[2] != want {
		t.Errorf("signature = %q, want HMAC-SHA256 over the signing input %q", parts[2], want)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "mallory" || claims["iss"] != p.Issuer() || claims["aud"] != DefaultClientID {
		t.Errorf("claims = %v, want sub/iss/aud defaults applied", claims)
	}
}

func TestWithListenAddrBindsFixedAddress(t *testing.T) {
	// Reserve a free port, release it and ask the provider to take it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	p := newProvider(t, WithListenAddr(addr))
	if p.Addr() != addr {
		t.Errorf("Addr() = %q, want %q", p.Addr(), addr)
	}
	if want := "http://" + addr; p.Issuer() != want {
		t.Errorf("Issuer() = %q, want %q", p.Issuer(), want)
	}
	doc := getJSON(t, p.Issuer()+"/.well-known/openid-configuration")
	if doc["issuer"] != p.Issuer() {
		t.Errorf("issuer = %v, want %q", doc["issuer"], p.Issuer())
	}

	// The address is now taken: a second provider on it must fail.
	if _, err := New(WithListenAddr(addr)); err == nil {
		t.Errorf("New(WithListenAddr(%q)) on a busy port: want error", addr)
	}
}

func TestWithRequestLogRecordsMethodAndPath(t *testing.T) {
	var buf bytes.Buffer
	p := newProvider(t, WithRequestLog(&buf))

	getJSON(t, p.URL()+"/.well-known/openid-configuration")
	postForm(t, p.URL()+"/device_authorization", url.Values{"client_id": {"c"}})

	got := buf.String()
	want := "GET /.well-known/openid-configuration\nPOST /device_authorization\n"
	if got != want {
		t.Errorf("request log = %q, want %q", got, want)
	}
}

// --- SSH provider contract (docs/PROVIDER-CONTRACT.md) ---

// newHostIdentity generates a fresh Ed25519 host identity in a temp dir.
func newHostIdentity(t *testing.T) *hostid.Identity {
	t.Helper()
	id, err := hostid.Generate(filepath.Join(t.TempDir(), "host.key"), "oidc-ssh@test")
	if err != nil {
		t.Fatalf("hostid.Generate: %v", err)
	}
	return id
}

// deviceFlowToken runs a complete device flow with the given extension
// parameters and returns the token response.
func deviceFlowToken(t *testing.T, p *Provider, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"client_id":   {"ssh-pam"},
		"scope":       {"openid profile email groups"},
		"device_name": {"host1"},
	}
	for k, v := range extra {
		form[k] = v
	}
	status, body := postForm(t, p.URL()+"/device_authorization", form)
	if status != http.StatusOK {
		t.Fatalf("device_authorization: status %d body %v", status, body)
	}
	code, _ := body["device_code"].(string)
	return poll(t, p, code)
}

// enrollToken obtains an access token through a device flow with intent=enroll.
func enrollToken(t *testing.T, p *Provider) string {
	t.Helper()
	status, body := deviceFlowToken(t, p, url.Values{"intent": {"enroll"}})
	if status != http.StatusOK {
		t.Fatalf("token: status %d body %v", status, body)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("token: missing access_token in %v", body)
	}
	return at
}

func enrollRequest(t *testing.T, p *Provider, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, p.SSHBase()+"/hosts/enroll", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST enroll: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("decode enroll response: %v (body %q)", err, data)
		}
	}
	return resp.StatusCode, out
}

func enrollBody(id *hostid.Identity, name string, accounts ...string) map[string]any {
	return map[string]any{
		"publicKey":    id.PublicKeyLine,
		"name":         name,
		"hostname":     name + ".internal.example",
		"groups":       []string{"bastions"},
		"accounts":     accounts,
		"agentVersion": "0.2.0-test",
	}
}

// enrollHost enrols id under name and returns the hostId.
func enrollHost(t *testing.T, p *Provider, id *hostid.Identity, name string, accounts ...string) string {
	t.Helper()
	status, body := enrollRequest(t, p, enrollToken(t, p), enrollBody(id, name, accounts...))
	if status != http.StatusCreated {
		t.Fatalf("enroll: status %d body %v", status, body)
	}
	hostID, _ := body["hostId"].(string)
	if hostID == "" {
		t.Fatalf("enroll: missing hostId in %v", body)
	}
	return hostID
}

func assertion(t *testing.T, id *hostid.Identity, hostID, aud string) string {
	t.Helper()
	tok, err := id.Assertion(hostID, aud, nil)
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	return tok
}

// getKeys calls authorized-keys with the given bearer and query and returns
// status, headers and body.
func getKeys(t *testing.T, p *Provider, bearer string, query url.Values) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, p.SSHBase()+"/authorized-keys?"+query.Encode(), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET authorized-keys: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, string(data)
}

func userKeyLine(t *testing.T, comment string) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	return `environment="OIDC_USER=` + comment + `",environment="OIDC_SUB=sub-` + comment + `" ` + line,
		ssh.FingerprintSHA256(sshPub)
}

func TestDiscoveryAdvertisesSSHAccessEndpoint(t *testing.T) {
	p := newProvider(t)
	doc := getJSON(t, p.URL()+"/.well-known/openid-configuration")
	if doc["ssh_access_endpoint"] != p.SSHBase() {
		t.Errorf("ssh_access_endpoint = %v, want %q", doc["ssh_access_endpoint"], p.SSHBase())
	}
	if p.SSHBase() != p.URL()+SSHBasePath || SSHBasePath != "/api/ssh" {
		t.Errorf("SSHBase() = %q, want %q", p.SSHBase(), p.URL()+"/api/ssh")
	}
}

func TestEnrollFlow(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)
	token := enrollToken(t, p)

	status, body := enrollRequest(t, p, token, enrollBody(id, "host01", "systems", "ops"))
	if status != http.StatusCreated {
		t.Fatalf("first enroll: status %d body %v", status, body)
	}
	hostID, _ := body["hostId"].(string)
	if len(hostID) != 24 {
		t.Errorf("hostId = %q, want 24 hex chars", hostID)
	}
	if body["name"] != "host01" {
		t.Errorf("name = %v", body["name"])
	}
	if groups, _ := body["groups"].([]any); len(groups) != 1 || groups[0] != "bastions" {
		t.Errorf("groups = %v", body["groups"])
	}
	if accounts, _ := body["accounts"].([]any); len(accounts) != 2 || accounts[0] != "systems" || accounts[1] != "ops" {
		t.Errorf("accounts = %v", body["accounts"])
	}
	if p.LastIntent() != "enroll" {
		t.Errorf("LastIntent = %q, want enroll", p.LastIntent())
	}

	// Re-enrolment with the same key and name updates metadata and keeps the id.
	again := enrollBody(id, "host01", "systems")
	status, body = enrollRequest(t, p, token, again)
	if status != http.StatusOK {
		t.Fatalf("re-enroll: status %d body %v", status, body)
	}
	if body["hostId"] != hostID {
		t.Errorf("re-enroll hostId = %v, want %q", body["hostId"], hostID)
	}
	if accounts, _ := body["accounts"].([]any); len(accounts) != 1 || accounts[0] != "systems" {
		t.Errorf("re-enroll accounts = %v, want [systems]", body["accounts"])
	}
	hosts := p.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("Hosts() = %d entries, want 1", len(hosts))
	}
	if h := hosts[hostID]; h.Name != "host01" || h.Hostname != "host01.internal.example" || len(h.Accounts) != 1 || !h.Active {
		t.Errorf("stored host = %+v", h)
	}

	// Same key under another name conflicts.
	status, _ = enrollRequest(t, p, token, enrollBody(id, "host02", "systems"))
	if status != http.StatusConflict {
		t.Errorf("same key, other name: status %d, want 409", status)
	}
	// Taken name with another key conflicts too.
	status, _ = enrollRequest(t, p, token, enrollBody(newHostIdentity(t), "host01", "systems"))
	if status != http.StatusConflict {
		t.Errorf("taken name, other key: status %d, want 409", status)
	}
	if len(p.Hosts()) != 1 {
		t.Errorf("conflicting enrolments must not create hosts; got %d", len(p.Hosts()))
	}
}

func TestEnrollRejectsBadTokens(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)

	status, _ := enrollRequest(t, p, "", enrollBody(id, "host01", "systems"))
	if status != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", status)
	}
	status, _ = enrollRequest(t, p, "at-garbage", enrollBody(id, "host01", "systems"))
	if status != http.StatusUnauthorized {
		t.Errorf("garbage token: status %d, want 401", status)
	}

	// A token from a plain login flow may not enrol hosts.
	tokStatus, tokBody := deviceFlowToken(t, p, nil)
	if tokStatus != http.StatusOK {
		t.Fatalf("login token: status %d body %v", tokStatus, tokBody)
	}
	if p.LastIntent() != "login" {
		t.Errorf("LastIntent = %q, want login by default", p.LastIntent())
	}
	loginToken, _ := tokBody["access_token"].(string)
	status, _ = enrollRequest(t, p, loginToken, enrollBody(id, "host01", "systems"))
	if status != http.StatusForbidden {
		t.Errorf("login-intent token: status %d, want 403", status)
	}
	if len(p.Hosts()) != 0 {
		t.Errorf("no host must be created; got %d", len(p.Hosts()))
	}
}

func TestEnrollValidatesBody(t *testing.T) {
	p := newProvider(t)
	token := enrollToken(t, p)
	id := newHostIdentity(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	cases := map[string]map[string]any{
		"garbage key": {"publicKey": "not a key", "name": "h", "groups": []string{}, "accounts": []string{"a"}},
		"rsa key":     {"publicKey": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rsaPub))), "name": "h", "groups": []string{}, "accounts": []string{"a"}},
		"no name":     {"publicKey": id.PublicKeyLine, "groups": []string{}, "accounts": []string{"a"}},
		"no groups":   {"publicKey": id.PublicKeyLine, "name": "h", "accounts": []string{"a"}},
		"no accounts": {"publicKey": id.PublicKeyLine, "name": "h", "groups": []string{}},
	}
	for name, body := range cases {
		status, resp := enrollRequest(t, p, token, body)
		if status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %v)", name, status, resp)
		}
	}
	if len(p.Hosts()) != 0 {
		t.Errorf("invalid enrolments must not create hosts; got %d", len(p.Hosts()))
	}
}

func TestAuthorizedKeys(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)
	hostID := enrollHost(t, p, id, "host01", "systems", "ops")

	alice, aliceFP := userKeyLine(t, "alice")
	bob, _ := userKeyLine(t, "bob")
	p.SetAuthorizedKeys("systems", []string{alice, bob})

	status, hdr, body := getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), url.Values{"account": {"systems"}})
	if status != http.StatusOK {
		t.Fatalf("status %d body %q", status, body)
	}
	if ct := hdr.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := hdr.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if body != alice+"\n"+bob+"\n" {
		t.Errorf("body = %q, want both lines", body)
	}
	if p.LastKeysAccount() != "systems" || p.LastKeysFingerprint() != "" || p.LastKeysEnv() != "" {
		t.Errorf("recorded account/fp/env = %q/%q/%q", p.LastKeysAccount(), p.LastKeysFingerprint(), p.LastKeysEnv())
	}

	// Fingerprint filter returns only the matching key.
	status, _, body = getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), url.Values{
		"account": {"systems"}, "fingerprint": {aliceFP}, "env": {"MY_USER"},
	})
	if status != http.StatusOK || body != alice+"\n" {
		t.Errorf("fingerprint filter: status %d body %q", status, body)
	}
	if p.LastKeysFingerprint() != aliceFP || p.LastKeysEnv() != "MY_USER" {
		t.Errorf("recorded fp/env = %q/%q", p.LastKeysFingerprint(), p.LastKeysEnv())
	}

	// An account with nothing programmed is an empty, authoritative 200.
	status, _, body = getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), url.Values{"account": {"ops"}})
	if status != http.StatusOK || body != "" {
		t.Errorf("empty account: status %d body %q", status, body)
	}
	if p.KeysRequests() != 3 {
		t.Errorf("KeysRequests = %d, want 3", p.KeysRequests())
	}
}

func TestAuthorizedKeysRejectsBadAssertions(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)
	hostID := enrollHost(t, p, id, "host01", "systems")
	p.SetAuthorizedKeys("systems", []string{"ssh-ed25519 AAAA alice"})
	q := url.Values{"account": {"systems"}}

	// Replay: the same assertion twice.
	tok := assertion(t, id, hostID, p.SSHBase())
	if status, _, _ := getKeys(t, p, tok, q); status != http.StatusOK {
		t.Fatalf("first use: status %d", status)
	}
	if status, _, _ := getKeys(t, p, tok, q); status != http.StatusUnauthorized {
		t.Errorf("replay: status %d, want 401", status)
	}
	// Wrong audience.
	if status, _, _ := getKeys(t, p, assertion(t, id, hostID, p.SSHBase()+"/"), q); status != http.StatusUnauthorized {
		t.Errorf("wrong aud: status %d, want 401", status)
	}
	// Unknown host id.
	if status, _, _ := getKeys(t, p, assertion(t, id, "000000000000000000000000", p.SSHBase()), q); status != http.StatusUnauthorized {
		t.Errorf("unknown host: status %d, want 401", status)
	}
	// Signed by another key for a known host id.
	if status, _, _ := getKeys(t, p, assertion(t, newHostIdentity(t), hostID, p.SSHBase()), q); status != http.StatusUnauthorized {
		t.Errorf("wrong key: status %d, want 401", status)
	}
	// Outside the time window.
	old, err := id.Assertion(hostID, p.SSHBase(), func() time.Time { return time.Now().Add(-5 * time.Minute) })
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	if status, _, _ := getKeys(t, p, old, q); status != http.StatusUnauthorized {
		t.Errorf("expired: status %d, want 401", status)
	}
	// No bearer, garbage bearer.
	if status, _, _ := getKeys(t, p, "", q); status != http.StatusUnauthorized {
		t.Errorf("no bearer: status %d, want 401", status)
	}
	if status, _, _ := getKeys(t, p, "not.a.jwt", q); status != http.StatusUnauthorized {
		t.Errorf("garbage bearer: status %d, want 401", status)
	}
	// Undeclared account.
	if status, _, _ := getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), url.Values{"account": {"root"}}); status != http.StatusForbidden {
		t.Errorf("undeclared account: status %d, want 403", status)
	}
	// Revoked host.
	p.RevokeHost(hostID)
	if status, _, _ := getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), q); status != http.StatusForbidden {
		t.Errorf("revoked host: status %d, want 403", status)
	}
}

func TestAuthorizedKeysOutcomes(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)
	hostID := p.AddHost("host01", mustParseKey(t, id.PublicKeyLine), []string{"systems"}, nil)
	q := url.Values{"account": {"systems"}}

	p.SetKeysOutcome(KeysServerError)
	status, _, _ := getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), q)
	if status != http.StatusInternalServerError {
		t.Errorf("KeysServerError: status %d, want 500", status)
	}

	p.SetKeysOutcome(KeysTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.SSHBase()+"/authorized-keys?"+q.Encode(), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+assertion(t, id, hostID, p.SSHBase()))
	start := time.Now()
	if _, err := http.DefaultClient.Do(req); err == nil { //nolint:bodyclose // the request must fail
		t.Errorf("KeysTimeout: expected the client to time out")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("KeysTimeout: handler did not release on context cancellation")
	}

	p.SetKeysOutcome(KeysOK)
	p.SetAuthorizedKeys("systems", []string{"ssh-ed25519 AAAA alice"})
	status, _, body := getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), q)
	if status != http.StatusOK || body != "ssh-ed25519 AAAA alice\n" {
		t.Errorf("KeysOK: status %d body %q", status, body)
	}
}

func mustParseKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	return pub
}

func TestDeviceAuthorizationRecordsExtensions(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)
	hostID := enrollHost(t, p, id, "host01", "systems")
	p.SetClaims(map[string]any{"groups": []string{"ssh-admins"}})

	tok := assertion(t, id, hostID, p.SSHBase())
	status, body := deviceFlowToken(t, p, url.Values{
		"host_assertion": {tok}, "account": {"systems"}, "intent": {"login"},
	})
	if status != http.StatusOK {
		t.Fatalf("token: status %d body %v", status, body)
	}
	if p.LastHostAssertion() != tok || p.LastAccount() != "systems" || p.LastIntent() != "login" {
		t.Errorf("recorded assertion/account/intent = %q/%q/%q", p.LastHostAssertion(), p.LastAccount(), p.LastIntent())
	}

	idToken, _ := body["id_token"].(string)
	_, claims, err := verifyRS256(idToken, publicKeyFromJWKS(t, p, KeyID))
	if err != nil {
		t.Fatalf("id_token: %v", err)
	}
	groups, _ := claims["groups"].([]any)
	if len(groups) != 2 || groups[0] != "ssh-admins" || groups[1] != "ssh:systems" {
		t.Errorf("groups = %v, want [ssh-admins ssh:systems]", claims["groups"])
	}

	// Without a host assertion the provider cannot apply host policy: no ssh:* group.
	status, body = deviceFlowToken(t, p, url.Values{"account": {"systems"}})
	if status != http.StatusOK {
		t.Fatalf("plain token: status %d body %v", status, body)
	}
	idToken, _ = body["id_token"].(string)
	_, claims, err = verifyRS256(idToken, publicKeyFromJWKS(t, p, KeyID))
	if err != nil {
		t.Fatalf("id_token: %v", err)
	}
	if groups, _ := claims["groups"].([]any); len(groups) != 1 || groups[0] != "ssh-admins" {
		t.Errorf("plain flow groups = %v, want [ssh-admins]", claims["groups"])
	}
	if p.LastHostAssertion() != "" {
		t.Errorf("LastHostAssertion = %q, want empty after a plain flow", p.LastHostAssertion())
	}
}

func TestDeviceAuthorizationRejectsBadExtensions(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)
	hostID := enrollHost(t, p, id, "host01", "systems")
	base := url.Values{"client_id": {"ssh-pam"}, "scope": {"openid"}}
	withParams := func(extra url.Values) url.Values {
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		for k, v := range extra {
			form[k] = v
		}
		return form
	}

	// Invalid assertion (wrong aud) is invalid_request.
	status, body := postForm(t, p.URL()+"/device_authorization", withParams(url.Values{
		"host_assertion": {assertion(t, id, hostID, "https://elsewhere.example/api/ssh")},
	}))
	expectError(t, status, body, "invalid_request")

	// A valid assertion consumed by device_authorization cannot be replayed.
	tok := assertion(t, id, hostID, p.SSHBase())
	if status, body := postForm(t, p.URL()+"/device_authorization", withParams(url.Values{"host_assertion": {tok}})); status != http.StatusOK {
		t.Fatalf("valid assertion: status %d body %v", status, body)
	}
	status, body = postForm(t, p.URL()+"/device_authorization", withParams(url.Values{"host_assertion": {tok}}))
	expectError(t, status, body, "invalid_request")

	// Unknown intent.
	status, body = postForm(t, p.URL()+"/device_authorization", withParams(url.Values{"intent": {"delete"}}))
	expectError(t, status, body, "invalid_request")

	// SetRequireHost demands an assertion.
	p.SetRequireHost(true)
	status, body = postForm(t, p.URL()+"/device_authorization", withParams(nil))
	expectError(t, status, body, "invalid_request")
	if status, body := postForm(t, p.URL()+"/device_authorization", withParams(url.Values{
		"host_assertion": {assertion(t, id, hostID, p.SSHBase())},
	})); status != http.StatusOK {
		t.Errorf("require host with assertion: status %d body %v", status, body)
	}
}

func TestPolicyDeny(t *testing.T) {
	p := newProvider(t)
	id := newHostIdentity(t)
	hostID := enrollHost(t, p, id, "host01", "systems")
	p.SetAuthorizedKeys("systems", []string{"ssh-ed25519 AAAA alice"})
	p.SetPolicyDeny(true)

	status, body := deviceFlowToken(t, p, url.Values{
		"host_assertion": {assertion(t, id, hostID, p.SSHBase())}, "account": {"systems"},
	})
	expectError(t, status, body, "access_denied")

	// The same policy answers authorized-keys with an empty, authoritative 200.
	status, _, keys := getKeys(t, p, assertion(t, id, hostID, p.SSHBase()), url.Values{"account": {"systems"}})
	if status != http.StatusOK || keys != "" {
		t.Errorf("policy deny keys: status %d body %q, want empty 200", status, keys)
	}

	// Flows without a host assertion are outside host policy and still succeed.
	if status, body := deviceFlowToken(t, p, nil); status != http.StatusOK {
		t.Errorf("plain flow under policy deny: status %d body %v", status, body)
	}
}
