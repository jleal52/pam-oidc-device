package testprovider

import (
	"bytes"
	"crypto"
	"crypto/hmac"
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
	"strings"
	"testing"
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
