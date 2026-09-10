package oidc_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/jleal52/pam-oidc-device/internal/oidc"
	"github.com/jleal52/pam-oidc-device/internal/testprovider"
)

const testScope = "openid profile groups"

func newProvider(t *testing.T, opts ...testprovider.Option) *testprovider.Provider {
	t.Helper()
	p, err := testprovider.New(opts...)
	if err != nil {
		t.Fatalf("testprovider.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func newClient(t *testing.T, p *testprovider.Provider) *oidc.Client {
	t.Helper()
	c, err := oidc.New(context.Background(), oidc.Options{
		Issuer:            p.Issuer(),
		ClientID:          testprovider.DefaultClientID,
		Scope:             testScope,
		HTTPTimeout:       5 * time.Second,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return c
}

func startFlow(t *testing.T, c *oidc.Client, deviceName string) *oauth2.DeviceAuthResponse {
	t.Helper()
	da, err := c.StartDeviceAuth(context.Background(), deviceName, nil)
	if err != nil {
		t.Fatalf("StartDeviceAuth: %v", err)
	}
	return da
}

// --- New ---

func TestNewDiscoversProvider(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	if c := newClient(t, p); c == nil {
		t.Fatal("New returned nil client")
	}
}

func TestNewWithoutDeviceEndpoint(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)

	_, err := oidc.New(context.Background(), oidc.Options{
		Issuer:            srv.URL,
		ClientID:          "x",
		Scope:             "openid",
		HTTPTimeout:       5 * time.Second,
		AllowInsecureHTTP: true,
	})
	if !errors.Is(err, oidc.ErrNoDeviceFlow) {
		t.Fatalf("err = %v, want ErrNoDeviceFlow", err)
	}
}

func TestNewDiscoveryFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	_, err := oidc.New(context.Background(), oidc.Options{
		Issuer:            srv.URL,
		ClientID:          "x",
		HTTPTimeout:       5 * time.Second,
		AllowInsecureHTTP: true,
	})
	if !errors.Is(err, oidc.ErrDiscovery) {
		t.Fatalf("err = %v, want ErrDiscovery", err)
	}
}

type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected HTTP request to %s", r.URL)
	return nil, errors.New("no network allowed")
}

func TestNewRejectsPlainHTTPIssuer(t *testing.T) {
	t.Parallel()
	_, err := oidc.New(context.Background(), oidc.Options{
		Issuer:      "http://idp.invalid",
		ClientID:    "x",
		HTTPTimeout: time.Second,
		HTTPClient:  &http.Client{Transport: failingTransport{t}},
	})
	if !errors.Is(err, oidc.ErrDiscovery) {
		t.Fatalf("err = %v, want ErrDiscovery", err)
	}
}

// --- StartDeviceAuth ---

func TestStartDeviceAuthSendsParameters(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)

	da := startFlow(t, c, "my-host")
	if da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		t.Fatalf("incomplete device auth response: %+v", da)
	}
	if got := p.LastDeviceName(); got != "my-host" {
		t.Errorf("device_name = %q, want %q", got, "my-host")
	}
	if got := p.LastClientID(); got != testprovider.DefaultClientID {
		t.Errorf("client_id = %q, want %q", got, testprovider.DefaultClientID)
	}
	if got := p.LastScope(); got != testScope {
		t.Errorf("scope = %q, want %q", got, testScope)
	}
}

func TestStartDeviceAuthOmitsEmptyDeviceName(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	startFlow(t, c, "")
	if got := p.LastDeviceName(); got != "" {
		t.Errorf("device_name = %q, want empty", got)
	}
}

func TestStartDeviceAuthSendsExtraParameters(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)

	extra := map[string]string{
		"account": "systems",
		"intent":  "login",
		// An empty value is not a parameter worth sending.
		"host_assertion": "",
	}
	if _, err := c.StartDeviceAuth(context.Background(), "h", extra); err != nil {
		t.Fatalf("StartDeviceAuth: %v", err)
	}

	form := p.LastDeviceParams()
	if got := form.Get("account"); got != "systems" {
		t.Errorf("account = %q, want %q", got, "systems")
	}
	if got := form.Get("intent"); got != "login" {
		t.Errorf("intent = %q, want %q", got, "login")
	}
	if _, ok := form["host_assertion"]; ok {
		t.Errorf("host_assertion sent with an empty value: %q", form.Get("host_assertion"))
	}
	// The parameters the client builds itself must survive untouched.
	if got := p.LastDeviceName(); got != "h" {
		t.Errorf("device_name = %q, want %q", got, "h")
	}
	if got := p.LastClientID(); got != testprovider.DefaultClientID {
		t.Errorf("client_id = %q, want %q", got, testprovider.DefaultClientID)
	}
}

func TestStartDeviceAuthWithoutExtraParameters(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)

	startFlow(t, c, "h")

	form := p.LastDeviceParams()
	for _, name := range []string{"host_assertion", "account", "intent"} {
		if _, ok := form[name]; ok {
			t.Errorf("%s was sent (%q) although no extra parameters were given", name, form.Get(name))
		}
	}
}

func TestStartDeviceAuthRejectsReservedParameters(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)

	for _, name := range []string{"client_id", "scope", "device_name", "", "two words"} {
		extra := map[string]string{name: "x"}
		if _, err := c.StartDeviceAuth(context.Background(), "h", extra); err == nil {
			t.Errorf("StartDeviceAuth with extra %q: got nil error, want a refusal", name)
		}
	}
}

// --- WaitForToken ---

func TestWaitForTokenAfterPending(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithPendingPolls(2), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	tok, err := c.WaitForToken(context.Background(), da, "")
	if err != nil {
		t.Fatalf("WaitForToken: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("empty access token")
	}
	raw, err := oidc.IDTokenFrom(tok)
	if err != nil || raw == "" {
		t.Fatalf("IDTokenFrom = (%q, %v)", raw, err)
	}
	if got := p.PollCount(); got != 3 {
		t.Errorf("PollCount = %d, want 3", got)
	}
}

func TestWaitForTokenHonoursSlowDown(t *testing.T) {
	if testing.Short() {
		t.Skip("slow_down forces a 5 s back-off (RFC 8628 §3.5)")
	}
	t.Parallel()
	p := newProvider(t, testprovider.WithInterval(1))
	p.SetSlowDownOnce()
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	start := time.Now()
	tok, err := c.WaitForToken(context.Background(), da, "")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("WaitForToken: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("empty access token")
	}
	if got := p.PollCount(); got != 2 {
		t.Errorf("PollCount = %d, want 2", got)
	}
	// First poll after 1 s answers slow_down; the interval then becomes
	// 1+5 s, so the second (successful) poll cannot happen before ~7 s.
	if elapsed < 6*time.Second {
		t.Errorf("elapsed = %v, want >= 6s (slow_down must add 5 s to the interval)", elapsed)
	}
}

func TestWaitForTokenDenied(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithOutcome(testprovider.Denied), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	_, err := c.WaitForToken(context.Background(), da, "")
	if !errors.Is(err, oidc.ErrAccessDenied) {
		t.Fatalf("err = %v, want ErrAccessDenied", err)
	}
}

func TestWaitForTokenExpired(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithOutcome(testprovider.Expired), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	_, err := c.WaitForToken(context.Background(), da, "")
	if !errors.Is(err, oidc.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestWaitForTokenContextTimeout(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithPendingPolls(1000), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := c.WaitForToken(ctx, da, "")
	if !errors.Is(err, oidc.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func TestWaitForTokenContextCancelled(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithPendingPolls(1000), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.WaitForToken(ctx, da, "")
	if !errors.Is(err, oidc.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

// --- VerifyIDToken ---

func verify(t *testing.T, c *oidc.Client, raw string, skew time.Duration) (*oidc.Identity, error) {
	t.Helper()
	return c.VerifyIDToken(context.Background(), raw, "preferred_username", "groups", skew)
}

func TestVerifyIDTokenOK(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{
		"sub":                "user-42",
		"preferred_username": "alice",
		"groups":             []string{"admins", "ssh-users"},
		"email":              "alice@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	id, err := verify(t, c, raw, 0)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if id.Subject != "user-42" {
		t.Errorf("Subject = %q", id.Subject)
	}
	if id.Username != "alice" {
		t.Errorf("Username = %q", id.Username)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "admins" || id.Groups[1] != "ssh-users" {
		t.Errorf("Groups = %v", id.Groups)
	}
	if id.Claims["email"] != "alice@example.com" {
		t.Errorf("Claims[email] = %v", id.Claims["email"])
	}
}

func TestVerifyIDTokenFromFlow(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithInterval(1), testprovider.WithClaims(map[string]any{
		"preferred_username": "bob",
		"groups":             []string{"ops"},
	}))
	c := newClient(t, p)
	da := startFlow(t, c, "h")
	tok, err := c.WaitForToken(context.Background(), da, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := oidc.IDTokenFrom(tok)
	if err != nil {
		t.Fatal(err)
	}
	id, err := verify(t, c, raw, 0)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if id.Username != "bob" || len(id.Groups) != 1 || id.Groups[0] != "ops" {
		t.Errorf("identity = %+v", id)
	}
}

func TestVerifyIDTokenCorruptSignature(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verify(t, c, p.CorruptSignature(raw), 0)
	if !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyIDTokenWrongIssuer(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"iss": "https://other.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 0); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyIDTokenWrongAudience(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"aud": "someone-else"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 0); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyIDTokenExpiredWithinSkew(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"sub": "user-1", "exp": time.Now().Add(-30 * time.Second).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 60*time.Second); err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
}

func TestVerifyIDTokenExpiredBeyondSkew(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"exp": time.Now().Add(-120 * time.Second).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 60*time.Second); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyIDTokenIssuedInFuture(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"iat": time.Now().Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 60*time.Second); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyIDTokenAlgNone(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw := p.SignWithAlgNone(map[string]any{"preferred_username": "mallory"})
	if _, err := verify(t, c, raw, 0); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyIDTokenGroupsAbsent(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"sub": "user-1", "preferred_username": "carol"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := verify(t, c, raw, 0)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if id.Groups == nil || len(id.Groups) != 0 {
		t.Errorf("Groups = %#v, want empty non-nil slice", id.Groups)
	}
}

func TestVerifyIDTokenGroupsNotArray(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"sub": "user-1", "groups": "admins"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 0); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyIDTokenUsernameNotString(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"sub": "user-1", "preferred_username": 12345})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 0); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// --- IDTokenFrom ---

func TestIDTokenFromMissing(t *testing.T) {
	t.Parallel()
	_, err := oidc.IDTokenFrom(&oauth2.Token{AccessToken: "at"})
	if !errors.Is(err, oidc.ErrNoIDToken) {
		t.Fatalf("err = %v, want ErrNoIDToken", err)
	}
	_, err = oidc.IDTokenFrom((&oauth2.Token{}).WithExtra(map[string]any{"id_token": 42}))
	if !errors.Is(err, oidc.ErrNoIDToken) {
		t.Fatalf("non-string id_token: err = %v, want ErrNoIDToken", err)
	}
}

// --- Review fixes: polling interval, endpoint schemes, error hygiene ---

// TestWaitForTokenNegativeIntervalDoesNotPanic covers a provider answering
// "interval": -1. Before clamping, x/oauth2 passed that straight to
// time.NewTicker, which panics on non-positive durations. After clamping the
// first poll happens after the RFC default of 5 s, so the test bounds the
// wait with a context and only expects ErrTimeout.
func TestWaitForTokenNegativeIntervalDoesNotPanic(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithInterval(-1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")
	if da.Interval != -1 {
		t.Fatalf("Interval = %d, want -1 from the provider", da.Interval)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := c.WaitForToken(ctx, da, "")
	if !errors.Is(err, oidc.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if got := p.PollCount(); got != 0 {
		t.Errorf("PollCount = %d, want 0 (clamped interval is 5 s)", got)
	}
}

// stubIssuer serves a discovery document plus device_authorization and
// token endpoints supplied by the test. Handlers may be nil: the default
// device_authorization handler issues a fixed device code with interval 1,
// and the default token handler approves nothing (405).
func stubIssuer(t *testing.T, tls bool, mutate func(doc map[string]any), deviceAuth, token http.HandlerFunc) (*httptest.Server, func() []string) {
	t.Helper()
	var (
		srv   *httptest.Server
		mu    sync.Mutex
		paths []string
	)
	record := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			next(w, r)
		}
	}
	if deviceAuth == nil {
		deviceAuth = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "dc-1",
				"user_code":        "ABCD-EFGH",
				"verification_uri": srv.URL + "/device",
				"expires_in":       600,
				"interval":         1,
			})
		}
	}
	if token == nil {
		token = func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not implemented", http.StatusMethodNotAllowed)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", record(func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                        srv.URL,
			"authorization_endpoint":        srv.URL + "/authorize",
			"token_endpoint":                srv.URL + "/token",
			"jwks_uri":                      srv.URL + "/jwks",
			"device_authorization_endpoint": srv.URL + "/device_authorization",
		}
		if mutate != nil {
			mutate(doc)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	mux.HandleFunc("POST /device_authorization", record(deviceAuth))
	mux.HandleFunc("POST /token", record(token))
	mux.HandleFunc("/", record(http.NotFound))
	if tls {
		srv = httptest.NewTLSServer(mux)
	} else {
		srv = httptest.NewServer(mux)
	}
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func TestNewAcceptsHTTPSEndpoints(t *testing.T) {
	t.Parallel()
	srv, _ := stubIssuer(t, true, nil, nil, nil)
	c, err := oidc.New(context.Background(), oidc.Options{
		Issuer:     srv.URL,
		ClientID:   "x",
		Scope:      "openid",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("New over TLS: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}

func TestNewRejectsPlainHTTPEndpoints(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"device_authorization_endpoint", "token_endpoint", "jwks_uri"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			srv, requests := stubIssuer(t, true, func(doc map[string]any) {
				doc[field] = "http://" + strings.TrimPrefix(doc[field].(string), "https://")
			}, nil, nil)
			_, err := oidc.New(context.Background(), oidc.Options{
				Issuer:     srv.URL,
				ClientID:   "x",
				Scope:      "openid",
				HTTPClient: srv.Client(),
			})
			if !errors.Is(err, oidc.ErrDiscovery) {
				t.Fatalf("err = %v, want ErrDiscovery", err)
			}
			if !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "https") {
				t.Errorf("error %q should name %s and https", err, field)
			}
			if got := requests(); len(got) != 1 || got[0] != "/.well-known/openid-configuration" {
				t.Errorf("requests = %v, want only the discovery document", got)
			}
		})
	}
}

func TestNewSkipsEndpointSchemeCheckWhenInsecure(t *testing.T) {
	t.Parallel()
	srv, _ := stubIssuer(t, false, nil, nil, nil)
	if _, err := oidc.New(context.Background(), oidc.Options{
		Issuer:            srv.URL,
		ClientID:          "x",
		Scope:             "openid",
		HTTPTimeout:       5 * time.Second,
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("New with AllowInsecureHTTP over plain http endpoints: %v", err)
	}
}

func TestNewRejectsNonPositiveHTTPTimeout(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{0, -time.Second} {
		_, err := oidc.New(context.Background(), oidc.Options{
			Issuer:      "https://idp.invalid",
			ClientID:    "x",
			HTTPTimeout: d,
		})
		if !errors.Is(err, oidc.ErrDiscovery) {
			t.Fatalf("HTTPTimeout=%v: err = %v, want ErrDiscovery", d, err)
		}
		if !strings.Contains(err.Error(), "http timeout must be positive") {
			t.Errorf("HTTPTimeout=%v: error %q should explain the timeout", d, err)
		}
	}
}

// rsaPublicKeyFromJWKS rebuilds the provider's RSA public key from the
// public JWKS document, the way an attacker would obtain it.
func rsaPublicKeyFromJWKS(t *testing.T, p *testprovider.Provider) *rsa.PublicKey {
	t.Helper()
	resp, err := http.Get(p.URL() + "/jwks") //nolint:gosec // test server URL
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc struct {
		Keys []struct {
			N string `json:"n"`
			E string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("jwks has %d keys, want 1", len(doc.Keys))
	}
	n, err := base64.RawURLEncoding.DecodeString(doc.Keys[0].N)
	if err != nil {
		t.Fatal(err)
	}
	e, err := base64.RawURLEncoding.DecodeString(doc.Keys[0].E)
	if err != nil {
		t.Fatal(err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
}

// TestVerifyIDTokenRejectsHS256WithPublicKey pins the algorithm allowlist:
// a token HMAC-signed with the (public) RSA key material as the secret must
// never verify, whatever encoding of the key the attacker guesses.
func TestVerifyIDTokenRejectsHS256WithPublicKey(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	pub := rsaPublicKeyFromJWKS(t, p)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string][]byte{
		"pkix-der": der,
		"pkix-pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}
	for name, secret := range secrets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := p.SignHS256(map[string]any{"preferred_username": "mallory", "groups": []string{"admins"}}, secret)
			if err != nil {
				t.Fatal(err)
			}
			id, err := verify(t, c, raw, 0)
			if !errors.Is(err, oidc.ErrInvalidToken) {
				t.Fatalf("err = %v (identity %+v), want ErrInvalidToken", err, id)
			}
			msg := err.Error()
			if !strings.Contains(msg, "HS256") || !strings.Contains(msg, "signature algorithm") {
				t.Errorf("error %q should say the HS256 signature algorithm is not accepted", msg)
			}
		})
	}
}

func TestVerifyIDTokenEmptySubject(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p)
	raw, err := p.SignIDToken(map[string]any{"sub": "", "preferred_username": "nobody"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, c, raw, 0); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// nastyDescription is a provider error_description with newlines, tabs,
// terminal escapes and a marker past the truncation limit.
var nastyDescription = "HEAD-MARKER line one\n\tline two\r\n\x1b[31mred\x1b[0m " +
	strings.Repeat("padding ", 60) + "TAIL-MARKER"

func assertSanitized(t *testing.T, err error, status, code string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\n\r\t\x1b") {
		t.Errorf("error is not a single clean line: %q", msg)
	}
	if len(msg) > 300 {
		t.Errorf("error is %d bytes long, want <= 300: %q", len(msg), msg)
	}
	for _, want := range []string{status, code, "HEAD-MARKER"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q should contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "TAIL-MARKER") {
		t.Errorf("error %q should be truncated before the tail marker", msg)
	}
}

func oauthErrorHandler(code, description string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
	}
}

func newStubClient(t *testing.T, srv *httptest.Server) *oidc.Client {
	t.Helper()
	c, err := oidc.New(context.Background(), oidc.Options{
		Issuer:            srv.URL,
		ClientID:          "x",
		Scope:             "openid",
		HTTPTimeout:       5 * time.Second,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return c
}

func TestStartDeviceAuthSanitizesProviderError(t *testing.T) {
	t.Parallel()
	srv, _ := stubIssuer(t, false, nil, oauthErrorHandler("invalid_client", nastyDescription), nil)
	c := newStubClient(t, srv)
	_, err := c.StartDeviceAuth(context.Background(), "h", nil)
	assertSanitized(t, err, "400", "invalid_client")
}

func TestWaitForTokenSanitizesProviderError(t *testing.T) {
	t.Parallel()
	srv, _ := stubIssuer(t, false, nil, nil, oauthErrorHandler("access_denied", nastyDescription))
	c := newStubClient(t, srv)
	da := startFlow(t, c, "h")
	_, err := c.WaitForToken(context.Background(), da, "")
	assertSanitized(t, err, "400", "access_denied")
	if !errors.Is(err, oidc.ErrAccessDenied) {
		t.Errorf("err = %v, want ErrAccessDenied to survive sanitization", err)
	}
}

func TestWaitForTokenNeverEchoesRawBody(t *testing.T) {
	t.Parallel()
	srv, _ := stubIssuer(t, false, nil, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, "<html><body>SECRET-BODY\nline two</body></html>")
	})
	c := newStubClient(t, srv)
	da := startFlow(t, c, "h")
	_, err := c.WaitForToken(context.Background(), da, "")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "SECRET-BODY") || strings.Contains(msg, "\n") {
		t.Errorf("error leaks the raw response body: %q", msg)
	}
	if !strings.Contains(msg, "502") {
		t.Errorf("error %q should mention the HTTP status", msg)
	}
}
