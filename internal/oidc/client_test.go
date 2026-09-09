package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	da, err := c.StartDeviceAuth(context.Background(), deviceName)
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
	if err == nil {
		t.Fatal("New accepted an http:// issuer without AllowInsecureHTTP")
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

// --- WaitForToken ---

func TestWaitForTokenAfterPending(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithPendingPolls(2), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	tok, err := c.WaitForToken(context.Background(), da)
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
	t.Parallel()
	p := newProvider(t, testprovider.WithInterval(1))
	p.SetSlowDownOnce()
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	tok, err := c.WaitForToken(context.Background(), da)
	if err != nil {
		t.Fatalf("WaitForToken: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("empty access token")
	}
	if got := p.PollCount(); got != 2 {
		t.Errorf("PollCount = %d, want 2", got)
	}
}

func TestWaitForTokenDenied(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithOutcome(testprovider.Denied), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	_, err := c.WaitForToken(context.Background(), da)
	if !errors.Is(err, oidc.ErrAccessDenied) {
		t.Fatalf("err = %v, want ErrAccessDenied", err)
	}
}

func TestWaitForTokenExpired(t *testing.T) {
	t.Parallel()
	p := newProvider(t, testprovider.WithOutcome(testprovider.Expired), testprovider.WithInterval(1))
	c := newClient(t, p)
	da := startFlow(t, c, "h")

	_, err := c.WaitForToken(context.Background(), da)
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
	_, err := c.WaitForToken(ctx, da)
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
	_, err := c.WaitForToken(ctx, da)
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
	tok, err := c.WaitForToken(context.Background(), da)
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
	raw, err := p.SignIDToken(map[string]any{"exp": time.Now().Add(-30 * time.Second).Unix()})
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
	raw, err := p.SignIDToken(map[string]any{"preferred_username": "carol"})
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
	raw, err := p.SignIDToken(map[string]any{"groups": "admins"})
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
	raw, err := p.SignIDToken(map[string]any{"preferred_username": 12345})
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
