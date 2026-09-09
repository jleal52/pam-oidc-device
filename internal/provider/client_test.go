package provider_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jleal52/pam-oidc-device/internal/hostid"
	"github.com/jleal52/pam-oidc-device/internal/provider"
	"github.com/jleal52/pam-oidc-device/internal/testprovider"
)

// escape is a terminal escape sequence: provider-supplied text that must
// never reach a log line intact.
const escape = "\x1b[31m"

// --- helpers ---

func newProvider(t *testing.T) *testprovider.Provider {
	t.Helper()
	p, err := testprovider.New()
	if err != nil {
		t.Fatalf("testprovider.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func newClient(t *testing.T, base string) *provider.Client {
	t.Helper()
	c, err := provider.New(provider.Options{
		Base:              base,
		HTTPTimeout:       5 * time.Second,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("provider.New(%q): %v", base, err)
	}
	return c
}

func newHostIdentity(t *testing.T) *hostid.Identity {
	t.Helper()
	id, err := hostid.Generate(filepath.Join(t.TempDir(), "host.key"), "oidc-ssh@test")
	if err != nil {
		t.Fatalf("hostid.Generate: %v", err)
	}
	return id
}

// assertion mints a fresh host assertion for hostID addressed to aud.
func assertion(t *testing.T, id *hostid.Identity, hostID, aud string) string {
	t.Helper()
	tok, err := id.Assertion(hostID, aud, nil)
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	return tok
}

// postForm posts a form and decodes the JSON answer.
func postForm(t *testing.T, endpoint string, form url.Values) map[string]any {
	t.Helper()
	resp, err := http.PostForm(endpoint, form) //nolint:gosec // test server URL
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", endpoint, err)
	}
	return out
}

// accessToken runs a complete device flow with the given intent and returns
// the access token the provider issued for it.
func accessToken(t *testing.T, p *testprovider.Provider, intent string) string {
	t.Helper()
	auth := postForm(t, p.URL()+"/device_authorization", url.Values{
		"client_id": {"ssh-pam"},
		"scope":     {"openid profile groups"},
		"intent":    {intent},
	})
	code, _ := auth["device_code"].(string)
	if code == "" {
		t.Fatalf("device_authorization: no device_code in %v", auth)
	}
	tok := postForm(t, p.URL()+"/token", url.Values{
		"grant_type":  {testprovider.DeviceGrantType},
		"client_id":   {"ssh-pam"},
		"device_code": {code},
	})
	at, _ := tok["access_token"].(string)
	if at == "" {
		t.Fatalf("token: no access_token in %v", tok)
	}
	return at
}

// keyLine returns a plausible authorized_keys line for a fresh Ed25519 key
// together with its SHA256 fingerprint.
func keyLine(t *testing.T, user, comment string) (line, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	key := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	line = fmt.Sprintf("environment=%q,environment=%q %s %s",
		"OIDC_USER="+user, "OIDC_SUB=sub-"+user, key, comment)
	return line, ssh.FingerprintSHA256(sshPub)
}

// enrolledHost registers a host directly and returns its id and identity.
func enrolledHost(t *testing.T, p *testprovider.Provider, accounts ...string) (string, *hostid.Identity) {
	t.Helper()
	id := newHostIdentity(t)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.PublicKeyLine))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	return p.AddHost("host01", pub, accounts, []string{"bastions"}), id
}

// stubServer serves handler under an /api/ssh base and returns a client for
// it plus a counter of the requests it received.
func stubServer(t *testing.T, handler http.HandlerFunc) (*provider.Client, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return newClient(t, srv.URL+"/api/ssh"), &calls
}

// --- New ---

func TestNewRejectsBadOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts provider.Options
	}{
		{"empty base", provider.Options{HTTPTimeout: time.Second}},
		{"blank base", provider.Options{Base: "   ", HTTPTimeout: time.Second}},
		{"relative base", provider.Options{Base: "/api/ssh", HTTPTimeout: time.Second}},
		{"base without host", provider.Options{Base: "https://", HTTPTimeout: time.Second}},
		{"http without the flag", provider.Options{Base: "http://idp.example.com/api/ssh", HTTPTimeout: time.Second}},
		{"unknown scheme", provider.Options{Base: "ftp://idp.example.com/api/ssh", HTTPTimeout: time.Second}},
		{"base with query", provider.Options{Base: "https://idp.example.com/api/ssh?x=1", HTTPTimeout: time.Second}},
		{"base with fragment", provider.Options{Base: "https://idp.example.com/api/ssh#f", HTTPTimeout: time.Second}},
		{"base with userinfo", provider.Options{Base: "https://u:p@idp.example.com/api/ssh", HTTPTimeout: time.Second}},
		{"zero timeout", provider.Options{Base: "https://idp.example.com/api/ssh"}},
		{"negative timeout", provider.Options{Base: "https://idp.example.com/api/ssh", HTTPTimeout: -time.Second}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if c, err := provider.New(tc.opts); err == nil {
				t.Fatalf("New(%+v) = %v, want an error", tc.opts, c)
			}
		})
	}
}

func TestNewAcceptsGoodOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts provider.Options
		base string
	}{
		{
			"https base",
			provider.Options{Base: "https://idp.example.com/api/ssh", HTTPTimeout: time.Second},
			"https://idp.example.com/api/ssh",
		},
		{
			"trailing slash kept verbatim",
			provider.Options{Base: "https://idp.example.com/api/ssh/", HTTPTimeout: time.Second},
			"https://idp.example.com/api/ssh/",
		},
		{
			"http with the flag",
			provider.Options{Base: "http://127.0.0.1:8080/api/ssh", HTTPTimeout: time.Second, AllowInsecureHTTP: true},
			"http://127.0.0.1:8080/api/ssh",
		},
		{
			"own http client needs no timeout",
			provider.Options{Base: "https://idp.example.com/api/ssh", HTTPClient: &http.Client{}},
			"https://idp.example.com/api/ssh",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := provider.New(tc.opts)
			if err != nil {
				t.Fatalf("New(%+v): %v", tc.opts, err)
			}
			if c.Base() != tc.base {
				t.Errorf("Base() = %q, want %q", c.Base(), tc.base)
			}
		})
	}
}

// --- Enroll ---

func TestEnrollCreatesHost(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	id := newHostIdentity(t)

	got, err := c.Enroll(context.Background(), accessToken(t, p, "enroll"), provider.EnrollRequest{
		PublicKey:    id.PublicKeyLine,
		Name:         "host01",
		Hostname:     "host01.internal.example",
		Accounts:     []string{"systems", "ops"},
		AgentVersion: "0.2.0-test",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !got.Created {
		t.Error("Created = false, want true for a 201")
	}
	if got.HostID == "" {
		t.Error("HostID is empty")
	}
	if got.Name != "host01" {
		t.Errorf("Name = %q, want host01", got.Name)
	}
	if strings.Join(got.Accounts, ",") != "systems,ops" {
		t.Errorf("Accounts = %v, want [systems ops]", got.Accounts)
	}
	// A nil Groups must travel as [] (the contract makes the field
	// mandatory), not as null.
	if got.Groups == nil || len(got.Groups) != 0 {
		t.Errorf("Groups = %v, want an empty slice", got.Groups)
	}

	host, ok := p.Hosts()[got.HostID]
	if !ok {
		t.Fatalf("host %q not registered, have %v", got.HostID, p.Hosts())
	}
	if host.Fingerprint != id.Fingerprint {
		t.Errorf("stored fingerprint = %q, want %q", host.Fingerprint, id.Fingerprint)
	}
	if host.AgentVersion != "0.2.0-test" {
		t.Errorf("stored agentVersion = %q, want 0.2.0-test", host.AgentVersion)
	}
	if host.Hostname != "host01.internal.example" {
		t.Errorf("stored hostname = %q, want host01.internal.example", host.Hostname)
	}
}

func TestEnrollAgainIsNotCreated(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	id := newHostIdentity(t)
	token := accessToken(t, p, "enroll")
	req := provider.EnrollRequest{
		PublicKey: id.PublicKeyLine,
		Name:      "host01",
		Groups:    []string{"bastions"},
		Accounts:  []string{"systems"},
	}

	first, err := c.Enroll(context.Background(), token, req)
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	req.Accounts = []string{"systems", "ops"}
	second, err := c.Enroll(context.Background(), token, req)
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if second.Created {
		t.Error("Created = true on re-enrolment, want false for a 200")
	}
	if second.HostID != first.HostID {
		t.Errorf("HostID = %q, want the original %q", second.HostID, first.HostID)
	}
	if strings.Join(second.Groups, ",") != "bastions" {
		t.Errorf("Groups = %v, want [bastions]", second.Groups)
	}
	if strings.Join(second.Accounts, ",") != "systems,ops" {
		t.Errorf("Accounts = %v, want the replaced [systems ops]", second.Accounts)
	}
}

func TestEnrollErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		run  func(t *testing.T, p *testprovider.Provider, c *provider.Client) error
		want error
	}{
		{
			name: "unknown access token",
			run: func(t *testing.T, _ *testprovider.Provider, c *provider.Client) error {
				t.Helper()
				id := newHostIdentity(t)
				_, err := c.Enroll(context.Background(), "at-nope", provider.EnrollRequest{
					PublicKey: id.PublicKeyLine, Name: "host01", Accounts: []string{"systems"},
				})
				return err
			},
			want: provider.ErrUnauthorized,
		},
		{
			name: "token issued for a login flow",
			run: func(t *testing.T, p *testprovider.Provider, c *provider.Client) error {
				t.Helper()
				id := newHostIdentity(t)
				_, err := c.Enroll(context.Background(), accessToken(t, p, "login"), provider.EnrollRequest{
					PublicKey: id.PublicKeyLine, Name: "host01", Accounts: []string{"systems"},
				})
				return err
			},
			want: provider.ErrForbidden,
		},
		{
			name: "key already enrolled under another name",
			run: func(t *testing.T, p *testprovider.Provider, c *provider.Client) error {
				t.Helper()
				id := newHostIdentity(t)
				token := accessToken(t, p, "enroll")
				req := provider.EnrollRequest{
					PublicKey: id.PublicKeyLine, Name: "host01", Accounts: []string{"systems"},
				}
				if _, err := c.Enroll(context.Background(), token, req); err != nil {
					t.Fatalf("first Enroll: %v", err)
				}
				req.Name = "host02"
				_, err := c.Enroll(context.Background(), token, req)
				return err
			},
			want: provider.ErrConflict,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newProvider(t)
			err := tc.run(t, p, newClient(t, p.SSHBase()))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("error message is not a single line: %q", err)
			}
		})
	}
}

func TestEnrollRejectsIncompleteRequests(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	id := newHostIdentity(t)

	tests := []struct {
		name  string
		token string
		req   provider.EnrollRequest
	}{
		{
			"no access token", "",
			provider.EnrollRequest{PublicKey: id.PublicKeyLine, Name: "host01", Accounts: []string{"systems"}},
		},
		{
			"no public key", "at-x",
			provider.EnrollRequest{Name: "host01", Accounts: []string{"systems"}},
		},
		{
			"no name", "at-x",
			provider.EnrollRequest{PublicKey: id.PublicKeyLine, Accounts: []string{"systems"}},
		},
		{
			"no accounts", "at-x",
			provider.EnrollRequest{PublicKey: id.PublicKeyLine, Name: "host01"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Enroll(context.Background(), tc.token, tc.req); err == nil {
				t.Fatal("Enroll: want an error")
			}
		})
	}
	if got := len(p.Hosts()); got != 0 {
		t.Errorf("provider registered %d hosts, want 0: the requests must not be sent", got)
	}
}

// --- AuthorizedKeys ---

func TestAuthorizedKeysReturnsLines(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")
	alice, _ := keyLine(t, "alice@example.com", "alice")
	bob, _ := keyLine(t, "bob@example.com", "bob")
	p.SetAuthorizedKeys("systems", []string{alice, bob})

	lines, err := c.AuthorizedKeys(context.Background(),
		assertion(t, id, hostID, p.SSHBase()), "systems", "", "OIDC_USER")
	if err != nil {
		t.Fatalf("AuthorizedKeys: %v", err)
	}
	if len(lines) != 2 || lines[0] != alice || lines[1] != bob {
		t.Fatalf("lines = %q, want %q", lines, []string{alice, bob})
	}
	if p.LastKeysAccount() != "systems" {
		t.Errorf("LastKeysAccount = %q, want systems", p.LastKeysAccount())
	}
	if p.LastKeysEnv() != "OIDC_USER" {
		t.Errorf("LastKeysEnv = %q, want OIDC_USER", p.LastKeysEnv())
	}
	if p.LastKeysFingerprint() != "" {
		t.Errorf("LastKeysFingerprint = %q, want it absent", p.LastKeysFingerprint())
	}
	if p.KeysRequests() != 1 {
		t.Errorf("KeysRequests = %d, want 1", p.KeysRequests())
	}
}

func TestAuthorizedKeysEmptyAnswer(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")

	lines, err := c.AuthorizedKeys(context.Background(),
		assertion(t, id, hostID, p.SSHBase()), "systems", "", "")
	if err != nil {
		t.Fatalf("AuthorizedKeys: %v", err)
	}
	if lines == nil {
		t.Fatal("lines = nil, want an empty slice")
	}
	if len(lines) != 0 {
		t.Fatalf("lines = %q, want none", lines)
	}
}

func TestAuthorizedKeysPassesFingerprint(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")
	alice, _ := keyLine(t, "alice@example.com", "alice")
	bob, bobFP := keyLine(t, "bob@example.com", "bob")
	p.SetAuthorizedKeys("systems", []string{alice, bob})

	lines, err := c.AuthorizedKeys(context.Background(),
		assertion(t, id, hostID, p.SSHBase()), "systems", bobFP, "")
	if err != nil {
		t.Fatalf("AuthorizedKeys: %v", err)
	}
	if len(lines) != 1 || lines[0] != bob {
		t.Fatalf("lines = %q, want only bob's key", lines)
	}
	if p.LastKeysFingerprint() != bobFP {
		t.Errorf("LastKeysFingerprint = %q, want %q", p.LastKeysFingerprint(), bobFP)
	}
}

func TestAuthorizedKeysDropsInvalidLines(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")
	alice, _ := keyLine(t, "alice@example.com", "alice")
	bob, _ := keyLine(t, "bob@example.com", "bob")
	coloured, _ := keyLine(t, "eve@example.com", escape+"eve")
	// A truncated key, a comment and a line carrying a terminal escape:
	// none of them may reach sshd, and none of them may hide the good keys.
	p.SetAuthorizedKeys("systems", []string{
		alice,
		"ssh-ed25519 not-base64 broken",
		"# a comment",
		coloured,
		bob,
	})

	keys, err := c.FetchAuthorizedKeys(context.Background(),
		assertion(t, id, hostID, p.SSHBase()), "systems", "", "")
	if err != nil {
		t.Fatalf("FetchAuthorizedKeys: %v", err)
	}
	if len(keys.Lines) != 2 || keys.Lines[0] != alice || keys.Lines[1] != bob {
		t.Fatalf("Lines = %q, want alice and bob", keys.Lines)
	}
	if keys.Dropped != 3 {
		t.Errorf("Dropped = %d, want 3", keys.Dropped)
	}
	if keys.Capped || keys.Truncated {
		t.Errorf("Capped = %v, Truncated = %v, want both false", keys.Capped, keys.Truncated)
	}
}

func TestAuthorizedKeysCapsLineCount(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")
	var lines []string
	for i := 0; i < provider.MaxKeysLines+20; i++ {
		line, _ := keyLine(t, fmt.Sprintf("user%d@example.com", i), fmt.Sprintf("user%d", i))
		lines = append(lines, line)
	}
	p.SetAuthorizedKeys("systems", lines)

	keys, err := c.FetchAuthorizedKeys(context.Background(),
		assertion(t, id, hostID, p.SSHBase()), "systems", "", "")
	if err != nil {
		t.Fatalf("FetchAuthorizedKeys: %v", err)
	}
	if len(keys.Lines) != provider.MaxKeysLines {
		t.Fatalf("len(Lines) = %d, want %d", len(keys.Lines), provider.MaxKeysLines)
	}
	if !keys.Capped {
		t.Error("Capped = false, want true")
	}
}

func TestAuthorizedKeysTruncatesOversizedBody(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")
	// Lines of about 8 KiB each, past the 64 KiB read limit but well under
	// the line cap, so that the cut lands in the middle of a line.
	var lines []string
	for total := 0; total <= provider.MaxKeysBytes+4096; {
		line, _ := keyLine(t, fmt.Sprintf("user%d@example.com", len(lines)), strings.Repeat("c", 8192))
		lines = append(lines, line)
		total += len(line) + 1
	}
	p.SetAuthorizedKeys("systems", lines)

	keys, err := c.FetchAuthorizedKeys(context.Background(),
		assertion(t, id, hostID, p.SSHBase()), "systems", "", "")
	if err != nil {
		t.Fatalf("FetchAuthorizedKeys: %v", err)
	}
	if !keys.Truncated {
		t.Error("Truncated = false, want true")
	}
	if len(keys.Lines) == 0 || len(keys.Lines) >= len(lines) {
		t.Fatalf("len(Lines) = %d, want between 1 and %d", len(keys.Lines), len(lines)-1)
	}
	if keys.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0: the partial line must be cut, not parsed", keys.Dropped)
	}
	for i, got := range keys.Lines {
		if got != lines[i] {
			t.Fatalf("Lines[%d] is not the line the provider sent", i)
		}
	}
}

func TestAuthorizedKeysErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// account overrides the account asked for, when set.
		account string
		// prepare tweaks the provider and returns the assertion to send.
		prepare func(t *testing.T, p *testprovider.Provider, hostID string, id *hostid.Identity) string
		want    error
	}{
		{
			name: "unknown host",
			prepare: func(t *testing.T, p *testprovider.Provider, _ string, id *hostid.Identity) string {
				t.Helper()
				return assertion(t, id, "no-such-host", p.SSHBase())
			},
			want: provider.ErrUnauthorized,
		},
		{
			name: "wrong audience",
			prepare: func(t *testing.T, _ *testprovider.Provider, hostID string, id *hostid.Identity) string {
				t.Helper()
				return assertion(t, id, hostID, "https://elsewhere.example.com/api/ssh")
			},
			want: provider.ErrUnauthorized,
		},
		{
			name: "revoked host",
			prepare: func(t *testing.T, p *testprovider.Provider, hostID string, id *hostid.Identity) string {
				t.Helper()
				p.RevokeHost(hostID)
				return assertion(t, id, hostID, p.SSHBase())
			},
			want: provider.ErrForbidden,
		},
		{
			name:    "account not declared at enrolment",
			account: "root",
			prepare: func(t *testing.T, p *testprovider.Provider, hostID string, id *hostid.Identity) string {
				t.Helper()
				return assertion(t, id, hostID, p.SSHBase())
			},
			want: provider.ErrForbidden,
		},
		{
			name: "provider broken",
			prepare: func(t *testing.T, p *testprovider.Provider, hostID string, id *hostid.Identity) string {
				t.Helper()
				p.SetKeysOutcome(testprovider.KeysServerError)
				return assertion(t, id, hostID, p.SSHBase())
			},
			want: provider.ErrUnavailable,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newProvider(t)
			c := newClient(t, p.SSHBase())
			hostID, id := enrolledHost(t, p, "systems")
			tok := tc.prepare(t, p, hostID, id)

			account := "systems"
			if tc.account != "" {
				account = tc.account
			}
			_, err := c.AuthorizedKeys(context.Background(), tok, account, "", "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("error message is not a single line: %q", err)
			}
		})
	}
}

func TestAuthorizedKeysTimeoutIsUnavailable(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")
	p.SetKeysOutcome(testprovider.KeysTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.AuthorizedKeys(ctx, assertion(t, id, hostID, p.SSHBase()), "systems", "", "")
	if !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %v, want the context deadline to end it", elapsed)
	}
}

func TestAuthorizedKeysRejectsIncompleteRequests(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	c := newClient(t, p.SSHBase())
	hostID, id := enrolledHost(t, p, "systems")

	if _, err := c.AuthorizedKeys(context.Background(), "", "systems", "", ""); err == nil {
		t.Error("AuthorizedKeys without an assertion: want an error")
	}
	if _, err := c.AuthorizedKeys(context.Background(), assertion(t, id, hostID, p.SSHBase()), "", "", ""); err == nil {
		t.Error("AuthorizedKeys without an account: want an error")
	}
	if p.KeysRequests() != 0 {
		t.Errorf("KeysRequests = %d, want 0: the requests must not be sent", p.KeysRequests())
	}
}

// --- status classification against a stub provider ---

func TestAuthorizedKeysRateLimited(t *testing.T) {
	t.Parallel()
	description := "slow\ndown" + escape + " " + strings.Repeat("x", 300)
	body, err := json.Marshal(map[string]string{
		"error":             "rate_limited",
		"error_description": description,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c, _ := stubServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write(body)
	})

	_, err = c.AuthorizedKeys(context.Background(), "assertion", "systems", "", "")
	if !errors.Is(err, provider.ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "\n"):
		t.Errorf("error message is not a single line: %q", msg)
	case !strings.Contains(msg, "HTTP 429"):
		t.Errorf("error message has no status: %q", msg)
	case !strings.Contains(msg, "(rate_limited)"):
		t.Errorf("error message has no error code: %q", msg)
	case !strings.Contains(msg, "slow down"):
		t.Errorf("error message has no description: %q", msg)
	case strings.Contains(msg, "\x1b"):
		t.Errorf("error message keeps a control character: %q", msg)
	case !strings.HasSuffix(msg, "..."):
		t.Errorf("error message is not truncated: %q", msg)
	case len(msg) > 400:
		t.Errorf("error message is %d bytes long: %q", len(msg), msg)
	}
}

func TestAuthorizedKeysUnexpectedStatus(t *testing.T) {
	t.Parallel()
	c, _ := stubServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	_, err := c.AuthorizedKeys(context.Background(), "assertion", "systems", "", "")
	if !errors.Is(err, provider.ErrBadResponse) {
		t.Fatalf("error = %v, want ErrBadResponse", err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	c, calls := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/authorized-keys") {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "the assertion must not reach this handler\n")
	})

	_, err := c.AuthorizedKeys(context.Background(), "assertion", "systems", "", "")
	if !errors.Is(err, provider.ErrBadResponse) {
		t.Fatalf("error = %v, want ErrBadResponse", err)
	}
	if *calls != 1 {
		t.Errorf("server saw %d requests, want 1: the redirect must not be followed", *calls)
	}
}

func TestEnrollUnavailableOnServerError(t *testing.T) {
	t.Parallel()
	c, _ := stubServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":"upstream_down"}`)
	})

	_, err := c.Enroll(context.Background(), "at-x", provider.EnrollRequest{
		PublicKey: "ssh-ed25519 AAAA host", Name: "host01", Accounts: []string{"systems"},
	})
	if !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Errorf("error message has no status: %q", err)
	}
}

func TestEnrollBadResponseBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{"not JSON", "not json at all"},
		{"no hostId", `{"name":"host01"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _ := stubServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := c.Enroll(context.Background(), "at-x", provider.EnrollRequest{
				PublicKey: "ssh-ed25519 AAAA host", Name: "host01", Accounts: []string{"systems"},
			})
			if !errors.Is(err, provider.ErrBadResponse) {
				t.Fatalf("error = %v, want ErrBadResponse", err)
			}
		})
	}
}

func TestUnreachableProviderIsUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL + "/api/ssh"
	srv.Close() // nothing listens on that port any more
	c := newClient(t, base)

	_, err := c.AuthorizedKeys(context.Background(), "assertion", "systems", "", "")
	if !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

// --- ResolveBase ---

func TestResolveBase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		apiBase           string
		issuer            string
		discoveryEndpoint string
		want              string
	}{
		{
			name:              "configured api base wins",
			apiBase:           "https://idp.example.com/ssh-api",
			issuer:            "https://idp.example.com",
			discoveryEndpoint: "https://idp.example.com/api/ssh",
			want:              "https://idp.example.com/ssh-api",
		},
		{
			name:              "discovery beats the issuer default",
			issuer:            "https://idp.example.com",
			discoveryEndpoint: "https://keys.example.com/api/ssh",
			want:              "https://keys.example.com/api/ssh",
		},
		{
			name:   "issuer with the default path",
			issuer: "https://idp.example.com",
			want:   "https://idp.example.com/api/ssh",
		},
		{
			name:   "issuer trailing slash is not doubled",
			issuer: "https://idp.example.com/",
			want:   "https://idp.example.com/api/ssh",
		},
		{
			name:    "trailing slash of an explicit base is kept",
			apiBase: "https://idp.example.com/api/ssh/",
			want:    "https://idp.example.com/api/ssh/",
		},
		{
			name:              "blank values are ignored",
			apiBase:           "   ",
			issuer:            "https://idp.example.com",
			discoveryEndpoint: " ",
			want:              "https://idp.example.com/api/ssh",
		},
		{name: "nothing known"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := provider.ResolveBase(tc.apiBase, tc.issuer, tc.discoveryEndpoint); got != tc.want {
				t.Errorf("ResolveBase(%q, %q, %q) = %q, want %q",
					tc.apiBase, tc.issuer, tc.discoveryEndpoint, got, tc.want)
			}
		})
	}
}

// TestResolveBaseMatchesDiscovery ties the resolution to what a provider
// actually advertises, so the default path cannot drift from the contract.
func TestResolveBaseMatchesDiscovery(t *testing.T) {
	t.Parallel()
	p := newProvider(t)
	resp, err := http.Get(p.Issuer() + "/.well-known/openid-configuration") //nolint:gosec // test server URL
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	endpoint, _ := doc["ssh_access_endpoint"].(string)

	if got := provider.ResolveBase("", p.Issuer(), endpoint); got != p.SSHBase() {
		t.Errorf("ResolveBase from discovery = %q, want %q", got, p.SSHBase())
	}
	if got := provider.ResolveBase("", p.Issuer(), ""); got != p.SSHBase() {
		t.Errorf("ResolveBase from the issuer = %q, want %q", got, p.SSHBase())
	}
}
