package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/hostid"
	"github.com/jleal52/pam-oidc-device/internal/testprovider"
)

// --- deviceAuthParams ---

// newIdentity generates a host key in a temporary directory and returns the
// identity together with the path of the key file.
func newIdentity(t *testing.T) (*hostid.Identity, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host.key")
	id, err := hostid.Generate(path, "oidc-ssh@test")
	if err != nil {
		t.Fatalf("hostid.Generate: %v", err)
	}
	return id, path
}

func TestDeviceAuthParamsWithoutHostID(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Issuer: "https://idp.example", IdentityKey: "/does/not/exist"}

	extra, err := deviceAuthParams(cfg, "systems", "", false)
	if err != nil {
		t.Fatalf("deviceAuthParams: %v", err)
	}
	if extra != nil {
		t.Fatalf("extra = %v, want nil for a host that is not enrolled", extra)
	}
}

func TestDeviceAuthParamsSignsAssertion(t *testing.T) {
	t.Parallel()
	id, keyPath := newIdentity(t)
	cfg := &config.Config{
		Issuer:      "https://idp.example",
		APIBase:     "https://idp.example/api/ssh",
		HostID:      "host-42",
		IdentityKey: keyPath,
	}

	extra, err := deviceAuthParams(cfg, "systems", "https://ignored.example/api/ssh", false)
	if err != nil {
		t.Fatalf("deviceAuthParams: %v", err)
	}
	if got := extra["account"]; got != "systems" {
		t.Errorf("account = %q, want %q", got, "systems")
	}
	if got := extra["intent"]; got != intentLogin {
		t.Errorf("intent = %q, want %q", got, intentLogin)
	}

	claims := verifyAssertion(t, extra["host_assertion"], id.Public)
	if claims["iss"] != "host-42" || claims["sub"] != "host-42" {
		t.Errorf("iss/sub = %v/%v, want host-42", claims["iss"], claims["sub"])
	}
	// api_base wins over the discovered endpoint (contract §5).
	if claims["aud"] != cfg.APIBase {
		t.Errorf("aud = %v, want %q", claims["aud"], cfg.APIBase)
	}
}

func TestDeviceAuthParamsFallsBackToDiscoveryAndIssuer(t *testing.T) {
	t.Parallel()
	id, keyPath := newIdentity(t)
	base := &config.Config{Issuer: "https://idp.example", HostID: "h", IdentityKey: keyPath}

	for _, tc := range []struct {
		name      string
		discovery string
		want      string
	}{
		{"discovery", "https://idp.example/ssh-api", "https://idp.example/ssh-api"},
		{"issuer", "", "https://idp.example/api/ssh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *base
			extra, err := deviceAuthParams(&cfg, "systems", tc.discovery, false)
			if err != nil {
				t.Fatalf("deviceAuthParams: %v", err)
			}
			if got := verifyAssertion(t, extra["host_assertion"], id.Public)["aud"]; got != tc.want {
				t.Errorf("aud = %v, want %q", got, tc.want)
			}
		})
	}
}

func TestDeviceAuthParamsMissingKey(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Issuer:      "https://idp.example",
		HostID:      "host-42",
		IdentityKey: filepath.Join(t.TempDir(), "absent.key"),
	}

	if _, err := deviceAuthParams(cfg, "systems", "", false); err == nil {
		t.Fatal("deviceAuthParams: got nil error for a missing key file")
	}
}

// verifyAssertion checks the EdDSA signature of a host assertion with pub
// and returns its claims.
func verifyAssertion(t *testing.T, token string, pub ed25519.PublicKey) map[string]any {
	t.Helper()
	if token == "" {
		t.Fatal("no host_assertion")
	}
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return claims
}

// --- run, end to end against the test provider ---

// writeConfig writes a configuration file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// runHelper drives one attempt exactly as main does, with an empty stdin
// (so the prompt is never acknowledged, as under a non-interactive client).
func runHelper(t *testing.T, configPath, user string) (code, reason, out string) {
	t.Helper()
	var buf bytes.Buffer
	p := newProtocol(&buf, strings.NewReader(""))
	lg := newLogger(false)
	defer lg.close()
	code, reason = run(p, lg, configPath, user, "10.0.0.1")
	if err := p.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return code, reason, buf.String()
}

func newTestProvider(t *testing.T) *testprovider.Provider {
	t.Helper()
	p, err := testprovider.New()
	if err != nil {
		t.Fatalf("testprovider.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestRunSendsHostAssertionAccountAndIntent(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	// No groups claim is set: the provider only grants "ssh:systems" to a
	// flow that proved which host and account it is for, so a successful
	// login is itself proof that the assertion verified.
	p.SetClaims(map[string]any{"email": "person@example.test"})
	p.SetRequireHost(true)

	id, keyPath := newIdentity(t)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.PublicKeyLine))
	if err != nil {
		t.Fatalf("parse public key line: %v", err)
	}
	hostID := p.AddHost("test-host", pub, []string{"systems"}, nil)

	configPath := writeConfig(t, fmt.Sprintf(`
issuer: %s
client_id: test-client
allow_insecure_http: true
timeout: 30s
http_timeout: 5s
api_base: %s
host_id: %s
identity_key: %s
users:
  systems: "ssh:systems"
`, p.Issuer(), p.SSHBase(), hostID, keyPath))

	code, reason, out := runHelper(t, configPath, "systems")
	if code != codeSuccess {
		t.Fatalf("code = %q (reason %q), want %q; protocol:\n%s", code, reason, codeSuccess, out)
	}
	if got := p.LastAccount(); got != "systems" {
		t.Errorf("account = %q, want %q", got, "systems")
	}
	if got := p.LastIntent(); got != intentLogin {
		t.Errorf("intent = %q, want %q", got, intentLogin)
	}
	verifyAssertion(t, p.LastHostAssertion(), id.Public)
	if !strings.Contains(out, "E OIDC_USER=person@example.test") {
		t.Errorf("session environment not exported; protocol:\n%s", out)
	}
}

func TestRunWithoutIdentitySendsNoExtensionParameters(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	p.SetClaims(map[string]any{
		"email":  "person@example.test",
		"groups": []string{"ssh:systems"},
	})

	configPath := writeConfig(t, fmt.Sprintf(`
issuer: %s
client_id: test-client
allow_insecure_http: true
timeout: 30s
http_timeout: 5s
users:
  systems: "ssh:systems"
`, p.Issuer()))

	code, reason, out := runHelper(t, configPath, "systems")
	if code != codeSuccess {
		t.Fatalf("code = %q (reason %q), want %q; protocol:\n%s", code, reason, codeSuccess, out)
	}
	form := p.LastDeviceParams()
	for _, name := range []string{"host_assertion", "account", "intent"} {
		if _, ok := form[name]; ok {
			t.Errorf("%s = %q was sent although the host is not enrolled", name, form.Get(name))
		}
	}
}

func TestRunContinuesWhenTheHostKeyIsUnreadable(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	p.SetClaims(map[string]any{
		"email":  "person@example.test",
		"groups": []string{"ssh:systems"},
	})

	configPath := writeConfig(t, fmt.Sprintf(`
issuer: %s
client_id: test-client
allow_insecure_http: true
timeout: 30s
http_timeout: 5s
host_id: host-42
identity_key: %s
users:
  systems: "ssh:systems"
`, p.Issuer(), filepath.Join(t.TempDir(), "absent.key")))

	// An enrolled host whose key cannot be read still logs in through the
	// plain device flow rather than locking everybody out.
	code, reason, out := runHelper(t, configPath, "systems")
	if code != codeSuccess {
		t.Fatalf("code = %q (reason %q), want %q; protocol:\n%s", code, reason, codeSuccess, out)
	}
	if got := p.LastHostAssertion(); got != "" {
		t.Errorf("host_assertion = %q, want none", got)
	}
}

func TestDeviceAuthParamsAnnouncesConfirmationOnlyWhenAsked(t *testing.T) {
	t.Parallel()
	id, keyPath := newIdentity(t)
	_ = id
	cfg := &config.Config{
		Issuer:      "https://idp.example",
		IdentityKey: keyPath,
		HostID:      "host-1",
		APIBase:     "https://idp.example/api/ssh",
	}

	off, err := deviceAuthParams(cfg, "systems", "", false)
	if err != nil {
		t.Fatalf("deviceAuthParams: %v", err)
	}
	if _, ok := off["confirmation_supported"]; ok {
		// Anunciarlo contra un proveedor que no lo entiende no rompe nada,
		// pero anunciarlo cuando el propio módulo no va a preguntar el PIN
		// sí: el proveedor lo generaría y nadie lo pediría.
		t.Errorf("se anunció confirmation_supported sin pedirlo: %v", off)
	}

	on, err := deviceAuthParams(cfg, "systems", "", true)
	if err != nil {
		t.Fatalf("deviceAuthParams: %v", err)
	}
	if on["confirmation_supported"] != "true" {
		t.Errorf("confirmation_supported = %q, quiero \"true\"", on["confirmation_supported"])
	}
	if on["host_assertion"] == "" || on["account"] != "systems" {
		t.Errorf("el resto del contrato se perdió: %v", on)
	}
}
