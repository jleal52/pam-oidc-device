package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const minimalYAML = `
issuer: https://idp.example.com
client_id: ssh-pam
users:
  systems: "ssh:admin"
`

func fixedHostname(name string) func() (string, error) {
	return func() (string, error) { return name, nil }
}

func mustParse(t *testing.T, data string) *Config {
	t.Helper()
	cfg, err := parseWithHostname([]byte(data), fixedHostname("host01"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return cfg
}

func TestParseDefaults(t *testing.T) {
	cfg := mustParse(t, minimalYAML)

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"issuer", cfg.Issuer, "https://idp.example.com"},
		{"client_id", cfg.ClientID, "ssh-pam"},
		{"scope", cfg.Scope, "openid profile email groups"},
		{"device_name", cfg.DeviceName, "host01"},
		{"username_claim", cfg.UsernameClaim, "email"},
		{"groups_claim", cfg.GroupsClaim, "groups"},
		{"session_env", cfg.SessionEnv, "OIDC_USER"},
		{"timeout", cfg.Timeout, 300 * time.Second},
		{"clock_skew", cfg.ClockSkew, 60 * time.Second},
		{"http_timeout", cfg.HTTPTimeout, 10 * time.Second},
		{"allow_insecure_http", cfg.AllowInsecureHTTP, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
	if len(cfg.Users) != 1 || cfg.Users["systems"] != "ssh:admin" {
		t.Errorf("users = %v, want {systems: ssh:admin}", cfg.Users)
	}
}

func TestParseAllFields(t *testing.T) {
	cfg := mustParse(t, `
issuer: https://sso.example.org/realms/main
client_id: my-client
scope: openid groups
device_name: bastion-1
username_claim: preferred_username
groups_claim: roles
session_env: SSO_USER
timeout: 2m
clock_skew: 30s
http_timeout: 5s
allow_insecure_http: true
users:
  systems: "ssh:admin"
  ops: "ssh:ops"
`)

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"issuer", cfg.Issuer, "https://sso.example.org/realms/main"},
		{"client_id", cfg.ClientID, "my-client"},
		{"scope", cfg.Scope, "openid groups"},
		{"device_name", cfg.DeviceName, "bastion-1"},
		{"username_claim", cfg.UsernameClaim, "preferred_username"},
		{"groups_claim", cfg.GroupsClaim, "roles"},
		{"session_env", cfg.SessionEnv, "SSO_USER"},
		{"timeout", cfg.Timeout, 2 * time.Minute},
		{"clock_skew", cfg.ClockSkew, 30 * time.Second},
		{"http_timeout", cfg.HTTPTimeout, 5 * time.Second},
		{"allow_insecure_http", cfg.AllowInsecureHTTP, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
	if len(cfg.Users) != 2 || cfg.Users["systems"] != "ssh:admin" || cfg.Users["ops"] != "ssh:ops" {
		t.Errorf("users = %v, want two entries", cfg.Users)
	}
}

func TestParseDeviceNameHostname(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		want  string
		hostF func() (string, error)
	}{
		{
			name:  "default expands hostname",
			yaml:  minimalYAML,
			want:  "bastion",
			hostF: fixedHostname("bastion"),
		},
		{
			name:  "placeholder inside literal",
			yaml:  minimalYAML + "device_name: \"ssh@{{hostname}}\"\n",
			want:  "ssh@bastion",
			hostF: fixedHostname("bastion"),
		},
		{
			name:  "no placeholder left untouched",
			yaml:  minimalYAML + "device_name: my-server\n",
			want:  "my-server",
			hostF: fixedHostname("bastion"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseWithHostname([]byte(tt.yaml), tt.hostF)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.DeviceName != tt.want {
				t.Errorf("device_name = %q, want %q", cfg.DeviceName, tt.want)
			}
		})
	}
}

func TestParseHostnameFailure(t *testing.T) {
	failing := func() (string, error) { return "", errors.New("boom") }
	_, err := parseWithHostname([]byte(minimalYAML), failing)
	if !errors.Is(err, ErrHostname) {
		t.Fatalf("err = %v, want ErrHostname", err)
	}
	// Without the placeholder the hostname function must not matter.
	cfg, err := parseWithHostname([]byte(minimalYAML+"device_name: static\n"), failing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeviceName != "static" {
		t.Errorf("device_name = %q, want static", cfg.DeviceName)
	}
}

func TestParseIssuerNormalisation(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"trailing slash preserved", "https://idp.example.com/", "https://idp.example.com/"},
		{"whitespace trimmed", "  https://idp.example.com  ", "https://idp.example.com"},
		{"path trailing slash preserved", "https://idp.example.com/realms/x/", "https://idp.example.com/realms/x/"},
		{"unchanged", "https://idp.example.com/realms/x", "https://idp.example.com/realms/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustParse(t, "issuer: '"+tt.in+"'\nclient_id: c\nusers: {u: g}\n")
			if cfg.Issuer != tt.want {
				t.Errorf("issuer = %q, want %q", cfg.Issuer, tt.want)
			}
		})
	}
}

func TestParseInsecureHTTP(t *testing.T) {
	_, err := parseWithHostname([]byte("issuer: http://idp.local\nclient_id: c\nusers: {u: g}\n"), fixedHostname("h"))
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("err = %v, want ErrInvalidIssuer", err)
	}
	cfg := mustParse(t, "issuer: http://idp.local\nclient_id: c\nallow_insecure_http: true\nusers: {u: g}\n")
	if cfg.Issuer != "http://idp.local" {
		t.Errorf("issuer = %q", cfg.Issuer)
	}
}

func TestParseValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want error
	}{
		{"missing issuer", "client_id: c\nusers: {u: g}\n", ErrMissingIssuer},
		{"blank issuer", "issuer: '   '\nclient_id: c\nusers: {u: g}\n", ErrMissingIssuer},
		{"relative issuer", "issuer: idp.example.com\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"unparseable issuer", "issuer: 'https://idp.example.com/%zz'\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"ftp issuer", "issuer: ftp://idp.example.com\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"issuer without host", "issuer: 'https://'\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"http issuer without insecure flag", "issuer: http://idp.example.com\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"issuer with query", "issuer: 'https://idp.example.com/?tenant=x'\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"issuer with fragment", "issuer: 'https://idp.example.com/realms/x#frag'\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"issuer with userinfo", "issuer: 'https://user:pass@idp.example.com'\nclient_id: c\nusers: {u: g}\n", ErrInvalidIssuer},
		{"missing client_id", "issuer: https://idp.example.com\nusers: {u: g}\n", ErrMissingClientID},
		{"blank client_id", "issuer: https://idp.example.com\nclient_id: '  '\nusers: {u: g}\n", ErrMissingClientID},
		{"missing users", "issuer: https://idp.example.com\nclient_id: c\n", ErrNoUsers},
		{"empty users map", "issuer: https://idp.example.com\nclient_id: c\nusers: {}\n", ErrNoUsers},
		{"user with empty group", "issuer: https://idp.example.com\nclient_id: c\nusers: {ops: ''}\n", ErrEmptyGroup},
		{"user with blank group", "issuer: https://idp.example.com\nclient_id: c\nusers: {ops: '  '}\n", ErrEmptyGroup},
		{"empty user name", "issuer: https://idp.example.com\nclient_id: c\nusers: {'': g}\n", ErrEmptyUser},
		{"blank user name", "issuer: https://idp.example.com\nclient_id: c\nusers: {'  ': g}\n", ErrEmptyUser},
		{"users colliding after trim", "issuer: https://idp.example.com\nclient_id: c\nusers: {ops: a, ' ops ': b}\n", ErrDuplicateUser},
		{"empty session_env", minimalYAML + "session_env: ''\n", ErrInvalidSessionEnv},
		{"session_env with equals", minimalYAML + "session_env: A=B\n", ErrInvalidSessionEnv},
		{"session_env starting with digit", minimalYAML + "session_env: 1X\n", ErrInvalidSessionEnv},
		{"session_env with dash", minimalYAML + "session_env: OIDC-USER\n", ErrInvalidSessionEnv},
		{"zero timeout", minimalYAML + "timeout: 0s\n", ErrInvalidDuration},
		{"negative timeout", minimalYAML + "timeout: -1s\n", ErrInvalidDuration},
		{"unparseable timeout", minimalYAML + "timeout: soon\n", ErrInvalidDuration},
		{"zero http_timeout", minimalYAML + "http_timeout: 0\n", ErrInvalidDuration},
		{"unparseable http_timeout", minimalYAML + "http_timeout: 10 seconds\n", ErrInvalidDuration},
		{"negative clock_skew", minimalYAML + "clock_skew: -5s\n", ErrInvalidDuration},
		{"unparseable clock_skew", minimalYAML + "clock_skew: abc\n", ErrInvalidDuration},
		{"empty scope", minimalYAML + "scope: ''\n", ErrInvalidScope},
		{"empty username_claim", minimalYAML + "username_claim: ''\n", ErrInvalidClaim},
		{"empty groups_claim", minimalYAML + "groups_claim: ''\n", ErrInvalidClaim},
		{"unknown key", minimalYAML + "jwks_cache: 1h\n", ErrInvalidYAML},
		{"invalid yaml", "issuer: [\n", ErrInvalidYAML},
		{"wrong type", "issuer: https://idp.example.com\nclient_id: c\nusers: [a, b]\n", ErrInvalidYAML},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseWithHostname([]byte(tt.yaml), fixedHostname("h"))
			if err == nil {
				t.Fatalf("expected error, got config %+v", cfg)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if cfg != nil {
				t.Errorf("config must be nil on error, got %+v", cfg)
			}
		})
	}
}

func TestParseUsersTrimmed(t *testing.T) {
	cfg := mustParse(t, "issuer: https://idp.example.com\nclient_id: c\nusers: {' ops ': ' ssh:ops '}\n")
	if len(cfg.Users) != 1 {
		t.Fatalf("users = %v, want exactly one entry", cfg.Users)
	}
	group, ok := cfg.LookupUser("ops")
	if !ok || group != "ssh:ops" {
		t.Errorf("LookupUser(\"ops\") = (%q, %v), want (\"ssh:ops\", true)", group, ok)
	}
	if _, ok := cfg.LookupUser(" ops "); ok {
		t.Errorf("untrimmed key must not be present in users")
	}
}

func TestParseSessionEnvValidNames(t *testing.T) {
	for _, name := range []string{"OIDC_USER", "_x", "a1", "SSO_USER_2"} {
		t.Run(name, func(t *testing.T) {
			cfg := mustParse(t, minimalYAML+"session_env: "+name+"\n")
			if cfg.SessionEnv != name {
				t.Errorf("session_env = %q, want %q", cfg.SessionEnv, name)
			}
		})
	}
}

func TestParseZeroClockSkewAllowed(t *testing.T) {
	cfg := mustParse(t, minimalYAML+"clock_skew: 0s\n")
	if cfg.ClockSkew != 0 {
		t.Errorf("clock_skew = %v, want 0", cfg.ClockSkew)
	}
}

func TestParseUsesOSHostname(t *testing.T) {
	want, err := os.Hostname()
	if err != nil {
		t.Skip("os.Hostname unavailable")
	}
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeviceName != want {
		t.Errorf("device_name = %q, want %q", cfg.DeviceName, want)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pam_oidc_device.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientID != "ssh-pam" {
		t.Errorf("client_id = %q", cfg.ClientID)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
	if cfg != nil {
		t.Errorf("config must be nil on error")
	}
}

func TestLoadInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("client_id: c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if !errors.Is(err, ErrMissingIssuer) {
		t.Errorf("err = %v, want ErrMissingIssuer", err)
	}
}

func TestLookupUser(t *testing.T) {
	cfg := mustParse(t, minimalYAML+"  ops: \"ssh:ops\"\n")

	tests := []struct {
		user      string
		wantGroup string
		wantOK    bool
	}{
		{"systems", "ssh:admin", true},
		{"ops", "ssh:ops", true},
		{"root", "", false},
		{"", "", false},
		{"Systems", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.user, func(t *testing.T) {
			group, ok := cfg.LookupUser(tt.user)
			if ok != tt.wantOK || group != tt.wantGroup {
				t.Errorf("LookupUser(%q) = (%q, %v), want (%q, %v)", tt.user, group, ok, tt.wantGroup, tt.wantOK)
			}
		})
	}
}

func TestLookupUserNilConfig(t *testing.T) {
	var cfg *Config
	if group, ok := cfg.LookupUser("systems"); ok || group != "" {
		t.Errorf("nil config LookupUser = (%q, %v), want (\"\", false)", group, ok)
	}
}

func TestDefaultPath(t *testing.T) {
	if DefaultPath != "/etc/security/pam_oidc_device.yaml" {
		t.Errorf("DefaultPath = %q", DefaultPath)
	}
}

func TestErrorMessagesPrefixed(t *testing.T) {
	_, err := parseWithHostname([]byte("client_id: c\nusers: {u: g}\n"), fixedHostname("h"))
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); len(got) < 8 || got[:8] != "config: " {
		t.Errorf("error %q must be prefixed with \"config: \"", got)
	}
}
