package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
		{"api_base", cfg.APIBase, ""},
		{"host_id", cfg.HostID, ""},
		{"identity_key", cfg.IdentityKey, "/etc/oidc-ssh/host.key"},
		{"cache_dir", cfg.CacheDir, "/var/cache/oidc-ssh"},
		{"cache_ttl", cfg.CacheTTL, 24 * time.Hour},
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
api_base: https://sso.example.org/ssh-api/
host_id: 6a9f0c2e-1b7d-4e0a-9c1f-2d3e4f5a6b7c
identity_key: /srv/oidc-ssh/host.key
cache_dir: /srv/oidc-ssh/cache
cache_ttl: 1h30m
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
		{"api_base", cfg.APIBase, "https://sso.example.org/ssh-api/"},
		{"host_id", cfg.HostID, "6a9f0c2e-1b7d-4e0a-9c1f-2d3e4f5a6b7c"},
		{"identity_key", cfg.IdentityKey, "/srv/oidc-ssh/host.key"},
		{"cache_dir", cfg.CacheDir, "/srv/oidc-ssh/cache"},
		{"cache_ttl", cfg.CacheTTL, 90 * time.Minute},
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
		{"negative cache_ttl", minimalYAML + "cache_ttl: -1h\n", ErrInvalidDuration},
		{"unparseable cache_ttl", minimalYAML + "cache_ttl: one day\n", ErrInvalidDuration},
		{"relative identity_key", minimalYAML + "identity_key: host.key\n", ErrRelativePath},
		{"empty identity_key", minimalYAML + "identity_key: ''\n", ErrRelativePath},
		{"relative cache_dir", minimalYAML + "cache_dir: cache\n", ErrRelativePath},
		{"empty cache_dir", minimalYAML + "cache_dir: ' '\n", ErrRelativePath},
		{"http api_base without insecure flag", minimalYAML + "api_base: http://idp.example.com/api/ssh\n", ErrInvalidAPIBase},
		{"relative api_base", minimalYAML + "api_base: /api/ssh\n", ErrInvalidAPIBase},
		{"api_base without host", minimalYAML + "api_base: 'https://'\n", ErrInvalidAPIBase},
		{"api_base with query", minimalYAML + "api_base: 'https://idp.example.com/api/ssh?x=1'\n", ErrInvalidAPIBase},
		{"api_base with fragment", minimalYAML + "api_base: 'https://idp.example.com/api/ssh#f'\n", ErrInvalidAPIBase},
		{"api_base with userinfo", minimalYAML + "api_base: 'https://u:p@idp.example.com/api/ssh'\n", ErrInvalidAPIBase},
		{"ftp api_base", minimalYAML + "api_base: ftp://idp.example.com/api/ssh\n", ErrInvalidAPIBase},
		{"host_id with space", minimalYAML + "host_id: 'a b'\n", ErrInvalidHostID},
		{"host_id with tab", minimalYAML + "host_id: \"a\\tb\"\n", ErrInvalidHostID},
		{"host_id with control char", minimalYAML + "host_id: \"a\\x01b\"\n", ErrInvalidHostID},
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

func TestParseZeroCacheTTLDisablesCache(t *testing.T) {
	cfg := mustParse(t, minimalYAML+"cache_ttl: 0s\n")
	if cfg.CacheTTL != 0 {
		t.Errorf("cache_ttl = %v, want 0", cfg.CacheTTL)
	}
}

func TestParseAPIBase(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"absent", minimalYAML, ""},
		{"empty means unset", minimalYAML + "api_base: ''\n", ""},
		{"blank means unset", minimalYAML + "api_base: '   '\n", ""},
		{"kept verbatim", minimalYAML + "api_base: https://idp.example.com/api/ssh\n", "https://idp.example.com/api/ssh"},
		{"trailing slash preserved", minimalYAML + "api_base: https://idp.example.com/api/ssh/\n", "https://idp.example.com/api/ssh/"},
		{"whitespace trimmed", minimalYAML + "api_base: '  https://idp.example.com/api/ssh  '\n", "https://idp.example.com/api/ssh"},
		{"different host than issuer", minimalYAML + "api_base: https://ssh.example.net/v1\n", "https://ssh.example.net/v1"},
		{"http with insecure flag", minimalYAML + "allow_insecure_http: true\napi_base: http://idp.local/api/ssh\n", "http://idp.local/api/ssh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustParse(t, tt.yaml)
			if cfg.APIBase != tt.want {
				t.Errorf("api_base = %q, want %q", cfg.APIBase, tt.want)
			}
		})
	}
}

func TestParseHostIDTrimmed(t *testing.T) {
	cfg := mustParse(t, minimalYAML+"host_id: '  h-01  '\n")
	if cfg.HostID != "h-01" {
		t.Errorf("host_id = %q, want h-01", cfg.HostID)
	}
}

func TestParsePathsTrimmed(t *testing.T) {
	cfg := mustParse(t, minimalYAML+"identity_key: ' /k/host.key '\ncache_dir: ' /c '\n")
	if cfg.IdentityKey != "/k/host.key" || cfg.CacheDir != "/c" {
		t.Errorf("identity_key/cache_dir = %q/%q", cfg.IdentityKey, cfg.CacheDir)
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
	path := filepath.Join(dir, "pam_oidc_ssh.yaml")
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
	if DefaultPath != "/etc/oidc-ssh/config.yaml" {
		t.Errorf("DefaultPath = %q", DefaultPath)
	}
	// Since 1.0.0 there is exactly one default location. The pre-0.2.0 path
	// under /etc/security was dropped with the rename: keeping a fallback
	// named after the old project would have kept that name alive on disk
	// forever. This asserts nobody puts it back by reflex.
	if len(defaultPaths) != 1 || defaultPaths[0] != DefaultPath {
		t.Errorf("defaultPaths = %v, want [DefaultPath]", defaultPaths)
	}
}

// writeYAML writes data to dir/name and returns the path.
func writeYAML(t *testing.T, dir, name, data string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFirstPrefersPrimary(t *testing.T) {
	dir := t.TempDir()
	primary := writeYAML(t, dir, "config.yaml", minimalYAML+"device_name: primary\n")
	legacy := writeYAML(t, dir, "legacy.yaml", minimalYAML+"device_name: legacy\n")
	cfg, err := loadFirst([]string{primary, legacy})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeviceName != "primary" {
		t.Errorf("device_name = %q, want primary", cfg.DeviceName)
	}
}

func TestLoadFirstFallsBackToLegacy(t *testing.T) {
	dir := t.TempDir()
	legacy := writeYAML(t, dir, "legacy.yaml", minimalYAML+"device_name: legacy\n")
	cfg, err := loadFirst([]string{filepath.Join(dir, "missing.yaml"), legacy})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeviceName != "legacy" {
		t.Errorf("device_name = %q, want legacy", cfg.DeviceName)
	}
}

func TestLoadFirstNoneExists(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")
	cfg, err := loadFirst([]string{a, b})
	if !errors.Is(err, ErrNoConfigFile) {
		t.Fatalf("err = %v, want ErrNoConfigFile", err)
	}
	if cfg != nil {
		t.Errorf("config must be nil on error")
	}
	for _, p := range []string{a, b} {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("error %q must name %s", err, p)
		}
	}
}

func TestLoadFirstInvalidPrimaryDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	primary := writeYAML(t, dir, "config.yaml", "client_id: only\n")
	legacy := writeYAML(t, dir, "legacy.yaml", minimalYAML)
	_, err := loadFirst([]string{primary, legacy})
	if !errors.Is(err, ErrMissingIssuer) {
		t.Fatalf("err = %v, want ErrMissingIssuer (a broken primary must not be masked by the legacy file)", err)
	}
}

func TestFindFirst(t *testing.T) {
	dir := t.TempDir()
	legacy := writeYAML(t, dir, "legacy.yaml", minimalYAML)
	got, err := findFirst([]string{filepath.Join(dir, "missing.yaml"), legacy})
	if err != nil || got != legacy {
		t.Fatalf("findFirst = (%q, %v), want (%q, nil)", got, err, legacy)
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

// TestPackagedExampleParses keeps packaging/config.example.yaml, the file
// shipped under /usr/share/doc, in step with the schema: every key in it
// must be known and every value valid.
func TestPackagedExampleParses(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "packaging", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load(config.example.yaml) error: %v", err)
	}
	if cfg.Issuer != "https://login.example.com" || cfg.ClientID != "ssh-bastion" {
		t.Fatalf("unexpected issuer/client_id: %q / %q", cfg.Issuer, cfg.ClientID)
	}
	if cfg.AllowInsecureHTTP {
		t.Fatal("the shipped example must not enable allow_insecure_http")
	}
	for _, u := range []string{"systems", "ops"} {
		if _, ok := cfg.LookupUser(u); !ok {
			t.Fatalf("example users map lacks %q", u)
		}
	}
	// The example documents its own defaults; they must still be the defaults.
	if cfg.Timeout != DefaultTimeout || cfg.HTTPTimeout != DefaultHTTPTimeout || cfg.ClockSkew != DefaultClockSkew {
		t.Fatalf("example durations diverge from defaults: %s %s %s", cfg.Timeout, cfg.HTTPTimeout, cfg.ClockSkew)
	}
	if cfg.IdentityKey != DefaultIdentityKey || cfg.CacheDir != DefaultCacheDir || cfg.CacheTTL != DefaultCacheTTL {
		t.Fatalf("example key-access settings diverge from defaults: %s %s %s", cfg.IdentityKey, cfg.CacheDir, cfg.CacheTTL)
	}
	// api_base and host_id are written by enrolment; the shipped example
	// must not pretend the host is enrolled.
	if cfg.APIBase != "" || cfg.HostID != "" {
		t.Fatalf("example must leave api_base/host_id unset, got %q / %q", cfg.APIBase, cfg.HostID)
	}
}
