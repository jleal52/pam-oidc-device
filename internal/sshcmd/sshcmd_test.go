package sshcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jleal52/oidc-ssh/internal/hostid"
	"github.com/jleal52/oidc-ssh/internal/testprovider"
)

// fixedNow is the clock every test runs on, so that ages in reports and
// audit lines are exact.
var fixedNow = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

// testKey is an authorized_keys line the fake provider hands out.
const testKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1J0hMLYSjWqQiNBnzZLDCu9M9ZHzJXjLQ1s8Ff9M0X person@example.test`

// recordingLogger keeps the audit lines a command wrote.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) Log(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
}

// only returns the single line the logger recorded, failing otherwise.
func (l *recordingLogger) only(t *testing.T) string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) != 1 {
		t.Fatalf("audit lines = %v, want exactly one", l.lines)
	}
	return l.lines[0]
}

// testEnv is an Env writing to buffers, with the process-level values
// pinned so that tests do not depend on the machine they run on.
type testEnv struct {
	*Env
	stdout *strings.Builder
	stderr *strings.Builder
	log    *recordingLogger
}

func newEnv(t *testing.T, configPath string) *testEnv {
	t.Helper()
	out, errOut, log := &strings.Builder{}, &strings.Builder{}, &recordingLogger{}
	return &testEnv{
		Env: &Env{
			Stdout:     out,
			Stderr:     errOut,
			ConfigPath: configPath,
			Log:        log,
			Now:        func() time.Time { return fixedNow },
			Geteuid:    func() int { return 0 },
			Hostname:   func() (string, error) { return "test-host.example", nil },
			Executable: func() (string, error) { return "/usr/libexec/oidc-ssh/oidc-ssh", nil },
		},
		stdout: out,
		stderr: errOut,
		log:    log,
	}
}

// newProvider starts a fake provider that speaks the SSH access contract.
func newProvider(t *testing.T) *testprovider.Provider {
	t.Helper()
	p, err := testprovider.New()
	if err != nil {
		t.Fatalf("testprovider.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// testIdentity generates a host key inside dir.
func testIdentity(t *testing.T, dir string) (*hostid.Identity, string) {
	t.Helper()
	path := filepath.Join(dir, "host.key")
	id, err := hostid.Generate(path, "oidc-ssh@test")
	if err != nil {
		t.Fatalf("hostid.Generate: %v", err)
	}
	return id, path
}

// publicKey parses an identity's public key line.
func publicKey(t *testing.T, id *hostid.Identity) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.PublicKeyLine))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return pub
}

// configOptions are the values that vary between the configuration files
// the tests write.
type configOptions struct {
	issuer      string
	apiBase     string
	hostID      string
	identityKey string
	cacheDir    string
	cacheTTL    string
}

// writeConfig writes a configuration file with comments and blank lines, so
// that a test rewriting it can check they survived, and returns its path.
func writeConfig(t *testing.T, dir string, opts configOptions) string {
	t.Helper()
	if opts.cacheTTL == "" {
		opts.cacheTTL = "24h"
	}
	var b strings.Builder
	b.WriteString("# Test configuration.\n\n")
	fmt.Fprintf(&b, "issuer: %s\n\n", opts.issuer)
	b.WriteString("# The client registered for the device flow.\nclient_id: test-client\n\n")
	b.WriteString("allow_insecure_http: true\n")
	b.WriteString("timeout: 30s\n")
	b.WriteString("http_timeout: 5s\n")
	fmt.Fprintf(&b, "cache_dir: %s\n", opts.cacheDir)
	fmt.Fprintf(&b, "cache_ttl: %s\n", opts.cacheTTL)
	if opts.identityKey != "" {
		fmt.Fprintf(&b, "identity_key: %s\n", opts.identityKey)
	}
	if opts.apiBase != "" {
		fmt.Fprintf(&b, "api_base: %s\n", opts.apiBase)
	}
	if opts.hostID != "" {
		fmt.Fprintf(&b, "host_id: %s\n", opts.hostID)
	}
	b.WriteString("\n# Who may become whom.\nusers:\n  systems: \"ssh:systems\"\n")

	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o640); err != nil { //nolint:gosec // 0640 root:oidc-ssh is the mode a real configuration has
		t.Fatalf("write config: %v", err)
	}
	return path
}

// readFile reads a file or fails the test.
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is inside t.TempDir()
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// wantContains fails unless got contains every want.
func wantContains(t *testing.T, what, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s does not contain %q:\n%s", what, w, got)
		}
	}
}

// publicKeyFingerprint returns the SHA256 fingerprint of an
// authorized_keys line, as sshd passes it in %f.
func publicKeyFingerprint(t *testing.T, line string) string {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("parse key line: %v", err)
	}
	return ssh.FingerprintSHA256(pub)
}
