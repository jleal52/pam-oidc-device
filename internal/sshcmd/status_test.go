package sshcmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/keycache"
	"github.com/jleal52/pam-oidc-device/internal/testprovider"
)

// newStatusFixture returns an enrolled host with a warm cache and an
// enrolment record, and the provider it is enrolled with.
func newStatusFixture(t *testing.T) (*testEnv, *testprovider.Provider, string) {
	t.Helper()
	dir := t.TempDir()
	p := newProvider(t)
	id, keyPath := testIdentity(t, dir)
	cacheDir := filepath.Join(dir, "cache")
	hostID := p.AddHost("test-host", publicKey(t, id), []string{"systems"}, []string{"servers"})
	configPath := writeConfig(t, dir, configOptions{
		issuer:      p.Issuer(),
		hostID:      hostID,
		identityKey: keyPath,
		cacheDir:    cacheDir,
	})
	if err := keycache.New(cacheDir, 24*time.Hour).Put("systems", "", []string{testKey}); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}
	if _, err := writeRecord(&config.Config{CacheDir: cacheDir}, &Record{
		HostID:     hostID,
		Name:       "test-host",
		Groups:     []string{"servers"},
		Accounts:   []string{"systems"},
		EnrolledAt: fixedNow.Add(-72 * time.Hour),
	}); err != nil {
		t.Fatalf("write record: %v", err)
	}
	return newEnv(t, configPath), p, hostID
}

func TestStatusReportsAnEnrolledHost(t *testing.T) {
	t.Parallel()
	env, p, hostID := newStatusFixture(t)

	if err := Status(context.Background(), env.Env); err != nil {
		t.Fatalf("Status: %v\n%s", err, env.stdout)
	}

	wantContains(t, "report", env.stdout.String(),
		"version:       "+Version,
		"host id:       "+hostID,
		// No api_base in the file, so the base comes from discovery.
		"api base:      "+p.SSHBase()+" (from ssh_access_endpoint)",
		"identity key:  ",
		", readable) SHA256:",
		"name=test-host groups=servers accounts=systems (72h0m0s ago)",
		"1 entry",
		"provider:      reachable (HTTP 200",
	)
}

func TestStatusFailsWhenTheHostIsNotEnrolled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := newProvider(t)
	configPath := writeConfig(t, dir, configOptions{
		issuer:   p.Issuer(),
		cacheDir: filepath.Join(dir, "cache"),
	})
	env := newEnv(t, configPath)

	err := Status(context.Background(), env.Env)

	if err == nil {
		t.Fatalf("Status returned nil for an unenrolled host:\n%s", env.stdout)
	}
	wantContains(t, "report", env.stdout.String(),
		"(not enrolled; run \"oidc-ssh enroll\")",
		"! the host is not enrolled",
	)
}

func TestStatusFailsWhenTheProviderIsUnreachable(t *testing.T) {
	t.Parallel()
	env, p, _ := newStatusFixture(t)
	p.Close()

	err := Status(context.Background(), env.Env)

	if err == nil {
		t.Fatalf("Status returned nil although the provider is down:\n%s", env.stdout)
	}
	wantContains(t, "report", env.stdout.String(), "provider:      unreachable", "! the provider is not reachable")
}

func TestStatusFailsWhenTheHostKeyCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	t.Parallel()
	env, _, _ := newStatusFixture(t)
	cfg, _, err := env.loadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := os.Chmod(cfg.IdentityKey, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := Status(context.Background(), env.Env); err == nil {
		t.Fatalf("Status returned nil although the host key is unreadable:\n%s", env.stdout)
	}
	wantContains(t, "report", env.stdout.String(), "NOT readable")
}

func TestStatusFlagsAWorldReadableHostKey(t *testing.T) {
	t.Parallel()
	env, _, _ := newStatusFixture(t)
	cfg, _, err := env.loadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := os.Chmod(cfg.IdentityKey, 0o644); err != nil { //nolint:gosec // the point of the test is that this mode is reported
		t.Fatalf("chmod: %v", err)
	}

	if err := Status(context.Background(), env.Env); err == nil {
		t.Fatalf("Status returned nil for a world-readable host key:\n%s", env.stdout)
	}
	wantContains(t, "report", env.stdout.String(), "too permissive")
}
