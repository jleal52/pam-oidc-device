package sshcmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/keycache"
)

// enrollFixture is a host that has not been enrolled yet.
type enrollFixture struct {
	env        *testEnv
	provider   *providerHandle
	dir        string
	keyPath    string
	cacheDir   string
	configPath string
}

// providerHandle is the fake provider plus the values a test needs from it.
type providerHandle struct {
	issuer  string
	sshBase string
	hosts   func() map[string]hostSnapshot
	intent  func() string
	device  func() string
	params  func() url.Values
}

// hostSnapshot is what the provider recorded about an enrolled host.
type hostSnapshot struct {
	Name     string
	Groups   []string
	Accounts []string
	Version  string
}

func newEnrollFixture(t *testing.T) *enrollFixture {
	t.Helper()
	dir := t.TempDir()
	p := newProvider(t)
	cacheDir := filepath.Join(dir, "cache")
	keyPath := filepath.Join(dir, "host.key")
	// No api_base: the base has to come from the discovery document.
	configPath := writeConfig(t, dir, configOptions{
		issuer:      p.Issuer(),
		identityKey: keyPath,
		cacheDir:    cacheDir,
	})
	return &enrollFixture{
		env:        newEnv(t, configPath),
		dir:        dir,
		keyPath:    keyPath,
		cacheDir:   cacheDir,
		configPath: configPath,
		provider: &providerHandle{
			issuer:  p.Issuer(),
			sshBase: p.SSHBase(),
			intent:  p.LastIntent,
			device:  p.LastDeviceName,
			params:  p.LastDeviceParams,
			hosts: func() map[string]hostSnapshot {
				out := map[string]hostSnapshot{}
				for id, h := range p.Hosts() {
					out[id] = hostSnapshot{Name: h.Name, Groups: h.Groups, Accounts: h.Accounts, Version: h.AgentVersion}
				}
				return out
			},
		},
	}
}

func TestEnrollRegistersTheHostAndRewritesTheConfiguration(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)

	err := Enroll(context.Background(), f.env.Env, EnrollOptions{
		Name:   "test-host",
		Groups: []string{"servers"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v\nstdout:\n%s\nstderr:\n%s", err, f.env.stdout, f.env.stderr)
	}

	// The key pair was generated with the mode the design calls for.
	info, err := os.Stat(f.keyPath)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("host key mode = %04o, want 0640", got)
	}

	// The provider knows the host, with the accounts taken from the users
	// mapping since none were given on the command line.
	hosts := f.provider.hosts()
	if len(hosts) != 1 {
		t.Fatalf("provider holds %d hosts, want 1", len(hosts))
	}
	var hostID string
	var host hostSnapshot
	for id, h := range hosts {
		hostID, host = id, h
	}
	if host.Name != "test-host" {
		t.Errorf("name = %q, want test-host", host.Name)
	}
	if strings.Join(host.Accounts, ",") != "systems" {
		t.Errorf("accounts = %v, want [systems]", host.Accounts)
	}
	if strings.Join(host.Groups, ",") != "servers" {
		t.Errorf("groups = %v, want [servers]", host.Groups)
	}
	if host.Version != Version {
		t.Errorf("agentVersion = %q, want %q", host.Version, Version)
	}
	if got := f.provider.intent(); got != intentEnroll {
		t.Errorf("intent = %q, want %q", got, intentEnroll)
	}
	if got := f.provider.device(); got != "test-host" {
		t.Errorf("device_name = %q, want test-host", got)
	}

	// The configuration now points at the enrolled identity, and the
	// comments it came with are still there.
	config := readFile(t, f.configPath)
	wantContains(t, "configuration", config,
		"host_id: "+hostID,
		"api_base: "+f.provider.sshBase,
		"# Test configuration.",
		"# Who may become whom.",
		configComment,
	)

	// The record the status command reads.
	var rec Record
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(f.cacheDir, recordName))), &rec); err != nil {
		t.Fatalf("enrolment record: %v", err)
	}
	if rec.HostID != hostID || rec.Name != "test-host" || rec.APIBase != f.provider.sshBase {
		t.Errorf("record = %+v", rec)
	}
	if !rec.EnrolledAt.Equal(fixedNow) {
		t.Errorf("enrolledAt = %s, want %s", rec.EnrolledAt, fixedNow)
	}

	// What the operator is told to do next.
	wantContains(t, "output", f.env.stdout.String(),
		"Open "+f.provider.issuer,
		"Generated a host key",
		"host id:   "+hostID,
		"AuthorizedKeysCommand /usr/libexec/pam-oidc-device/oidc-ssh authorized-keys %u %f",
		"AuthorizedKeysCommandUser oidc-ssh",
		"PermitUserEnvironment OIDC_USER,OIDC_SUB",
		"LoginGraceTime 50",
		"Match User systems",
		"AuthorizedKeysFile none",
	)
}

func TestEnrollKeepsTheKeyAndClearsTheCacheOnReenrolment(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)
	opts := EnrollOptions{Name: "test-host"}
	if err := Enroll(context.Background(), f.env.Env, opts); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	firstKey := readFile(t, f.keyPath)
	cache := keycache.New(f.cacheDir, 24*time.Hour)
	if err := cache.Put("systems", "", []string{testKey}); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}
	if _, _, ok := cache.Get("systems", ""); !ok {
		t.Fatal("the cache was not warmed")
	}

	f.env.stdout.Reset()
	if err := Enroll(context.Background(), f.env.Env, opts); err != nil {
		t.Fatalf("second Enroll: %v", err)
	}

	// Same key: re-enrolment is how a host refreshes its metadata, not how
	// it gets a new identity.
	if got := readFile(t, f.keyPath); got != firstKey {
		t.Error("the host key was replaced on re-enrolment")
	}
	if _, _, ok := cache.Get("systems", ""); ok {
		t.Error("the cache survived re-enrolment; it may hold keys the old enrolment allowed")
	}
	// The provider recognised the key instead of creating a second host.
	if n := len(f.provider.hosts()); n != 1 {
		t.Errorf("provider holds %d hosts, want 1", n)
	}
	wantContains(t, "output", f.env.stdout.String(), "Host updated")
}

func TestEnrollNeedsRoot(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)
	f.env.Geteuid = func() int { return 1000 }

	err := Enroll(context.Background(), f.env.Env, EnrollOptions{Name: "test-host"})

	if !errors.Is(err, ErrNotRoot) {
		t.Fatalf("err = %v, want ErrNotRoot", err)
	}
	if _, statErr := os.Stat(f.keyPath); !os.IsNotExist(statErr) {
		t.Error("a host key was generated by an unprivileged run")
	}
}

func TestEnrollNeedsAName(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)

	if err := Enroll(context.Background(), f.env.Env, EnrollOptions{}); err == nil {
		t.Fatal("got nil error, want a complaint about --name")
	}
}

func TestEnrollOverridesAreWrittenBack(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)

	// The configuration names a provider that does not exist; the flags
	// point the enrolment at the real one and must persist it, or the next
	// login would go back to the wrong issuer.
	broken := writeConfig(t, f.dir, configOptions{
		issuer:      "http://127.0.0.1:1/",
		identityKey: f.keyPath,
		cacheDir:    f.cacheDir,
	})
	f.env.ConfigPath = broken

	err := Enroll(context.Background(), f.env.Env, EnrollOptions{
		Name:     "test-host",
		Issuer:   f.provider.issuer,
		ClientID: "other-client",
		APIBase:  f.provider.sshBase,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	wantContains(t, "configuration", readFile(t, broken),
		"issuer: "+f.provider.issuer,
		"client_id: other-client",
		"api_base: "+f.provider.sshBase,
	)
}

func TestEnrollAnnouncesTheGroupsItClaims(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)

	err := Enroll(context.Background(), f.env.Env, EnrollOptions{
		Name: "test-host",
		// Given in this order and this case; normalised once.
		Groups: []string{" Anakin-Swarm ", "PROD"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// The approver sees the groups before approving, in the order they
	// were claimed...
	if got := f.provider.params().Get("groups"); got != "anakin-swarm,prod" {
		t.Errorf("groups = %q, want %q", got, "anakin-swarm,prod")
	}
	// ...and the enrolment body repeats exactly that list, so a provider
	// comparing the two accepts it.
	for _, h := range f.provider.hosts() {
		if strings.Join(h.Groups, ",") != "anakin-swarm,prod" {
			t.Errorf("stored groups = %v, want [anakin-swarm prod]", h.Groups)
		}
	}
}

func TestEnrollWithoutGroupsSendsNoGroupsParameter(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)

	if err := Enroll(context.Background(), f.env.Env, EnrollOptions{Name: "test-host"}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if _, ok := f.provider.params()["groups"]; ok {
		t.Errorf("groups was sent (%q) although none were claimed", f.provider.params().Get("groups"))
	}
	for _, h := range f.provider.hosts() {
		if len(h.Groups) != 0 {
			t.Errorf("stored groups = %v, want none", h.Groups)
		}
	}
}
