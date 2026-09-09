package sshcmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/testprovider"
)

// keysFixture is an enrolled host talking to a fake provider.
type keysFixture struct {
	provider   *testprovider.Provider
	env        *testEnv
	dir        string
	cacheDir   string
	configPath string
	hostID     string
}

// newKeysFixture writes a configuration for a host the provider already
// knows, so that only the authorized-keys query is under test. cacheTTL is
// the value of cache_ttl in that configuration.
func newKeysFixture(t *testing.T, cacheTTL string) *keysFixture {
	t.Helper()
	dir := t.TempDir()
	p := newProvider(t)
	id, keyPath := testIdentity(t, dir)
	cacheDir := filepath.Join(dir, "cache")
	hostID := p.AddHost("test-host", publicKey(t, id), []string{"systems"}, []string{"servers"})
	configPath := writeConfig(t, dir, configOptions{
		issuer:      p.Issuer(),
		apiBase:     p.SSHBase(),
		hostID:      hostID,
		identityKey: keyPath,
		cacheDir:    cacheDir,
		cacheTTL:    cacheTTL,
	})
	env := newEnv(t, configPath)
	// Host assertions live for 60 seconds and the provider checks them
	// against its own clock, so this fixture runs on the real one; a
	// pinned clock would look like an assertion from another day.
	env.Now = time.Now

	return &keysFixture{
		provider:   p,
		env:        env,
		dir:        dir,
		cacheDir:   cacheDir,
		configPath: configPath,
		hostID:     hostID,
	}
}

// run performs one query and returns what went to standard output and the
// audit line.
func (f *keysFixture) run(t *testing.T, account, fingerprint string) (stdout, audit string) {
	t.Helper()
	f.env.stdout.Reset()
	f.env.log.lines = nil
	AuthorizedKeys(context.Background(), f.env.Env, account, fingerprint)
	return f.env.stdout.String(), f.env.log.only(t)
}

func TestAuthorizedKeysServesTheProvidersAnswer(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetAuthorizedKeys("systems", []string{testKey})

	stdout, audit := f.run(t, "systems", "")

	if stdout != testKey+"\n" {
		t.Errorf("stdout = %q, want the key line and nothing else", stdout)
	}
	if audit != "account=systems fingerprint=- result=ok lines=1" {
		t.Errorf("audit = %q", audit)
	}
	// The host asks for the variable its configuration names, so that the
	// provider can put the person's identity in the session.
	if got := f.provider.LastKeysEnv(); got != "OIDC_USER" {
		t.Errorf("env = %q, want OIDC_USER", got)
	}
	// A good answer becomes the last known good one.
	if _, err := os.Stat(filepath.Join(f.cacheDir, "systems", "_all")); err != nil {
		t.Errorf("answer not cached: %v", err)
	}
}

func TestAuthorizedKeysForwardsTheFingerprint(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetAuthorizedKeys("systems", []string{testKey})
	fingerprint := publicKeyFingerprint(t, testKey)

	stdout, audit := f.run(t, "systems", fingerprint)

	if stdout != testKey+"\n" {
		t.Errorf("stdout = %q, want the key line", stdout)
	}
	if got := f.provider.LastKeysFingerprint(); got != fingerprint {
		t.Errorf("fingerprint = %q, want %q", got, fingerprint)
	}
	wantContains(t, "audit", audit, "fingerprint="+fingerprint, "result=ok")
}

func TestAuthorizedKeysEmptyAnswerDeniesAndIsNotCached(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	// The provider has no keys for the account: nobody may log in.

	stdout, audit := f.run(t, "systems", "")

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	if audit != "account=systems fingerprint=- result=empty lines=0" {
		t.Errorf("audit = %q", audit)
	}
	if entries, _ := os.ReadDir(f.cacheDir); len(entries) != 0 {
		t.Errorf("the denial was cached: %v", entries)
	}
}

func TestAuthorizedKeysDenialIsNeverServedFromTheCache(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetAuthorizedKeys("systems", []string{testKey})
	if stdout, _ := f.run(t, "systems", ""); stdout == "" {
		t.Fatal("the cache was not warmed")
	}

	// Access is withdrawn: the provider answers 200 with no keys, which is
	// a decision and must override anything remembered.
	f.provider.SetAuthorizedKeys("systems", nil)
	stdout, audit := f.run(t, "systems", "")

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing: a cached key survived a denial", stdout)
	}
	wantContains(t, "audit", audit, "result=empty")
}

func TestAuthorizedKeysRefusalPrintsNothing(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetAuthorizedKeys("ops", []string{testKey})

	// "ops" was not declared at enrolment, so the provider answers 403.
	stdout, audit := f.run(t, "ops", "")

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	wantContains(t, "audit", audit, "account=ops", "result=denied", "lines=0")
}

func TestAuthorizedKeysServesTheCacheWhenTheProviderIsDown(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetAuthorizedKeys("systems", []string{testKey})
	if stdout, _ := f.run(t, "systems", ""); stdout == "" {
		t.Fatal("the cache was not warmed")
	}

	f.provider.SetKeysOutcome(testprovider.KeysServerError)
	stdout, audit := f.run(t, "systems", "")

	if stdout != testKey+"\n" {
		t.Errorf("stdout = %q, want the cached key line", stdout)
	}
	wantContains(t, "audit", audit, "result=cache", "lines=1", "source=cache", "age=")
}

func TestAuthorizedKeysColdCacheDeniesWhenTheProviderIsDown(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetKeysOutcome(testprovider.KeysServerError)

	stdout, audit := f.run(t, "systems", "")

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	wantContains(t, "audit", audit, "result=error", "lines=0")
}

func TestAuthorizedKeysWithoutCacheDoesNotFallBack(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "0s")
	f.provider.SetAuthorizedKeys("systems", []string{testKey})
	if stdout, _ := f.run(t, "systems", ""); stdout == "" {
		t.Fatal("the provider answered nothing while it was up")
	}
	if _, err := os.Stat(f.cacheDir); !os.IsNotExist(err) {
		t.Errorf("a disabled cache created %s (err=%v)", f.cacheDir, err)
	}

	f.provider.SetKeysOutcome(testprovider.KeysServerError)
	stdout, audit := f.run(t, "systems", "")

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing when the cache is disabled", stdout)
	}
	wantContains(t, "audit", audit, "result=error")
}

func TestAuthorizedKeysGivesUpWhenTheProviderStalls(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetKeysOutcome(testprovider.KeysTimeout)

	started := time.Now()
	stdout, audit := f.run(t, "systems", "")

	// http_timeout in the fixture is 5s; the provider would stall for 10s.
	if elapsed := time.Since(started); elapsed > 9*time.Second {
		t.Errorf("waited %s, want the query to be bounded by http_timeout", elapsed)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	wantContains(t, "audit", audit, "result=error")
}

func TestAuthorizedKeysWithoutEnrolmentAsksNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := newProvider(t)
	configPath := writeConfig(t, dir, configOptions{
		issuer:   p.Issuer(),
		cacheDir: filepath.Join(dir, "cache"),
	})
	env := newEnv(t, configPath)

	AuthorizedKeys(context.Background(), env.Env, "systems", "")

	if got := env.stdout.String(); got != "" {
		t.Errorf("stdout = %q, want nothing", got)
	}
	if n := p.KeysRequests(); n != 0 {
		t.Errorf("%d requests reached the provider, want none from an unenrolled host", n)
	}
	wantContains(t, "audit", env.log.only(t), "result=error", "not_enrolled")
}

func TestAuthorizedKeysWithoutConfigurationIsQuiet(t *testing.T) {
	t.Parallel()
	env := newEnv(t, filepath.Join(t.TempDir(), "absent.yaml"))

	AuthorizedKeys(context.Background(), env.Env, "systems", "")

	if got := env.stdout.String(); got != "" {
		t.Errorf("stdout = %q, want nothing", got)
	}
	wantContains(t, "audit", env.log.only(t), "account=systems", "result=error", "lines=0")
}

func TestAuthorizedKeysNeverWritesToStderr(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetKeysOutcome(testprovider.KeysServerError)
	f.run(t, "systems", "")

	if got := f.env.stderr.String(); got != "" {
		t.Errorf("stderr = %q; sshd must see nothing but the keys", got)
	}
}

func TestAuthorizedKeysSanitisesTheAuditLine(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")

	// An account name sshd would never pass, but the audit line must not
	// be forgeable through it either.
	_, audit := f.run(t, "sys\ntems result=ok", "")

	if strings.Contains(audit, "\n") {
		t.Errorf("audit line carries a newline: %q", audit)
	}
	// Whitespace inside a value collapses to "_", so the text the account
	// smuggled in stays part of the account field instead of becoming a
	// field of its own.
	results := 0
	for _, field := range strings.Fields(audit) {
		if strings.HasPrefix(field, "result=") {
			results++
		}
	}
	if results != 1 {
		t.Errorf("audit line has %d result fields: %q", results, audit)
	}
}

func TestAuthorizedKeysRefusesImplausibleAccounts(t *testing.T) {
	t.Parallel()
	f := newKeysFixture(t, "24h")
	f.provider.SetAuthorizedKeys("systems", []string{testKey})

	// sshd expands %u from the login request. A name shaped like an option
	// (which the flag parser would have swallowed, leaving the fingerprint
	// as the account) or like a path must never reach the provider.
	for _, account := range []string{"-config=/tmp/evil.yaml", "SHA256:AAAA", "../systems", "", strings.Repeat("a", 65)} {
		before := f.provider.KeysRequests()
		stdout, audit := f.run(t, account, "")
		if stdout != "" {
			t.Errorf("account %q: stdout = %q, want nothing", account, stdout)
		}
		if got := f.provider.KeysRequests(); got != before {
			t.Errorf("account %q: the query reached the provider", account)
		}
		wantContains(t, "audit", audit, "result=error")
	}
}
