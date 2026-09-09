package keycache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testAccount = "deploy"
	// testFingerprint is a real SHA-256 OpenSSH fingerprint shape: it carries
	// both '/' and '+', the two base64 characters that must not reach a
	// filename as-is.
	testFingerprint = "SHA256:aB/cD+eF0123456789abcdefghijklmnopqrstuvwxyz"
	testTTL         = 24 * time.Hour
)

var testLines = []string{
	`environment="OIDC_USER=alice@example.com",environment="OIDC_SUB=7f3a" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample1 alice`,
	`environment="OIDC_USER=bob@example.com",environment="OIDC_SUB=9c1d" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample2 bob`,
}

// clock is a controllable time source for tests.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestCache(t *testing.T, ttl time.Duration) (*Cache, *clock, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache")
	clk := &clock{t: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	return newWithClock(dir, ttl, clk.now), clk, dir
}

func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

func TestRoundtrip(t *testing.T) {
	t.Parallel()
	c, clk, _ := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.t = clk.t.Add(90 * time.Minute)

	got, age, ok := c.Get(testAccount, testFingerprint)
	if !ok {
		t.Fatal("Get: ok = false, want true")
	}
	if age != 90*time.Minute {
		t.Errorf("age = %v, want 90m", age)
	}
	if strings.Join(got, "\n") != strings.Join(testLines, "\n") {
		t.Errorf("lines = %q, want %q", got, testLines)
	}
}

func TestRoundtripAllKeys(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, "", testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, testAccount, "_all")); err != nil {
		t.Fatalf("expected <dir>/<account>/_all: %v", err)
	}
	got, _, ok := c.Get(testAccount, "")
	if !ok || len(got) != len(testLines) {
		t.Fatalf("Get(account, \"\") = %q, %v; want the stored lines", got, ok)
	}
}

func TestGetMissing(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestCache(t, testTTL)

	if lines, age, ok := c.Get(testAccount, testFingerprint); ok || lines != nil || age != 0 {
		t.Errorf("Get on empty cache = %q, %v, %v; want nil, 0, false", lines, age, ok)
	}
}

func TestPutReplacesEntry(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := c.Put(testAccount, testFingerprint, testLines[:1]); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	got, _, ok := c.Get(testAccount, testFingerprint)
	if !ok || len(got) != 1 || got[0] != testLines[0] {
		t.Errorf("Get after replace = %q, %v; want only the first line", got, ok)
	}
}

func TestExpiredEntryIsRemoved(t *testing.T) {
	t.Parallel()
	c, clk, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.t = clk.t.Add(testTTL + time.Second)

	if lines, _, ok := c.Get(testAccount, testFingerprint); ok || lines != nil {
		t.Errorf("Get after TTL = %q, %v; want nil, false", lines, ok)
	}
	if files := listFiles(t, dir); len(files) != 0 {
		t.Errorf("expired file not removed: %v", files)
	}
}

func TestEntryAtExactTTLIsStillValid(t *testing.T) {
	t.Parallel()
	c, clk, _ := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.t = clk.t.Add(testTTL)

	if _, age, ok := c.Get(testAccount, testFingerprint); !ok || age != testTTL {
		t.Errorf("Get at age == ttl: ok=%v age=%v; want true, %v", ok, age, testTTL)
	}
}

func TestDisabledCache(t *testing.T) {
	t.Parallel()
	for _, ttl := range []time.Duration{0, -time.Hour} {
		c, _, dir := newTestCache(t, ttl)

		if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
			t.Fatalf("Put on disabled cache: %v", err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("ttl=%v: disabled cache created its directory (err=%v)", ttl, err)
		}
		if _, _, ok := c.Get(testAccount, testFingerprint); ok {
			t.Errorf("ttl=%v: Get on disabled cache returned ok", ttl)
		}
		if err := c.Purge(); err != nil {
			t.Errorf("ttl=%v: Purge on disabled cache: %v", ttl, err)
		}
	}
}

func TestEmptyLinesNotStored(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// An empty answer is an authoritative denial: it must neither be
	// stored nor replace the previous entry.
	for _, empty := range [][]string{nil, {}} {
		if err := c.Put(testAccount, testFingerprint, empty); err != nil {
			t.Fatalf("Put(empty): %v", err)
		}
	}
	got, _, ok := c.Get(testAccount, testFingerprint)
	if !ok || len(got) != len(testLines) {
		t.Errorf("previous entry disturbed by empty Put: %q, %v", got, ok)
	}

	c2, _, dir2 := newTestCache(t, testTTL)
	if err := c2.Put(testAccount, testFingerprint, nil); err != nil {
		t.Fatalf("Put(nil) on fresh cache: %v", err)
	}
	if files := listFiles(t, dir2); len(files) != 0 {
		t.Errorf("empty Put created files: %v", files)
	}
	_ = dir
}

func TestFingerprintSanitised(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	want := filepath.Join(testAccount, "SHA256aB_cD-eF0123456789abcdefghijklmnopqrstuvwxyz")
	files := listFiles(t, dir)
	if len(files) != 1 || files[0] != want {
		t.Fatalf("files = %v, want [%s]", files, want)
	}
}

func TestFingerprintPaddingDropped(t *testing.T) {
	t.Parallel()
	got := sanitizeFingerprint("MD5:ab+/cd==")
	if got != "MD5ab-_cd" {
		t.Errorf("sanitizeFingerprint = %q, want MD5ab-_cd", got)
	}
}

func TestFingerprintTraversalIsSanitised(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, "../x", testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); !os.IsNotExist(err) {
		t.Fatalf("path traversal: file written outside the account dir (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "x")); !os.IsNotExist(err) {
		t.Fatalf("path traversal: file written outside the cache dir (err=%v)", err)
	}
	files := listFiles(t, dir)
	if len(files) != 1 || filepath.Dir(files[0]) != testAccount || strings.ContainsAny(filepath.Base(files[0]), "./") {
		t.Fatalf("files = %v, want one flat file under %s/", files, testAccount)
	}
	if _, _, ok := c.Get(testAccount, "../x"); !ok {
		t.Error("Get with the same odd fingerprint should find the entry")
	}
}

func TestInvalidAccountRejected(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	for _, acct := range []string{"", "../x", "Deploy", "1abc", "a/b", "a b", "a.b", strings.Repeat("a", 33), "user\n"} {
		if err := c.Put(acct, testFingerprint, testLines); err == nil {
			t.Errorf("Put(%q) accepted, want error", acct)
		}
		if _, _, ok := c.Get(acct, testFingerprint); ok {
			t.Errorf("Get(%q) returned ok", acct)
		}
	}
	if files := listFiles(t, dir); len(files) != 0 {
		t.Errorf("invalid accounts created files: %v", files)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "x")); !os.IsNotExist(err) {
		t.Fatalf("path traversal via account (err=%v)", err)
	}

	for _, acct := range []string{"a", "_svc", "deploy-1", "www-data", strings.Repeat("a", 32)} {
		if err := c.Put(acct, testFingerprint, testLines); err != nil {
			t.Errorf("Put(%q): %v, want nil", acct, err)
		}
	}
}

func TestAtomicWriteLeavesNoTempFile(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	// A stale temp file from an interrupted earlier write must not break Put.
	acctDir := filepath.Join(dir, testAccount)
	if err := os.MkdirAll(acctDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(acctDir, "_all.tmp")
	if err := os.WriteFile(stale, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := c.Put(testAccount, "", testLines); err != nil {
		t.Fatalf("Put with stale tmp present: %v", err)
	}
	for _, f := range listFiles(t, dir) {
		if strings.HasSuffix(f, ".tmp") {
			t.Errorf("temp file left behind: %s", f)
		}
	}
	if got, _, ok := c.Get(testAccount, ""); !ok || len(got) != len(testLines) {
		t.Errorf("Get after Put over stale tmp = %q, %v", got, ok)
	}
}

func TestMalformedHeader(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	acctDir := filepath.Join(dir, testAccount)
	if err := os.MkdirAll(acctDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty":         "",
		"no-header":     testLines[0] + "\n",
		"bad-version":   "# oidc-ssh cache v2 2026-09-10T12:00:00Z\n" + testLines[0] + "\n",
		"bad-timestamp": "# oidc-ssh cache v1 yesterday\n" + testLines[0] + "\n",
		"header-only":   "# oidc-ssh cache v1 2026-09-10T12:00:00Z\n",
	}
	for name, content := range cases {
		if err := os.WriteFile(filepath.Join(acctDir, "_all"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if lines, _, ok := c.Get(testAccount, ""); ok {
			t.Errorf("%s: Get returned ok with lines %q", name, lines)
		}
	}
}

func TestFutureTimestampIsNotServed(t *testing.T) {
	t.Parallel()
	c, clk, _ := newTestCache(t, testTTL)

	if err := c.Put(testAccount, "", testLines); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.t = clk.t.Add(-time.Hour) // clock went backwards past the write
	if _, _, ok := c.Get(testAccount, ""); ok {
		t.Error("entry written in the future was served")
	}
}

func TestPurge(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatal(err)
	}
	if err := c.Put("other", "", testLines); err != nil {
		t.Fatal(err)
	}
	if err := c.Purge(); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if files := listFiles(t, dir); len(files) != 0 {
		t.Errorf("files after Purge: %v", files)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Errorf("Purge removed the cache dir itself (err=%v)", err)
	}
	if _, _, ok := c.Get(testAccount, testFingerprint); ok {
		t.Error("Get after Purge returned ok")
	}
	// Purge on a directory that does not exist is not an error.
	c2, _, _ := newTestCache(t, testTTL)
	if err := c2.Purge(); err != nil {
		t.Errorf("Purge on missing dir: %v", err)
	}
}

func TestFileAndDirModes(t *testing.T) {
	t.Parallel()
	c, _, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, testFingerprint, testLines); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, filepath.Join(dir, testAccount)} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %o, want 0700", d, got)
		}
	}
	files := listFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	info, err := os.Stat(filepath.Join(dir, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode = %o, want 0600", got)
	}
}

func TestHeaderFormat(t *testing.T) {
	t.Parallel()
	c, clk, dir := newTestCache(t, testTTL)

	if err := c.Put(testAccount, "", testLines); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, testAccount, "_all")) //nolint:gosec // path is inside t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	want := "# oidc-ssh cache v1 " + clk.t.Format(time.RFC3339) + "\n" + strings.Join(testLines, "\n") + "\n"
	if string(raw) != want {
		t.Errorf("file content:\n%s\nwant:\n%s", raw, want)
	}
}

func TestNewUsesWallClock(t *testing.T) {
	t.Parallel()
	c := New(filepath.Join(t.TempDir(), "cache"), testTTL)
	if err := c.Put(testAccount, "", testLines); err != nil {
		t.Fatal(err)
	}
	_, age, ok := c.Get(testAccount, "")
	if !ok || age < 0 || age > time.Minute {
		t.Errorf("Get via New: ok=%v age=%v", ok, age)
	}
}
