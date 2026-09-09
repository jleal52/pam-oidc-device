// Package keycache stores the last-known-good authorized_keys answer the
// provider returned for an (account, fingerprint) pair, so that a host can
// keep letting known people in while the provider is unreachable.
//
// The cache implements the semantics of docs/PROVIDER-CONTRACT.md §4.3: it
// only ever holds non-empty answers (an empty answer is an authoritative
// denial and is never stored), every successful answer replaces the entry,
// and an entry is served only while it is younger than the configured TTL.
// Deciding *when* to consult the cache (only when the provider is
// unavailable) and logging every use of it are the caller's job.
//
// Layout on disk is one file per entry, <dir>/<account>/<fingerprint>, where
// the fingerprint is sanitised to a flat filename and the special name "_all"
// stands for a query without fingerprint. Files are written atomically with
// mode 0600 inside directories created with mode 0700.
package keycache

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// header is the first line of every cache file. The version lets a future
// format change invalidate old files instead of misreading them; the
// timestamp is the write time and drives TTL evaluation, so a copied or
// touched file does not extend its own life.
const (
	headerPrefix = "# oidc-ssh cache v1 "
	allKeysName  = "_all"
	tmpSuffix    = ".tmp"
	dirMode      = 0o700
	fileMode     = 0o600
)

// accountRE is the set of account names the cache accepts. It matches the
// conservative POSIX login-name convention and, being a whitelist without
// '/' or '.', rules out any path component tricks.
var accountRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ErrAccount is returned by Put when the account name is not acceptable as a
// directory name (see accountRE).
var ErrAccount = errors.New("keycache: invalid account name")

// Cache is a per-(account, fingerprint) store of authorized_keys lines with a
// TTL. A Cache with a non-positive TTL is disabled: Put and Purge do nothing
// and Get never finds anything.
type Cache struct {
	dir string
	ttl time.Duration
	now func() time.Time
}

// New returns a Cache rooted at dir that serves entries younger than ttl.
// A ttl <= 0 disables the cache entirely. The directory is created on the
// first Put; it need not exist beforehand.
func New(dir string, ttl time.Duration) *Cache {
	return newWithClock(dir, ttl, time.Now)
}

func newWithClock(dir string, ttl time.Duration, now func() time.Time) *Cache {
	return &Cache{dir: dir, ttl: ttl, now: now}
}

// enabled reports whether the cache stores anything at all.
func (c *Cache) enabled() bool { return c.ttl > 0 }

// Put stores lines as the last-known-good answer for (account, fingerprint),
// replacing any earlier entry. An empty fingerprint stands for the query
// without fingerprint ("all keys for account"). An empty lines slice is an
// authoritative denial and is never stored: Put returns nil and leaves any
// existing entry untouched. Put returns ErrAccount for an account name that
// does not match ^[a-z_][a-z0-9_-]{0,31}$.
//
// The file is written to a temporary name in the same directory and renamed
// into place, so readers never observe a partial entry.
func (c *Cache) Put(account, fingerprint string, lines []string) error {
	if !c.enabled() || len(lines) == 0 {
		return nil
	}
	path, err := c.path(account, fingerprint)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.WriteString(headerPrefix)
	buf.WriteString(c.now().UTC().Format(time.RFC3339))
	buf.WriteByte('\n')
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}

	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return fmt.Errorf("keycache: create dir: %w", err)
	}
	return writeAtomic(path, buf.Bytes())
}

// Get returns the cached lines for (account, fingerprint) together with the
// entry's age. ok is false when the cache is disabled, the entry is missing
// or unreadable, its header is malformed, or it is older than the TTL; an
// expired or malformed entry is removed as a side effect.
func (c *Cache) Get(account, fingerprint string) (lines []string, age time.Duration, ok bool) {
	if !c.enabled() {
		return nil, 0, false
	}
	path, err := c.path(account, fingerprint)
	if err != nil {
		return nil, 0, false
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is built from a whitelisted account and a sanitised fingerprint under c.dir.
	if err != nil {
		return nil, 0, false
	}

	lines, written, err := parse(raw)
	if err != nil {
		_ = os.Remove(path)
		return nil, 0, false
	}
	age = c.now().Sub(written)
	if age < 0 || age > c.ttl {
		// Expired, or written by a clock ahead of ours: either way not
		// trustworthy as "recent".
		_ = os.Remove(path)
		return nil, 0, false
	}
	return lines, age, true
}

// Purge removes every cached entry. The cache directory itself is kept (and
// a missing directory is not an error), so the cache remains usable
// afterwards.
func (c *Cache) Purge() error {
	if !c.enabled() {
		return nil
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("keycache: read dir: %w", err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(c.dir, e.Name())); err != nil {
			return fmt.Errorf("keycache: purge: %w", err)
		}
	}
	return nil
}

// path returns the file that holds the entry for (account, fingerprint),
// validating the account and sanitising the fingerprint so that the result
// is always exactly two components below c.dir.
func (c *Cache) path(account, fingerprint string) (string, error) {
	if !accountRE.MatchString(account) {
		return "", fmt.Errorf("%w: %q", ErrAccount, account)
	}
	name := allKeysName
	if fingerprint != "" {
		name = sanitizeFingerprint(fingerprint)
		if name == "" {
			name = allKeysName
		}
	}
	return filepath.Join(c.dir, account, name), nil
}

// sanitizeFingerprint maps an OpenSSH fingerprint such as "SHA256:ab/cd+ef="
// to a flat filename: the base64 characters '/' and '+' become their
// base64url counterparts '_' and '-', while ':' and '=' are dropped. Any
// other character outside [A-Za-z0-9] is dropped too, so the result can
// never contain a path separator or be "." or "..".
func sanitizeFingerprint(fp string) string {
	var b strings.Builder
	b.Grow(len(fp))
	for _, r := range fp {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '/':
			b.WriteByte('_')
		case r == '+':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// parse splits a cache file into its lines and write timestamp, rejecting
// anything whose header is not exactly what Put writes.
func parse(raw []byte) (lines []string, written time.Time, err error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	if !sc.Scan() {
		return nil, time.Time{}, errors.New("keycache: empty file")
	}
	first := sc.Text()
	if !strings.HasPrefix(first, headerPrefix) {
		return nil, time.Time{}, errors.New("keycache: missing header")
	}
	written, err = time.Parse(time.RFC3339, strings.TrimPrefix(first, headerPrefix))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("keycache: bad header timestamp: %w", err)
	}
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, fmt.Errorf("keycache: read: %w", err)
	}
	if len(lines) == 0 {
		return nil, time.Time{}, errors.New("keycache: no lines")
	}
	return lines, written, nil
}

// writeAtomic writes data to path via a temporary file in the same directory
// followed by a rename, so a crash mid-write leaves either the old entry or
// the new one, never a truncated file. A stale temporary file from an
// earlier interrupted write is simply overwritten.
func writeAtomic(path string, data []byte) error {
	tmp := path + tmpSuffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode) //nolint:gosec // tmp lives under the cache dir; 0600 is the intended mode.
	if err != nil {
		return fmt.Errorf("keycache: create temp file: %w", err)
	}
	// Make sure the mode is strict even if the file pre-existed with looser
	// permissions (O_CREATE only applies the mode to a new file).
	if err := f.Chmod(fileMode); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("keycache: chmod temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("keycache: write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("keycache: sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("keycache: close temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("keycache: rename into place: %w", err)
	}
	return nil
}
