package sshcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/hostid"
	"github.com/jleal52/pam-oidc-device/internal/provider"
)

// maxDiscoveryBody bounds the discovery document read by the connectivity
// probe.
const maxDiscoveryBody = 1 << 20

// Status prints what this host knows about its enrolment and whether it
// could act on it: the identity, the endpoints, the state of the files the
// login path reads, the age of the key cache and a probe of the provider.
//
// It is meant to be run as the unprivileged AuthorizedKeysCommand user as
// well as by root, because "can that user read the host key?" is exactly
// the question a broken key-based login raises. Every check that fails is
// printed with a "!" marker and makes Status return an error, so a runbook
// can rely on the exit code.
func Status(ctx context.Context, env *Env) error {
	env.fill()
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	path, err := env.configPath()
	if err != nil {
		env.printf("configuration: %v\n", err)
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		env.printf("configuration: %s\n", path)
		env.printf("               ! %v\n", err)
		return err
	}

	discovered, probe, probeErr := probeProvider(ctx, cfg)
	if probeErr != nil {
		fail("the provider is not reachable: %v", probeErr)
	}
	base := provider.ResolveBase(cfg.APIBase, cfg.Issuer, discovered)

	env.printf("version:       %s\n", Version)
	env.printf("configuration: %s%s\n", path, fileNote(path, 0o002, &problems))
	env.printf("issuer:        %s\n", cfg.Issuer)
	env.printf("client id:     %s\n", cfg.ClientID)
	env.printf("api base:      %s (%s)\n", base, baseSource(cfg, discovered))
	env.printf("identity key:  %s%s\n", cfg.IdentityKey, keyNote(cfg.IdentityKey, &problems))

	if cfg.HostID == "" {
		env.printf("host id:       (not enrolled; run \"oidc-ssh enroll\")\n")
		fail("the host is not enrolled: the configuration has no host_id")
	} else {
		env.printf("host id:       %s\n", cfg.HostID)
	}
	env.printf("enrolment:     %s\n", enrolmentNote(env, cfg))
	env.printf("key cache:     %s\n", cacheNote(env, cfg))
	env.printf("provider:      %s\n", probe)

	for _, p := range problems {
		env.printf("! %s\n", p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("oidc-ssh: %d check(s) failed", len(problems))
	}
	return nil
}

// baseSource names where the API base came from, which is the first thing
// to look at when a host talks to the wrong endpoint.
func baseSource(cfg *config.Config, discovered string) string {
	switch {
	case strings.TrimSpace(cfg.APIBase) != "":
		return "from api_base"
	case strings.TrimSpace(discovered) != "":
		return "from ssh_access_endpoint"
	default:
		return "derived from the issuer"
	}
}

// fileNote describes a file for the report: its mode, whether this process
// can read it, and whether it is more permissive than badBits allows.
func fileNote(path string, badBits fs.FileMode, problems *[]string) string {
	info, err := os.Stat(path)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: %v", path, err))
		return " (missing)"
	}
	note := fmt.Sprintf(" (mode %04o", info.Mode().Perm())
	if err := readable(path); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s is not readable by this user: %v", path, err))
		note += ", NOT readable"
	} else {
		note += ", readable"
	}
	if info.Mode().Perm()&badBits != 0 {
		*problems = append(*problems, fmt.Sprintf("%s has mode %04o, which is too permissive", path, info.Mode().Perm()))
		note += ", too permissive"
	}
	return note + ")"
}

// keyNote is fileNote for the private key, which no other user may read or
// write, plus its fingerprint when it can be loaded.
func keyNote(path string, problems *[]string) string {
	note := fileNote(path, 0o027, problems)
	id, err := hostid.Load(path)
	if err != nil {
		return note
	}
	return note + " " + id.Fingerprint
}

// readable reports whether this process can open path for reading. It is
// the question that matters for the AuthorizedKeysCommand user, and the
// only way to answer it without reimplementing the kernel's rules.
func readable(path string) error {
	f, err := os.Open(path) //nolint:gosec // path comes from the operator's configuration.
	if err != nil {
		return err
	}
	return f.Close()
}

// enrolmentNote summarises the record enrolment left behind.
func enrolmentNote(env *Env, cfg *config.Config) string {
	rec, err := readRecord(cfg)
	switch {
	case err != nil:
		return fmt.Sprintf("(unreadable: %v)", err)
	case rec == nil:
		return "(no record in " + recordPath(cfg) + ")"
	}
	return fmt.Sprintf("name=%s groups=%s accounts=%s (%s ago)",
		rec.Name, listOrNone(rec.Groups), listOrNone(rec.Accounts),
		env.Now().UTC().Sub(rec.EnrolledAt).Round(time.Second))
}

// cacheNote describes the last-known-good cache: whether it is enabled,
// whether this user can write to it and how fresh the newest entry is.
func cacheNote(env *Env, cfg *config.Config) string {
	if cfg.CacheTTL <= 0 {
		return cfg.CacheDir + " (disabled: cache_ttl is 0)"
	}
	note := fmt.Sprintf("%s (ttl %s", cfg.CacheDir, cfg.CacheTTL)
	if err := writable(cfg.CacheDir); err != nil {
		note += ", NOT writable: " + err.Error()
	} else {
		note += ", writable"
	}
	entries, newest := cacheEntries(cfg.CacheDir)
	switch entries {
	case 0:
		note += ", empty"
	case 1:
		note += fmt.Sprintf(", 1 entry, %s old", env.Now().Sub(newest).Round(time.Second))
	default:
		note += fmt.Sprintf(", %d entries, newest %s old", entries, env.Now().Sub(newest).Round(time.Second))
	}
	return note + ")"
}

// writable reports whether this process can create a file in dir, by trying
// to. There is no way to ask the kernel without acting, and a stale probe
// file is harmless next to a login that silently stops caching.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".oidc-ssh-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// cacheEntries counts the cached answers under dir and returns the write
// time of the most recent one. The enrolment record and temporary files are
// not answers and do not count.
func cacheEntries(dir string) (count int, newest time.Time) {
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is reported as "no entries", not as a failure.
		}
		name := d.Name()
		if name == recordName || strings.HasSuffix(name, ".tmp") || strings.HasPrefix(name, ".") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil //nolint:nilerr // same: a file that vanished mid-walk is not a failure.
		}
		count++
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return count, newest
}

// probeProvider fetches the discovery document and returns the
// ssh_access_endpoint it advertises together with a one-line verdict. It is
// a plain GET rather than full OpenID Connect discovery on purpose: the
// question is whether this host can reach the provider at all.
func probeProvider(ctx context.Context, cfg *config.Config) (endpoint, verdict string, err error) {
	url := strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	ctx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "unreachable: " + err.Error(), err
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: cfg.HTTPTimeout}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return "", "unreachable: " + err.Error(), err
	}
	defer func() { _ = resp.Body.Close() }()
	elapsed := time.Since(started).Round(time.Millisecond)

	if resp.StatusCode != http.StatusOK {
		verdict = fmt.Sprintf("%s: HTTP %d in %s", url, resp.StatusCode, elapsed)
		return "", verdict, fmt.Errorf("discovery answered HTTP %d", resp.StatusCode)
	}
	var meta struct {
		Issuer            string `json:"issuer"`
		SSHAccessEndpoint string `json:"ssh_access_endpoint"`
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBody))
	if readErr != nil || json.Unmarshal(body, &meta) != nil {
		return "", fmt.Sprintf("%s: HTTP 200 in %s, but the document is not JSON", url, elapsed),
			errors.New("discovery document is not valid JSON")
	}
	verdict = fmt.Sprintf("reachable (HTTP 200 in %s)", elapsed)
	if meta.Issuer != "" && meta.Issuer != cfg.Issuer {
		verdict += fmt.Sprintf(", but it calls itself %q", meta.Issuer)
		return meta.SSHAccessEndpoint, verdict, fmt.Errorf("the discovery document names issuer %q, not %q", meta.Issuer, cfg.Issuer)
	}
	return meta.SSHAccessEndpoint, verdict, nil
}
