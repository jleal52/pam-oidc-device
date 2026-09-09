package sshcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/config"
)

// recordName is the file, inside the cache directory, where enrolment
// leaves what the provider recorded about this host. Nothing on the login
// path reads it: it exists so that "oidc-ssh status" can answer "which
// groups and accounts is this host enrolled with?" without a network call.
const recordName = "host.json"

// recordMode is the mode of that file. It holds no secret — the private key
// never leaves host.key — but it lives in a directory that is 0700 for the
// AuthorizedKeysCommand user, so the directory is what really restricts it.
const recordMode = 0o644

// Record is the enrolment result as stored on disk.
type Record struct {
	HostID       string    `json:"hostId"`
	Name         string    `json:"name"`
	Hostname     string    `json:"hostname,omitempty"`
	Groups       []string  `json:"groups"`
	Accounts     []string  `json:"accounts"`
	Issuer       string    `json:"issuer"`
	APIBase      string    `json:"apiBase"`
	Fingerprint  string    `json:"fingerprint"`
	AgentVersion string    `json:"agentVersion,omitempty"`
	EnrolledAt   time.Time `json:"enrolledAt"`
}

// recordPath returns the location of the enrolment record.
func recordPath(cfg *config.Config) string {
	return filepath.Join(cfg.CacheDir, recordName)
}

// writeRecord stores rec, creating the cache directory if it is missing.
// It reports whether it had to create that directory, because a directory
// created here belongs to root while the cache is meant to belong to the
// unprivileged AuthorizedKeysCommand user.
func writeRecord(cfg *config.Config, rec *Record) (createdDir bool, err error) {
	if _, err := os.Stat(cfg.CacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
			return false, fmt.Errorf("oidc-ssh: create %s: %w", cfg.CacheDir, err)
		}
		createdDir = true
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return createdDir, fmt.Errorf("oidc-ssh: encode enrolment record: %w", err)
	}
	path := recordPath(cfg)
	if err := os.WriteFile(path, append(data, '\n'), recordMode); err != nil {
		return createdDir, fmt.Errorf("oidc-ssh: write %s: %w", path, err)
	}
	return createdDir, nil
}

// readRecord loads the enrolment record, or returns a nil record when there
// is none.
func readRecord(cfg *config.Config) (*Record, error) {
	path := recordPath(cfg)
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from the operator's cache_dir.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("oidc-ssh: read %s: %w", path, err)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("oidc-ssh: parse %s: %w", path, err)
	}
	return &rec, nil
}
