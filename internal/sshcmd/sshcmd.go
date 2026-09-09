// Package sshcmd implements the three subcommands of the oidc-ssh tool:
// enrolment of a host with an OpenID Connect provider, the
// AuthorizedKeysCommand sshd runs at every public-key login, and a status
// report for runbooks.
//
// The logic lives here rather than in package main so that it can be tested
// without building and running a binary, and so that the command line stays
// a thin layer of flag parsing. Everything the commands touch outside the
// process — the clock, the effective uid, the hostname, the output streams
// and the audit log — arrives through an Env, which tests fill in.
//
// The commands differ sharply in how much they may assume. Enrolment is an
// interactive administrator operation: it runs as root, talks to a person
// and reports failures as errors. AuthorizedKeys runs unprivileged, on the
// critical path of every SSH login, with sshd reading its standard output:
// it writes key lines there and nothing else, never fails the login with a
// diagnostic, and records what happened in syslog instead.
package sshcmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/pamlog"
	"github.com/jleal52/pam-oidc-device/internal/provider"
)

// Version is the agent version reported to the provider at enrolment.
// Release builds stamp it with
// -ldflags "-X github.com/jleal52/pam-oidc-device/internal/sshcmd.Version=<v>".
var Version = "dev"

// ErrNotRoot is returned by Enroll when the process is not root.
var ErrNotRoot = errors.New("oidc-ssh: enrolment must run as root")

// Logger receives one audit line per authorized-keys query. Implementations
// must never panic and must never write to standard output: sshd reads it.
type Logger interface {
	Log(line string)
}

// nopLogger discards audit lines. It is the default so that a caller that
// forgets to set one cannot crash a login.
type nopLogger struct{}

func (nopLogger) Log(string) {}

// Env carries everything the commands need from the process, so that a test
// can supply its own. The zero value is usable: fill applies the defaults.
type Env struct {
	// Stdout receives command output. For authorized-keys it receives the
	// key lines and nothing else.
	Stdout io.Writer
	// Stderr receives diagnostics from enroll and status.
	// AuthorizedKeys never writes to it.
	Stderr io.Writer
	// ConfigPath is the configuration file to read; empty means the
	// default search order (config.FindDefault).
	ConfigPath string
	// Log receives the audit line of an authorized-keys query.
	Log Logger
	// Now, Geteuid, Hostname and Executable default to time.Now,
	// os.Geteuid, os.Hostname and os.Executable.
	Now        func() time.Time
	Geteuid    func() int
	Hostname   func() (string, error)
	Executable func() (string, error)
}

// fill replaces the unset fields of e by their defaults. Every command calls
// it first, so no method has to check for nil.
func (e *Env) fill() {
	if e.Stdout == nil {
		e.Stdout = io.Discard
	}
	if e.Stderr == nil {
		e.Stderr = io.Discard
	}
	if e.Log == nil {
		e.Log = nopLogger{}
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Geteuid == nil {
		e.Geteuid = os.Geteuid
	}
	if e.Hostname == nil {
		e.Hostname = os.Hostname
	}
	if e.Executable == nil {
		e.Executable = os.Executable
	}
}

// configPath returns the configuration file the commands read and write:
// e.ConfigPath when set, otherwise the first existing default. When neither
// default exists the error names both.
func (e *Env) configPath() (string, error) {
	if e.ConfigPath != "" {
		return e.ConfigPath, nil
	}
	return config.FindDefault()
}

// loadConfig reads and validates the configuration file, returning its path
// as well so that messages and rewrites can name it.
func (e *Env) loadConfig() (*config.Config, string, error) {
	path, err := e.configPath()
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, path, err
	}
	return cfg, path, nil
}

// newProviderClient builds the SSH access API client for base.
func newProviderClient(cfg *config.Config, base string) (*provider.Client, error) {
	return provider.New(provider.Options{
		Base:              base,
		HTTPTimeout:       cfg.HTTPTimeout,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
	})
}

// printf writes to e.Stdout, ignoring write errors: a broken pipe on the
// report of a command that already did its work is not worth an exit code.
func (e *Env) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(e.Stdout, format, args...)
}

// warnf writes a "warning: ..." line to e.Stderr.
func (e *Env) warnf(format string, args ...any) {
	_, _ = fmt.Fprintf(e.Stderr, "warning: "+format+"\n", args...)
}

// sanitize prepares a value for a log line; see pamlog.Sanitize.
func sanitize(s string) string { return pamlog.Sanitize(s, pamlog.MaxValueLen) }
