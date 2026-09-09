package main

import (
	"context"
	"flag"
	"io"
	"os"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/sshcmd"
)

// runAuthorizedKeys parses the arguments sshd passes through
// AuthorizedKeysCommand and prints the keys allowed for the account.
//
// It exits 0 whatever happens short of a usage error, and writes to stderr
// only for that usage error: standard output carries the answer sshd reads,
// and anything else on it would be parsed as a key.
func runAuthorizedKeys(args []string) int {
	fs := flag.NewFlagSet("oidc-ssh authorized-keys", flag.ContinueOnError)
	fs.Usage = func() {
		// io.WriteString, not fmt.Fprint: the sshd tokens %u and %f in
		// the text look like formatting directives to go vet.
		_, _ = io.WriteString(fs.Output(), `usage: oidc-ssh authorized-keys [flags] <account> [fingerprint]

Prints the authorized_keys lines the provider allows for <account> on this
host. Meant to be run by sshd:

    AuthorizedKeysCommand /usr/libexec/pam-oidc-device/oidc-ssh authorized-keys %u %f
    AuthorizedKeysCommandUser oidc-ssh

flags:
`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "configuration file (default: "+config.DefaultPath+", then "+config.LegacyPath+")")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return exitUsage
	}

	logger, closeLog := newSyslogLogger()
	defer closeLog()

	env := &sshcmd.Env{
		Stdout: os.Stdout,
		// Stderr stays unset: nothing from this path may reach sshd's
		// logs, the audit line goes to syslog instead.
		ConfigPath: *configPath,
		Log:        logger,
	}
	sshcmd.AuthorizedKeys(context.Background(), env, fs.Arg(0), fs.Arg(1))
	return exitOK
}
