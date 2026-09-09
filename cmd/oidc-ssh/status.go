package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/sshcmd"
)

// runStatus parses the flags of "oidc-ssh status" and runs it. It exits
// non-zero when a check fails, so that a runbook can test it.
func runStatus(args []string) int {
	fs := flag.NewFlagSet("oidc-ssh status", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), `usage: oidc-ssh status [flags]

Reports the enrolment of this host, whether the current user can read the
configuration and the host key, how fresh the key cache is, and whether the
provider answers. Exits non-zero when a check fails.

flags:
`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "configuration file (default: "+config.DefaultPath+", then "+config.LegacyPath+")")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "oidc-ssh status: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	env := &sshcmd.Env{Stdout: os.Stdout, Stderr: os.Stderr, ConfigPath: *configPath}
	if err := sshcmd.Status(context.Background(), env); err != nil {
		return exitFailure
	}
	return exitOK
}
