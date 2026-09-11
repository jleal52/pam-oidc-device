package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jleal52/oidc-ssh/internal/config"
	"github.com/jleal52/oidc-ssh/internal/sshcmd"
)

// runEnroll parses the flags of "oidc-ssh enroll" and runs it.
func runEnroll(args []string) int {
	fs := flag.NewFlagSet("oidc-ssh enroll", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), `usage: oidc-ssh enroll --name <host> [flags]

Registers this host with the provider: generates the host key if there is
none, asks a person to approve the enrolment in a browser, and writes the
assigned host_id and api_base back into the configuration. Must run as root.

flags:
`)
		fs.PrintDefaults()
	}

	var opts sshcmd.EnrollOptions
	configPath := fs.String("config", "", "configuration file (default: "+config.DefaultPath+")")
	fs.StringVar(&opts.Issuer, "issuer", "", "OpenID Connect issuer URL (default: the configured issuer)")
	fs.StringVar(&opts.ClientID, "client-id", "", "OAuth 2.0 client id (default: the configured client_id)")
	fs.StringVar(&opts.Name, "name", "", "unique name for this host at the provider (required)")
	fs.StringVar(&opts.Hostname, "hostname", "", "machine hostname to report (default: the system hostname)")
	fs.StringVar(&opts.APIBase, "api-base", "", "SSH access API base URL (default: discovery, then <issuer>/api/ssh)")
	fs.Var(stringList{&opts.Groups}, "group", "host group code to claim, trimmed and lower-cased; repeat for several")
	fs.Var(stringList{&opts.Accounts}, "account", "local account to serve keys for; repeat for several (default: the users mapping)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "oidc-ssh enroll: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	env := &sshcmd.Env{Stdout: os.Stdout, Stderr: os.Stderr, ConfigPath: *configPath}
	if err := sshcmd.Enroll(context.Background(), env, opts); err != nil {
		return fail(err)
	}
	return exitOK
}

// stringList collects a flag that may be given several times.
type stringList struct{ values *[]string }

func (l stringList) String() string {
	if l.values == nil {
		return ""
	}
	return strings.Join(*l.values, ",")
}

func (l stringList) Set(v string) error {
	*l.values = append(*l.values, v)
	return nil
}
