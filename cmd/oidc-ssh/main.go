// oidc-ssh manages key-based SSH access granted by an OpenID Connect
// provider, as specified in docs/PROVIDER-CONTRACT.md.
//
//	oidc-ssh enroll --name <host> [flags]     register this host (root)
//	oidc-ssh authorized-keys <account> [fp]   what sshd runs at every login
//	oidc-ssh status                           what this host knows and can do
//
// The binary shares its configuration file with the PAM module, so a host
// can offer both key-based login and the interactive device flow.
//
// authorized-keys is the one subcommand on the critical path of every SSH
// login: it prints key lines on standard output and nothing else, never
// exits non-zero for anything but a usage error, and records what it did in
// syslog (authpriv) rather than on a stream sshd is reading.
package main

import (
	"fmt"
	"io"
	"log/syslog"
	"os"

	"github.com/jleal52/pam-oidc-device/internal/sshcmd"
)

// syslogTag identifies this tool's lines in the authpriv facility.
const syslogTag = "oidc-ssh"

// Exit codes. Anything other than a usage error on authorized-keys must
// stay 0: sshd treats a failing AuthorizedKeysCommand no differently from
// one that printed nothing, and an exit code is not a diagnostic.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitUsage
	}
	switch cmd := args[0]; cmd {
	case "enroll":
		return runEnroll(args[1:])
	case "authorized-keys":
		return runAuthorizedKeys(args[1:])
	case "status":
		return runStatus(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return exitOK
	case "version", "--version":
		_, _ = fmt.Fprintf(os.Stdout, "oidc-ssh %s\n", sshcmd.Version)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "oidc-ssh: unknown command %q\n", cmd)
		usage(os.Stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `usage: oidc-ssh <command> [flags]

commands:
  enroll            register this host with the provider (must run as root)
  authorized-keys   print the keys allowed for an account (run by sshd)
  status            report the enrolment, the file permissions and the provider
  version           print the version

Run "oidc-ssh <command> --help" for the flags of a command.
`)
}

// fail reports an error on stderr and returns the failure exit code. The
// message is printed as it comes: errors from the packages below already
// name themselves ("oidc-ssh: ...", "config: ...", "provider: ...").
func fail(err error) int {
	_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
	return exitFailure
}

// newSyslogLogger returns the audit sink for authorized-keys and a function
// that closes it. When syslog cannot be opened the sink discards: the login
// path has no stream left to complain on, since stdout belongs to sshd and
// stderr would only add noise to its logs.
func newSyslogLogger() (sshcmd.Logger, func()) {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, syslogTag)
	if err != nil {
		return discardLogger{}, func() {}
	}
	return &syslogLogger{w: w}, func() { _ = w.Close() }
}

type syslogLogger struct{ w *syslog.Writer }

func (l *syslogLogger) Log(line string) { _ = l.w.Info(line) }

type discardLogger struct{}

func (discardLogger) Log(string) {}
