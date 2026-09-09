// Command mock-provider runs internal/testprovider as a standalone process.
//
// It is a test tool, not a real identity provider: the device flow always
// ends with the programmed --outcome after --pending "authorization_pending"
// replies, and the ID token carries exactly the claims given on the command
// line. Its only purpose is to give the PAM module something to talk to in
// the pamtester integration test (test/integration), where the module runs
// in a separate process and cannot use the in-memory provider directly.
//
// Every request is echoed to stderr as "METHOD PATH" so the test can assert
// which endpoints were hit. The issuer URL is printed to stdout once the
// server is listening. The process blocks until SIGINT or SIGTERM.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jleal52/pam-oidc-device/internal/testprovider"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "mock-provider: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("mock-provider", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8089", "address to listen on (host:port)")
	outcome := fs.String("outcome", "approved", "final token endpoint answer: approved, denied or expired")
	pending := fs.Int("pending", 1, "number of authorization_pending replies before the outcome")
	interval := fs.Int("interval", 1, "polling interval advertised to the client, in seconds")
	username := fs.String("username", "alice@example.com", "value of the email claim in the ID token")
	groups := fs.String("groups", "ssh:admin", "comma-separated values of the groups claim in the ID token")
	sub := fs.String("sub", "user-1", "value of the sub claim in the ID token")
	if err := fs.Parse(args); err != nil {
		return err
	}

	oc, err := parseOutcome(*outcome)
	if err != nil {
		return err
	}
	if *pending < 0 {
		return fmt.Errorf("--pending must not be negative, got %d", *pending)
	}
	if *interval < 1 {
		return fmt.Errorf("--interval must be at least 1, got %d", *interval)
	}

	p, err := testprovider.New(
		testprovider.WithListenAddr(*listen),
		testprovider.WithOutcome(oc),
		testprovider.WithPendingPolls(*pending),
		testprovider.WithInterval(*interval),
		testprovider.WithClaims(map[string]any{
			"email":  *username,
			"groups": splitGroups(*groups),
			"sub":    *sub,
		}),
		testprovider.WithRequestLog(os.Stderr),
	)
	if err != nil {
		return err
	}
	defer p.Close()

	fmt.Println(p.Issuer())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	return nil
}

func parseOutcome(s string) (testprovider.Outcome, error) {
	switch s {
	case "approved":
		return testprovider.Approved, nil
	case "denied":
		return testprovider.Denied, nil
	case "expired":
		return testprovider.Expired, nil
	default:
		return 0, fmt.Errorf("unknown --outcome %q: want approved, denied or expired", s)
	}
}

// splitGroups turns "a,b, c" into ["a","b","c"], dropping empty entries so
// that --groups "" yields a user with no groups at all.
func splitGroups(s string) []string {
	out := make([]string, 0)
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
