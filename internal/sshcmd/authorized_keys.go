package sshcmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/hostid"
	"github.com/jleal52/pam-oidc-device/internal/keycache"
	"github.com/jleal52/pam-oidc-device/internal/pamlog"
	"github.com/jleal52/pam-oidc-device/internal/provider"
)

// Results recorded in the result= field of the audit line.
const (
	// resultOK: the provider answered with at least one key.
	resultOK = "ok"
	// resultEmpty: the provider answered with no keys. That is an
	// authoritative denial, never a reason to look at the cache.
	resultEmpty = "empty"
	// resultDenied: the provider refused the query (401 or 403).
	resultDenied = "denied"
	// resultCache: the provider was unreachable and a cached answer that
	// is still young enough was served in its place.
	resultCache = "cache"
	// resultError: anything else. No keys are printed.
	resultError = "error"
)

// AuthorizedKeys prints the authorized_keys lines the provider allows for
// account on this host, in the format and on the stream sshd expects from
// an AuthorizedKeysCommand: key lines on standard output, one per line, and
// absolutely nothing else. fingerprint is the SHA256 fingerprint of the key
// the client offered (sshd's %f); when it is empty the provider is asked for
// every key of the account.
//
// It never reports failure to sshd. A configuration problem, an unreachable
// provider or a refusal all end as an empty answer, which denies the login,
// plus one audit line on the Logger. A cached answer is served only when the
// provider could not be reached at all and the entry is younger than
// cache_ttl; a decision by the provider is never papered over.
func AuthorizedKeys(ctx context.Context, env *Env, account, fingerprint string) {
	env.fill()
	audit := &keysAudit{account: account, fingerprint: fingerprint, result: resultError}
	lines := fetchKeys(ctx, env, audit)
	// Print first: an audit line is worth less than the login it guards.
	writeLines(env, lines)
	audit.lines = len(lines)
	env.Log.Log(audit.line())
}

// fetchKeys runs the query and records its outcome in audit. It recovers
// from a panic anywhere below it, because a crash on this path would deny
// every login on the host.
func fetchKeys(ctx context.Context, env *Env, audit *keysAudit) (lines []string) {
	defer func() {
		if r := recover(); r != nil {
			lines = nil
			audit.result, audit.err = resultError, fmt.Errorf("panic: %v", r)
		}
	}()

	if !validAccount(audit.account) {
		audit.fail(errors.New("not a plausible local account name"))
		return nil
	}
	cfg, _, err := env.loadConfig()
	if err != nil {
		audit.fail(err)
		return nil
	}
	if cfg.HostID == "" {
		audit.fail(errors.New("host is not enrolled (no host_id in the configuration)"))
		return nil
	}
	// No discovery here: this runs at every login, and the answer is
	// already in the file. Enrolment writes the base it resolved into
	// api_base precisely so that this path never needs a second round
	// trip; without it the issuer decides, as the contract prescribes.
	base := provider.ResolveBase(cfg.APIBase, cfg.Issuer, "")
	client, err := newProviderClient(cfg, base)
	if err != nil {
		audit.fail(err)
		return nil
	}
	id, err := hostid.Load(cfg.IdentityKey)
	if err != nil {
		audit.fail(err)
		return nil
	}
	assertion, err := id.Assertion(cfg.HostID, base, env.Now)
	if err != nil {
		audit.fail(err)
		return nil
	}

	// Bound the query independently of the HTTP client's own timeout: sshd
	// is waiting, and LoginGraceTime is the only other thing that would
	// ever stop us.
	ctx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout)
	defer cancel()

	keys, err := client.FetchAuthorizedKeys(ctx, assertion, audit.account, audit.fingerprint, cfg.SessionEnv)
	if err != nil {
		return keysAfterError(cfg, audit, err)
	}
	audit.dropped, audit.capped, audit.truncated = keys.Dropped, keys.Capped, keys.Truncated
	if len(keys.Lines) == 0 {
		// An empty answer is the provider saying "nobody"; it is not
		// cached and does not fall back to an earlier answer.
		audit.result = resultEmpty
		return nil
	}
	if err := newCache(cfg).Put(audit.account, audit.fingerprint, keys.Lines); err != nil {
		// The answer is good even if it could not be remembered.
		audit.err = err
	}
	audit.result = resultOK
	return keys.Lines
}

// keysAfterError decides what to serve when the query failed. Only a
// provider that could not answer at all (network failure, timeout, 5xx)
// opens the door to the cache; a refusal or a malformed answer denies.
func keysAfterError(cfg *config.Config, audit *keysAudit, err error) []string {
	switch {
	case errors.Is(err, provider.ErrUnauthorized), errors.Is(err, provider.ErrForbidden):
		audit.result, audit.err = resultDenied, err
		return nil
	case !errors.Is(err, provider.ErrUnavailable):
		audit.fail(err)
		return nil
	}

	lines, age, ok := newCache(cfg).Get(audit.account, audit.fingerprint)
	if !ok {
		audit.fail(err)
		return nil
	}
	audit.result, audit.err = resultCache, err
	audit.source, audit.age = "cache", age
	return lines
}

// accountRE is what an account name has to look like before this command
// acts on it. sshd expands %u from the login request, so the value is
// remote input until proven otherwise: the pattern keeps a name that looks
// like an option (a leading "-") or like a fingerprint from ever reaching
// the flag parser's leftovers, a URL or a path. It is deliberately wider
// than any distribution's useradd policy and narrower than "anything".
var accountRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)

// validAccount reports whether account is worth asking the provider about.
func validAccount(account string) bool { return accountRE.MatchString(account) }

// newCache builds the last-known-good cache described by cfg. A cache_ttl
// of zero yields a cache that stores and returns nothing.
func newCache(cfg *config.Config) *keycache.Cache {
	return keycache.New(cfg.CacheDir, cfg.CacheTTL)
}

// writeLines prints the key lines to standard output. Write errors are
// ignored: there is no other channel to report them on, and sshd will draw
// its own conclusion from what it did receive.
func writeLines(env *Env, lines []string) {
	if len(lines) == 0 {
		return
	}
	w := bufio.NewWriter(env.Stdout)
	for _, l := range lines {
		_, _ = w.WriteString(l)
		_ = w.WriteByte('\n')
	}
	_ = w.Flush()
}

// keysAudit accumulates the fields of the single syslog line every query
// writes.
type keysAudit struct {
	account     string
	fingerprint string
	result      string
	lines       int
	source      string
	age         time.Duration
	dropped     int
	capped      bool
	truncated   bool
	err         error
}

// fail records an error outcome.
func (a *keysAudit) fail(err error) {
	a.result, a.err = resultError, err
}

// line renders the audit line: account, fingerprint, result and the number
// of lines served, followed by the fields that only some outcomes carry.
// Every value is sanitised, since the account and the fingerprint come from
// sshd and the error text can come from the provider.
func (a *keysAudit) line() string {
	var b strings.Builder
	fmt.Fprintf(&b, "account=%s fingerprint=%s result=%s lines=%d",
		valueOrDash(a.account), valueOrDash(a.fingerprint), valueOrDash(a.result), a.lines)
	if a.source != "" {
		fmt.Fprintf(&b, " source=%s age=%s", sanitize(a.source), a.age.Round(time.Second))
	}
	if a.dropped > 0 {
		fmt.Fprintf(&b, " dropped=%d", a.dropped)
	}
	if a.capped {
		b.WriteString(" capped=true")
	}
	if a.truncated {
		b.WriteString(" truncated=true")
	}
	if a.err != nil {
		fmt.Fprintf(&b, " err=%s", pamlog.Sanitize(a.err.Error(), pamlog.MaxErrLen))
	}
	return b.String()
}

// valueOrDash sanitises v and renders an empty value as "-" so that the
// line always has the same number of fields.
func valueOrDash(v string) string {
	if s := sanitize(v); s != "" {
		return s
	}
	return "-"
}
