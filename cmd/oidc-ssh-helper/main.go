// oidc-ssh-helper runs one authentication attempt on behalf of the
// pam_oidc_ssh PAM module and reports back over stdout.
//
// The module itself is a thin C shared object (pam/pam_oidc_ssh.c): it
// execs this binary for every login so that no Go runtime ever lives inside
// the application calling PAM. That matters for OpenSSH, which runs
// pam_authenticate in a child created with fork(), an environment where a Go
// runtime inherited from the parent cannot function.
//
// Protocol (this process → module), one line each, '\n'-terminated:
//
//	I <text>            PAM_TEXT_INFO message for the user
//	P <text>            PAM_PROMPT_ECHO_OFF; the module answers with one line
//	                    on this process' stdin once the user has acknowledged
//	                    (the answer itself is discarded)
//	E <NAME>=<value>    environment variable to export into the session
//	R <code> <reason>   final result: success | ignore | auth_err | authinfo_unavail | user_unknown
//
// Flags: --config <path> (default /etc/oidc-ssh/config.yaml),
// --user <local account>, --rhost <client address>, --debug. The audit line
// goes to syslog (authpriv), or to stderr when syslog is unavailable.
//
// When the host is enrolled (host_id and identity_key in the configuration)
// the device authorization request also carries the contract's extension
// parameters — host_assertion, account and intent — so that the provider
// knows which machine and which local account the login is for. An
// unenrolled host sends none of them and the flow is the plain device flow
// of RFC 8628.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"sort"
	"strings"

	"github.com/jleal52/oidc-ssh/internal/auth"
	"github.com/jleal52/oidc-ssh/internal/config"
	"github.com/jleal52/oidc-ssh/internal/hostid"
	"github.com/jleal52/oidc-ssh/internal/oidc"
	"github.com/jleal52/oidc-ssh/internal/pamlog"
	"github.com/jleal52/oidc-ssh/internal/provider"
)

const syslogTag = "pam_oidc_ssh"

// discoveryTimeoutFactor bounds discovery (metadata document plus, in the
// worst case, redirect handling and TLS setup) to a small multiple of the
// per-request HTTP timeout.
const discoveryTimeoutFactor = 3

// Result codes of the protocol "R" line.
const (
	codeSuccess         = "success"
	codeIgnore          = "ignore"
	codeAuthErr         = "auth_err"
	codeAuthinfoUnavail = "authinfo_unavail"
	codeUserUnknown     = "user_unknown"
)

// Reasons produced here (the authenticator has its own).
const (
	reasonNoUser = "no_user"
	reasonConfig = "config"
	reasonEnv    = "invalid_env"
	reasonPanic  = "panic"
)

var errInvalidEnv = errors.New("invalid environment value")

func main() {
	fs := flag.NewFlagSet("oidc-ssh-helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "configuration file (default: "+config.DefaultPath+")")
	user := fs.String("user", "", "local account requested from PAM")
	rhost := fs.String("rhost", "", "client address (PAM_RHOST)")
	debug := fs.Bool("debug", false, "verbose syslog")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", syslogTag, err)
		os.Exit(2)
	}

	out := newProtocol(os.Stdout, os.Stdin)
	lg := newLogger(*debug)
	defer lg.close()

	code, reason := run(out, lg, *configPath, *user, *rhost)
	out.result(code, reason)
	if err := out.flush(); err != nil {
		os.Exit(1)
	}
}

// loadConfig reads the configuration from path, or from the default search
// list when path is empty.
func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return config.LoadDefault()
	}
	return config.Load(path)
}

// run performs the attempt and never panics: a panic is logged and reported
// as authinfo_unavail so the module fails closed.
func run(out *protocol, lg *logger, configPath, user, rhost string) (code, reason string) {
	hostname, _ := os.Hostname()
	attempt := pamlog.Attempt{Host: hostname, LocalUser: user, RHost: rhost}
	defer func() {
		if r := recover(); r != nil {
			code, reason = codeAuthinfoUnavail, reasonPanic
			func() {
				defer func() { _ = recover() }()
				attempt.Result, attempt.Reason = pamlog.ResultError, reasonPanic
				attempt.Err = fmt.Errorf("panic: %v", r)
				lg.attempt(attempt)
			}()
		}
	}()

	if user == "" {
		attempt.Result, attempt.Reason = pamlog.ResultError, reasonNoUser
		attempt.Err = errors.New("empty PAM user")
		lg.attempt(attempt)
		return codeUserUnknown, reasonNoUser
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		attempt.Result, attempt.Reason, attempt.Err = pamlog.ResultError, reasonConfig, err
		lg.attempt(attempt)
		return codeAuthinfoUnavail, reasonConfig
	}
	lg.debugf("loaded %s (issuer %s, %d mapped users)", configPath, cfg.Issuer, len(cfg.Users))

	// Decide PAM_IGNORE before touching the network: an unmanaged account
	// (root, a service user...) must not pay for discovery or wait out a
	// provider outage.
	if _, ok := cfg.LookupUser(user); !ok {
		attempt.Result, attempt.Reason = pamlog.ResultIgnore, auth.ReasonNotMapped
		lg.attempt(attempt)
		return codeIgnore, auth.ReasonNotMapped
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.HTTPTimeout*discoveryTimeoutFactor)
	client, err := oidc.New(ctx, oidc.Options{
		Issuer:            cfg.Issuer,
		ClientID:          cfg.ClientID,
		Scope:             cfg.Scope,
		HTTPTimeout:       cfg.HTTPTimeout,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
	})
	cancel()
	if err != nil {
		// Same message the authenticator shows when a later request fails:
		// the user must not be left staring at a silent prompt.
		_ = out.Info(auth.MsgProviderUnavailable)
		attempt.Result, attempt.Reason = pamlog.ResultError, auth.ReasonProviderUnavailable
		attempt.Err = fmt.Errorf("discovery: %w", err)
		lg.attempt(attempt)
		return codeAuthinfoUnavail, auth.ReasonProviderUnavailable
	}
	lg.debugf("discovery ok for %s, starting device flow for %s", cfg.Issuer, user)

	// Device flow extensions of the provider contract §6. They tell the
	// provider which enrolled host and which local account the login is
	// for; a host that is not enrolled sends nothing extra and gets the
	// plain flow.
	// Confirmación con PIN: se lee del discovery ANTES de pedir el código.
	// Solo si el proveedor lo anuncia se declara `confirmation_supported` y
	// se prepara el prompt; así un módulo nuevo contra un proveedor viejo
	// sigue entrando como siempre.
	confirm := client.SSH().ConfirmationSupported
	extra, err := deviceAuthParams(cfg, user, sshAccessEndpoint(client), confirm)
	if err != nil {
		// Carry on without them. The assertion only adds context to a
		// decision the provider makes anyway, so a stale key path or an
		// unreadable key must not lock out a host whose plain device flow
		// still works; a provider that only serves managed hosts refuses
		// the request itself.
		lg.noticef("continuing without a host assertion: %v", err)
		extra = nil
	}
	if extra != nil {
		lg.debugf("device flow for host %s, account %s", cfg.HostID, user)
	}

	// The authenticator bounds its own wait (config timeout and device code
	// lifetime); the module additionally enforces a wall-clock limit.
	// El PIN solo aplica si además se manda la assertion: es la misma
	// condición que usa el proveedor para generarlo (flujo SSH identificado).
	res := auth.New(cfg, client, out).
		WithDeviceAuthParams(extra).
		WithConfirmation(confirm && extra != nil).
		Authenticate(context.Background(), user)
	attempt.User, attempt.Subject = res.Username, res.Subject
	attempt.Reason, attempt.Err = res.Reason, res.Err

	switch res.Code {
	case auth.Success:
		if err := exportEnv(out, res.Env); err != nil {
			// Never grant a session whose identity variables are missing:
			// a value the provider crafted is an authentication failure.
			attempt.Result, attempt.Reason, attempt.Err = pamlog.ResultDenied, reasonEnv, err
			lg.attempt(attempt)
			return codeAuthErr, reasonEnv
		}
		attempt.Result = pamlog.ResultSuccess
		lg.attempt(attempt)
		return codeSuccess, ""
	case auth.Ignore:
		attempt.Result = pamlog.ResultIgnore
		lg.attempt(attempt)
		return codeIgnore, res.Reason
	case auth.AuthErr:
		attempt.Result = pamlog.ResultDenied
		lg.attempt(attempt)
		return codeAuthErr, res.Reason
	default:
		attempt.Result = pamlog.ResultError
		lg.attempt(attempt)
		return codeAuthinfoUnavail, res.Reason
	}
}

// intentLogin is the value of the "intent" parameter for a login; the other
// intent of the contract, "enroll", belongs to the oidc-ssh command.
const intentLogin = "login"

// deviceAuthParams builds the device authorization extension parameters of
// the provider contract §6 for a login as account.
//
// A host that carries no host_id in its configuration is not enrolled: it
// returns a nil map and nil error, and the request is byte for byte the one
// earlier releases sent. Otherwise it mints a fresh host assertion —
// addressed to the API base the contract's resolution order yields, which
// is what the provider checks the "aud" claim against — and returns it
// alongside the account and the intent.
func deviceAuthParams(cfg *config.Config, account, discoveryEndpoint string, confirmation bool) (map[string]string, error) {
	if cfg.HostID == "" {
		return nil, nil
	}
	base := provider.ResolveBase(cfg.APIBase, cfg.Issuer, discoveryEndpoint)
	if base == "" {
		return nil, errors.New("no api_base, ssh_access_endpoint or issuer to address the assertion to")
	}
	id, err := hostid.Load(cfg.IdentityKey)
	if err != nil {
		return nil, err
	}
	assertion, err := id.Assertion(cfg.HostID, base, nil)
	if err != nil {
		return nil, err
	}
	params := map[string]string{
		"host_assertion": assertion,
		"account":        account,
		"intent":         intentLogin,
	}
	if confirmation {
		params["confirmation_supported"] = "true"
	}
	return params, nil
}

// sshAccessEndpoint returns the ssh_access_endpoint the provider advertises
// in its discovery document, or "" when it advertises none. The document was
// already fetched, so this costs no request.
func sshAccessEndpoint(client *oidc.Client) string {
	return client.SSH().AccessEndpoint
}

// exportEnv emits the session variables in a stable order. Names were

// validated by the configuration (or are constants); values come from token
// claims, so anything that is not clean UTF-8 text is rejected before it can
// reach the module.
func exportEnv(out *protocol, env map[string]string) error {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := env[name]
		if !pamlog.ValidEnvValue(name) || strings.ContainsAny(name, "= ") {
			return fmt.Errorf("%w: variable name %q", errInvalidEnv, pamlog.Sanitize(name, pamlog.MaxValueLen))
		}
		if !pamlog.ValidEnvValue(value) {
			return fmt.Errorf("%w: %s contains control characters or invalid UTF-8", errInvalidEnv, name)
		}
		out.env(name, value)
	}
	return nil
}

// protocol speaks the line protocol. Every line is flushed immediately so
// the module can forward messages while the flow is still running.
type protocol struct {
	w *bufio.Writer
	r *bufio.Reader
}

func newProtocol(w io.Writer, r io.Reader) *protocol {
	return &protocol{w: bufio.NewWriter(w), r: bufio.NewReader(r)}
}

func (p *protocol) line(kind byte, payload string) {
	// The protocol is line based: a newline inside a payload would be read
	// as a second command. Prompts are sanitised (control characters except
	// \n and \t removed) and then newlines are folded into spaces.
	payload = strings.NewReplacer("\n", " ", "\r", " ").Replace(payload)
	_ = p.w.WriteByte(kind)
	_ = p.w.WriteByte(' ')
	_, _ = p.w.WriteString(payload)
	_ = p.w.WriteByte('\n')
	_ = p.w.Flush()
}

// Info implements auth.Prompter.
func (p *protocol) Info(msg string) error {
	p.line('I', pamlog.SanitizePrompt(msg))
	return nil
}

// Prompt implements auth.Prompter: it asks the module to show msg as an
// echo-off prompt and blocks until the module reports that the user has
// answered. EOF on stdin (the module cannot prompt) is returned as an error,
// which the authenticator treats as "carry on without waiting".
func (p *protocol) Prompt(msg string) error {
	p.line('P', pamlog.SanitizePrompt(msg))
	if _, err := p.r.ReadString('\n'); err != nil {
		return fmt.Errorf("prompt not acknowledged: %w", err)
	}
	return nil
}

// Ask implements auth.Prompter: it asks the module to show msg as an
// echo-off prompt and returns what the user typed. The module answers with
// one line; EOF (an older module, or one that cannot prompt) is an error,
// because without the answer there is no PIN to send.
//
// The answer never reaches the log: it is the confirmation PIN.
func (p *protocol) Ask(msg string) (string, error) {
	p.line('Q', pamlog.SanitizePrompt(msg))
	line, err := p.r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("prompt not answered: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (p *protocol) env(name, value string) { p.line('E', name+"="+value) }

func (p *protocol) result(code, reason string) {
	if reason == "" {
		reason = "-"
	}
	p.line('R', code+" "+reason)
}

func (p *protocol) flush() error { return p.w.Flush() }

// logger writes to the authpriv facility, or to stderr when syslog cannot
// be opened. Logging never fails the login: every error is swallowed.
type logger struct {
	w     *syslog.Writer
	debug bool
}

func newLogger(debug bool) *logger {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, syslogTag)
	if err != nil {
		w = nil
	}
	return &logger{w: w, debug: debug}
}

func (l *logger) close() {
	if l.w != nil {
		_ = l.w.Close()
	}
}

// log writes msg at the given level. Debug lines are dropped unless the
// module was loaded with the debug argument.
func (l *logger) log(level pamlog.Level, msg string) {
	if level == pamlog.LevelDebug && !l.debug {
		return
	}
	if l.w != nil {
		var err error
		switch level {
		case pamlog.LevelDebug:
			err = l.w.Debug(msg)
		case pamlog.LevelInfo:
			err = l.w.Info(msg)
		case pamlog.LevelNotice:
			err = l.w.Notice(msg)
		default:
			err = l.w.Err(msg)
		}
		if err == nil {
			return
		}
	}
	// Fallback; a write error (closed stderr) is irrelevant.
	_, _ = fmt.Fprintf(os.Stderr, "%s[%d]: <%s> %s\n", syslogTag, os.Getpid(), level, msg)
}

func (l *logger) debugf(format string, args ...any) {
	if !l.debug {
		return
	}
	l.log(pamlog.LevelDebug, pamlog.Sanitize(fmt.Sprintf(format, args...), 0))
}

// noticef reports a degraded but non-fatal condition; unlike debugf it is
// always logged.
func (l *logger) noticef(format string, args ...any) {
	l.log(pamlog.LevelNotice, pamlog.Sanitize(fmt.Sprintf(format, args...), 0))
}

// attempt writes the audit line for one attempt at the level its result
// commands.
func (l *logger) attempt(a pamlog.Attempt) {
	l.log(pamlog.LevelFor(a.Result), a.Line())
}
