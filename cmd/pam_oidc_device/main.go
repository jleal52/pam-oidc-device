//go:build cgo && linux && pam

// Package main is the PAM module pam_oidc_device.so.
//
// It is built with -buildmode=c-shared (make so, which passes -tags pam:
// the package needs libpam headers, so it is opt-in and stays out of plain
// go build/test/vet runs) and exports pam_sm_authenticate,
// pam_sm_setcred and pam_sm_acct_mgmt. The module is deliberately thin: it
// reads the module arguments, resolves the PAM user, loads the
// configuration, runs the device flow through internal/auth and translates
// the outcome into a PAM return code, a PAM environment and one syslog line.
//
// Module arguments:
//
//	config=<path>  configuration file (default /etc/security/pam_oidc_device.yaml)
//	debug          also log ignored users and progress at LOG_DEBUG
package main

/*
#cgo LDFLAGS: -lpam
#include "pam_shim.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"sort"
	"strings"
	"unsafe"

	"github.com/jleal52/pam-oidc-device/internal/auth"
	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/oidc"
	"github.com/jleal52/pam-oidc-device/internal/pamlog"
	"github.com/jleal52/pam-oidc-device/internal/pammap"
)

// syslogTag identifies the module in the authpriv log.
const syslogTag = "pam_oidc_device"

// discoveryTimeoutFactor bounds OpenID discovery: it is a handful of small
// requests, so a few HTTP timeouts is plenty.
const discoveryTimeoutFactor = 3

// Reasons produced by this layer, complementing the auth.Reason* values.
const (
	reasonNoUser = "no_user"
	reasonConfig = "config"
	reasonPutenv = "putenv"
	reasonPanic  = "panic"
)

// main is required by -buildmode=c-shared and never runs.
func main() {}

// options are the module arguments from the PAM configuration line.
type options struct {
	configPath string
	debug      bool
	unknown    []string
}

// parseArgs reads argv[0..argc). Unknown arguments are collected so they can
// be logged once instead of silently ignored.
func parseArgs(argc C.int, argv *C.pam_argv_t) options {
	o := options{configPath: config.DefaultPath}
	if argc <= 0 || argv == nil {
		return o
	}
	for _, arg := range unsafe.Slice(argv, int(argc)) {
		if arg == nil {
			continue
		}
		s := C.GoString((*C.char)(arg))
		switch {
		case s == "debug":
			o.debug = true
		case strings.HasPrefix(s, "config="):
			if v := strings.TrimPrefix(s, "config="); v != "" {
				o.configPath = v
			}
		default:
			o.unknown = append(o.unknown, s)
		}
	}
	return o
}

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
	// Fallback; the write error (closed stderr under sshd) is irrelevant.
	_, _ = fmt.Fprintf(os.Stderr, "%s[%d]: <%s> %s\n", syslogTag, os.Getpid(), level, msg)
}

func (l *logger) debugf(format string, args ...any) {
	if !l.debug {
		return
	}
	l.log(pamlog.LevelDebug, pamlog.Sanitize(fmt.Sprintf(format, args...), 0))
}

// attempt writes the audit line for one attempt at the level its result
// commands.
func (l *logger) attempt(a pamlog.Attempt) {
	l.log(pamlog.LevelFor(a.Result), a.Line())
}

// prompter shows PAM_TEXT_INFO messages through the PAM conversation.
type prompter struct {
	pamh *C.pam_handle_t
	lg   *logger
}

// Info implements auth.Prompter. A failing conversation is reported to the
// caller, which ignores it by contract, and to the debug log.
func (p *prompter) Info(msg string) error {
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	if rc := C.shim_info(p.pamh, cmsg); rc != C.PAM_SUCCESS {
		p.lg.debugf("conversation failed with PAM code %d", int(rc))
		return fmt.Errorf("pam conversation returned %d", int(rc))
	}
	return nil
}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv *C.pam_argv_t) (rc C.int) {
	_ = flags
	var lg *logger
	// A Go panic must never unwind into sshd: recover, log and deny.
	defer func() {
		if r := recover(); r != nil {
			if lg == nil {
				lg = newLogger(false)
			}
			lg.attempt(pamlog.Attempt{
				Result: pamlog.ResultError,
				Reason: reasonPanic,
				Err:    fmt.Errorf("panic: %v", r),
			})
			rc = C.PAM_AUTHINFO_UNAVAIL
		}
		if lg != nil {
			lg.close()
		}
	}()

	opts := parseArgs(argc, argv)
	lg = newLogger(opts.debug)
	if len(opts.unknown) > 0 {
		lg.log(pamlog.LevelNotice, "ignoring unknown module arguments: "+
			pamlog.Sanitize(strings.Join(opts.unknown, ","), pamlog.MaxValueLen))
	}
	return authenticate(pamh, opts, lg)
}

// authenticate runs one attempt and returns the PAM code. It is separate
// from the exported entry point so that the panic guard wraps all of it.
func authenticate(pamh *C.pam_handle_t, opts options, lg *logger) C.int {
	hostname, _ := os.Hostname()
	attempt := pamlog.Attempt{Host: hostname}

	// The user string is owned by PAM: read it, never free it.
	var cUser *C.char
	if rc := C.shim_get_user(pamh, &cUser); rc != C.PAM_SUCCESS || cUser == nil {
		attempt.Result, attempt.Reason = pamlog.ResultError, reasonNoUser
		attempt.Err = fmt.Errorf("pam_get_user returned %d", int(rc))
		lg.attempt(attempt)
		return C.PAM_USER_UNKNOWN
	}
	user := C.GoString(cUser)
	attempt.LocalUser = user
	attempt.RHost = C.GoString(C.shim_get_rhost(pamh))
	if user == "" {
		attempt.Result, attempt.Reason = pamlog.ResultError, reasonNoUser
		attempt.Err = errors.New("empty PAM user")
		lg.attempt(attempt)
		return C.PAM_USER_UNKNOWN
	}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		attempt.Result, attempt.Reason, attempt.Err = pamlog.ResultError, reasonConfig, err
		lg.attempt(attempt)
		return C.PAM_AUTHINFO_UNAVAIL
	}
	lg.debugf("loaded %s (issuer %s, %d mapped users)", opts.configPath, cfg.Issuer, len(cfg.Users))

	// Decide PAM_IGNORE before touching the network: an unmanaged account
	// (root, a service user...) must not pay for discovery or wait out a
	// provider outage.
	if _, ok := cfg.LookupUser(user); !ok {
		attempt.Result, attempt.Reason = pamlog.ResultIgnore, auth.ReasonNotMapped
		lg.attempt(attempt)
		return C.PAM_IGNORE
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
		attempt.Result, attempt.Reason = pamlog.ResultError, auth.ReasonProviderUnavailable
		attempt.Err = fmt.Errorf("discovery: %w", err)
		lg.attempt(attempt)
		return C.PAM_AUTHINFO_UNAVAIL
	}
	lg.debugf("discovery ok for %s, starting device flow for %s", cfg.Issuer, user)

	// The authenticator bounds its own wait (config timeout and device code
	// lifetime), so the outer context is unbounded on purpose.
	res := auth.New(cfg, client, &prompter{pamh: pamh, lg: lg}).Authenticate(context.Background(), user)
	attempt.User, attempt.Subject = res.Username, res.Subject
	attempt.Result, attempt.Reason, attempt.Err = pammap.Result(res.Code), res.Reason, res.Err

	code := pammap.ToPAM(res.Code)
	if code == pammap.PAMSuccess {
		if err := exportEnv(pamh, res.Env); err != nil {
			// Never grant a session whose identity variables are missing.
			attempt.Result, attempt.Reason, attempt.Err = pamlog.ResultError, reasonPutenv, err
			lg.attempt(attempt)
			return C.PAM_AUTHINFO_UNAVAIL
		}
	}
	lg.attempt(attempt)
	return C.int(code)
}

// exportEnv publishes env into the PAM environment in a stable order.
func exportEnv(pamh *C.pam_handle_t, env map[string]string) error {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := env[name]
		if strings.ContainsRune(name, 0) || strings.ContainsRune(value, 0) {
			return fmt.Errorf("environment variable %q contains a NUL byte", name)
		}
		kv := C.CString(name + "=" + value)
		rc := C.shim_putenv(pamh, kv)
		C.free(unsafe.Pointer(kv))
		if rc != C.PAM_SUCCESS {
			return fmt.Errorf("pam_putenv(%s) returned %d", name, int(rc))
		}
	}
	return nil
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv *C.pam_argv_t) C.int {
	_, _, _, _ = pamh, flags, argc, argv
	return C.PAM_SUCCESS
}

//export pam_sm_acct_mgmt
func pam_sm_acct_mgmt(pamh *C.pam_handle_t, flags C.int, argc C.int, argv *C.pam_argv_t) C.int {
	_, _, _, _ = pamh, flags, argc, argv
	return C.PAM_SUCCESS
}
