// Package auth orchestrates a single login attempt: it maps the requested
// local account to the group a user must hold, drives the device
// authorization flow through a Flow, talks to the user through a Prompter
// and reduces the outcome to a Result that the PAM layer can translate into
// a return code and log lines.
//
// The package has no PAM dependency so that the whole decision logic can be
// tested with fakes.
package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/oauth2"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/oidc"
)

// Code is the outcome of an authentication attempt, one per PAM return
// code the module can produce.
type Code int

// Outcomes of Authenticate.
const (
	// Success means the user was authenticated and Result.Env is set.
	Success Code = iota
	// Ignore means the local user is not managed by this module, so the
	// PAM stack should fall through to the next module.
	Ignore
	// AuthErr means the user was not authenticated (denied, expired,
	// invalid token, wrong group...).
	AuthErr
	// AuthInfoUnavail means the identity provider could not be reached or
	// answered unexpectedly; the outcome says nothing about the user.
	AuthInfoUnavail
)

// String returns a short, lower-case name suitable for logs.
func (c Code) String() string {
	switch c {
	case Success:
		return "success"
	case Ignore:
		return "ignore"
	case AuthErr:
		return "auth_err"
	case AuthInfoUnavail:
		return "authinfo_unavail"
	default:
		return fmt.Sprintf("Code(%d)", int(c))
	}
}

// Machine-readable reasons carried in Result.Reason.
const (
	ReasonNotMapped           = "not_mapped"
	ReasonProviderUnavailable = "provider_unavailable"
	ReasonDenied              = "denied"
	ReasonTimeout             = "timeout"
	ReasonExpired             = "expired"
	ReasonNoIDToken           = "no_id_token"
	ReasonInvalidToken        = "invalid_token"
	ReasonMissingGroup        = "missing_group"
	ReasonEmptyUsername       = "empty_username"
)

// Messages shown to the user through the Prompter.
const (
	msgProviderUnavailable = "Identity provider unavailable, cannot continue."
	msgOpenURL             = "Open the following URL in a browser and approve this login:"
	msgDenied              = "Login denied."
	msgExpired             = "The code expired before approval; try again."
	msgTimeout             = "No approval received in time."
)

// EnvSubject is the environment variable that receives the token subject.
const EnvSubject = "OIDC_SUB"

// Result is the outcome of Authenticate.
type Result struct {
	// Code is the outcome to translate into a PAM return code.
	Code Code
	// Reason is a machine-readable cause, empty on Success. One of the
	// Reason* constants.
	Reason string
	// Username is the value of the configured username claim. Set once
	// the ID token has been verified, on success and on missing_group.
	Username string
	// Subject is the token "sub" claim, set together with Username.
	Subject string
	// Group is the group required to log in as the local user. Set as
	// soon as the user is found in the configuration.
	Group string
	// Env holds the variables to export into the session on Success:
	// the configured session_env set to Username, and OIDC_SUB set to
	// Subject. Nil otherwise.
	Env map[string]string
	// Err is the underlying error for logging, nil on Success and Ignore.
	// It wraps the oidc sentinel errors and never contains token material.
	Err error
}

// Prompter shows informational text to the user (PAM_TEXT_INFO). Errors
// returned by Info are ignored by the Authenticator: a broken conversation
// must never change the outcome of the login, which is decided by the
// identity provider alone.
type Prompter interface {
	Info(msg string) error
}

// Flow is the subset of the OIDC client driven by the Authenticator. It is
// satisfied by *oidc.Client.
type Flow interface {
	StartDeviceAuth(ctx context.Context, deviceName string) (*oauth2.DeviceAuthResponse, error)
	WaitForToken(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error)
	VerifyIDToken(ctx context.Context, raw, usernameClaim, groupsClaim string, skew time.Duration) (*oidc.Identity, error)
}

var _ Flow = (*oidc.Client)(nil)

// Authenticator runs the login decision for one configuration.
type Authenticator struct {
	cfg    *config.Config
	flow   Flow
	prompt Prompter
	now    func() time.Time
}

// New returns an Authenticator using cfg, flow and prompt.
func New(cfg *config.Config, flow Flow, prompt Prompter) *Authenticator {
	return &Authenticator{cfg: cfg, flow: flow, prompt: prompt, now: time.Now}
}

// Authenticate runs the device flow for a login as localUser and returns
// the outcome. It never panics on a failing Prompter and never returns an
// error containing token material.
func (a *Authenticator) Authenticate(ctx context.Context, localUser string) Result {
	group, ok := a.cfg.LookupUser(localUser)
	if !ok {
		return Result{Code: Ignore, Reason: ReasonNotMapped}
	}
	res := Result{Group: group}

	da, err := a.flow.StartDeviceAuth(ctx, a.cfg.DeviceName)
	if err != nil {
		a.info(msgProviderUnavailable)
		return a.fail(res, AuthInfoUnavail, ReasonProviderUnavailable, fmt.Errorf("start device authorization: %w", err))
	}
	a.showInstructions(da)

	tok, err := a.waitForToken(ctx, da)
	if err != nil {
		return a.waitFailure(res, err)
	}

	raw, err := oidc.IDTokenFrom(tok)
	if err != nil {
		return a.fail(res, AuthErr, ReasonNoIDToken, err)
	}
	id, err := a.flow.VerifyIDToken(ctx, raw, a.cfg.UsernameClaim, a.cfg.GroupsClaim, a.cfg.ClockSkew)
	if err != nil {
		return a.fail(res, AuthErr, ReasonInvalidToken, fmt.Errorf("verify id_token: %w", err))
	}
	if id.Username == "" {
		return a.fail(res, AuthErr, ReasonEmptyUsername,
			fmt.Errorf("id_token for subject %q has no %q claim", id.Subject, a.cfg.UsernameClaim))
	}
	res.Username, res.Subject = id.Username, id.Subject

	if !slices.Contains(id.Groups, group) {
		a.info(fmt.Sprintf("Not allowed to log in as %s on this host.", localUser))
		return a.fail(res, AuthErr, ReasonMissingGroup,
			fmt.Errorf("user %q (subject %q) is not a member of group %q", id.Username, id.Subject, group))
	}

	res.Code = Success
	res.Env = map[string]string{
		a.cfg.SessionEnv: id.Username,
		EnvSubject:       id.Subject,
	}
	return res
}

// showInstructions prints the URL and the user code. The complete URI is
// preferred when the provider offers one; the code is always printed so
// the user can compare it with the approval page.
func (a *Authenticator) showInstructions(da *oauth2.DeviceAuthResponse) {
	uri := da.VerificationURIComplete
	if uri == "" {
		uri = da.VerificationURI
	}
	a.info(msgOpenURL)
	a.info("  " + uri)
	a.info("Code: " + da.UserCode)
}

// waitForToken polls for the token with a deadline bounded by the
// configured timeout and by the device code lifetime, whichever is
// shorter.
func (a *Authenticator) waitForToken(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	wait := a.cfg.Timeout
	if !da.Expiry.IsZero() {
		if remaining := da.Expiry.Sub(a.now()); remaining < wait {
			wait = remaining
		}
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return a.flow.WaitForToken(ctx, da)
}

// waitFailure maps a WaitForToken error to a Result and tells the user
// what happened when the failure is theirs to act on.
func (a *Authenticator) waitFailure(res Result, err error) Result {
	switch {
	case errors.Is(err, oidc.ErrAccessDenied):
		a.info(msgDenied)
		return a.fail(res, AuthErr, ReasonDenied, err)
	case errors.Is(err, oidc.ErrExpired):
		a.info(msgExpired)
		return a.fail(res, AuthErr, ReasonExpired, err)
	case errors.Is(err, oidc.ErrTimeout):
		a.info(msgTimeout)
		return a.fail(res, AuthErr, ReasonTimeout, err)
	default:
		return a.fail(res, AuthInfoUnavail, ReasonProviderUnavailable, fmt.Errorf("wait for token: %w", err))
	}
}

func (a *Authenticator) fail(res Result, code Code, reason string, err error) Result {
	res.Code, res.Reason, res.Err = code, reason, err
	return res
}

// info sends a line to the user. A failing conversation is deliberately
// ignored: the PAM layer is the one that can log it, and it must not
// change the outcome of the login.
func (a *Authenticator) info(msg string) {
	if a.prompt == nil {
		return
	}
	_ = a.prompt.Info(msg)
}
