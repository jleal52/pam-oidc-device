package auth_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/jleal52/oidc-ssh/internal/auth"
	"github.com/jleal52/oidc-ssh/internal/config"
	"github.com/jleal52/oidc-ssh/internal/oidc"
)

const testYAML = `
issuer: https://idp.example.com
client_id: pam-test
device_name: test-host
timeout: 120s
users:
  systems: ssh:admin
`

var fixedNow = time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

// fakeFlow implements auth.Flow with overridable function fields. Every
// call is counted so tests can assert that a branch made no network calls.
type fakeFlow struct {
	startCalls, waitCalls, verifyCalls int
	// lastExtra is the extra parameter map of the last StartDeviceAuth call.
	lastExtra map[string]string
	// lastConfirmation is the PIN of the last WaitForToken call.
	lastConfirmation string

	start  func(ctx context.Context, deviceName string) (*oauth2.DeviceAuthResponse, error)
	wait   func(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error)
	verify func(ctx context.Context, raw, usernameClaim, groupsClaim string, skew time.Duration) (*oidc.Identity, error)
}

func (f *fakeFlow) StartDeviceAuth(ctx context.Context, deviceName string, extra map[string]string) (*oauth2.DeviceAuthResponse, error) {
	f.startCalls++
	f.lastExtra = extra
	if f.start == nil {
		return nil, errors.New("fakeFlow: StartDeviceAuth not configured")
	}
	return f.start(ctx, deviceName)
}

func (f *fakeFlow) WaitForToken(ctx context.Context, da *oauth2.DeviceAuthResponse, confirmation string) (*oauth2.Token, error) {
	f.waitCalls++
	f.lastConfirmation = confirmation
	if f.wait == nil {
		return nil, errors.New("fakeFlow: WaitForToken not configured")
	}
	return f.wait(ctx, da)
}

func (f *fakeFlow) VerifyIDToken(ctx context.Context, raw, usernameClaim, groupsClaim string, skew time.Duration) (*oidc.Identity, error) {
	f.verifyCalls++
	if f.verify == nil {
		return nil, errors.New("fakeFlow: VerifyIDToken not configured")
	}
	return f.verify(ctx, raw, usernameClaim, groupsClaim, skew)
}

// recordingPrompter records every Info and Prompt line (prompts prefixed
// with "? "); err, when set, is returned from each call.
type recordingPrompter struct {
	lines  []string
	err    error
	answer string
	askErr error
}

func (p *recordingPrompter) Info(msg string) error {
	p.lines = append(p.lines, msg)
	return p.err
}

func (p *recordingPrompter) Prompt(msg string) error {
	p.lines = append(p.lines, "? "+msg)
	return p.err
}

// Ask records the question (prefixed with "?? ") and returns answer. When
// askErr is set it is returned instead, modelling a module that cannot
// prompt.
func (p *recordingPrompter) Ask(msg string) (string, error) {
	p.lines = append(p.lines, "?? "+msg)
	if p.askErr != nil {
		return "", p.askErr
	}
	return p.answer, nil
}

func newConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(testYAML))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return cfg
}

func deviceAuth() *oauth2.DeviceAuthResponse {
	return &oauth2.DeviceAuthResponse{
		DeviceCode:              "device-code",
		UserCode:                "ABCD-EFGH",
		VerificationURI:         "https://idp.example.com/device",
		VerificationURIComplete: "https://idp.example.com/device?user_code=ABCD-EFGH",
		Expiry:                  fixedNow.Add(10 * time.Minute),
		Interval:                5,
	}
}

func tokenWithID(raw string) *oauth2.Token {
	tok := &oauth2.Token{AccessToken: "access-token-secret"}
	if raw == "" {
		return tok
	}
	return tok.WithExtra(map[string]any{"id_token": raw})
}

func identity(username string, groups ...string) *oidc.Identity {
	return &oidc.Identity{Subject: "sub-123", Username: username, Groups: groups}
}

// happyFlow returns a fakeFlow that walks the whole flow to success.
func happyFlow() *fakeFlow {
	return &fakeFlow{
		start: func(_ context.Context, _ string) (*oauth2.DeviceAuthResponse, error) {
			return deviceAuth(), nil
		},
		wait: func(_ context.Context, _ *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
			return tokenWithID("raw-id-token"), nil
		},
		verify: func(_ context.Context, _, _, _ string, _ time.Duration) (*oidc.Identity, error) {
			return identity("alice@example.com", "ssh:admin", "staff"), nil
		},
	}
}

var expectedPromptLines = []string{
	"Open the following URL in a browser and approve this login:",
	"  https://idp.example.com/device?user_code=ABCD-EFGH",
	"? Code: ABCD-EFGH. Press Enter after approving in the browser: ",
}

func newAuthenticator(t *testing.T, flow auth.Flow, prompt auth.Prompter) *auth.Authenticator {
	t.Helper()
	a := auth.New(newConfig(t), flow, prompt)
	auth.SetNow(a, func() time.Time { return fixedNow })
	return a
}

func assertResult(t *testing.T, got auth.Result, code auth.Code, reason string) {
	t.Helper()
	if got.Code != code {
		t.Errorf("Code = %v, want %v (reason %q, err %v)", got.Code, code, got.Reason, got.Err)
	}
	if got.Reason != reason {
		t.Errorf("Reason = %q, want %q", got.Reason, reason)
	}
	if code != auth.Success && got.Env != nil {
		t.Errorf("Env = %v, want nil on failure", got.Env)
	}
}

func assertLines(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prompt lines = %q, want %q", got, want)
	}
}

func withPrompt(extra ...string) []string {
	return append(append([]string{}, expectedPromptLines...), extra...)
}

// --- Rule 1: unmapped user ---

func TestIgnoreWhenUserNotMapped(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "root")

	assertResult(t, res, auth.Ignore, "not_mapped")
	if res.Err != nil {
		t.Errorf("Err = %v, want nil", res.Err)
	}
	if flow.startCalls+flow.waitCalls+flow.verifyCalls != 0 {
		t.Errorf("flow was called (start=%d wait=%d verify=%d), want no calls", flow.startCalls, flow.waitCalls, flow.verifyCalls)
	}
	if len(prompt.lines) != 0 {
		t.Errorf("prompt lines = %q, want none", prompt.lines)
	}
}

// --- Rule 2: provider unavailable at start ---

func TestProviderUnavailableWhenStartFails(t *testing.T) {
	t.Parallel()
	cause := errors.New("connection refused")
	flow := happyFlow()
	var gotDeviceName string
	flow.start = func(_ context.Context, deviceName string) (*oauth2.DeviceAuthResponse, error) {
		gotDeviceName = deviceName
		return nil, cause
	}
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.AuthInfoUnavail, "provider_unavailable")
	if !errors.Is(res.Err, cause) {
		t.Errorf("Err = %v, want wrapping %v", res.Err, cause)
	}
	if gotDeviceName != "test-host" {
		t.Errorf("device name = %q, want %q", gotDeviceName, "test-host")
	}
	assertLines(t, prompt.lines, []string{"Identity provider unavailable, cannot continue."})
	if flow.waitCalls != 0 || flow.verifyCalls != 0 {
		t.Errorf("wait=%d verify=%d, want 0", flow.waitCalls, flow.verifyCalls)
	}
}

// --- Rule 3: prompt lines ---

func TestPromptUsesCompleteURIAndCode(t *testing.T) {
	t.Parallel()
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, happyFlow(), prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.Success, "")
	assertLines(t, prompt.lines, expectedPromptLines)
}

func TestPromptFallsBackToVerificationURI(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	flow.start = func(_ context.Context, _ string) (*oauth2.DeviceAuthResponse, error) {
		da := deviceAuth()
		da.VerificationURIComplete = ""
		return da, nil
	}
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.Success, "")
	assertLines(t, prompt.lines, []string{
		"Open the following URL in a browser and approve this login:",
		"  https://idp.example.com/device",
		"? Code: ABCD-EFGH. Press Enter after approving in the browser: ",
	})
}

// --- Rule 4: waiting for the token ---

func TestWaitDeadlineIsBoundedByTimeoutAndExpiry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expiry   time.Time
		wantWait time.Duration
	}{
		{"expiry shorter than timeout", fixedNow.Add(30 * time.Second), 30 * time.Second},
		{"timeout shorter than expiry", fixedNow.Add(time.Hour), 120 * time.Second},
		{"zero expiry uses timeout", time.Time{}, 120 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flow := happyFlow()
			flow.start = func(_ context.Context, _ string) (*oauth2.DeviceAuthResponse, error) {
				da := deviceAuth()
				da.Expiry = tc.expiry
				return da, nil
			}
			var deadline time.Time
			var hasDeadline bool
			flow.wait = func(ctx context.Context, _ *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
				deadline, hasDeadline = ctx.Deadline()
				return tokenWithID("raw-id-token"), nil
			}
			start := time.Now()
			res := newAuthenticator(t, flow, &recordingPrompter{}).Authenticate(context.Background(), "systems")
			end := time.Now()

			assertResult(t, res, auth.Success, "")
			if !hasDeadline {
				t.Fatal("WaitForToken context has no deadline")
			}
			// The deadline is start+wantWait computed on the wall clock at
			// some point between start and end.
			if deadline.Before(start.Add(tc.wantWait)) || deadline.After(end.Add(tc.wantWait)) {
				t.Errorf("deadline %v, want %v after a point in [%v, %v]", deadline, tc.wantWait, start, end)
			}
			if deadline.After(end.Add(120 * time.Second)) {
				t.Errorf("deadline %v exceeds cfg.Timeout", deadline)
			}
			if !tc.expiry.IsZero() && deadline.Sub(end) > tc.expiry.Sub(fixedNow) {
				t.Errorf("deadline %v exceeds device code lifetime %v", deadline, tc.expiry.Sub(fixedNow))
			}
		})
	}
}

func TestWaitDeadlineDoesNotOutliveParentContext(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	parentDeadline, _ := parent.Deadline()

	flow := happyFlow()
	var deadline time.Time
	flow.wait = func(ctx context.Context, _ *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
		deadline, _ = ctx.Deadline()
		return tokenWithID("raw-id-token"), nil
	}
	res := newAuthenticator(t, flow, &recordingPrompter{}).Authenticate(parent, "systems")

	assertResult(t, res, auth.Success, "")
	if deadline.After(parentDeadline) {
		t.Errorf("deadline %v exceeds parent deadline %v", deadline, parentDeadline)
	}
}

func TestWaitErrorsAreMapped(t *testing.T) {
	t.Parallel()
	other := errors.New("token endpoint returned 500")
	cases := []struct {
		name       string
		err        error
		code       auth.Code
		reason     string
		wantPrompt []string
	}{
		{"denied", oidc.ErrAccessDenied, auth.AuthErr, "denied", withPrompt("Login denied.")},
		{"expired", oidc.ErrExpired, auth.AuthErr, "expired", withPrompt("The code expired before approval; try again.")},
		{"timeout", oidc.ErrTimeout, auth.AuthErr, "timeout", withPrompt("No approval received in time.")},
		{"other", other, auth.AuthInfoUnavail, "provider_unavailable", withPrompt()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flow := happyFlow()
			wrapped := errors.Join(errors.New("wrapped"), tc.err)
			flow.wait = func(_ context.Context, _ *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
				return nil, wrapped
			}
			prompt := &recordingPrompter{}
			res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

			assertResult(t, res, tc.code, tc.reason)
			if !errors.Is(res.Err, tc.err) {
				t.Errorf("Err = %v, want wrapping %v", res.Err, tc.err)
			}
			assertLines(t, prompt.lines, tc.wantPrompt)
			if flow.verifyCalls != 0 {
				t.Errorf("verify called %d times, want 0", flow.verifyCalls)
			}
		})
	}
}

func TestExpiredDeviceCodeSkipsWait(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		expiry time.Time
	}{
		{"expired in the past", fixedNow.Add(-time.Second)},
		{"expires exactly now", fixedNow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flow := happyFlow()
			flow.start = func(_ context.Context, _ string) (*oauth2.DeviceAuthResponse, error) {
				da := deviceAuth()
				da.Expiry = tc.expiry
				return da, nil
			}
			prompt := &recordingPrompter{}
			res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

			assertResult(t, res, auth.AuthErr, "expired")
			if !errors.Is(res.Err, oidc.ErrExpired) {
				t.Errorf("Err = %v, want wrapping %v", res.Err, oidc.ErrExpired)
			}
			// The URL and code are useless once expired: only the message.
			assertLines(t, prompt.lines, []string{"The code expired before approval; try again."})
			if flow.waitCalls != 0 || flow.verifyCalls != 0 {
				t.Errorf("wait=%d verify=%d, want 0/0", flow.waitCalls, flow.verifyCalls)
			}
		})
	}
}

func TestNilDeviceAuthIsProviderUnavailable(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	flow.start = func(_ context.Context, _ string) (*oauth2.DeviceAuthResponse, error) {
		return nil, nil // the contract violation under test
	}
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.AuthInfoUnavail, "provider_unavailable")
	if res.Err == nil {
		t.Error("Err = nil, want an error")
	}
	assertLines(t, prompt.lines, []string{"Identity provider unavailable, cannot continue."})
	if flow.waitCalls != 0 || flow.verifyCalls != 0 {
		t.Errorf("wait=%d verify=%d, want 0/0", flow.waitCalls, flow.verifyCalls)
	}
}

// --- Rule 5: id_token extraction and verification ---

func TestNoIDTokenIsAuthErr(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	flow.wait = func(_ context.Context, _ *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
		return tokenWithID(""), nil
	}
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.AuthErr, "no_id_token")
	if !errors.Is(res.Err, oidc.ErrNoIDToken) {
		t.Errorf("Err = %v, want wrapping %v", res.Err, oidc.ErrNoIDToken)
	}
	assertLines(t, prompt.lines, expectedPromptLines)
	if flow.verifyCalls != 0 {
		t.Errorf("verify called %d times, want 0", flow.verifyCalls)
	}
}

func TestInvalidTokenIsAuthErr(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	var gotRaw, gotUserClaim, gotGroupsClaim string
	var gotSkew time.Duration
	flow.verify = func(_ context.Context, raw, usernameClaim, groupsClaim string, skew time.Duration) (*oidc.Identity, error) {
		gotRaw, gotUserClaim, gotGroupsClaim, gotSkew = raw, usernameClaim, groupsClaim, skew
		return nil, oidc.ErrInvalidToken
	}
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.AuthErr, "invalid_token")
	if !errors.Is(res.Err, oidc.ErrInvalidToken) {
		t.Errorf("Err = %v, want wrapping %v", res.Err, oidc.ErrInvalidToken)
	}
	if gotRaw != "raw-id-token" || gotUserClaim != "email" || gotGroupsClaim != "groups" || gotSkew != 60*time.Second {
		t.Errorf("VerifyIDToken called with (%q, %q, %q, %v)", gotRaw, gotUserClaim, gotGroupsClaim, gotSkew)
	}
	assertLines(t, prompt.lines, expectedPromptLines)
}

// --- Rule 6: empty username ---

func TestEmptyUsernameIsAuthErr(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	flow.verify = func(_ context.Context, _, _, _ string, _ time.Duration) (*oidc.Identity, error) {
		return identity("", "ssh:admin"), nil
	}
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.AuthErr, "empty_username")
	if res.Err == nil {
		t.Error("Err = nil, want an error")
	}
	if res.Subject != "sub-123" || res.Username != "" {
		t.Errorf("Subject/Username = %q/%q, want %q/%q for logging", res.Subject, res.Username, "sub-123", "")
	}
	assertLines(t, prompt.lines, expectedPromptLines)
}

// --- Rule 7: missing group ---

func TestMissingGroupIsAuthErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		groups []string
	}{
		{"unrelated groups", []string{"staff", "ops"}},
		{"nil groups", nil},
		{"empty groups", []string{}},
		// Matching is exact: near misses must be rejected.
		{"longer name", []string{"ssh:adminx"}},
		{"different case", []string{"SSH:ADMIN"}},
		{"leading space", []string{" ssh:admin"}},
		{"missing prefix", []string{"admin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flow := happyFlow()
			flow.verify = func(_ context.Context, _, _, _ string, _ time.Duration) (*oidc.Identity, error) {
				return identity("bob@example.com", tc.groups...), nil
			}
			prompt := &recordingPrompter{}
			res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

			assertResult(t, res, auth.AuthErr, "missing_group")
			if res.Err == nil {
				t.Error("Err = nil, want an error")
			}
			if res.Env != nil {
				t.Errorf("Env = %v, want nil", res.Env)
			}
			if res.Group != "ssh:admin" {
				t.Errorf("Group = %q, want %q", res.Group, "ssh:admin")
			}
			if res.Username != "bob@example.com" || res.Subject != "sub-123" {
				t.Errorf("Username/Subject = %q/%q, want identity values for logging", res.Username, res.Subject)
			}
			assertLines(t, prompt.lines, withPrompt("Not allowed to log in as systems on this host."))
		})
	}
}

// --- Rule 8: success ---

func TestSuccessExportsEnv(t *testing.T) {
	t.Parallel()
	prompt := &recordingPrompter{}
	res := newAuthenticator(t, happyFlow(), prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.Success, "")
	if res.Err != nil {
		t.Errorf("Err = %v, want nil", res.Err)
	}
	if res.Username != "alice@example.com" || res.Subject != "sub-123" || res.Group != "ssh:admin" {
		t.Errorf("Username/Subject/Group = %q/%q/%q", res.Username, res.Subject, res.Group)
	}
	wantEnv := map[string]string{"OIDC_USER": "alice@example.com", "OIDC_SUB": "sub-123"}
	if !reflect.DeepEqual(res.Env, wantEnv) {
		t.Errorf("Env = %v, want %v", res.Env, wantEnv)
	}
	assertLines(t, prompt.lines, expectedPromptLines)
}

// --- Device authorization extension parameters ---

func TestDeviceAuthParamsAreForwarded(t *testing.T) {
	t.Parallel()
	extra := map[string]string{"host_assertion": "jwt", "account": "systems", "intent": "login"}
	flow := happyFlow()
	res := newAuthenticator(t, flow, &recordingPrompter{}).
		WithDeviceAuthParams(extra).
		Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.Success, "")
	if !reflect.DeepEqual(flow.lastExtra, extra) {
		t.Errorf("extra = %v, want %v", flow.lastExtra, extra)
	}
}

func TestDeviceAuthParamsDefaultToNone(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	newAuthenticator(t, flow, &recordingPrompter{}).Authenticate(context.Background(), "systems")

	if flow.lastExtra != nil {
		t.Errorf("extra = %v, want nil when none were set", flow.lastExtra)
	}
}

// --- Prompter failures are never fatal ---

func TestPrompterErrorIsIgnored(t *testing.T) {
	t.Parallel()
	prompt := &recordingPrompter{err: errors.New("conversation failed")}
	flow := happyFlow()
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.Success, "")
	assertLines(t, prompt.lines, expectedPromptLines)
	if flow.waitCalls != 1 || flow.verifyCalls != 1 {
		t.Errorf("wait=%d verify=%d, want 1/1", flow.waitCalls, flow.verifyCalls)
	}
}

// --- Errors never leak tokens ---

func TestResultErrorNeverContainsTokens(t *testing.T) {
	t.Parallel()
	flow := happyFlow()
	flow.verify = func(_ context.Context, _, _, _ string, _ time.Duration) (*oidc.Identity, error) {
		return nil, oidc.ErrInvalidToken
	}
	res := newAuthenticator(t, flow, &recordingPrompter{}).Authenticate(context.Background(), "systems")
	if res.Err == nil {
		t.Fatal("Err = nil, want an error")
	}
	for _, secret := range []string{"raw-id-token", "access-token-secret"} {
		if strings.Contains(res.Err.Error(), secret) {
			t.Errorf("Err %q contains %q", res.Err, secret)
		}
	}
}

// --- Misc ---

func TestCodeString(t *testing.T) {
	t.Parallel()
	cases := map[auth.Code]string{
		auth.Unknown:         "unknown",
		auth.Success:         "success",
		auth.Ignore:          "ignore",
		auth.AuthErr:         "auth_err",
		auth.AuthInfoUnavail: "authinfo_unavail",
		auth.Code(42):        "Code(42)",
	}
	for code, want := range cases {
		if got := code.String(); got != want {
			t.Errorf("Code(%d).String() = %q, want %q", int(code), got, want)
		}
	}
}

// A zero Result must never read as a successful login: any path that
// forgets to set Code fails closed.
func TestZeroResultIsNotSuccess(t *testing.T) {
	t.Parallel()
	var res auth.Result
	if res.Code == auth.Success {
		t.Error("Result{}.Code == Success, want fail-closed zero value")
	}
	if res.Code != auth.Unknown {
		t.Errorf("Result{}.Code = %v, want Unknown", res.Code)
	}
	if got := auth.Code(0).String(); got != "unknown" {
		t.Errorf("Code(0).String() = %q, want %q", got, "unknown")
	}
}

// ── Confirmación con PIN ────────────────────────────────────────────────
//
// El PIN cierra el ataque de «apruébame este enlace»: quien aprueba en el
// navegador no es necesariamente quien tiene el terminal, y hasta ahora nada
// lo comprobaba. El número va de la web al terminal, así que la aprobación no
// le sirve a quien no está delante de él.

func TestAuthenticateWithConfirmationSendsThePin(t *testing.T) {
	flow := happyFlow()
	prompt := &recordingPrompter{answer: "4271"}
	a := newAuthenticator(t, flow, prompt)
	a.WithConfirmation(true)

	res := a.Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.Success, "")
	if flow.lastConfirmation != "4271" {
		t.Errorf("confirmación enviada = %q, quiero %q", flow.lastConfirmation, "4271")
	}
	// El prompt tiene que PEDIR el PIN, no limitarse a esperar un Enter.
	var asked bool
	for _, l := range prompt.lines {
		if strings.HasPrefix(l, "?? ") && strings.Contains(l, "PIN") {
			asked = true
		}
	}
	if !asked {
		t.Errorf("no se pidió el PIN; líneas: %q", prompt.lines)
	}
}

func TestAuthenticateWithoutConfirmationSendsNoPin(t *testing.T) {
	flow := happyFlow()
	prompt := &recordingPrompter{answer: "no-debería-usarse"}
	res := newAuthenticator(t, flow, prompt).Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.Success, "")
	if flow.lastConfirmation != "" {
		t.Errorf("confirmación = %q, quiero vacía: el camino de siempre no manda PIN", flow.lastConfirmation)
	}
	for _, l := range prompt.lines {
		if strings.HasPrefix(l, "?? ") {
			t.Errorf("se preguntó el PIN sin estar en modo confirmación: %q", l)
		}
	}
}

func TestAuthenticateWithConfirmationRefusesAnEmptyPin(t *testing.T) {
	flow := happyFlow()
	a := newAuthenticator(t, flow, &recordingPrompter{answer: "   "})
	a.WithConfirmation(true)

	res := a.Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.AuthErr, auth.ReasonNoConfirmation)
	// Sin PIN no hay nada que canjear: preguntar al proveedor sería gastar
	// una petición para que la rechace.
	if flow.waitCalls != 0 {
		t.Errorf("waitCalls = %d, quiero 0", flow.waitCalls)
	}
}

func TestAuthenticateWithConfirmationFailsWhenItCannotAsk(t *testing.T) {
	flow := happyFlow()
	a := newAuthenticator(t, flow, &recordingPrompter{askErr: errors.New("sin conversación")})
	a.WithConfirmation(true)

	res := a.Authenticate(context.Background(), "systems")

	// A diferencia de Prompt, aquí no se puede «seguir igualmente»: sin
	// respuesta no hay PIN, y colgarse esperando sería peor que fallar.
	assertResult(t, res, auth.AuthErr, auth.ReasonNoConfirmation)
	if flow.waitCalls != 0 {
		t.Errorf("waitCalls = %d, quiero 0", flow.waitCalls)
	}
}

func TestAuthenticateWithConfirmationExplainsARejectedPin(t *testing.T) {
	flow := happyFlow()
	flow.wait = func(_ context.Context, _ *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
		return nil, fmt.Errorf("%w: rechazado", oidc.ErrAccessDenied)
	}
	prompt := &recordingPrompter{answer: "0000"}
	a := newAuthenticator(t, flow, prompt)
	a.WithConfirmation(true)

	res := a.Authenticate(context.Background(), "systems")

	assertResult(t, res, auth.AuthErr, auth.ReasonDenied)
	// El mensaje tiene que decir que el intento está anulado: no hay
	// reintento, y quien espere un segundo prompt se queda mirando.
	var told bool
	for _, l := range prompt.lines {
		if strings.Contains(l, "void") {
			told = true
		}
	}
	if !told {
		t.Errorf("no se avisó de que el intento queda anulado; líneas: %q", prompt.lines)
	}
}
