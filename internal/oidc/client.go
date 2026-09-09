// Package oidc wraps OpenID Connect discovery, the OAuth 2.0 Device
// Authorization Grant (RFC 8628) and ID token verification behind a small
// client that the authentication layer can drive step by step.
//
// The package deliberately takes plain parameters instead of the module's
// configuration type so that it can be tested and reused in isolation.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Sentinel errors. Callers should test them with errors.Is; the returned
// errors wrap the underlying cause where there is one.
var (
	ErrDiscovery    = errors.New("oidc: discovery failed")
	ErrNoDeviceFlow = errors.New("oidc: provider does not advertise device_authorization_endpoint")
	ErrAccessDenied = errors.New("oidc: access denied")
	ErrExpired      = errors.New("oidc: device code expired")
	ErrTimeout      = errors.New("oidc: timed out waiting for authorization")
	ErrNoIDToken    = errors.New("oidc: token response has no id_token")
	ErrInvalidToken = errors.New("oidc: invalid id_token")
)

// supportedSigningAlgs lists the ID token signature algorithms accepted by
// VerifyIDToken. Unsigned tokens ("alg": "none") are always rejected, and so
// are HMAC algorithms: accepting them would let a token signed with the
// provider's public key material as the secret pass verification.
var supportedSigningAlgs = []string{gooidc.RS256, gooidc.ES256}

// Polling interval bounds, in seconds. RFC 8628 §3.2 says clients MUST use
// 5 when the provider gives no interval; a non-positive value is treated the
// same way because x/oauth2 hands it to time.NewTicker, which panics. The
// upper bound keeps a misbehaving provider from stalling the login.
const (
	defaultPollInterval int64 = 5
	maxPollInterval     int64 = 60
)

// Limits applied to provider-supplied text before it is placed in an error.
const (
	maxErrorCodeLen        = 40
	maxErrorDescriptionLen = 200
)

// Options configures a Client.
type Options struct {
	// Issuer is the OpenID Connect issuer URL used for discovery.
	Issuer string
	// ClientID is the OAuth 2.0 client identifier (public client).
	ClientID string
	// Scope is the space-separated list of scopes requested.
	Scope string
	// HTTPTimeout bounds every single HTTP request to the provider.
	HTTPTimeout time.Duration
	// AllowInsecureHTTP permits a plain http:// issuer. Only for tests.
	AllowInsecureHTTP bool
	// HTTPClient, when set, replaces the client built from HTTPTimeout.
	// Intended for tests.
	HTTPClient *http.Client
}

// Client talks to a single OpenID Connect provider.
type Client struct {
	httpClient *http.Client
	provider   *gooidc.Provider
	oauth      oauth2.Config
}

// Identity is what VerifyIDToken extracts from a valid ID token.
type Identity struct {
	// Subject is the "sub" claim.
	Subject string
	// Username is the value of the configured username claim, or empty
	// when the claim is absent.
	Username string
	// Groups is the value of the configured groups claim, or an empty
	// (non-nil) slice when the claim is absent.
	Groups []string
	// Claims holds every claim of the token as decoded JSON.
	Claims map[string]any
}

// New runs OpenID Connect discovery against o.Issuer and returns a Client
// ready to start the device flow. It fails with ErrDiscovery when the
// issuer cannot be reached or its metadata is invalid, and with
// ErrNoDeviceFlow when the provider does not advertise a
// device_authorization_endpoint.
func New(ctx context.Context, o Options) (*Client, error) {
	u, err := url.Parse(o.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid issuer %q: %w", ErrDiscovery, o.Issuer, err)
	}
	if u.Scheme != "https" && !o.AllowInsecureHTTP {
		return nil, fmt.Errorf("%w: issuer %q must use https", ErrDiscovery, o.Issuer)
	}

	httpClient := o.HTTPClient
	if httpClient == nil {
		if o.HTTPTimeout <= 0 {
			return nil, fmt.Errorf("%w: http timeout must be positive, got %v", ErrDiscovery, o.HTTPTimeout)
		}
		httpClient = &http.Client{
			Timeout: o.HTTPTimeout,
			// Never follow redirects: the issuer and its endpoints must be
			// exactly what discovery says.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	provider, err := gooidc.NewProvider(gooidc.ClientContext(ctx, httpClient), o.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}

	var meta discoveredEndpoints
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	if meta.DeviceAuthorizationEndpoint == "" {
		return nil, ErrNoDeviceFlow
	}
	if err := checkEndpointsHTTPS(meta, o.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}

	ep := provider.Endpoint()
	return &Client{
		httpClient: httpClient,
		provider:   provider,
		oauth: oauth2.Config{
			ClientID: o.ClientID,
			Endpoint: oauth2.Endpoint{
				AuthURL:       ep.AuthURL,
				TokenURL:      ep.TokenURL,
				DeviceAuthURL: meta.DeviceAuthorizationEndpoint,
				AuthStyle:     oauth2.AuthStyleInParams,
			},
			Scopes: strings.Fields(o.Scope),
		},
	}, nil
}

// discoveredEndpoints is the subset of the provider metadata the client
// relies on beyond what go-oidc already validates.
type discoveredEndpoints struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JWKSURI                     string `json:"jwks_uri"`
}

// checkEndpointsHTTPS verifies that every endpoint the client will talk to
// uses https, unless allowInsecure is set (tests only). An https issuer is
// not enough on its own: the discovery document is provider-controlled, and
// a plain-http token endpoint or JWKS would expose the device code, the
// tokens, or the signing keys to the network.
func checkEndpointsHTTPS(meta discoveredEndpoints, allowInsecure bool) error {
	if allowInsecure {
		return nil
	}
	endpoints := []struct{ name, value string }{
		{"device_authorization_endpoint", meta.DeviceAuthorizationEndpoint},
		{"token_endpoint", meta.TokenEndpoint},
		{"jwks_uri", meta.JWKSURI},
	}
	for _, ep := range endpoints {
		if ep.value == "" {
			return fmt.Errorf("provider metadata has no %s (an https URL is required)", ep.name)
		}
		u, err := url.Parse(ep.value)
		if err != nil {
			return fmt.Errorf("provider metadata has an invalid %s: %w", ep.name, err)
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return fmt.Errorf("provider metadata %s must use https, got scheme %q", ep.name, u.Scheme)
		}
	}
	return nil
}

// reservedDeviceParams are the parameters of the device authorization
// request that StartDeviceAuth builds itself. Letting a caller override
// them through extra would silently change who is asking for what.
var reservedDeviceParams = map[string]bool{
	"client_id":   true,
	"scope":       true,
	"device_name": true,
}

// StartDeviceAuth requests a device and user code from the provider
// (RFC 8628 §3.1). When deviceName is non-empty it is sent as the
// non-standard "device_name" parameter, which some providers display on the
// consent page.
//
// Every pair of extra is sent as an additional parameter of the same
// request, in sorted order; entries with an empty name or value are
// skipped. RFC 6749 §3.1 requires a provider to ignore parameters it does
// not understand, so unknown extras are harmless. It is an error to pass a
// parameter the client builds itself (client_id, scope, device_name) or a
// name carrying whitespace or control characters; the request is not sent
// in that case.
func (c *Client) StartDeviceAuth(ctx context.Context, deviceName string, extra map[string]string) (*oauth2.DeviceAuthResponse, error) {
	var opts []oauth2.AuthCodeOption
	if deviceName != "" {
		opts = append(opts, oauth2.SetAuthURLParam("device_name", deviceName))
	}
	names := make([]string, 0, len(extra))
	for name := range extra {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := checkParamName(name); err != nil {
			return nil, err
		}
		if extra[name] == "" {
			continue
		}
		opts = append(opts, oauth2.SetAuthURLParam(name, extra[name]))
	}
	da, err := c.oauth.DeviceAuth(c.oauthContext(ctx), opts...)
	if err != nil {
		return nil, wrapProviderError("device authorization request", err)
	}
	return da, nil
}

// checkParamName rejects an extra parameter name that is empty, reserved or
// not a plain token.
func checkParamName(name string) error {
	if name == "" {
		return errors.New("oidc: device authorization parameter with an empty name")
	}
	if reservedDeviceParams[name] {
		return fmt.Errorf("oidc: device authorization parameter %q is reserved", name)
	}
	for _, r := range name {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return fmt.Errorf("oidc: device authorization parameter name %q is not a token", name)
		}
	}
	return nil
}

// Metadata decodes the provider's discovery document into v, which must be
// a pointer to a struct with the JSON tags of the fields wanted. It gives
// access to metadata beyond the standard endpoints — the contract's
// ssh_access_endpoint, for one — without a second request: the document was
// already fetched by New.
func (c *Client) Metadata(v any) error {
	if err := c.provider.Claims(v); err != nil {
		return fmt.Errorf("oidc: decode provider metadata: %w", err)
	}
	return nil
}

// WaitForToken polls the token endpoint (RFC 8628 §3.4) until the user
// completes or rejects the authorization, the device code expires, or ctx
// is done. The provider's interval and slow_down hints are honoured, with
// the interval clamped to [1, 60] seconds (a missing or non-positive value
// becomes the RFC default of 5).
func (c *Client) WaitForToken(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	if da == nil {
		return nil, errors.New("oidc: nil device authorization response")
	}
	polled := *da
	polled.Interval = clampInterval(da.Interval)

	tok, err := c.oauth.DeviceAccessToken(c.oauthContext(ctx), &polled)
	if err == nil {
		return tok, nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil, fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		switch re.ErrorCode {
		case "access_denied":
			return nil, fmt.Errorf("%w: %w", ErrAccessDenied, sanitizeProviderError(err))
		case "expired_token":
			return nil, fmt.Errorf("%w: %w", ErrExpired, sanitizeProviderError(err))
		}
	}
	return nil, wrapProviderError("token request", err)
}

// clampInterval bounds a provider-supplied polling interval (seconds).
func clampInterval(sec int64) int64 {
	switch {
	case sec < 1:
		return defaultPollInterval
	case sec > maxPollInterval:
		return maxPollInterval
	default:
		return sec
	}
}

// providerError is the sanitized form of an error response from the
// provider. Its message is a single line built from the HTTP status, the
// OAuth error code and a whitespace-collapsed, truncated error_description;
// the raw response body never appears in it. Unwrap exposes the original
// *oauth2.RetrieveError for callers that need the structured fields.
type providerError struct {
	summary string
	cause   *oauth2.RetrieveError
}

func (e *providerError) Error() string { return e.summary }
func (e *providerError) Unwrap() error { return e.cause }

// sanitizeProviderError replaces an error carrying a provider response
// (*oauth2.RetrieveError) by a providerError summary, since x/oauth2
// otherwise prints the verbatim response body, which the provider controls
// and which ends up in syslog. Other errors (network failures, context
// errors) are returned unchanged.
func sanitizeProviderError(err error) error {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return err
	}
	return &providerError{summary: summarizeRetrieveError(re), cause: re}
}

// wrapProviderError wraps the sanitized err as "oidc: <op> failed: ...".
func wrapProviderError(op string, err error) error {
	return fmt.Errorf("oidc: %s failed: %w", op, sanitizeProviderError(err))
}

func summarizeRetrieveError(re *oauth2.RetrieveError) string {
	var sb strings.Builder
	sb.WriteString("provider returned")
	if re.Response != nil {
		fmt.Fprintf(&sb, " HTTP %d", re.Response.StatusCode)
	} else {
		sb.WriteString(" an error")
	}
	if code := sanitizeProviderText(re.ErrorCode, maxErrorCodeLen); code != "" {
		fmt.Fprintf(&sb, " (%s)", code)
	}
	if desc := sanitizeProviderText(re.ErrorDescription, maxErrorDescriptionLen); desc != "" {
		sb.WriteString(": ")
		sb.WriteString(desc)
	}
	return sb.String()
}

// sanitizeProviderText makes provider-supplied text safe for a log line:
// runs of whitespace and non-printable characters (including terminal
// escapes) collapse to a single space, leading and trailing space is
// dropped, and the result is truncated to limit runes with "..." appended.
func sanitizeProviderText(s string, limit int) string {
	out := make([]rune, 0, len(s))
	pendingSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			pendingSpace = true
			continue
		}
		if pendingSpace && len(out) > 0 {
			out = append(out, ' ')
		}
		pendingSpace = false
		out = append(out, r)
	}
	if len(out) > limit {
		return string(out[:limit]) + "..."
	}
	return string(out)
}

// VerifyIDToken checks the signature, issuer, audience and validity window
// of raw and extracts an Identity from it.
//
// skew is the tolerated clock difference between this host and the
// provider: a token whose "exp" passed less than skew ago is still
// accepted, and a token whose "iat" lies more than skew in the future is
// rejected. usernameClaim names the claim carrying the login name;
// groupsClaim names the claim carrying a JSON array of group names.
//
// No nonce is checked: the nonce of OpenID Connect Core §3.1.2.1 binds an ID
// token to a browser session, and the device flow has none. The device_code
// presented to the token endpoint is what ties this response to the request
// started by StartDeviceAuth.
//
// When the token carries "nbf", go-oidc accepts it up to 5 minutes early.
// Because the verifier's clock is shifted back by skew, that leeway is
// effectively narrowed to 5 minutes minus skew.
func (c *Client) VerifyIDToken(ctx context.Context, raw, usernameClaim, groupsClaim string, skew time.Duration) (*Identity, error) {
	if skew < 0 {
		skew = 0
	}
	verifier := c.provider.VerifierContext(gooidc.ClientContext(ctx, c.httpClient), &gooidc.Config{
		ClientID:             c.oauth.ClientID,
		SupportedSigningAlgs: supportedSigningAlgs,
		// go-oidc compares "exp" against Now(); shifting the clock back by
		// skew tolerates tokens that expired up to skew ago.
		Now: func() time.Time { return time.Now().Add(-skew) },
	})
	idToken, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !idToken.IssuedAt.IsZero() && idToken.IssuedAt.After(time.Now().Add(skew)) {
		return nil, fmt.Errorf("%w: issued in the future (iat %v)", ErrInvalidToken, idToken.IssuedAt)
	}
	if idToken.Subject == "" {
		return nil, fmt.Errorf("%w: empty sub claim", ErrInvalidToken)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	username, err := stringClaim(claims, usernameClaim)
	if err != nil {
		return nil, err
	}
	groups, err := stringSliceClaim(claims, groupsClaim)
	if err != nil {
		return nil, err
	}

	return &Identity{
		Subject:  idToken.Subject,
		Username: username,
		Groups:   groups,
		Claims:   claims,
	}, nil
}

// IDTokenFrom returns the raw id_token carried in a token response, or
// ErrNoIDToken when the provider did not include one.
func IDTokenFrom(tok *oauth2.Token) (string, error) {
	if tok == nil {
		return "", ErrNoIDToken
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", ErrNoIDToken
	}
	return raw, nil
}

// oauthContext makes the oauth2 package use the client's HTTP client.
func (c *Client) oauthContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
}

// stringClaim returns claims[name] as a string; an absent claim yields "".
func stringClaim(claims map[string]any, name string) (string, error) {
	v, ok := claims[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: claim %q is not a string", ErrInvalidToken, name)
	}
	return s, nil
}

// stringSliceClaim returns claims[name] as a slice of strings; an absent
// claim yields an empty, non-nil slice.
func stringSliceClaim(claims map[string]any, name string) ([]string, error) {
	v, ok := claims[name]
	if !ok || v == nil {
		return []string{}, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: claim %q is not an array", ErrInvalidToken, name)
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, fmt.Errorf("%w: claim %q contains a non-string element", ErrInvalidToken, name)
		}
		out = append(out, s)
	}
	return out, nil
}
