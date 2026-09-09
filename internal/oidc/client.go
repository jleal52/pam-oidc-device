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
	"strings"
	"time"

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
// VerifyIDToken. Unsigned tokens ("alg": "none") are always rejected.
var supportedSigningAlgs = []string{gooidc.RS256, gooidc.ES256}

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

	var meta struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	if meta.DeviceAuthorizationEndpoint == "" {
		return nil, ErrNoDeviceFlow
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

// StartDeviceAuth requests a device and user code from the provider
// (RFC 8628 §3.1). When deviceName is non-empty it is sent as the
// non-standard "device_name" parameter, which some providers display on the
// consent page.
func (c *Client) StartDeviceAuth(ctx context.Context, deviceName string) (*oauth2.DeviceAuthResponse, error) {
	var opts []oauth2.AuthCodeOption
	if deviceName != "" {
		opts = append(opts, oauth2.SetAuthURLParam("device_name", deviceName))
	}
	da, err := c.oauth.DeviceAuth(c.oauthContext(ctx), opts...)
	if err != nil {
		return nil, fmt.Errorf("oidc: device authorization request failed: %w", err)
	}
	return da, nil
}

// WaitForToken polls the token endpoint (RFC 8628 §3.4) until the user
// completes or rejects the authorization, the device code expires, or ctx
// is done. The provider's interval and slow_down hints are honoured.
func (c *Client) WaitForToken(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	tok, err := c.oauth.DeviceAccessToken(c.oauthContext(ctx), da)
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
			return nil, fmt.Errorf("%w: %w", ErrAccessDenied, err)
		case "expired_token":
			return nil, fmt.Errorf("%w: %w", ErrExpired, err)
		}
	}
	return nil, fmt.Errorf("oidc: token request failed: %w", err)
}

// VerifyIDToken checks the signature, issuer, audience and validity window
// of raw and extracts an Identity from it.
//
// skew is the tolerated clock difference between this host and the
// provider: a token whose "exp" passed less than skew ago is still
// accepted, and a token whose "iat" lies more than skew in the future is
// rejected. usernameClaim names the claim carrying the login name;
// groupsClaim names the claim carrying a JSON array of group names.
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
