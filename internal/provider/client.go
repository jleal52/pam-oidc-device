// Package provider implements the client side of the SSH access contract in
// docs/PROVIDER-CONTRACT.md: host enrolment (§3) and the authorized-keys
// query (§4) that a host runs at every public-key login attempt.
//
// Failures are classified into sentinel errors so that callers can apply the
// contract's caching rule (§4.3) without parsing messages: only
// ErrUnavailable — a network failure, a timeout, a TLS error or any 5xx —
// allows the last-known-good cache to be served. ErrUnauthorized,
// ErrForbidden, ErrRateLimited, ErrConflict and ErrBadResponse are decisions
// or defects, and a host must deny the login rather than paper over them
// with a cached answer.
//
// The package takes plain parameters instead of the module's configuration
// type so that it can be tested and reused in isolation.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Sentinel errors. Callers should test them with errors.Is; the returned
// errors wrap the underlying cause where there is one.
//
// Only ErrUnavailable permits falling back to the key cache (contract §4.3);
// every other error is an authoritative answer or a client-side defect.
var (
	// ErrUnauthorized is a 401: the access token or the host assertion was
	// missing, malformed, expired, replayed or unknown to the provider.
	ErrUnauthorized = errors.New("provider: unauthorized")
	// ErrForbidden is a 403: the credential was valid but the provider
	// refuses the operation (host revoked, account not declared at
	// enrolment, enrolment not allowed for this token).
	ErrForbidden = errors.New("provider: forbidden")
	// ErrRateLimited is a 429.
	ErrRateLimited = errors.New("provider: rate limited")
	// ErrConflict is a 409 from enrolment: the public key or the name is
	// already registered to a different host.
	ErrConflict = errors.New("provider: conflict")
	// ErrUnavailable means the provider could not be reached or could not
	// answer: connection, TLS or timeout errors and any 5xx status. It is
	// the only error that permits serving the cached last-known-good
	// authorized keys.
	ErrUnavailable = errors.New("provider: unavailable")
	// ErrBadResponse is any other unexpected status or an answer that does
	// not match the contract (unparsable body, missing hostId).
	ErrBadResponse = errors.New("provider: unexpected response")
)

// DefaultBasePath is appended to the issuer when neither the configuration
// nor discovery names the SSH access API (contract §5).
const DefaultBasePath = "/api/ssh"

// Limits applied to provider answers.
const (
	// MaxKeysBytes is the most an authorized-keys body may contribute; the
	// rest of the response is discarded, and so is the partial line the cut
	// leaves behind.
	MaxKeysBytes = 64 << 10
	// MaxKeysLines is the most keys a single answer may carry.
	MaxKeysLines = 100
	// maxJSONBody bounds a JSON response body (enrolment).
	maxJSONBody = 64 << 10
	// maxErrorBody bounds how much of an error body is read to build the
	// error message.
	maxErrorBody = 8 << 10
	// Limits applied to provider-supplied text before it is placed in an
	// error, mirroring internal/oidc.
	maxErrorCodeLen        = 40
	maxErrorDescriptionLen = 200
)

// Options configures a Client.
type Options struct {
	// Base is the SSH access API base URL (contract §5). It must be an
	// absolute https URL without query, fragment or userinfo, and it is
	// used verbatim — a trailing slash is neither added nor removed —
	// because it doubles as the audience of host assertions, on which
	// provider and host must agree byte for byte.
	Base string
	// HTTPTimeout bounds every single HTTP request to the provider. It is
	// required unless HTTPClient is set.
	HTTPTimeout time.Duration
	// AllowInsecureHTTP permits a plain http:// base. Only for tests.
	AllowInsecureHTTP bool
	// HTTPClient, when set, replaces the client built from HTTPTimeout.
	// Intended for tests.
	HTTPClient *http.Client
}

// Client talks to the SSH access API of a single provider. It is safe for
// concurrent use.
type Client struct {
	// base is Options.Base verbatim, the audience of host assertions.
	base string
	// endpoint is base without a trailing slash, so that appending a path
	// cannot produce a double slash.
	endpoint   string
	httpClient *http.Client
}

// New validates o.Base and returns a Client. The base must be absolute, use
// https unless o.AllowInsecureHTTP is set, and carry no query, fragment or
// userinfo; it is stored verbatim (see Options.Base). When o.HTTPClient is
// nil, o.HTTPTimeout must be positive and the client built from it never
// follows redirects, as the contract requires (§7).
func New(o Options) (*Client, error) {
	base := o.Base
	if strings.TrimSpace(base) == "" {
		return nil, errors.New("provider: base URL is required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("provider: invalid base URL %q: %w", base, err)
	}
	switch {
	case u.Host == "":
		return nil, fmt.Errorf("provider: base URL %q is not absolute", base)
	case u.RawQuery != "" || u.ForceQuery:
		return nil, fmt.Errorf("provider: base URL %q must not contain a query component", base)
	case strings.Contains(base, "#"):
		return nil, fmt.Errorf("provider: base URL %q must not contain a fragment", base)
	case u.User != nil:
		return nil, fmt.Errorf("provider: base URL %q must not contain userinfo", base)
	case u.Scheme == "https":
	case u.Scheme == "http" && o.AllowInsecureHTTP:
	case u.Scheme == "http":
		return nil, fmt.Errorf("provider: base URL %q uses http (allowed only for testing)", base)
	default:
		return nil, fmt.Errorf("provider: base URL %q must use https", base)
	}

	httpClient := o.HTTPClient
	if httpClient == nil {
		if o.HTTPTimeout <= 0 {
			return nil, fmt.Errorf("provider: http timeout must be positive, got %v", o.HTTPTimeout)
		}
		httpClient = &http.Client{
			Timeout: o.HTTPTimeout,
			// Never follow redirects: these endpoints are authenticated
			// with a bearer credential that must not be replayed to
			// whatever host a redirect names.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Client{
		base:       base,
		endpoint:   strings.TrimSuffix(base, "/"),
		httpClient: httpClient,
	}, nil
}

// Base returns the API base URL verbatim. It is the value host assertions
// must carry as their audience.
func (c *Client) Base() string { return c.base }

// EnrollRequest is the body of an enrolment request (contract §3).
type EnrollRequest struct {
	// PublicKey is the host's Ed25519 public key in OpenSSH format.
	PublicKey string
	// Name is the stable, unique host name.
	Name string
	// Hostname is the machine's own hostname, informational.
	Hostname string
	// Groups are the provider-defined host groups claimed; it may be empty
	// but is always sent.
	Groups []string
	// Accounts are the local accounts the host will ask keys for. Requests
	// for any other account are refused by the provider.
	Accounts []string
	// AgentVersion is this client's version, informational.
	AgentVersion string
}

// EnrollResponse is what the provider returns for an accepted enrolment.
type EnrollResponse struct {
	// HostID is the opaque identifier assigned to the host. It becomes the
	// iss and sub of every host assertion.
	HostID string
	// Name is the name the provider recorded.
	Name string
	// Groups and Accounts are the values the provider stored.
	Groups   []string
	Accounts []string
	// Created is true when the provider answered 201 (a new host) and
	// false when it answered 200 (re-enrolment of a known key).
	Created bool
}

// enrollWire is the JSON body sent to {base}/hosts/enroll. Groups and
// accounts are always present, as the contract requires, even when empty.
type enrollWire struct {
	PublicKey    string   `json:"publicKey"`
	Name         string   `json:"name"`
	Hostname     string   `json:"hostname,omitempty"`
	Groups       []string `json:"groups"`
	Accounts     []string `json:"accounts"`
	AgentVersion string   `json:"agentVersion,omitempty"`
}

// enrollResult is the JSON body of a 200 or 201 answer.
type enrollResult struct {
	HostID   string   `json:"hostId"`
	Name     string   `json:"name"`
	Groups   []string `json:"groups"`
	Accounts []string `json:"accounts"`
}

// Enroll registers this host with the provider (contract §3). accessToken is
// an OAuth 2.0 access token obtained through a device flow with
// intent=enroll; the provider decides who may enrol.
//
// A 201 yields Created true, a 200 (re-enrolment of a known key) Created
// false. Failures map to ErrUnauthorized (401), ErrForbidden (403),
// ErrConflict (409), ErrRateLimited (429), ErrUnavailable (5xx, network,
// timeout, TLS) and ErrBadResponse for anything else. Enrolment has no cache
// to fall back to; ErrUnavailable simply means "try again later".
func (c *Client) Enroll(ctx context.Context, accessToken string, req EnrollRequest) (*EnrollResponse, error) {
	const op = "enrolment request"
	switch {
	case strings.TrimSpace(accessToken) == "":
		return nil, errors.New("provider: enrolment needs an access token")
	case strings.TrimSpace(req.PublicKey) == "":
		return nil, errors.New("provider: enrolment needs a public key")
	case strings.TrimSpace(req.Name) == "":
		return nil, errors.New("provider: enrolment needs a host name")
	case len(req.Accounts) == 0:
		return nil, errors.New("provider: enrolment needs at least one account")
	}

	body, err := json.Marshal(enrollWire{
		PublicKey:    req.PublicKey,
		Name:         req.Name,
		Hostname:     req.Hostname,
		Groups:       nonNil(req.Groups),
		Accounts:     nonNil(req.Accounts),
		AgentVersion: req.AgentVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("provider: encode enrolment request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/hosts/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: build enrolment request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, transportError(op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, responseError(op, resp)
	}

	raw, _, err := readLimited(resp.Body, maxJSONBody)
	if err != nil {
		return nil, transportError(op, err)
	}
	var result enrollResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("%w: %s: body is not valid JSON", ErrBadResponse, op)
	}
	if result.HostID == "" {
		return nil, fmt.Errorf("%w: %s: answer has no hostId", ErrBadResponse, op)
	}
	return &EnrollResponse{
		HostID:   result.HostID,
		Name:     result.Name,
		Groups:   nonNil(result.Groups),
		Accounts: nonNil(result.Accounts),
		Created:  resp.StatusCode == http.StatusCreated,
	}, nil
}

// Keys is the outcome of an authorized-keys query. Lines holds the accepted
// authorized_keys lines, in the order the provider sent them; the counters
// describe what was discarded on the way, so that the caller can log it.
type Keys struct {
	// Lines are the valid authorized_keys lines, never nil.
	Lines []string
	// Dropped counts lines the provider sent that are not valid
	// authorized_keys entries. They are ignored rather than fatal: one bad
	// line must not lock everybody out.
	Dropped int
	// Capped is true when the answer carried more than MaxKeysLines valid
	// lines and the rest were ignored.
	Capped bool
	// Truncated is true when the body exceeded MaxKeysBytes; the excess and
	// the partial line at the cut were discarded.
	Truncated bool
}

// AuthorizedKeys asks the provider which public keys may log in as account
// on this host (contract §4) and returns the accepted authorized_keys lines.
//
// assertion is a fresh host assertion (contract §2.2) whose audience is
// Base(). fingerprint, when not empty, is the SHA256 fingerprint of the key
// sshd is offering and narrows the answer to that key; envName, when not
// empty, names the environment variable that will carry the person's
// identity.
//
// An empty answer is an authoritative denial: it returns an empty slice and
// a nil error, and the caller must neither cache it nor fall back to an
// earlier answer. Of the errors, only ErrUnavailable (5xx, network failure,
// timeout or TLS error) permits serving the cached last-known-good answer;
// ErrUnauthorized, ErrForbidden, ErrRateLimited and ErrBadResponse must deny
// the login.
//
// Use FetchAuthorizedKeys instead to learn how many lines were discarded.
func (c *Client) AuthorizedKeys(ctx context.Context, assertion, account, fingerprint, envName string) ([]string, error) {
	keys, err := c.FetchAuthorizedKeys(ctx, assertion, account, fingerprint, envName)
	if err != nil {
		return nil, err
	}
	return keys.Lines, nil
}

// FetchAuthorizedKeys is AuthorizedKeys with the discard counters attached;
// see that method for the semantics of the answer and of the errors.
//
// At most MaxKeysBytes of the body are read and at most MaxKeysLines valid
// lines are kept. Lines that ssh.ParseAuthorizedKey rejects, and lines
// carrying control characters (which the contract forbids and which sshd
// would be fed verbatim), are dropped and counted.
func (c *Client) FetchAuthorizedKeys(ctx context.Context, assertion, account, fingerprint, envName string) (*Keys, error) {
	const op = "authorized-keys request"
	switch {
	case strings.TrimSpace(assertion) == "":
		return nil, errors.New("provider: authorized keys need a host assertion")
	case strings.TrimSpace(account) == "":
		return nil, errors.New("provider: authorized keys need an account")
	}

	q := url.Values{"account": {account}}
	if fingerprint != "" {
		q.Set("fingerprint", fingerprint)
	}
	if envName != "" {
		q.Set("env", envName)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/authorized-keys?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("provider: build authorized-keys request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+assertion)
	httpReq.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, transportError(op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, responseError(op, resp)
	}

	raw, truncated, err := readLimited(resp.Body, MaxKeysBytes)
	if err != nil {
		return nil, transportError(op, err)
	}
	if truncated {
		raw = dropPartialLine(raw)
	}
	return parseKeys(raw, truncated), nil
}

// parseKeys turns an authorized-keys body into a Keys, applying the line
// validation and the MaxKeysLines cap.
func parseKeys(body []byte, truncated bool) *Keys {
	keys := &Keys{Lines: []string{}, Truncated: truncated}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !validKeyLine(line) {
			keys.Dropped++
			continue
		}
		if len(keys.Lines) >= MaxKeysLines {
			keys.Capped = true
			break
		}
		keys.Lines = append(keys.Lines, line)
	}
	return keys
}

// validKeyLine reports whether line is a single authorized_keys entry safe
// to hand to sshd.
func validKeyLine(line string) bool {
	for _, r := range line {
		// Tab is the one control character OpenSSH treats as a separator;
		// anything else (escapes, NUL) has no business in a key line.
		if r != '\t' && unicode.IsControl(r) {
			return false
		}
	}
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return err == nil
}

// dropPartialLine removes the trailing fragment left by a body that was cut
// at the read limit, so that half a key is never parsed.
func dropPartialLine(data []byte) []byte {
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		return data[:i+1]
	}
	return nil
}

// ResolveBase picks the SSH access API base URL the way contract §5
// prescribes: the configured apiBase wins, then the ssh_access_endpoint of
// the discovery document, and failing both the issuer with DefaultBasePath
// appended. It returns "" when nothing is known. The result is not
// validated; New does that.
func ResolveBase(apiBase, issuer, discoveryEndpoint string) string {
	if base := strings.TrimSpace(apiBase); base != "" {
		return base
	}
	if base := strings.TrimSpace(discoveryEndpoint); base != "" {
		return base
	}
	if iss := strings.TrimSpace(issuer); iss != "" {
		return strings.TrimSuffix(iss, "/") + DefaultBasePath
	}
	return ""
}

// --- errors ---

// transportError classifies a failure to obtain an answer at all — DNS,
// connection refused, TLS, a timeout or a cancelled context — as
// ErrUnavailable, the one class that lets the caller serve its cache.
func transportError(op string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, op, err)
}

// responseError builds the one-line error for a non-success status. The
// sanitized error and error_description of a JSON body are appended; a body
// in any other format is not echoed, since it is provider-controlled text
// that ends up in syslog.
func responseError(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: provider returned HTTP %d", op, resp.StatusCode)
	code, desc := jsonError(resp.Header.Get("Content-Type"), body)
	if code = sanitizeProviderText(code, maxErrorCodeLen); code != "" {
		fmt.Fprintf(&sb, " (%s)", code)
	}
	if desc = sanitizeProviderText(desc, maxErrorDescriptionLen); desc != "" {
		sb.WriteString(": ")
		sb.WriteString(desc)
	}
	return fmt.Errorf("%w: %s", sentinelFor(resp.StatusCode), sb.String())
}

// sentinelFor maps an HTTP status to the sentinel the caller acts on.
func sentinelFor(status int) error {
	switch {
	case status == http.StatusUnauthorized:
		return ErrUnauthorized
	case status == http.StatusForbidden:
		return ErrForbidden
	case status == http.StatusConflict:
		return ErrConflict
	case status == http.StatusTooManyRequests:
		return ErrRateLimited
	case status >= 500:
		return ErrUnavailable
	default:
		return ErrBadResponse
	}
}

// jsonError extracts the OAuth-style error and error_description of a JSON
// error body. Anything else yields two empty strings.
func jsonError(contentType string, body []byte) (code, description string) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return "", ""
	}
	var payload struct {
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
		Message          json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", ""
	}
	if payload.ErrorDescription == "" {
		payload.ErrorDescription = messageText(payload.Message)
	}
	return payload.Error, payload.ErrorDescription
}

// messageText reads the `message` field that most REST stacks put the useful
// part of a 400 in, as either a string or an array of them. The contract
// (§4.2) fixes status codes, not a body shape, so a provider that answers
// {"error":"Bad Request","message":["name must be lowercase"]} is within its
// rights — and without this the host printed only "HTTP 400 (Bad Request)"
// and threw away the one sentence that said what to fix. Seen for real while
// enrolling a host whose hostname was uppercase.
func messageText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return strings.Join(many, "; ")
	}
	return ""
}

// sanitizeProviderText makes provider-supplied text safe for a log line:
// runs of whitespace and non-printable characters (including terminal
// escapes) collapse to a single space, leading and trailing space is
// dropped, and the result is truncated to limit runes with "..." appended.
// It mirrors the helper of the same name in internal/oidc.
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

// --- helpers ---

// readLimited reads at most limit bytes from r, reporting whether more were
// available.
func readLimited(r io.Reader, limit int) (data []byte, truncated bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// nonNil returns s, or an empty slice when s is nil, so that JSON encoding
// yields [] instead of null for fields the contract makes mandatory.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
