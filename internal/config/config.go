// Package config loads and validates the YAML configuration of the PAM module.
//
// The configuration file is read once per login attempt, so parsing favours
// strictness over speed: unknown keys are rejected, every value is validated
// and defaults are applied before the result is handed to the caller.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the location of the configuration file when the PAM module
// is invoked without an explicit "config=" argument.
const DefaultPath = "/etc/security/pam_oidc_device.yaml"

// hostnamePlaceholder is replaced by the machine hostname inside device_name.
const hostnamePlaceholder = "{{hostname}}"

// Default values applied to fields that are absent from the YAML document.
const (
	DefaultScope         = "openid profile email groups"
	DefaultDeviceName    = hostnamePlaceholder
	DefaultUsernameClaim = "email"
	DefaultGroupsClaim   = "groups"
	DefaultSessionEnv    = "OIDC_USER"
	DefaultTimeout       = 300 * time.Second
	DefaultClockSkew     = 60 * time.Second
	DefaultHTTPTimeout   = 10 * time.Second
)

// Sentinel errors returned (wrapped) by Parse and Load. Use errors.Is to match.
var (
	ErrInvalidYAML       = errors.New("invalid YAML")
	ErrMissingIssuer     = errors.New("issuer is required")
	ErrInvalidIssuer     = errors.New("issuer must be an absolute https URL")
	ErrMissingClientID   = errors.New("client_id is required")
	ErrNoUsers           = errors.New("users must map at least one local user to a group")
	ErrEmptyUser         = errors.New("users contains an empty user name")
	ErrEmptyGroup        = errors.New("users contains a user without a group")
	ErrInvalidSessionEnv = errors.New("session_env must not be empty")
	ErrInvalidScope      = errors.New("scope must not be empty")
	ErrInvalidClaim      = errors.New("claim name must not be empty")
	ErrInvalidDuration   = errors.New("invalid duration")
	ErrHostname          = errors.New("cannot resolve hostname")
)

// Config is the validated, ready-to-use module configuration.
type Config struct {
	// Issuer is the OIDC issuer URL, without trailing slash. Discovery is
	// performed at <Issuer>/.well-known/openid-configuration.
	Issuer string `yaml:"issuer"`
	// ClientID is the public OAuth2 client registered for the device flow.
	ClientID string `yaml:"client_id"`
	// Scope is the space-separated scope list requested from the provider.
	Scope string `yaml:"scope"`
	// DeviceName is shown to the user during the device flow prompt.
	DeviceName string `yaml:"device_name"`
	// UsernameClaim is the id_token claim exported as the session user name.
	UsernameClaim string `yaml:"username_claim"`
	// GroupsClaim is the id_token claim holding the list of user groups.
	GroupsClaim string `yaml:"groups_claim"`
	// SessionEnv is the environment variable that receives UsernameClaim.
	SessionEnv string `yaml:"session_env"`
	// Timeout bounds the whole device flow (user interaction included).
	Timeout time.Duration `yaml:"timeout"`
	// ClockSkew is the tolerance applied when checking token timestamps.
	ClockSkew time.Duration `yaml:"clock_skew"`
	// HTTPTimeout bounds every single HTTP request to the provider.
	HTTPTimeout time.Duration `yaml:"http_timeout"`
	// AllowInsecureHTTP permits a plain http:// issuer. It exists only for
	// tests against a local mock provider and is unsafe in production.
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`
	// Users maps a local account name to the group a user must hold in
	// GroupsClaim to log in as that account.
	Users map[string]string `yaml:"users"`
}

// rawConfig mirrors Config with string durations so that YAML values such as
// "300s" or "5m" can be parsed with time.ParseDuration and reported with a
// meaningful error instead of yaml.v3's integer-only decoding.
type rawConfig struct {
	Issuer            *string           `yaml:"issuer"`
	ClientID          *string           `yaml:"client_id"`
	Scope             *string           `yaml:"scope"`
	DeviceName        *string           `yaml:"device_name"`
	UsernameClaim     *string           `yaml:"username_claim"`
	GroupsClaim       *string           `yaml:"groups_claim"`
	SessionEnv        *string           `yaml:"session_env"`
	Timeout           *string           `yaml:"timeout"`
	ClockSkew         *string           `yaml:"clock_skew"`
	HTTPTimeout       *string           `yaml:"http_timeout"`
	AllowInsecureHTTP bool              `yaml:"allow_insecure_http"`
	Users             map[string]string `yaml:"users"`
}

// HostnameFunc returns the local hostname used to expand {{hostname}}.
type HostnameFunc func() (string, error)

// Load reads the YAML file at path and returns the validated configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the administrator-supplied config file
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w (file %s)", err, path)
	}
	return cfg, nil
}

// Parse decodes a YAML document, applies defaults, expands {{hostname}} with
// os.Hostname and validates the result.
func Parse(data []byte) (*Config, error) {
	return ParseWithHostname(data, os.Hostname)
}

// ParseWithHostname is Parse with an injectable hostname resolver. The
// resolver is only called when device_name contains {{hostname}}.
func ParseWithHostname(data []byte, hostname HostnameFunc) (*Config, error) {
	raw, err := decode(data)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Issuer:            strings.TrimSpace(deref(raw.Issuer, "")),
		ClientID:          strings.TrimSpace(deref(raw.ClientID, "")),
		Scope:             strings.TrimSpace(deref(raw.Scope, DefaultScope)),
		DeviceName:        deref(raw.DeviceName, DefaultDeviceName),
		UsernameClaim:     strings.TrimSpace(deref(raw.UsernameClaim, DefaultUsernameClaim)),
		GroupsClaim:       strings.TrimSpace(deref(raw.GroupsClaim, DefaultGroupsClaim)),
		SessionEnv:        strings.TrimSpace(deref(raw.SessionEnv, DefaultSessionEnv)),
		AllowInsecureHTTP: raw.AllowInsecureHTTP,
		Users:             raw.Users,
	}

	if cfg.Timeout, err = parseDuration("timeout", raw.Timeout, DefaultTimeout); err != nil {
		return nil, err
	}
	if cfg.ClockSkew, err = parseDuration("clock_skew", raw.ClockSkew, DefaultClockSkew); err != nil {
		return nil, err
	}
	if cfg.HTTPTimeout, err = parseDuration("http_timeout", raw.HTTPTimeout, DefaultHTTPTimeout); err != nil {
		return nil, err
	}

	if cfg.DeviceName, err = expandHostname(cfg.DeviceName, hostname); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LookupUser returns the group required to log in as the given local user.
func (c *Config) LookupUser(name string) (group string, ok bool) {
	if c == nil {
		return "", false
	}
	group, ok = c.Users[name]
	return group, ok
}

func decode(data []byte) (*rawConfig, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var raw rawConfig
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("config: %w: %v", ErrInvalidYAML, err)
	}
	return &raw, nil
}

func deref(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}

func parseDuration(field string, raw *string, def time.Duration) (time.Duration, error) {
	if raw == nil {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(*raw))
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w: %q", field, ErrInvalidDuration, *raw)
	}
	return d, nil
}

func expandHostname(name string, hostname HostnameFunc) (string, error) {
	if !strings.Contains(name, hostnamePlaceholder) {
		return name, nil
	}
	if hostname == nil {
		hostname = os.Hostname
	}
	h, err := hostname()
	if err != nil {
		return "", fmt.Errorf("config: device_name: %w: %v", ErrHostname, err)
	}
	return strings.ReplaceAll(name, hostnamePlaceholder, h), nil
}

func (c *Config) validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("config: %w", ErrMissingIssuer)
	}
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	if err := validateIssuer(c.Issuer, c.AllowInsecureHTTP); err != nil {
		return err
	}
	if c.ClientID == "" {
		return fmt.Errorf("config: %w", ErrMissingClientID)
	}
	if c.Scope == "" {
		return fmt.Errorf("config: %w", ErrInvalidScope)
	}
	if c.UsernameClaim == "" {
		return fmt.Errorf("config: username_claim: %w", ErrInvalidClaim)
	}
	if c.GroupsClaim == "" {
		return fmt.Errorf("config: groups_claim: %w", ErrInvalidClaim)
	}
	if c.SessionEnv == "" {
		return fmt.Errorf("config: %w", ErrInvalidSessionEnv)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("config: timeout: %w: must be positive, got %s", ErrInvalidDuration, c.Timeout)
	}
	if c.HTTPTimeout <= 0 {
		return fmt.Errorf("config: http_timeout: %w: must be positive, got %s", ErrInvalidDuration, c.HTTPTimeout)
	}
	if c.ClockSkew < 0 {
		return fmt.Errorf("config: clock_skew: %w: must not be negative, got %s", ErrInvalidDuration, c.ClockSkew)
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("config: %w", ErrNoUsers)
	}
	for user, group := range c.Users {
		if strings.TrimSpace(user) == "" {
			return fmt.Errorf("config: %w", ErrEmptyUser)
		}
		if strings.TrimSpace(group) == "" {
			return fmt.Errorf("config: users: %q: %w", user, ErrEmptyGroup)
		}
	}
	return nil
}

func validateIssuer(issuer string, allowInsecure bool) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("config: %w: %v", ErrInvalidIssuer, err)
	}
	if u.Host == "" {
		return fmt.Errorf("config: %w: %q", ErrInvalidIssuer, issuer)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure {
			return nil
		}
		return fmt.Errorf("config: %w: %q uses http (set allow_insecure_http: true only for testing)", ErrInvalidIssuer, issuer)
	default:
		return fmt.Errorf("config: %w: %q", ErrInvalidIssuer, issuer)
	}
}
