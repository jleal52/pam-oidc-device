package sshcmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jleal52/pam-oidc-device/internal/config"
	"github.com/jleal52/pam-oidc-device/internal/hostid"
	"github.com/jleal52/pam-oidc-device/internal/keycache"
	"github.com/jleal52/pam-oidc-device/internal/oidc"
	"github.com/jleal52/pam-oidc-device/internal/provider"
)

// intentEnroll is the device flow intent that asks the provider for an
// access token usable at the enrolment endpoint.
const intentEnroll = "enroll"

// discoveryTimeoutFactor bounds discovery to a small multiple of the
// per-request HTTP timeout, as it may involve TLS setup and a redirect.
const discoveryTimeoutFactor = 3

// identityDirMode is the mode of the directory holding the host key when
// enrolment has to create it.
const identityDirMode = 0o750

// defaultCommandPath is where the packages install the binary; it is only
// used in the suggested sshd configuration when the running executable
// cannot be located.
const defaultCommandPath = "/usr/libexec/pam-oidc-device/oidc-ssh"

// EnrollOptions are the command line arguments of "oidc-ssh enroll".
// Issuer, ClientID and APIBase override the configured values and are
// written back to the configuration file; the rest describe the host to the
// provider.
type EnrollOptions struct {
	Issuer   string
	ClientID string
	Name     string
	Hostname string
	// Groups are the provider-defined host groups this host claims, in the
	// order they were given. They are trimmed and lower-cased once and
	// then used unchanged in both steps of the enrolment.
	Groups   []string
	Accounts []string
	APIBase  string
}

// Enroll registers this host with the provider and records the result.
//
// It generates the host key pair if there is none, runs a device flow with
// intent=enroll so that a person authorises the enrolment in a browser,
// posts the public key to the provider, and writes the assigned host_id and
// the resolved api_base back into the configuration file. The last step is
// what turns the host from "runs the plain device flow" into "answers
// AuthorizedKeysCommand", so it happens only once everything before it has
// succeeded.
//
// Enrolment must run as root: it reads and writes the configuration and the
// private key, both of which are root-owned.
func Enroll(ctx context.Context, env *Env, opts EnrollOptions) error {
	env.fill()
	if env.Geteuid() != 0 {
		return ErrNotRoot
	}

	cfg, configPath, err := env.loadConfig()
	if err != nil {
		return err
	}
	applyOverrides(cfg, opts)

	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return errors.New("oidc-ssh: enrolment needs a host name (--name)")
	}
	hostname := strings.TrimSpace(opts.Hostname)
	if hostname == "" {
		hostname, _ = env.Hostname()
	}
	accounts := trimAll(opts.Accounts)
	if len(accounts) == 0 {
		// The accounts this host will ask keys for are, by construction,
		// the ones its configuration maps to a group.
		accounts = configuredAccounts(cfg)
	}
	if len(accounts) == 0 {
		return errors.New("oidc-ssh: enrolment needs at least one account (--account, or a users mapping in the configuration)")
	}

	// Normalise the group codes once. The approval page is shown the very
	// list the enrolment body will carry, and a provider that compares the
	// two rejects a mismatch, so nothing may reorder or re-case them in
	// between.
	groups := normaliseGroups(opts.Groups)

	id, generated, err := loadOrCreateIdentity(cfg.IdentityKey, "oidc-ssh@"+hostname)
	if err != nil {
		return err
	}
	if generated {
		env.printf("Generated a host key in %s\n", cfg.IdentityKey)
	}

	client, err := discover(ctx, cfg)
	if err != nil {
		return err
	}
	token, err := authorizeEnrolment(ctx, env, cfg, client, name, groups)
	if err != nil {
		return err
	}

	base := provider.ResolveBase(cfg.APIBase, cfg.Issuer, sshAccessEndpoint(client))
	pc, err := newProviderClient(cfg, base)
	if err != nil {
		return err
	}
	enrollCtx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout)
	defer cancel()
	res, err := pc.Enroll(enrollCtx, token, provider.EnrollRequest{
		PublicKey:    id.PublicKeyLine,
		Name:         name,
		Hostname:     hostname,
		Groups:       groups,
		Accounts:     accounts,
		AgentVersion: Version,
	})
	if err != nil {
		return fmt.Errorf("oidc-ssh: %w", err)
	}

	if err := setConfigValues(configPath, configUpdates(cfg, opts, base, res.HostID), configComment); err != nil {
		// The host is enrolled at the provider but the file does not say
		// so, so say exactly what to write by hand.
		return fmt.Errorf("%w\nthe provider assigned host_id %s and api_base %s: set them in %s by hand",
			err, res.HostID, base, configPath)
	}
	storeRecord(env, cfg, res, id, base, hostname)

	report(env, cfg, res, id, base, configPath)
	return nil
}

// configComment introduces the keys enrolment appends to a configuration
// file that did not carry them.
const configComment = "# Written by \"oidc-ssh enroll\"."

// applyOverrides lets the command line win over the configuration file for
// the three values enrolment may legitimately change.
func applyOverrides(cfg *config.Config, opts EnrollOptions) {
	if v := strings.TrimSpace(opts.Issuer); v != "" {
		cfg.Issuer = v
	}
	if v := strings.TrimSpace(opts.ClientID); v != "" {
		cfg.ClientID = v
	}
	if v := strings.TrimSpace(opts.APIBase); v != "" {
		cfg.APIBase = v
	}
}

// configUpdates lists the keys enrolment writes back: always the identity
// the provider assigned and the base the host must use afterwards, plus any
// value the command line overrode, so that the file describes what the host
// actually does.
func configUpdates(cfg *config.Config, opts EnrollOptions, base, hostID string) map[string]string {
	values := map[string]string{"host_id": hostID, "api_base": base}
	if strings.TrimSpace(opts.Issuer) != "" {
		values["issuer"] = cfg.Issuer
	}
	if strings.TrimSpace(opts.ClientID) != "" {
		values["client_id"] = cfg.ClientID
	}
	return values
}

// discover runs OpenID Connect discovery against the configured issuer.
func discover(ctx context.Context, cfg *config.Config) (*oidc.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout*discoveryTimeoutFactor)
	defer cancel()
	client, err := oidc.New(ctx, oidc.Options{
		Issuer:            cfg.Issuer,
		ClientID:          cfg.ClientID,
		Scope:             cfg.Scope,
		HTTPTimeout:       cfg.HTTPTimeout,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc-ssh: %w", err)
	}
	return client, nil
}

// authorizeEnrolment runs the device flow and returns the access token the
// enrolment endpoint expects. Unlike a login, what matters here is the
// access token rather than the ID token: the provider decides who may enrol
// a host and issues the token accordingly.
func authorizeEnrolment(ctx context.Context, env *Env, cfg *config.Config, client *oidc.Client, name string, groups []string) (string, error) {
	extra := map[string]string{"intent": intentEnroll}
	if len(groups) > 0 {
		// An unsigned hint, like device_name: the host has no identity the
		// provider knows yet. It exists so that the approval page can show
		// which groups the machine is asking to join, since those groups
		// are what will later decide who may log in to it.
		extra["groups"] = strings.Join(groups, ",")
	}
	da, err := client.StartDeviceAuth(ctx, name, extra)
	if err != nil {
		return "", fmt.Errorf("oidc-ssh: %w", err)
	}
	if da == nil {
		return "", errors.New("oidc-ssh: the provider returned no device authorization response")
	}
	if uri := da.VerificationURIComplete; uri != "" {
		env.printf("Open %s to approve the enrolment of %q.\n", uri, name)
		env.printf("If the page does not show the code, enter %s.\n", da.UserCode)
	} else {
		env.printf("Open %s and enter the code %s to approve the enrolment of %q.\n", da.VerificationURI, da.UserCode, name)
	}
	env.printf("Waiting for approval...\n")

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	tok, err := client.WaitForToken(ctx, da)
	if err != nil {
		return "", fmt.Errorf("oidc-ssh: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("oidc-ssh: the provider issued no access token")
	}
	return tok.AccessToken, nil
}

// loadOrCreateIdentity returns the host key pair at path, generating it (and
// its directory) when there is none. It reports whether it generated one.
func loadOrCreateIdentity(path, comment string) (*hostid.Identity, bool, error) {
	id, err := hostid.Load(path)
	switch {
	case err == nil:
		return id, false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, fmt.Errorf("oidc-ssh: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), identityDirMode); err != nil {
		return nil, false, fmt.Errorf("oidc-ssh: create %s: %w", filepath.Dir(path), err)
	}
	id, err = hostid.Generate(path, comment)
	if err != nil {
		return nil, false, fmt.Errorf("oidc-ssh: %w", err)
	}
	return id, true, nil
}

// storeRecord drops the stale cache and writes the enrolment record. Both
// are conveniences — nothing on the login path depends on them — so a
// failure is a warning, not a failed enrolment.
func storeRecord(env *Env, cfg *config.Config, res *provider.EnrollResponse, id *hostid.Identity, base, hostname string) {
	// Answers cached for the previous enrolment must not outlive it. The
	// TTL plays no part in what Purge does, but a cache that is switched
	// off refuses to act, so give it a nominal one.
	if err := keycache.New(cfg.CacheDir, time.Hour).Purge(); err != nil {
		env.warnf("could not clear the key cache in %s: %v", cfg.CacheDir, err)
	}
	createdDir, err := writeRecord(cfg, &Record{
		HostID:       res.HostID,
		Name:         res.Name,
		Hostname:     hostname,
		Groups:       res.Groups,
		Accounts:     res.Accounts,
		Issuer:       cfg.Issuer,
		APIBase:      base,
		Fingerprint:  id.Fingerprint,
		AgentVersion: Version,
		EnrolledAt:   env.Now().UTC(),
	})
	if err != nil {
		env.warnf("could not write the enrolment record: %v", err)
	}
	if createdDir {
		env.warnf("%s did not exist and now belongs to root; give it to the AuthorizedKeysCommand user "+
			"(chown <user> %s) or the cache will stay empty", cfg.CacheDir, cfg.CacheDir)
	}
}

// report prints what was enrolled and the sshd configuration that puts it
// to use.
func report(env *Env, cfg *config.Config, res *provider.EnrollResponse, id *hostid.Identity, base, configPath string) {
	state := "updated"
	if res.Created {
		state = "enrolled"
	}
	env.printf("\nHost %s as %q\n", state, res.Name)
	env.printf("  host id:   %s\n", res.HostID)
	env.printf("  key:       %s (%s)\n", cfg.IdentityKey, id.Fingerprint)
	env.printf("  provider:  %s\n", cfg.Issuer)
	env.printf("  api base:  %s\n", base)
	env.printf("  groups:    %s\n", listOrNone(res.Groups))
	env.printf("  accounts:  %s\n", listOrNone(res.Accounts))
	env.printf("  config:    %s\n", configPath)
	env.printf("\nAdd this to /etc/ssh/sshd_config and reload sshd:\n\n%s\n", sshdConfig(env, cfg, res.Accounts))
}

// sshdConfig renders the sshd configuration that makes the provider the
// source of authorized keys for the enrolled accounts.
func sshdConfig(env *Env, cfg *config.Config, accounts []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "AuthorizedKeysCommand %s authorized-keys %%u %%f\n", commandPath(env))
	b.WriteString("AuthorizedKeysCommandUser oidc-ssh\n")
	fmt.Fprintf(&b, "PermitUserEnvironment %s,OIDC_SUB\n", cfg.SessionEnv)
	b.WriteString("KbdInteractiveAuthentication yes\n")
	// The device flow can take timeout + four HTTP round trips; sshd kills
	// a session that has not authenticated within LoginGraceTime.
	grace := int((cfg.Timeout + 4*cfg.HTTPTimeout).Seconds())
	fmt.Fprintf(&b, "LoginGraceTime %d\n", grace)
	if len(accounts) > 0 {
		fmt.Fprintf(&b, "\nMatch User %s\n", strings.Join(accounts, ","))
		b.WriteString("    AuthenticationMethods publickey,keyboard-interactive:pam\n")
		b.WriteString("    PubkeyAuthentication yes\n")
		b.WriteString("    AuthorizedKeysFile none\n")
	}
	return b.String()
}

// commandPath is the absolute path of this binary, or the location the
// packages install it in when it cannot be determined.
func commandPath(env *Env) string {
	if env.Executable != nil {
		if path, err := env.Executable(); err == nil && filepath.IsAbs(path) {
			return path
		}
	}
	return defaultCommandPath
}

// sshAccessEndpoint returns the ssh_access_endpoint the provider advertises
// in its discovery document, or "" when it advertises none.
func sshAccessEndpoint(client *oidc.Client) string {
	var meta struct {
		SSHAccessEndpoint string `json:"ssh_access_endpoint"`
	}
	if err := client.Metadata(&meta); err != nil {
		return ""
	}
	return meta.SSHAccessEndpoint
}

// configuredAccounts returns the local accounts the configuration maps to a
// group, in a stable order.
func configuredAccounts(cfg *config.Config) []string {
	accounts := make([]string, 0, len(cfg.Users))
	for account := range cfg.Users {
		accounts = append(accounts, account)
	}
	sort.Strings(accounts)
	return accounts
}

// normaliseGroups trims and lower-cases the host group codes, dropping the
// empty ones. It is applied exactly once per enrolment: the device
// authorization request announces the result and the enrolment body repeats
// it verbatim, so that what a person approved is what the provider records.
// normaliseGroups trims, lowercases and de-duplicates the requested group
// codes, keeping the order they were given in.
//
// De-duplication matters beyond tidiness: the same list is announced in the
// device authorization request and repeated in the enrolment body, and a
// provider that binds the approval to those codes may reject a list with
// repeats. Normalising once, here, keeps the two requests identical.
func normaliseGroups(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, g := range in {
		if g = strings.ToLower(strings.TrimSpace(g)); g == "" {
			continue
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

// trimAll trims each element and drops the empty ones.
func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// listOrNone renders a list for the report.
func listOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
