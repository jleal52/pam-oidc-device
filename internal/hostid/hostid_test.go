package hostid_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"

	"github.com/jleal52/pam-oidc-device/internal/hostid"
)

const testComment = "oidc-ssh@host.example"

func generate(t *testing.T) (string, *hostid.Identity) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host_key")
	id, err := hostid.Generate(path, testComment)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return path, id
}

func TestGenerateWritesKeyFile(t *testing.T) {
	t.Parallel()
	path, id := generate(t)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("key file mode = %o, want 0640", got)
	}

	raw := readFile(t, path)
	if !strings.HasPrefix(string(raw), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Errorf("key file is not in OpenSSH private key format: %q", firstLine(raw))
	}

	if len(id.Private) != ed25519.PrivateKeySize || len(id.Public) != ed25519.PublicKeySize {
		t.Fatalf("unexpected key sizes: private %d, public %d", len(id.Private), len(id.Public))
	}
	if got := id.Private.Public().(ed25519.PublicKey); !got.Equal(id.Public) {
		t.Errorf("Public does not match Private")
	}

	pub, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(id.PublicKeyLine))
	if err != nil {
		t.Fatalf("PublicKeyLine does not parse as an authorized key: %v (%q)", err, id.PublicKeyLine)
	}
	if len(rest) != 0 {
		t.Errorf("PublicKeyLine has trailing data: %q", rest)
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("PublicKeyLine type = %q, want %q", pub.Type(), ssh.KeyAlgoED25519)
	}
	if comment != testComment {
		t.Errorf("PublicKeyLine comment = %q, want %q", comment, testComment)
	}
	if !strings.HasPrefix(id.PublicKeyLine, "ssh-ed25519 AAAA") {
		t.Errorf("PublicKeyLine = %q, want prefix %q", id.PublicKeyLine, "ssh-ed25519 AAAA")
	}
	if strings.HasSuffix(id.PublicKeyLine, "\n") {
		t.Errorf("PublicKeyLine must not end with a newline")
	}

	if want := ssh.FingerprintSHA256(pub); id.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", id.Fingerprint, want)
	}
	if !strings.HasPrefix(id.Fingerprint, "SHA256:") || strings.HasSuffix(id.Fingerprint, "=") {
		t.Errorf("Fingerprint = %q, want SHA256:<unpadded base64>", id.Fingerprint)
	}
}

func TestGenerateRefusesToOverwrite(t *testing.T) {
	t.Parallel()
	path, first := generate(t)

	before := readFile(t, path)

	id, err := hostid.Generate(path, testComment)
	if !errors.Is(err, hostid.ErrExists) {
		t.Fatalf("second Generate error = %v, want ErrExists", err)
	}
	if id != nil {
		t.Errorf("second Generate returned an identity alongside the error")
	}

	after := readFile(t, path)
	if string(before) != string(after) {
		t.Errorf("key file was modified by the refused Generate")
	}
	loaded, err := hostid.Load(path)
	if err != nil {
		t.Fatalf("Load after refused Generate: %v", err)
	}
	if loaded.Fingerprint != first.Fingerprint {
		t.Errorf("fingerprint changed after refused Generate")
	}
}

func TestGenerateRequiresParentDirectory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing", "host_key")
	if _, err := hostid.Generate(path, testComment); err == nil {
		t.Fatalf("Generate into a missing directory succeeded")
	}
}

func TestLoadRoundTrip(t *testing.T) {
	t.Parallel()
	path, generated := generate(t)

	loaded, err := hostid.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Private.Equal(generated.Private) {
		t.Errorf("Load: Private differs from Generate")
	}
	if !loaded.Public.Equal(generated.Public) {
		t.Errorf("Load: Public differs from Generate")
	}
	if loaded.PublicKeyLine != generated.PublicKeyLine {
		t.Errorf("Load: PublicKeyLine = %q, want %q", loaded.PublicKeyLine, generated.PublicKeyLine)
	}
	if loaded.Fingerprint != generated.Fingerprint {
		t.Errorf("Load: Fingerprint = %q, want %q", loaded.Fingerprint, generated.Fingerprint)
	}
}

func TestLoadRejectsNonEd25519(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(rsaKey, "rsa test key")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "rsa_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write rsa key: %v", err)
	}

	id, err := hostid.Load(path)
	if !errors.Is(err, hostid.ErrKeyType) {
		t.Fatalf("Load(rsa) error = %v, want ErrKeyType", err)
	}
	if id != nil {
		t.Errorf("Load(rsa) returned an identity alongside the error")
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := hostid.Load(path); err == nil {
		t.Fatalf("Load(garbage) succeeded")
	}
	if _, err := hostid.Load(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load(absent) error = %v, want os.ErrNotExist", err)
	}
}

type assertionClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	ID       string `json:"jti"`
}

func parseAssertion(t *testing.T, id *hostid.Identity, token string) (*jose.JSONWebSignature, assertionClaims) {
	t.Helper()
	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("jose.ParseSigned: %v", err)
	}
	payload, err := sig.Verify(id.Public)
	if err != nil {
		t.Fatalf("Verify with the host public key: %v", err)
	}
	var claims assertionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v (%s)", err, payload)
	}
	return sig, claims
}

func TestAssertionClaimsAndSignature(t *testing.T) {
	t.Parallel()
	_, id := generate(t)

	fixed := time.Date(2026, time.September, 10, 12, 0, 0, 500_000_000, time.UTC)
	now := func() time.Time { return fixed }

	token, err := id.Assertion("host-1234", "https://sshd.example/enroll", now)
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3 (compact JWS)", len(parts))
	}

	sig, claims := parseAssertion(t, id, token)

	if len(sig.Signatures) != 1 {
		t.Fatalf("token has %d signatures, want 1", len(sig.Signatures))
	}
	hdr := sig.Signatures[0].Header
	if hdr.Algorithm != string(jose.EdDSA) {
		t.Errorf("alg = %q, want EdDSA", hdr.Algorithm)
	}
	if typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string); typ != "JWT" {
		t.Errorf("typ = %q, want JWT", typ)
	}

	if claims.Issuer != "host-1234" {
		t.Errorf("iss = %q, want host-1234", claims.Issuer)
	}
	if claims.Subject != "host-1234" {
		t.Errorf("sub = %q, want host-1234", claims.Subject)
	}
	if claims.Audience != "https://sshd.example/enroll" {
		t.Errorf("aud = %q, want https://sshd.example/enroll", claims.Audience)
	}
	if claims.IssuedAt != fixed.Unix() {
		t.Errorf("iat = %d, want %d", claims.IssuedAt, fixed.Unix())
	}
	if want := claims.IssuedAt + int64(hostid.AssertionLifetime/time.Second); claims.Expiry != want {
		t.Errorf("exp = %d, want iat+60s = %d", claims.Expiry, want)
	}
	if len(claims.ID) != 22 {
		t.Errorf("jti = %q has length %d, want 22 (16 bytes base64url, unpadded)", claims.ID, len(claims.ID))
	}
	if raw, err := base64.RawURLEncoding.DecodeString(claims.ID); err != nil || len(raw) != 16 {
		t.Errorf("jti = %q is not 16 bytes of unpadded base64url: %v", claims.ID, err)
	}

	// The audience must be a plain string, not a single-element array.
	var generic map[string]json.RawMessage
	payload, err := sig.Verify(id.Public)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := json.Unmarshal(payload, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.HasPrefix(string(generic["aud"]), `"`) {
		t.Errorf("aud is encoded as %s, want a JSON string", generic["aud"])
	}
	for _, k := range []string{"iss", "sub", "aud", "iat", "exp", "jti"} {
		if _, ok := generic[k]; !ok {
			t.Errorf("claim %q missing from payload %s", k, payload)
		}
	}
}

func TestAssertionRejectsWrongKey(t *testing.T) {
	t.Parallel()
	_, id := generate(t)
	_, other := generate(t)

	token, err := id.Assertion("host", "aud", time.Now)
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("jose.ParseSigned: %v", err)
	}
	if _, err := sig.Verify(other.Public); err == nil {
		t.Fatalf("assertion verified with a different host's public key")
	}
}

func TestAssertionUniqueJTI(t *testing.T) {
	t.Parallel()
	_, id := generate(t)

	seen := make(map[string]bool)
	for i := 0; i < 5; i++ {
		token, err := id.Assertion("host", "aud", time.Now)
		if err != nil {
			t.Fatalf("Assertion #%d: %v", i, err)
		}
		_, claims := parseAssertion(t, id, token)
		if seen[claims.ID] {
			t.Fatalf("jti %q repeated", claims.ID)
		}
		seen[claims.ID] = true
	}
}

func TestAssertionRequiresIdentifiers(t *testing.T) {
	t.Parallel()
	_, id := generate(t)
	if _, err := id.Assertion("", "aud", time.Now); err == nil {
		t.Errorf("Assertion with empty hostID succeeded")
	}
	if _, err := id.Assertion("host", "", time.Now); err == nil {
		t.Errorf("Assertion with empty audience succeeded")
	}
}

func TestAssertionDefaultsClock(t *testing.T) {
	t.Parallel()
	_, id := generate(t)
	before := time.Now().Unix()
	token, err := id.Assertion("host", "aud", nil)
	if err != nil {
		t.Fatalf("Assertion(nil clock): %v", err)
	}
	_, claims := parseAssertion(t, id, token)
	if claims.IssuedAt < before || claims.IssuedAt > time.Now().Unix() {
		t.Errorf("iat = %d, want roughly now (%d)", claims.IssuedAt, before)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // path is inside t.TempDir()
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func firstLine(b []byte) string {
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
