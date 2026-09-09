// Package hostid manages the long-lived identity of a host that enrolls with
// an OIDC provider: an Ed25519 key pair stored on disk in OpenSSH private key
// format, plus short-lived EdDSA-signed JWT assertions the host presents to
// prove it holds the private key.
//
// The private key file uses the same format as ssh-keygen so operators can
// inspect it with familiar tooling (ssh-keygen -y -f, ssh-keygen -lf) and the
// published public key line can be pasted wherever an authorized_keys-style
// entry is expected.
package hostid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"
)

// AssertionLifetime is how long a host assertion stays valid after it is
// issued (exp = iat + AssertionLifetime). It is deliberately short: an
// assertion is meant to be minted immediately before it is sent.
const AssertionLifetime = 60 * time.Second

// keyFileMode is the permission set of the private key file. Group read is
// allowed so that an unprivileged helper in the key's group can load it.
const keyFileMode = 0o640

// Sentinel errors. Callers should test them with errors.Is; the returned
// errors wrap the underlying cause where there is one.
var (
	// ErrExists is returned by Generate when a file already exists at the
	// requested path. Generate never overwrites an existing key.
	ErrExists = errors.New("hostid: key file already exists")
	// ErrKeyType is returned by Load when the file holds a private key that
	// is not Ed25519.
	ErrKeyType = errors.New("hostid: key is not ed25519")
)

// Identity is an Ed25519 host key pair together with its OpenSSH
// presentation.
type Identity struct {
	// Private is the Ed25519 private key (seed and public half, 64 bytes).
	Private ed25519.PrivateKey
	// Public is the Ed25519 public key.
	Public ed25519.PublicKey
	// PublicKeyLine is the single-line OpenSSH public key,
	// "ssh-ed25519 AAAA... <comment>", without a trailing newline.
	PublicKeyLine string
	// Fingerprint is the SHA-256 fingerprint of the public key in the format
	// printed by ssh-keygen -lf: "SHA256:" followed by unpadded base64.
	Fingerprint string
}

// Generate creates a fresh Ed25519 key pair, writes the private key to path
// in OpenSSH private key format with mode 0640 and returns the resulting
// Identity. The comment is embedded in the key file and appended to
// PublicKeyLine; callers typically pass "oidc-ssh@<hostname>".
//
// Generate fails with ErrExists if path already exists and never replaces an
// existing file. The parent directory must already exist.
func Generate(path, comment string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hostid: generate key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("hostid: marshal private key: %w", err)
	}

	// O_EXCL makes the existence check and the create atomic, so two
	// concurrent Generate calls cannot both believe they created the file.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFileMode) //nolint:gosec // 0640 is the intended mode; see keyFileMode.
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrExists, path)
		}
		return nil, fmt.Errorf("hostid: create key file: %w", err)
	}
	// The mode passed to OpenFile is filtered by the umask; set it explicitly
	// so the file ends up with keyFileMode regardless of the caller's umask.
	if err := f.Chmod(keyFileMode); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("hostid: chmod key file: %w", err)
	}
	if err := writeKeyFile(f, pem.EncodeToMemory(block)); err != nil {
		_ = os.Remove(path)
		return nil, err
	}

	return newIdentity(priv, pub, comment)
}

// writeKeyFile writes data to f, syncs it and closes it, returning the first
// error encountered. It always closes f.
func writeKeyFile(f *os.File, data []byte) error {
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	switch {
	case writeErr != nil:
		return fmt.Errorf("hostid: write key file: %w", writeErr)
	case syncErr != nil:
		return fmt.Errorf("hostid: sync key file: %w", syncErr)
	case closeErr != nil:
		return fmt.Errorf("hostid: close key file: %w", closeErr)
	}
	return nil
}

// Load reads an OpenSSH private key file previously written by Generate (or
// by ssh-keygen -t ed25519) and returns its Identity. Keys of any other type
// are rejected with ErrKeyType. Encrypted keys are not supported.
func Load(path string) (*Identity, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator configuration, not user input.
	if err != nil {
		return nil, fmt.Errorf("hostid: read key file: %w", err)
	}

	parsed, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("hostid: parse key file %s: %w", path, err)
	}

	var priv ed25519.PrivateKey
	switch k := parsed.(type) {
	case ed25519.PrivateKey:
		priv = k
	case *ed25519.PrivateKey:
		priv = *k
	default:
		return nil, fmt.Errorf("%w: %s holds %T", ErrKeyType, path, parsed)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: %s has %d-byte key", ErrKeyType, path, len(priv))
	}

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyType, path)
	}

	// ParseRawPrivateKey drops the comment, so recover it from the PEM block
	// to keep PublicKeyLine identical to what Generate produced.
	return newIdentity(priv, pub, keyComment(raw))
}

// keyComment extracts the comment stored in an OpenSSH private key file, or
// returns "" if the file is not in that format or has none.
func keyComment(raw []byte) string {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return ""
	}
	// openssh-key-v1 layout: magic, cipher, kdf, kdfopts, nkeys, pubkey,
	// then a private section of (check1, check2, keytype, pub, priv, comment,
	// padding). Only the unencrypted case is handled; anything else yields "".
	const magic = "openssh-key-v1\x00"
	if !strings.HasPrefix(string(block.Bytes), magic) {
		return ""
	}
	var outer struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}
	if err := ssh.Unmarshal(block.Bytes[len(magic):], &outer); err != nil || outer.CipherName != "none" {
		return ""
	}
	var inner struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Pub     []byte
		Priv    []byte
		Comment string
		Rest    []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(outer.PrivKeyBlock, &inner); err != nil {
		return ""
	}
	return inner.Comment
}

// newIdentity derives the OpenSSH presentation of an Ed25519 key pair.
func newIdentity(priv ed25519.PrivateKey, pub ed25519.PublicKey, comment string) (*Identity, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("hostid: build ssh public key: %w", err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return &Identity{
		Private:       priv,
		Public:        pub,
		PublicKeyLine: line,
		Fingerprint:   ssh.FingerprintSHA256(sshPub),
	}, nil
}

// assertionClaims is the JWT payload of a host assertion. aud is a single
// string on purpose: the assertion is always addressed to exactly one party.
type assertionClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	ID       string `json:"jti"`
}

// Assertion mints a compact JWT signed with the host's private key (alg
// EdDSA, typ JWT) that proves possession of the key to audience. Claims are
// iss = sub = hostID, aud = audience, iat = now(), exp = iat +
// AssertionLifetime and a random 16-byte jti (unpadded base64url). If now is
// nil, time.Now is used.
func (id *Identity) Assertion(hostID, audience string, now func() time.Time) (string, error) {
	if hostID == "" {
		return "", errors.New("hostid: assertion needs a host id")
	}
	if audience == "" {
		return "", errors.New("hostid: assertion needs an audience")
	}
	if now == nil {
		now = time.Now
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("hostid: generate jti: %w", err)
	}

	issued := now().Unix()
	payload, err := json.Marshal(assertionClaims{
		Issuer:   hostID,
		Subject:  hostID,
		Audience: audience,
		IssuedAt: issued,
		Expiry:   issued + int64(AssertionLifetime/time.Second),
		ID:       base64.RawURLEncoding.EncodeToString(nonce[:]),
	})
	if err != nil {
		return "", fmt.Errorf("hostid: encode claims: %w", err)
	}

	opts := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: id.Private}, opts)
	if err != nil {
		return "", fmt.Errorf("hostid: create signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("hostid: sign assertion: %w", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("hostid: serialize assertion: %w", err)
	}
	return token, nil
}
