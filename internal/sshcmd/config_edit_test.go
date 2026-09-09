package sshcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commentedConfig = `# pam-oidc-device configuration.

issuer: https://login.example.com

# The client registered for the device flow.
client_id: ssh-bastion

# host_id: written by enroll
identity_key: /etc/oidc-ssh/host.key   # 0640 root:oidc-ssh

users:
  systems: "ssh:systems"
`

func TestWithConfigValuesReplacesInPlace(t *testing.T) {
	t.Parallel()
	out, err := withConfigValues([]byte(commentedConfig), map[string]string{
		"identity_key": "/srv/oidc/host.key",
	}, configComment)
	if err != nil {
		t.Fatalf("withConfigValues: %v", err)
	}

	got := string(out)
	wantContains(t, "result", got,
		// The value changed and its trailing comment stayed with it
		// (its alignment is rebuilt, the comment itself is not).
		"identity_key: /srv/oidc/host.key # 0640 root:oidc-ssh",
		// Every comment and blank line around it survived.
		"# pam-oidc-device configuration.",
		"# The client registered for the device flow.",
		"# host_id: written by enroll",
		"\n\nissuer: https://login.example.com\n",
		"users:\n  systems: \"ssh:systems\"\n",
	)
	if strings.Contains(got, "/etc/oidc-ssh/host.key") {
		t.Errorf("the old value is still there:\n%s", got)
	}
	if n := strings.Count(got, "identity_key:"); n != 1 {
		t.Errorf("identity_key appears %d times, want 1:\n%s", n, got)
	}
}

func TestWithConfigValuesAppendsMissingKeys(t *testing.T) {
	t.Parallel()
	out, err := withConfigValues([]byte(commentedConfig), map[string]string{
		"host_id":  "6a9f0c2e",
		"api_base": "https://login.example.com/api/ssh",
	}, configComment)
	if err != nil {
		t.Fatalf("withConfigValues: %v", err)
	}

	got := string(out)
	// Appended in sorted order under the comment, after the original text.
	want := configComment + "\napi_base: https://login.example.com/api/ssh\nhost_id: 6a9f0c2e\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("file does not end with the appended block %q:\n%s", want, got)
	}
	if !strings.HasPrefix(got, commentedConfig) {
		t.Errorf("the original text was modified:\n%s", got)
	}
	// The commented-out example is a comment, not an entry, and stays one.
	wantContains(t, "result", got, "# host_id: written by enroll")
}

func TestWithConfigValuesQuotesWhenNeeded(t *testing.T) {
	t.Parallel()
	out, err := withConfigValues([]byte("issuer: https://login.example.com\n"), map[string]string{
		"host_id": "yes",
	}, "")
	if err != nil {
		t.Fatalf("withConfigValues: %v", err)
	}
	// "yes" unquoted would come back as a boolean on the next read.
	wantContains(t, "result", string(out), `host_id: "yes"`)
}

func TestWithConfigValuesRefusesWhatItCannotRewrite(t *testing.T) {
	t.Parallel()
	for name, doc := range map[string]string{
		"folded value":  "host_id: >-\n  6a9f\n  0c2e\n",
		"flow mapping":  "{issuer: https://login.example.com, host_id: old}\n",
		"not a mapping": "- issuer\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := withConfigValues([]byte(doc), map[string]string{"host_id": "new"}, ""); err == nil {
				t.Errorf("got nil error, want a refusal to rewrite %q", doc)
			}
		})
	}
}

func TestSetConfigValuesKeepsTheFileMode(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(commentedConfig), 0o640); err != nil { //nolint:gosec // the point of the test is that this mode survives
		t.Fatalf("write: %v", err)
	}

	if err := setConfigValues(path, map[string]string{"host_id": "6a9f0c2e"}, configComment); err != nil {
		t.Fatalf("setConfigValues: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("mode = %04o, want 0640", got)
	}
	wantContains(t, "file", readFile(t, path), "host_id: 6a9f0c2e")
	// The temporary file used for the atomic replacement is gone.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temporary file left behind (err=%v)", err)
	}
}

func TestSetConfigValuesLeavesAnUnchangedFileAlone(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(commentedConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := setConfigValues(path, map[string]string{"client_id": "ssh-bastion"}, configComment); err != nil {
		t.Fatalf("setConfigValues: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("the file was rewritten although nothing changed")
	}
	if got := readFile(t, path); got != commentedConfig {
		t.Errorf("content changed:\n%s", got)
	}
}
