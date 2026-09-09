package sshcmd

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// configFileMode is the mode a configuration file gets when the rewrite has
// to create one from scratch, which only happens if the original vanished
// between reading and writing.
const configFileMode fs.FileMode = 0o640

// setConfigValues rewrites the configuration file at path so that every key
// of values carries the given value.
//
// It is deliberately not a re-serialisation of the document: an operator's
// configuration is full of comments and blank lines that explain the
// deployment, and yaml.v3 loses the blank lines when it re-encodes. The file
// is parsed with yaml.v3 to find where each key lives and to be sure the
// entry really is a plain scalar occupying one line; only those lines are
// replaced, byte for byte, and keys that are absent are appended at the end
// under comment. Everything else in the file survives untouched.
//
// An entry that cannot be rewritten safely — a folded or multi-line value, a
// flow mapping — is reported as an error naming the key, so that the
// operator can set it by hand rather than have the tool mangle the file.
func setConfigValues(path string, values map[string]string, comment string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("oidc-ssh: stat %s: %w", path, err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is the operator's configuration file.
	if err != nil {
		return fmt.Errorf("oidc-ssh: read %s: %w", path, err)
	}
	updated, err := withConfigValues(data, values, comment)
	if err != nil {
		return err
	}
	if bytes.Equal(updated, data) {
		return nil
	}
	return writePreserving(path, updated, info)
}

// withConfigValues returns data with the given keys set; see
// setConfigValues, which is where the file handling lives.
func withConfigValues(data []byte, values map[string]string, comment string) ([]byte, error) {
	root, err := topLevelMapping(data)
	if err != nil {
		return nil, err
	}

	lines := splitLines(data)
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var appended []string
	for _, key := range keys {
		encoded, err := encodeScalar(values[key])
		if err != nil {
			return nil, fmt.Errorf("oidc-ssh: cannot write %s: %w", key, err)
		}
		k, v := mappingEntry(root, key)
		if k == nil {
			appended = append(appended, key+": "+encoded)
			continue
		}
		index := k.Line - 1
		if index < 0 || index >= len(lines) || !isSingleLineEntry(lines[index], key, v) {
			return nil, fmt.Errorf("oidc-ssh: cannot rewrite %s at line %d automatically; set it to %s by hand", key, k.Line, encoded)
		}
		line := strings.Repeat(" ", k.Column-1) + key + ": " + encoded
		if v.LineComment != "" {
			line += " " + v.LineComment
		}
		lines[index] = line
	}

	out := strings.Join(lines, "\n")
	if len(appended) > 0 {
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if comment != "" {
			out += "\n" + comment + "\n"
		}
		out += strings.Join(appended, "\n") + "\n"
	}
	return []byte(out), nil
}

// topLevelMapping parses data and returns its top-level block mapping.
func topLevelMapping(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("oidc-ssh: parse configuration: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("oidc-ssh: configuration is not a single YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || root.Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("oidc-ssh: configuration is not a block mapping")
	}
	return root, nil
}

// mappingEntry returns the key and value nodes of key in the mapping m, or
// two nils when the mapping has no such key.
func mappingEntry(m *yaml.Node, key string) (k, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// isSingleLineEntry reports whether line holds the whole "key: value" entry
// of the value node v, and nothing else. It re-parses the line on its own:
// if that yields exactly the same one-key mapping with the same scalar, then
// replacing the line replaces the entry and cannot disturb its
// surroundings.
func isSingleLineEntry(line, key string, v *yaml.Node) bool {
	if v == nil || v.Kind != yaml.ScalarNode || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return false
	}
	probe, err := topLevelMapping([]byte(strings.TrimSpace(line)))
	if err != nil || len(probe.Content) != 2 {
		return false
	}
	pk, pv := probe.Content[0], probe.Content[1]
	return pk.Value == key && pv.Kind == yaml.ScalarNode && pv.Value == v.Value && pv.Tag == v.Tag
}

// encodeScalar renders s as a YAML scalar, quoting it when it needs it.
func encodeScalar(s string) (string, error) {
	out, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}
	encoded := strings.TrimRight(string(out), "\n")
	if strings.Contains(encoded, "\n") {
		return "", fmt.Errorf("value does not fit on one line")
	}
	return encoded, nil
}

// splitLines splits data into lines, dropping the final empty element that a
// trailing newline produces so that Join restores the file exactly.
func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	// Join adds no trailing newline, so keep one as an empty last element.
	return append(lines, "")
}

// writePreserving replaces the file at path with data through a temporary
// file in the same directory, keeping the mode, owner and group of info.
//
// Preserving the owner matters as much as the content: the configuration is
// typically 0640 root:oidc-ssh so that the unprivileged AuthorizedKeysCommand
// user can read it, and a rewrite that left it root:root would break every
// key-based login on the host.
func writePreserving(path string, data []byte, info fs.FileInfo) error {
	mode := configFileMode
	if info != nil {
		mode = info.Mode().Perm()
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) //nolint:gosec // the mode is the one the replaced file had.
	if err != nil {
		return fmt.Errorf("oidc-ssh: create %s: %w", tmp, err)
	}
	err = func() error {
		if err := f.Chmod(mode); err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
		return f.Sync()
	}()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil && info != nil {
		err = preserveOwner(tmp, info)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("oidc-ssh: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("oidc-ssh: replace %s: %w", path, err)
	}
	return nil
}
