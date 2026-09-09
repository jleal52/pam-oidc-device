//go:build !unix

package sshcmd

import "io/fs"

// preserveOwner does nothing on platforms without POSIX file owners. The
// tool only ever runs on Linux; this keeps the package buildable elsewhere
// so that tests and editors work.
func preserveOwner(string, fs.FileInfo) error { return nil }
