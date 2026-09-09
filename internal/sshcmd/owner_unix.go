//go:build unix

package sshcmd

import (
	"io/fs"
	"os"
	"syscall"
)

// preserveOwner gives the file at path the owner and group of info. It is a
// no-op when the platform does not expose them or when the caller is not
// privileged enough to change them, which is the case only outside
// enrolment (enrolment runs as root).
func preserveOwner(path string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Chown(path, int(st.Uid), int(st.Gid)); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}
