//go:build linux

package installer

import (
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

var safeExecRE = regexp.MustCompile(`^/[A-Za-z0-9/._-]+$`)

// TrustedBinary verifies that the currently executing Go binary is a root-owned,
// non-group/world-writable regular file inside root-trusted directories.
func TrustedBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", secureio.Stop("Could not locate the installed binary path.")
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil || !safeExecRE.MatchString(resolved) {
		return "", secureio.Stop("The installed binary path cannot safely be used by systemd.")
	}
	for _, dir := range []string{filepath.Dir(exe), filepath.Dir(resolved)} {
		fd, err := secureio.TrustedDir(dir, nil)
		if err != nil {
			return "", err
		}
		_ = unix.Close(fd)
	}
	var st unix.Stat_t
	if err := unix.Lstat(resolved, &st); err != nil ||
		(st.Mode&unix.S_IFMT) != unix.S_IFREG || st.Uid != 0 || st.Mode&0o022 != 0 {
		return "", secureio.Stop("The systemd entry point is not safely owned.")
	}
	return resolved, nil
}

func viciSocketIdentity() (dev uint64, ino uint64, exists bool, err error) {
	var st unix.Stat_t
	if lerr := unix.Lstat(host.VICIPath, &st); lerr != nil {
		if os.IsNotExist(lerr) {
			return 0, 0, false, nil
		}
		return 0, 0, false, secureio.Stop("The VICI socket path has unsafe type or ownership.")
	}
	if (st.Mode&unix.S_IFMT) != unix.S_IFSOCK || st.Uid != 0 || st.Nlink != 1 {
		return 0, 0, false, secureio.Stop("The VICI socket path has unsafe type or ownership.")
	}
	return uint64(st.Dev), uint64(st.Ino), true, nil
}
