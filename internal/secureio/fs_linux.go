//go:build linux

package secureio

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

const DefaultFileLimit = 2 * 1024 * 1024

func ModePtr(m uint32) *uint32 {
	return &m
}

// TrustedDir walks path component-by-component from / with O_NOFOLLOW|O_DIRECTORY,
// verifying root ownership and no group/world write permissions on every segment.
func TrustedDir(path string, expectedMode *uint32) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, Stop("A protected directory is not absolute.")
	}
	clean := filepath.Clean(path)
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, Stop("Could not open root directory.")
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = unix.Close(fd)
		}
	}()

	if clean != "/" {
		parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return -1, Stop("Invalid protected directory.")
			}
			child, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if err != nil {
				if errors.Is(err, unix.ENOENT) {
					return -1, os.ErrNotExist
				}
				return -1, Stop("A protected directory could not be opened safely.")
			}
			_ = unix.Close(fd)
			fd = child
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				return -1, Stop("Could not stat protected directory.")
			}
			if st.Uid != 0 || st.Mode&0o022 != 0 {
				return -1, Stop("A protected directory is writable by another account.")
			}
		}
	}

	if expectedMode != nil {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return -1, Stop("Could not stat protected directory.")
		}
		if (st.Mode & 0o7777) != *expectedMode {
			return -1, Stop("A protected directory has unexpected permissions.")
		}
	}

	closeOnErr = false
	return fd, nil
}

func SyncDir(path string) error {
	fd, err := TrustedDir(path, nil)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func MakeDirectory(path string, mode uint32) error {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	fd, err := TrustedDir(parent, nil)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	created := false
	err = unix.Mkdirat(fd, base, mode)
	if err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return Stop("Could not create protected directory.")
	}
	if created {
		child, err := unix.Openat(fd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return Stop("Could not verify newly created protected directory.")
		}
		defer unix.Close(child)
		var st unix.Stat_t
		if err := unix.Fstat(child, &st); err != nil || st.Uid != 0 {
			return Stop("A newly created protected directory has unexpected ownership.")
		}
		if err := unix.Fchmod(child, mode); err != nil {
			return Stop("Could not set permissions on protected directory.")
		}
		_ = unix.Fsync(child)
	}
	_ = unix.Fsync(fd)

	checkFD, err := TrustedDir(path, &mode)
	if err != nil {
		return err
	}
	_ = unix.Close(checkFD)
	return nil
}

func ReadFile(path string, mode uint32, limit int64, parentMode *uint32) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultFileLimit
	}
	dirFD, err := TrustedDir(filepath.Dir(path), parentMode)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)

	fileFD, err := unix.Openat(dirFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, Stop("A protected file could not be opened safely.")
	}
	f := os.NewFile(uintptr(fileFD), path)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fileFD, &st); err != nil {
		return nil, Stop("Could not stat protected file.")
	}
	if (st.Mode&unix.S_IFMT) != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || (st.Mode&0o7777) != mode {
		return nil, Stop("A protected file has unsafe type, ownership, links or permissions.")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, Stop("Could not read protected file.")
	}
	if int64(len(data)) > limit {
		return nil, Stop("A protected file exceeds its size limit.")
	}
	return data, nil
}

func AtomicWrite(path string, content []byte, mode uint32) error {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	dirFD, err := TrustedDir(parent, nil)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmpName := ".ipsecvpn-" + hex.EncodeToString(rnd[:])
	tmpFD, err := unix.Openat(dirFD, tmpName, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW, mode)
	if err != nil {
		return Stop("Could not create temporary file for atomic write.")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(dirFD, tmpName, 0)
		}
	}()

	tmpFile := os.NewFile(uintptr(tmpFD), filepath.Join(parent, tmpName))
	if err := unix.Fchmod(tmpFD, mode); err != nil {
		_ = tmpFile.Close()
		return Stop("Could not set permissions on temporary file.")
	}
	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return Stop("Could not write temporary file.")
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return Stop("Could not fsync temporary file.")
	}
	if err := tmpFile.Close(); err != nil {
		return Stop("Could not close temporary file.")
	}
	if err := unix.Renameat(dirFD, tmpName, dirFD, base); err != nil {
		return Stop("Could not atomically replace target file.")
	}
	cleanup = false
	_ = unix.Fsync(dirFD)
	return nil
}

func RemoveFile(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Stop("Could not remove protected file.")
	}
	return SyncDir(filepath.Dir(path))
}

func WriteRecord(path string, payload any) error {
	data, err := MarshalRecord(payload)
	if err != nil {
		return err
	}
	return AtomicWrite(path, data, 0o600)
}

func ReadRecord(path string) (any, error) {
	raw, err := ReadFile(path, 0o600, DefaultFileLimit, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return UnmarshalRecord(raw)
}

func AcquireLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, Stop("Could not open transaction lock file.")
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		(st.Mode&unix.S_IFMT) != unix.S_IFREG ||
		st.Uid != 0 || st.Nlink != 1 || (st.Mode&0o7777) != 0o600 {
		_ = f.Close()
		return nil, Stop("The transaction lock file is not safely owned.")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, Stop("LOCKED: another deployment transaction is in progress.")
	}
	return f, nil
}

func ReadKeys(p *profile.Profile) (map[string][]byte, error) {
	keys := make(map[string][]byte)
	if p == nil {
		return keys, nil
	}
	seen := make(map[string]struct{}, len(p.SiteLinks))
	dirMode := uint32(0o700)
	for _, l := range p.SiteLinks {
		path, err := ValidateSecretRef(l.SecretRef)
		if err != nil {
			return nil, err
		}
		raw, err := ReadFile(path, 0o600, 65, &dirMode)
		if err != nil {
			return nil, Stop("An IKE key is missing or cannot be opened securely.")
		}
		key, err := ValidatePSKBytes(raw)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[string(key)]; dup {
			return nil, Stop("All site links must use distinct IKE keys.")
		}
		seen[string(key)] = struct{}{}
		keys[l.KeyID()] = key
	}
	return keys, nil
}
