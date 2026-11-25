//go:build !linux

package secureio

import (
	"os"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

const DefaultFileLimit = 2 * 1024 * 1024

func ModePtr(m uint32) *uint32 {
	return &m
}

func TrustedDir(path string, expectedMode *uint32) (int, error) {
	return -1, Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func SyncDir(path string) error {
	return Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func MakeDirectory(path string, mode uint32) error {
	return Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func ReadFile(path string, mode uint32, limit int64, parentMode *uint32) ([]byte, error) {
	return nil, Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func AtomicWrite(path string, content []byte, mode uint32) error {
	return Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func RemoveFile(path string) error {
	return Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func WriteRecord(path string, payload any) error {
	return Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func ReadRecord(path string) (any, error) {
	return nil, Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func AcquireLock(path string) (*os.File, error) {
	return nil, Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func ReadKeys(p *profile.Profile) (map[string][]byte, error) {
	return nil, Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}
