//go:build !linux

package installer

import "github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"

func TrustedBinary() (string, error) {
	return "", secureio.Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func viciSocketIdentity() (uint64, uint64, bool, error) {
	return 0, 0, false, secureio.Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}
