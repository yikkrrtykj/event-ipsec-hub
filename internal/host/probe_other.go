//go:build !linux

package host

import "github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"

func ReadHostAuthorization() (string, error) {
	return "", secureio.Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func (h *OSHost) Probe() (map[string]string, error) {
	return nil, secureio.Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}

func (h *OSHost) AssertPrivateDaemon(pid int) error {
	return secureio.Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
}
