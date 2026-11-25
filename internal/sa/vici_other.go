//go:build !linux

package sa

import (
	"github.com/strongswan/govici/vici"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

func OpenSession(expectedPID int, socketPath string) (*vici.Session, error) {
	return nil, secureio.StopWithReason("VICI_UNAVAILABLE", "Local VICI Unix sockets require Linux.")
}
