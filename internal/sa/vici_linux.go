//go:build linux

package sa

import (
	"context"
	"net"
	"time"

	"github.com/strongswan/govici/vici"
	"golang.org/x/sys/unix"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

// OpenSession opens a govici session over the local VICI Unix socket after verifying
// via SO_PEERCRED that the peer is the exact owned root charon-systemd PID.
func OpenSession(expectedPID int, socketPath string) (*vici.Session, error) {
	if socketPath == "" {
		socketPath = host.VICIPath
	}
	var peerErr error
	dialer := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		var d net.Dialer
		d.Timeout = 8 * time.Second
		conn, err := d.DialContext(ctx, "unix", socketPath)
		if err != nil {
			return nil, err
		}
		uconn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			peerErr = secureio.StopWithReason("UNOWNED_DAEMON", "The VICI socket peer is not the owned daemon.")
			return nil, peerErr
		}
		rawConn, err := uconn.SyscallConn()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		var ucred *unix.Ucred
		var sockErr error
		if ctrlErr := rawConn.Control(func(fd uintptr) {
			ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); ctrlErr != nil {
			_ = conn.Close()
			return nil, ctrlErr
		}
		if sockErr != nil {
			_ = conn.Close()
			return nil, sockErr
		}
		if int(ucred.Pid) != expectedPID || ucred.Uid != 0 {
			_ = conn.Close()
			peerErr = secureio.StopWithReason("UNOWNED_DAEMON", "The VICI socket peer is not the owned daemon.")
			return nil, peerErr
		}
		return conn, nil
	}
	sess, err := vici.NewSession(vici.WithDialContext(dialer))
	if err != nil {
		if peerErr != nil {
			return nil, peerErr
		}
		return nil, secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
	}
	return sess, nil
}
