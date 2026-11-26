//go:build linux

package rpc

import (
	"context"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

// Server listens on a root-owned Unix socket and verifies peer UID via SO_PEERCRED.
type Server struct {
	SocketPath  string
	AllowedUIDs map[uint32]bool // empty = allow root (0) only
	Handler     Handler
}

func (s *Server) Serve(ctx context.Context) error {
	sockPath := s.SocketPath
	if sockPath == "" {
		sockPath = DefaultSocketPath
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(sockPath)
	_ = os.Chmod(sockPath, 0o660)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		if err := s.verifyPeer(conn); err != nil {
			_ = conn.Close()
			continue
		}
		go ServeConn(ctx, conn, s.Handler)
	}
}

func (s *Server) verifyPeer(conn net.Conn) error {
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return secureio.Stop("RPC peer is not a Unix domain socket.")
	}
	raw, err := uconn.SyscallConn()
	if err != nil {
		return err
	}
	var ucred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return sockErr
	}
	if ucred.Uid == 0 {
		return nil
	}
	if s.AllowedUIDs != nil && s.AllowedUIDs[ucred.Uid] {
		return nil
	}
	return secureio.Stop("Unauthorized RPC peer UID.")
}
