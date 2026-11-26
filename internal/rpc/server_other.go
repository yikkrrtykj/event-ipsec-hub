//go:build !linux

package rpc

import (
	"context"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

type Server struct {
	SocketPath  string
	AllowedUIDs map[uint32]bool
	Handler     Handler
}

func (s *Server) Serve(ctx context.Context) error {
	return secureio.Stop("Unix socket SO_PEERCRED RPC server requires Linux.")
}
