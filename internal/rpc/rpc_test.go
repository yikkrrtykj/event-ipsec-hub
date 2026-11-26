package rpc

import (
	"context"
	"encoding/json"
	"net"
	"testing"
)

func TestRPCRoundTripOverPipe(t *testing.T) {
	handler := func(_ context.Context, method string, params json.RawMessage) (any, error) {
		if method == MethodPing {
			return map[string]any{"pong": true, "role": "root-agent"}, nil
		}
		return nil, nil
	}

	client := &DialClient{
		Dial: func(ctx context.Context) (net.Conn, error) {
			c1, c2 := net.Pipe()
			go ServeConn(ctx, c2, handler)
			return c1, nil
		},
	}

	var out map[string]any
	if err := client.Call(context.Background(), MethodPing, nil, &out); err != nil {
		t.Fatalf("RPC ping failed: %v", err)
	}
	if out["pong"] != true || out["role"] != "root-agent" {
		t.Fatalf("unexpected RPC response: %+v", out)
	}
}
