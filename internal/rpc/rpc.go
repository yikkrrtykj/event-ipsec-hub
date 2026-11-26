package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"
)

const DefaultSocketPath = "/run/ipsecvpn/agent.sock"

// Request is a strictly typed control request sent from unprivileged `web` to root `agent`.
// Designing this as a clean JSON-RPC envelope lets future multi-Hub deployments swap only the
// transport (Unix Socket -> mTLS gRPC/HTTP2) without changing handler logic.
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Reason string          `json:"reason,omitempty"`
}

// Well-known privileged agent RPC methods.
const (
	MethodPing            = "agent.ping"
	MethodStatus          = "hub.status"
	MethodCheckHost       = "hub.check"
	MethodApplyProfile    = "hub.apply"
	MethodRollback        = "hub.rollback"
	MethodReconnect       = "hub.reconnect"
	MethodRekey           = "hub.rekey"
	MethodWriteSecret     = "secret.write"
	MethodReadSecretAudit = "secret.read_for_export"
	MethodFailoverGate    = "failover.gate"
	MethodSyncAllowlist   = "firewall.sync_web_allowlist"
)

type ApplyParams struct {
	YAMLContent string `json:"yaml_content"`
	Confirmed   bool   `json:"confirmed"`
	Maintenance bool   `json:"maintenance"`
	Operator    string `json:"operator"`
}

type RollbackParams struct {
	BackupID    string `json:"backup_id"`
	Confirmed   bool   `json:"confirmed"`
	Maintenance bool   `json:"maintenance"`
	Operator    string `json:"operator"`
}

type ReconnectParams struct {
	Site     string `json:"site,omitempty"`
	Operator string `json:"operator"`
}

type RekeyParams struct {
	Site     string `json:"site"`
	Kind     string `json:"kind"` // child | ike
	Operator string `json:"operator"`
}

type WriteSecretParams struct {
	SecretRef string `json:"secret_ref"`
	SiteID    string `json:"site_id"`
	PSKHex    string `json:"psk_hex"`
	Operator  string `json:"operator"`
}

type ReadSecretAuditParams struct {
	SecretRef string `json:"secret_ref"`
	SiteID    string `json:"site_id"`
	Operator  string `json:"operator"`
	RemoteIP  string `json:"remote_ip"`
}

type FailoverGateParams struct {
	Locked   bool   `json:"locked"`
	Operator string `json:"operator"`
}

type SyncAllowlistParams struct {
	Port  int      `json:"port"`
	CIDRs []string `json:"cidrs"`
}

// Handler executes one validated RPC method on the privileged agent side.
type Handler func(ctx context.Context, method string, params json.RawMessage) (any, error)

// Client calls the privileged Hub Agent (abstracted for local Unix socket or future remote mTLS).
type Client interface {
	Call(ctx context.Context, method string, params any, out any) error
}

// DialClient calls an RPC server over a net.Conn dialer (Unix socket on Linux, TCP/pipe in tests).
type DialClient struct {
	Dial    func(ctx context.Context) (net.Conn, error)
	Timeout time.Duration
}

func NewUnixClient(socketPath string) *DialClient {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &DialClient{
		Timeout: 30 * time.Second,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
}

func (c *DialClient) Call(ctx context.Context, method string, params any, out any) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := c.Dial(cctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := cctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		rawParams = b
	}
	req := Request{ID: "1", Method: method, Params: rawParams}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			return errors.New("agent RPC failed")
		}
		return errors.New(resp.Error)
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}

// ServeConn handles one RPC request/response exchange on an accepted connection.
func ServeConn(ctx context.Context, conn net.Conn, handler Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "invalid RPC request"})
		return
	}
	res, err := handler(ctx, req.Method, req.Params)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(Response{ID: req.ID, OK: false, Error: err.Error()})
		return
	}
	raw, err := json.Marshal(res)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(Response{ID: req.ID, OK: false, Error: "failed to encode RPC response"})
		return
	}
	_ = json.NewEncoder(conn).Encode(Response{ID: req.ID, OK: true, Result: raw})
}
