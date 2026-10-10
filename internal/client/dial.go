package client

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"syscall"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// DaemonUnavailableError means no daemon answers on the socket and none could
// be started. The CLI maps it to the prerequisite exit code.
type DaemonUnavailableError struct {
	Socket string
	Detail string
	Err    error
}

func (e *DaemonUnavailableError) Error() string {
	msg := "daemon is not reachable on " + e.Socket
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

func (e *DaemonUnavailableError) Unwrap() error { return e.Err }

// PeerMismatchError means the listener on the socket is not ours (or could not
// be identified), so nothing was sent to it (spec §2.1.1 mutual verification).
type PeerMismatchError struct {
	Socket string
	Detail string
}

func (e *PeerMismatchError) Error() string {
	return fmt.Sprintf("refusing to talk to %s: %s", e.Socket, e.Detail)
}

type peerLookup func(*net.UnixConn) (uint32, error)

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialOnce(ctx)
	if err == nil || c.opts.Autostart == nil || !daemonAbsent(err) {
		return conn, c.explain(err)
	}
	conn, err = c.autostart.ensure(ctx, c.opts.Autostart, c.dialOnce)
	var unavailable *DaemonUnavailableError
	if errors.As(err, &unavailable) {
		unavailable.Socket = c.opts.Socket
	}
	return conn, err
}

// dialOnce connects and verifies the peer before returning the connection.
func (c *Client) dialOnce(ctx context.Context) (net.Conn, error) {
	if len(c.opts.Socket) >= sunPathMax {
		return nil, smerr.New(smerr.CodeInvalidArgument, "",
			fmt.Sprintf("socket path is %d bytes, over the platform limit of %d: set daemon.socket to a shorter path", len(c.opts.Socket), sunPathMax-1))
	}
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "unix", c.opts.Socket)
	if err != nil {
		return nil, err
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, &PeerMismatchError{Socket: c.opts.Socket, Detail: "not a Unix connection"}
	}
	uid, err := c.peer(conn)
	switch {
	case err != nil:
		_ = conn.Close()
		return nil, &PeerMismatchError{Socket: c.opts.Socket, Detail: "cannot identify the listener: " + err.Error()}
	case uid != c.uid:
		_ = conn.Close()
		return nil, &PeerMismatchError{Socket: c.opts.Socket, Detail: fmt.Sprintf("it is owned by uid %d, not uid %d", uid, c.uid)}
	}
	return conn, nil
}

// explain turns a bare dial failure into the typed error callers branch on.
func (c *Client) explain(err error) error {
	if err == nil || !daemonAbsent(err) {
		return err
	}
	return &DaemonUnavailableError{Socket: c.opts.Socket, Detail: "no daemon is running and autostart is off", Err: err}
}

func daemonAbsent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}
