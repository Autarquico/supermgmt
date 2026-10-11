package api

import (
	"context"
	"log/slog"
	"net"
	"slices"
)

// PeerLookup reads the UID of the process at the other end of a Unix
// connection. PeerUID is the platform implementation; tests inject failures.
type PeerLookup func(*net.UnixConn) (uint32, error)

// RestrictToUID wraps l so that it only ever yields connections whose peer UID
// is uid (spec §2.1.1, ADR-0014). A mismatch or a failed lookup closes the
// connection before a byte is read: the check fails closed.
func RestrictToUID(l net.Listener, uid uint32, lookup PeerLookup, log *slog.Logger) net.Listener {
	return RestrictToUIDs(l, []uint32{uid}, lookup, log)
}

// RestrictToUIDs is RestrictToUID for several users: the admin socket admits
// root and the service user (spec §23.1).
func RestrictToUIDs(l net.Listener, uids []uint32, lookup PeerLookup, log *slog.Logger) net.Listener {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &peerListener{Listener: l, uids: slices.Clone(uids), lookup: lookup, log: log}
}

type peerListener struct {
	net.Listener
	uids   []uint32
	lookup PeerLookup
	log    *slog.Logger
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, ok := l.admit(conn); ok {
			return &peerConn{Conn: conn, uid: uid}, nil
		}
		_ = conn.Close()
	}
}

func (l *peerListener) admit(conn net.Conn) (uint32, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		l.log.Warn("refused a connection that is not a Unix connection")
		return 0, false
	}
	uid, err := l.lookup(unixConn)
	switch {
	case err != nil:
		l.log.Warn("refused a connection: peer credentials unavailable", slog.Any("error", err))
		return 0, false
	case !slices.Contains(l.uids, uid):
		l.log.Warn("refused a connection from another user", slog.Uint64("peer_uid", uint64(uid)))
		return 0, false
	}
	return uid, true
}

// peerConn is a connection whose peer UID was verified at accept time.
type peerConn struct {
	net.Conn
	uid uint32
}

type peerKey struct{}

// connContext is http.Server.ConnContext: it hands the verified UID to the
// handlers, which refuse a request that arrives without one.
func connContext(ctx context.Context, conn net.Conn) context.Context {
	if pc, ok := conn.(*peerConn); ok {
		return context.WithValue(ctx, peerKey{}, pc.uid)
	}
	return ctx
}

func verifiedPeer(ctx context.Context) (uint32, bool) {
	uid, ok := ctx.Value(peerKey{}).(uint32)
	return uid, ok
}
