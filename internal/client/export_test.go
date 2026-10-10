package client

import "net"

// WithExpectedUID makes c require a daemon running as uid.
func WithExpectedUID(c *Client, uid uint32) { c.uid = uid }

// WithPeerLookup replaces the peer-credential lookup (fault injection).
func WithPeerLookup(c *Client, lookup func(*net.UnixConn) (uint32, error)) { c.peer = lookup }
