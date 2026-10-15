package client

import (
	"net"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

// WithExpectedUID makes c require a daemon running as uid.
func WithExpectedUID(c *Client, uid uint32) { c.uid = uid }

// WithPeerLookup replaces the peer-credential lookup (fault injection).
func WithPeerLookup(c *Client, lookup func(*net.UnixConn) (uint32, error)) { c.peer = lookup }

// WithCloudflaredDirs replaces the fixed cloudflared search list and returns a restore func.
func WithCloudflaredDirs(dirs ...string) func() {
	old := cloudflaredDirs
	cloudflaredDirs = dirs
	return func() { cloudflaredDirs = old }
}

// InteractiveCommandWithCloudflared is InteractiveCommand with cloudflared at path.
func InteractiveCommandWithCloudflared(info wire.ConnectInfo, tool wire.Tool, knownHosts, path string) ([]string, error) {
	return interactiveCommand(info, tool, knownHosts, func() (string, error) { return path, nil })
}
