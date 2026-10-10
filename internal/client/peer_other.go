//go:build !linux && !darwin

package client

import (
	"errors"
	"net"
)

const sunPathMax = 100

// Peer credentials exist only on the supported local-mode platforms; anywhere
// else the client fails closed.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are not supported on this platform")
}
