//go:build !linux && !darwin

package api

import (
	"errors"
	"net"
)

// PeerUID fails closed: peer credentials exist only on the supported
// local-mode platforms.
func PeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are not supported on this platform")
}
