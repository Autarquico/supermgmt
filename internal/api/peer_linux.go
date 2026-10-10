package api

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID reads the peer's UID with SO_PEERCRED.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // fd fits int
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", sockErr)
	}
	return cred.Uid, nil
}
