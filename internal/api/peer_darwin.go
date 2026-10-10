package api

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID reads the peer's UID with LOCAL_PEERCRED, the mechanism behind getpeereid.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, fmt.Errorf("LOCAL_PEERCRED: %w", sockErr)
	}
	return cred.Uid, nil
}
