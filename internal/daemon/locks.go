package daemon

import (
	"errors"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
)

// SocketInUseError means another daemon, possibly for a different database,
// holds the socket lock (spec §2.1.1).
type SocketInUseError struct {
	Socket string
	PID    int
}

func (e *SocketInUseError) Error() string {
	if e.PID == 0 {
		return fmt.Sprintf("socket in use: %s is owned by another daemon", e.Socket)
	}
	return fmt.Sprintf("socket in use: %s is owned by the daemon with PID %d", e.Socket, e.PID)
}

// Locks are the two flocks a daemon holds for its whole life (spec §2.1.1).
type Locks struct {
	database, socket *database.Lock
}

// AcquireLocks takes the database lock and then the socket lock, both
// non-blocking. A held database lock is a *database.LockHeldError naming the
// PID; a held socket lock is a *SocketInUseError. The socket directory must
// already be verified: the socket lock file lives in it.
//
// The socket lock is the database package's flock on "<canonical path>.lock",
// applied to the socket path: the same protocol, the same realpath of the
// parent, the PID recorded in the file.
func AcquireLocks(databasePath, socket string) (*Locks, error) {
	db, err := database.AcquireDatabaseLock(databasePath)
	if err != nil {
		return nil, err
	}
	sock, err := database.AcquireDatabaseLock(socket)
	if err != nil {
		_ = db.Release()
		var held *database.LockHeldError
		if errors.As(err, &held) {
			return nil, &SocketInUseError{Socket: socket, PID: held.PID}
		}
		return nil, err
	}
	return &Locks{database: db, socket: sock}, nil
}

// Release drops both locks.
func (l *Locks) Release() error {
	return errors.Join(l.socket.Release(), l.database.Release())
}
