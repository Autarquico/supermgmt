// Package domain holds the SuperMgmt core types: identifiers, time, closed
// enums, value types and plain entities. It performs no I/O.
package domain

import (
	"strings"

	"github.com/google/uuid"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ID is a lowercase canonical UUIDv7 (ADR-0002).
type ID string

func (id ID) String() string { return string(id) }

// IDGenerator issues new identifiers.
type IDGenerator interface{ NewID() ID }

// UUIDv7Generator issues random time-ordered UUIDv7 identifiers.
type UUIDv7Generator struct{}

// NewID returns a fresh UUIDv7. uuid.NewV7 fails only if the system random
// source fails, which Go treats as unrecoverable, so the failure is fatal here too.
func (UUIDv7Generator) NewID() ID {
	return ID(uuid.Must(uuid.NewV7()).String())
}

// ParseID accepts only lowercase canonical UUID text of version 7.
func ParseID(s string) (ID, error) {
	u, err := uuid.Parse(s)
	if err != nil || len(s) != 36 || s != strings.ToLower(s) ||
		u.Version() != 7 || u.Variant() != uuid.RFC4122 {
		return "", smerr.New(smerr.CodeInvalidArgument, "", "invalid id: want lowercase canonical UUIDv7")
	}
	return ID(s), nil
}
