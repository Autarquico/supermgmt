// Package installer implements `sm install` (spec §3, ADR-0019): it detects
// the host, lays out users, directories, binary, configuration and service
// units, starts the service and hands out the bootstrap code. Every system
// interaction sits behind an interface in ports.go. Offline database work
// (restore, key import) runs as `sm` subprocesses, never in-process.
package installer

import (
	"errors"
	"fmt"
)

// Exit codes of spec §3.7.
const (
	ExitInvalid       = 2
	ExitUnsupported   = 3
	ExitPrerequisite  = 4
	ExitCreation      = 6
	ExitConfiguration = 7
	ExitConnectivity  = 8
	ExitRestore       = 9
	ExitCancelled     = 10
)

// Error is an installer failure carrying its process exit code.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(code int, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

func failWrap(code int, context string, err error) error {
	return &Error{Code: code, Err: fmt.Errorf("%s: %w", context, err)}
}

// ExitCode is the process exit code for err: 0 for nil, the installer code
// for an *Error, 1 otherwise.
func ExitCode(err error) int {
	var e *Error
	switch {
	case err == nil:
		return 0
	case errors.As(err, &e):
		return e.Code
	}
	return 1
}
