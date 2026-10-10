//go:build pins

// This file is never compiled. It keeps the M1 modules that no package imports
// yet in go.mod across `go mod tidy` (which considers every build tag). Delete
// each import as soon as a real one lands, and the file when it is empty.

package tui

import (
	_ "github.com/creack/pty"
	_ "golang.org/x/sys/unix"
)
