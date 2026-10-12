//go:build crashpoints

package installer

import "errors"

// crashpointsEnabled is true only under the crashpoints build tag, which the
// crash-injection tests use (ADR-0026). Release binaries never carry it.
const crashpointsEnabled = true

// errCrashed is what a crash hook returns to end the run "here": the error
// unwinds without rollback, leaving the disk as a real crash would.
var errCrashed = errors.New("installer: simulated crash")

func isCrash(err error) bool { return errors.Is(err, errCrashed) }
