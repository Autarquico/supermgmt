//go:build !crashpoints

package installer

// crashpointsEnabled is false in every release build: crash points are no-ops.
const crashpointsEnabled = false

func isCrash(error) bool { return false }
