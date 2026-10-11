//go:build !crashpoints

package backup

// crashpointsCompiled is false in every release build: hit is a no-op.
const crashpointsCompiled = false

func (env) hit(string) error { return nil }
