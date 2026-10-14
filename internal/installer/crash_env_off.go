//go:build !crashpoints

package installer

// crashFromEnv is inert in release builds: SUPERMGMT_CRASH_AT is ignored.
func crashFromEnv(map[string]string, string) error { return nil }
