package backup

import "context"

// TestEnv tunes restore and recovery for tests. Zero values mean production defaults.
type TestEnv struct {
	DatabaseLimit, MemberLimit, TotalLimit int64
	// Crash ends the run at a crash point; it only has effect under the
	// crashpoints build tag.
	Crash func(point string) error
}

func (t TestEnv) env() env {
	e := env{crash: t.Crash}
	if t.DatabaseLimit+t.MemberLimit+t.TotalLimit > 0 {
		e.limits = defaultLimits()
		if t.DatabaseLimit > 0 {
			e.limits.database = t.DatabaseLimit
		}
		if t.MemberLimit > 0 {
			e.limits.member = t.MemberLimit
		}
		if t.TotalLimit > 0 {
			e.limits.total = t.TotalLimit
		}
	}
	return e
}

// RestoreWith is Restore under a test environment.
func RestoreWith(ctx context.Context, o RestoreOptions, t TestEnv) error {
	return restore(ctx, o, t.env())
}

// RecoverWith is Recover under a test environment.
func RecoverWith(dataDir string, t TestEnv) error { return recoverRestore(dataDir, t.env()) }

// CrashpointsCompiled reports whether this build carries crash points.
const CrashpointsCompiled = crashpointsCompiled
