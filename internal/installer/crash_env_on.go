//go:build crashpoints

package installer

import "os"

// crashAtEnv names the environment variable that picks the point where a
// crashpoints build ends the process (ADR-0035).
const crashAtEnv = "SUPERMGMT_CRASH_AT"

// crashExitCode is the exit status of a deliberate crash.
const crashExitCode = 86

// upgradeCrashPoints is every point the upgrade passes, in ADR-0035 order.
// A test fails when a hit literal in upgrade.go is missing here.
var upgradeCrashPoints = []string{
	"U:staged", "U:prev-linked", "U:prepared:recorded",
	"U:hold:applied", "U:stopped:applied", "U:stopped:recorded",
	"U:backed_up:applied", "U:backup:retaken", "U:backed_up:recorded",
	"U:swap:before", "U:swap:renamed", "U:swapped:recorded",
	"U:started:applied", "U:started:recorded", "U:done:recorded",
	"U:abort:restarted", "U:revert:renamed", "U:revert:started",
	"U:reverting:recorded", "U:failed:recorded",
}

// crashFromEnv exits the process when the host environment names point.
func crashFromEnv(env map[string]string, point string) error {
	if env[crashAtEnv] == point {
		os.Exit(crashExitCode)
	}
	return nil
}
