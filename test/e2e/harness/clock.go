//go:build e2e

package harness

import "time"

// Now is the wall clock. The e2e tests drive real processes, containers and certificates, which
// all judge time by it, so there is nothing to inject.
func Now() time.Time {
	return time.Now() //nolint:forbidigo // real processes and x509 validity run on the wall clock
}
