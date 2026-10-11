//go:build crashpoints

package backup

// crashpointsCompiled is true only under the crashpoints build tag, which the
// crash-injection tests use (ADR-0020). Release binaries never carry it.
const crashpointsCompiled = true

// hit lets a test end the process "here": the returned error unwinds without
// any cleanup, leaving the disk as a real crash would.
func (e env) hit(point string) error {
	if e.crash == nil {
		return nil
	}
	return e.crash(point)
}
