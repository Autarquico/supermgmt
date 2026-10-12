package installer

import "context"

// runUninstall removes the software, and the data only when separately
// confirmed (spec §29.4, ADR-0027). M3 T6.
func (in *Installer) runUninstall(_ context.Context, _ Options) error {
	return fail(ExitUnsupported, "install mode %q is not implemented yet", ModeUninstall)
}
