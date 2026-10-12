package installer

import "context"

// runUpgrade replaces the installed binary (spec §29.3, ADR-0027). M3 T6.
func (in *Installer) runUpgrade(_ context.Context, _ Options) error {
	return fail(ExitUnsupported, "install mode %q is not implemented yet", ModeUpgrade)
}
