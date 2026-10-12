package installer

import "context"

// runProxmoxLXC creates the appliance container (spec §3.5, ADR-0026). M3 T5.
func (in *Installer) runProxmoxLXC(_ context.Context, _ Options) error {
	return fail(ExitUnsupported, "install mode %q is not implemented yet", ModeProxmoxLXC)
}
