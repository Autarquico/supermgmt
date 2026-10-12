package installer

import "context"

// runAuto picks proxmox-lxc, local or server from the host (ADR-0026). M3 T5.
func (in *Installer) runAuto(_ context.Context, _ Options) error {
	return fail(ExitUnsupported, "install mode %q is not implemented yet", ModeAuto)
}
