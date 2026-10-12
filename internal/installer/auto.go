package installer

import "context"

// runAuto picks proxmox-lxc, local or server from the host (spec §3.4,
// ADR-0026) and runs that mode.
func (in *Installer) runAuto(ctx context.Context, o Options) error {
	mode, err := in.detectMode()
	if err != nil {
		return err
	}
	in.say("auto: installing in %s mode", mode)
	o.Mode = mode
	return in.Run(ctx, o)
}

func (in *Installer) detectMode() (Mode, error) {
	h := in.d.Host
	switch {
	case in.d.PVE != nil:
		return ModeProxmoxLXC, nil
	case h.GOOS == "darwin" || (h.GOOS == "linux" && hasDesktop(h.Env)):
		return ModeLocal, nil
	case h.GOOS != "linux":
		return "", fail(ExitUnsupported, "unsupported OS %q", h.GOOS)
	case !in.interactive():
		return "", fail(ExitInvalid, "no desktop or Proxmox host detected and no terminal to ask on; set SUPERMGMT_MODE (server, local, client, ...)")
	}
	if err := in.confirm("No desktop or Proxmox host detected. Install the SuperMgmt server on this host?"); err != nil {
		return "", err
	}
	return ModeServer, nil
}

func hasDesktop(env map[string]string) bool {
	for _, name := range []string{"XDG_CURRENT_DESKTOP", "WAYLAND_DISPLAY", "DISPLAY"} {
		if env[name] != "" {
			return true
		}
	}
	return false
}
