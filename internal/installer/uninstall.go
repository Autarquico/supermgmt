package installer

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// purgePhrase is what an operator types to confirm deleting data on a local
// or server install; on a Proxmox host the typed confirmation is the VMID.
const purgePhrase = "delete my data"

// runUninstall removes the software, and the data only when separately
// confirmed (spec §29.4, ADR-0027).
func (in *Installer) runUninstall(ctx context.Context, o Options) error {
	return in.uninstall(ctx, o, defaultHooks())
}

func (in *Installer) uninstall(ctx context.Context, o Options, h provisionHooks) error {
	in.reportHost()
	rec, appliance, err := in.selectAppliance(o)
	if err != nil {
		return err
	}
	if appliance {
		return in.uninstallAppliance(ctx, o, h, rec)
	}
	t, err := in.uninstallTarget(o)
	if err != nil {
		return err
	}
	if t.server {
		release, err := in.lockInstaller()
		if err != nil {
			return err
		}
		defer release()
	}
	return (&remover{in: in, d: in.d, o: o, h: h, t: t}).run(ctx)
}

// uninstallTarget is the installation, or, for a purge, what an earlier
// uninstall left behind (data and configuration without software).
func (in *Installer) uninstallTarget(o Options) (upgradeTarget, error) {
	t, err := in.installedTarget(o, false)
	if err == nil || !o.PurgeData || ExitCode(err) != ExitPrerequisite {
		return t, err
	}
	files := in.d.Files
	if sl := o.serverLayout(); files.Exists(sl.DataDir) || files.Exists(sl.ConfigFile) {
		if in.d.Host.UID != 0 {
			return upgradeTarget{}, fail(ExitPrerequisite, "removing the server data must run as root")
		}
		return upgradeTarget{l: sl, server: true}, nil
	}
	if ul := o.userLayout(in.d.Host); files.Exists(ul.DataDir) || files.Exists(ul.ConfigFile) {
		return upgradeTarget{l: ul}, nil
	}
	return t, err
}

// remover is one local or server uninstall.
type remover struct {
	in *Installer
	d  Deps
	o  Options
	h  provisionHooks
	t  upgradeTarget
}

func (r *remover) hit(point string) error { return r.h.at(point) }

func (r *remover) run(ctx context.Context) error {
	if err := r.confirm(); err != nil {
		return err
	}
	if err := r.removeSoftware(ctx); err != nil {
		return err
	}
	if !r.o.PurgeData {
		r.in.say("removed the software; configuration, data and backups stay in %s and %s (rerun with --purge-data to delete them)", r.t.l.ConfigDir, r.t.l.DataDir)
		return nil
	}
	return r.purgeData()
}

func (r *remover) paths() []string {
	l := r.t.l
	if r.t.server {
		return []string{l.DataDir, l.ConfigDir}
	}
	return []string{l.DataDir, l.ConfigFile}
}

// confirm asks once: the plan, or, when data goes too, the typed phrase. A
// run without a terminal deletes data only with --purge-data and --yes.
func (r *remover) confirm() error {
	t, o := r.t, r.o
	if !o.PurgeData {
		r.in.say("plan: stop and remove %s and its service unit; keep configuration, data and backups", t.l.Binary)
		return r.in.confirmPlan(o)
	}
	for _, p := range r.paths() {
		if err := safeToDelete(p, r.d.Host.Home); err != nil {
			return failWrap(ExitInvalid, "refusing to delete "+p, err)
		}
	}
	r.in.say("plan: remove the software AND DELETE %s", strings.Join(r.paths(), ", "))
	if !r.in.interactive() {
		if !o.Yes {
			return fail(ExitInvalid, "deleting data without a terminal needs --purge-data and SUPERMGMT_YES=1")
		}
		return nil
	}
	answer, err := r.d.Prompter.Ask("Type \"" + purgePhrase + "\" to delete the data")
	if err != nil {
		return failWrap(ExitCancelled, "read answer", err)
	}
	if strings.TrimSpace(answer) != purgePhrase {
		return fail(ExitCancelled, "cancelled: the data stays")
	}
	return nil
}

// removeSoftware is stop, disable, unit, binaries; every step may be redone.
func (r *remover) removeSoftware(ctx context.Context) error {
	files, t := r.d.Files, r.t
	if t.unit != nil && files.Exists(t.unit.Path) {
		if err := t.services.Stop(ctx, *t.unit); err != nil {
			return failWrap(ExitConfiguration, "stop "+t.unit.Name, err)
		}
		if err := t.services.WaitStopped(ctx, *t.unit, stopTimeout); err != nil {
			return failWrap(ExitConfiguration, "verify "+t.unit.Name+" terminated", err)
		}
		if err := r.hit("UN:stopped"); err != nil {
			return err
		}
		if err := t.services.Disable(ctx, *t.unit); err != nil {
			return failWrap(ExitConfiguration, "disable "+t.unit.Name, err)
		}
		if err := r.hit("UN:disabled"); err != nil {
			return err
		}
		if err := files.RemoveAll(t.unit.Path); err != nil {
			return failWrap(ExitConfiguration, "remove "+t.unit.Path, err)
		}
		if err := r.hit("UN:unit-removed"); err != nil {
			return err
		}
		if err := t.services.Load(ctx, *t.unit); err != nil {
			return failWrap(ExitConfiguration, "reload the service manager", err)
		}
	}
	for _, p := range []string{t.l.Binary, t.previous(), t.staged(), t.previous() + ".link", t.l.Binary + ".revert"} {
		if err := files.RemoveAll(p); err != nil {
			return failWrap(ExitConfiguration, "remove "+p, err)
		}
	}
	return r.hit("UN:binary-removed")
}

func (r *remover) purgeData() error {
	for _, p := range r.paths() {
		if err := r.d.Files.RemoveAll(p); err != nil {
			return failWrap(ExitConfiguration, "delete "+p, err)
		}
		if err := r.hit("UN:purged"); err != nil {
			return err
		}
	}
	r.in.say("deleted %s; the service account %s was left in place", strings.Join(r.paths(), ", "), ServiceUser)
	return nil
}

// protectedDirs are never deleted, whatever the configuration says.
var protectedDirs = []string{
	"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/run", "/sbin", "/sys",
	"/tmp", "/usr", "/var", "/var/lib", "/var/tmp", "/usr/local", "/usr/local/bin", "/usr/bin", "/Users", "/Library",
}

// safeToDelete guards --purge-data against a configuration that points at a
// system directory or at the home directory.
func safeToDelete(p, home string) error {
	switch {
	case !filepath.IsAbs(p) || filepath.Clean(p) != p:
		return errors.New("path is not absolute and clean")
	case home != "" && (p == home || strings.HasPrefix(home+"/", p+"/")):
		return errors.New("path is the home directory or contains it")
	}
	for _, d := range protectedDirs {
		if p == d {
			return errors.New("path is a system directory")
		}
	}
	return nil
}
