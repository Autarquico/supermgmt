package installer

import (
	"context"
	"errors"
	"path"
	"slices"
	"strconv"
	"strings"
)

// uninstallAppliance acts on one appliance, found by its record. The default
// removes the software inside the container and stops it; --purge-data
// destroys the container and removes this install's Proxmox identities and
// nothing else (ADR-0027, Q9).
func (in *Installer) uninstallAppliance(ctx context.Context, o Options, h provisionHooks, rec applianceRecord) error {
	if in.d.Host.UID != 0 {
		return fail(ExitPrerequisite, "uninstalling an appliance must run as root on the Proxmox host")
	}
	release, err := in.lockInstaller()
	if err != nil {
		return err
	}
	defer release()
	a := applianceRemover{in: in, d: in.d, o: o, h: h, rec: rec}
	if o.PurgeData {
		return a.purge(ctx)
	}
	return a.removeSoftware(ctx)
}

type applianceRemover struct {
	in  *Installer
	d   Deps
	o   Options
	h   provisionHooks
	rec applianceRecord
}

func (a *applianceRemover) hit(point string) error { return a.h.at(point) }

// removeSoftware runs `sm install uninstall` inside the container and stops
// it. The container, its data, the record and the Proxmox identities stay.
func (a *applianceRemover) removeSoftware(ctx context.Context) error {
	pve, vmid := a.d.PVE, a.rec.VMID
	st, err := a.in.proveGuest(ctx, a.rec)
	if err != nil {
		return err
	}
	if !st.Exists {
		a.in.say("container %d no longer exists; nothing to uninstall (--purge-data removes the Proxmox identities)", vmid)
		return nil
	}
	a.in.say("plan: remove the SuperMgmt software inside container %d and stop it; the container, its data and the Proxmox identities stay", vmid)
	if err := a.in.confirmPlan(a.o); err != nil {
		return err
	}
	if st.Status != "running" {
		if err := pve.Start(ctx, vmid); err != nil {
			return failWrap(ExitConfiguration, "start container "+strconv.Itoa(vmid), err)
		}
	}
	if err := a.hit("UN:ct-running"); err != nil {
		return err
	}
	if err := a.uninstallInside(ctx); err != nil {
		return err
	}
	if err := a.hit("UN:ct-uninstalled"); err != nil {
		return err
	}
	if err := pve.Stop(ctx, vmid); err != nil {
		return failWrap(ExitConfiguration, "stop container "+strconv.Itoa(vmid), err)
	}
	a.in.say("removed the software in container %d and stopped it; --purge-data destroys the container and its Proxmox identities", vmid)
	return a.hit("UN:ct-stopped")
}

// uninstallInside is skipped when the software is already gone, so a rerun converges.
func (a *applianceRemover) uninstallInside(ctx context.Context) error {
	binary := applianceLayout().Binary
	_, err := a.d.PVE.Exec(ctx, a.rec.VMID, "", []string{"/usr/bin/test", "-x", binary}, nil, false)
	var status *ExitStatus
	switch {
	case errors.As(err, &status) && status.Code == 1:
		return nil
	case err != nil:
		return failWrap(ExitConfiguration, "look for sm inside the container", err)
	}
	out, err := a.d.PVE.Exec(ctx, a.rec.VMID, "", []string{binary, "install", "uninstall"}, nil, false)
	_, _ = a.d.Out.Write(out)
	if err != nil {
		return delegatedFailure(err)
	}
	return nil
}

// ---- purge ----

func (a *applianceRemover) purge(ctx context.Context) error {
	user, roles, err := a.rec.identities()
	if err != nil {
		return err
	}
	st, owned, err := a.in.guestOwnership(ctx, a.rec)
	if err != nil {
		return err
	}
	if err := a.confirmPurge(user, roles, st.Exists && owned); err != nil {
		return err
	}
	if st.Exists && owned {
		if err := a.destroyGuest(ctx, st); err != nil {
			return err
		}
	} else if st.Exists {
		a.in.say("container %d does not carry install id %s: it is NOT destroyed", a.rec.VMID, a.rec.InstallID)
	}
	if err := a.hit("UN:lxc-destroyed"); err != nil {
		return err
	}
	if err := a.removeIdentities(ctx, user, roles); err != nil {
		return err
	}
	return a.removeRecord()
}

// confirmPurge is the separate data-deletion confirmation: the typed VMID, or
// without a terminal an explicit --vmid with --purge-data and SUPERMGMT_YES=1.
func (a *applianceRemover) confirmPurge(user string, roles []string, destroys bool) error {
	vmid := strconv.Itoa(a.rec.VMID)
	what := "container " + vmid + " is gone already"
	if destroys {
		what = "DESTROY container " + vmid + " with all its data"
	}
	a.in.say("plan: %s; remove the Proxmox user %s, its token, roles %s and their ACLs (install %s only; the template stays)",
		what, user, strings.Join(roles, ", "), a.rec.InstallID)
	if !a.in.interactive() {
		if !a.o.Yes || a.o.VMID != a.rec.VMID {
			return fail(ExitInvalid, "destroying an appliance without a terminal needs --vmid %s, --purge-data and SUPERMGMT_YES=1", vmid)
		}
		return nil
	}
	answer, err := a.d.Prompter.Ask("Type the VMID " + vmid + " to confirm")
	if err != nil {
		return failWrap(ExitCancelled, "read answer", err)
	}
	if strings.TrimSpace(answer) != vmid {
		return fail(ExitCancelled, "cancelled: container %s stays", vmid)
	}
	return nil
}

func (a *applianceRemover) destroyGuest(ctx context.Context, st GuestState) error {
	pve, vmid := a.d.PVE, a.rec.VMID
	if st.Status != "stopped" {
		if err := pve.Stop(ctx, vmid); err != nil {
			return failWrap(ExitConfiguration, "stop container "+strconv.Itoa(vmid), err)
		}
	}
	if err := pve.Destroy(ctx, vmid); err != nil {
		return failWrap(ExitConfiguration, "destroy container "+strconv.Itoa(vmid), err)
	}
	if after, err := pve.State(ctx, vmid); err != nil || after.Exists {
		return fail(ExitConfiguration, "container %d still exists after destroy", vmid)
	}
	return nil
}

// identities derives the names this install owns from its id and refuses a
// record that names anything else, so a damaged record cannot aim a removal
// at somebody else's user or role.
func (rec applianceRecord) identities() (user string, roles []string, err error) {
	user = userIDFor(rec.InstallID)
	allowed := []string{auditRoleFor(rec.InstallID), powerRoleFor(rec.InstallID)}
	if rec.User != user || rec.Token != user+"!"+pveTokenID {
		return "", nil, fail(ExitConfiguration, "the appliance record %s names a user or token that this install id does not own; refusing to remove it", recordPath(rec.VMID))
	}
	for _, r := range rec.Roles {
		if !slices.Contains(allowed, r) {
			return "", nil, fail(ExitConfiguration, "the appliance record %s names role %q that this install id does not own; refusing to remove it", recordPath(rec.VMID), r)
		}
	}
	return user, rec.Roles, nil
}

// removeIdentities takes away, in this order, the ACLs of the user and its
// tokens, the token, the user and the roles. Each step reads the resource
// back first, so a rerun after a crash finishes the job.
func (a *applianceRemover) removeIdentities(ctx context.Context, user string, roles []string) error {
	pve := a.d.PVE
	acls, err := pve.ACLs(ctx)
	if err != nil {
		return failWrap(ExitConfiguration, "list the Proxmox ACLs", err)
	}
	for _, acl := range acls {
		if acl.User == user || strings.HasPrefix(acl.Token, user+"!") {
			if err := pve.RemoveACL(ctx, acl); err != nil {
				return failWrap(ExitConfiguration, "remove the ACL "+aclName(acl), err)
			}
		}
	}
	if err := a.hit("UN:acls-removed"); err != nil {
		return err
	}
	if exists, err := pve.TokenExists(ctx, user, pveTokenID); err != nil {
		return failWrap(ExitConfiguration, "look up the token of "+user, err)
	} else if exists {
		if err := pve.RemoveToken(ctx, user, pveTokenID); err != nil {
			return failWrap(ExitConfiguration, "remove the token of "+user, err)
		}
	}
	if err := a.hit("UN:token-removed"); err != nil {
		return err
	}
	if exists, err := pve.UserExists(ctx, user); err != nil {
		return failWrap(ExitConfiguration, "look up "+user, err)
	} else if exists {
		if err := pve.RemoveUser(ctx, user); err != nil {
			return failWrap(ExitConfiguration, "remove "+user, err)
		}
	}
	if err := a.hit("UN:user-removed"); err != nil {
		return err
	}
	for _, role := range roles {
		if exists, err := pve.RoleExists(ctx, role); err != nil {
			return failWrap(ExitConfiguration, "look up role "+role, err)
		} else if exists {
			if err := pve.RemoveRole(ctx, role); err != nil {
				return failWrap(ExitConfiguration, "remove role "+role, err)
			}
		}
	}
	return a.hit("UN:roles-removed")
}

// removeRecord goes last: while it exists a crashed purge can be finished.
func (a *applianceRemover) removeRecord() error {
	f := a.d.Files
	if err := f.RemoveAll(recordPath(a.rec.VMID)); err != nil {
		return failWrap(ExitConfiguration, "remove the appliance record", err)
	}
	if err := f.SyncDir(path.Dir(recordPath(a.rec.VMID))); err != nil {
		return failWrap(ExitConfiguration, "sync "+appliancesDir, err)
	}
	a.in.say("removed appliance %d: container, Proxmox identities and record", a.rec.VMID)
	return a.hit("UN:record-removed")
}
