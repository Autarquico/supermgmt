package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

// Everything an upgrade or uninstall run from the Proxmox host needs to find
// and prove its appliance (ADR-0026 record, ADR-0027).

var reInstallID = regexp.MustCompile(`^[0-9a-f]{8}$`)

// selectAppliance says whether this run targets an appliance and which one.
// On a Proxmox host with exactly one record that is it; with several, --vmid
// is required; with none the run is an ordinary local or server run.
func (in *Installer) selectAppliance(o Options) (applianceRecord, bool, error) {
	if in.d.PVE == nil {
		if o.VMID != 0 {
			return applianceRecord{}, false, fail(ExitUnsupported, "--vmid applies on a Proxmox VE host only")
		}
		return applianceRecord{}, false, nil
	}
	if o.VMID != 0 {
		if err := validVMID(o.VMID); err != nil {
			return applianceRecord{}, false, failWrap(ExitInvalid, "--vmid", err)
		}
		rec, err := in.readRecord(o.VMID)
		if errors.Is(err, fs.ErrNotExist) {
			return rec, false, fail(ExitInvalid, "no appliance record for VMID %d: this installer did not create that container, so it is left alone", o.VMID)
		}
		return rec, err == nil, err
	}
	records, err := in.listRecords()
	if err != nil {
		return applianceRecord{}, false, err
	}
	switch len(records) {
	case 0:
		return applianceRecord{}, false, nil
	case 1:
		return records[0], true, nil
	}
	vmids := make([]string, len(records))
	for i, r := range records {
		vmids[i] = strconv.Itoa(r.VMID)
	}
	return applianceRecord{}, false, fail(ExitInvalid, "several appliances are installed (VMIDs %s); pass --vmid", strings.Join(vmids, ", "))
}

func (in *Installer) listRecords() ([]applianceRecord, error) {
	names, err := in.d.Files.ListDir(appliancesDir)
	if err != nil {
		return nil, failWrap(ExitConfiguration, "list the appliance records", err)
	}
	var records []applianceRecord
	for _, name := range names {
		vmid, err := strconv.Atoi(strings.TrimSuffix(name, ".json"))
		if err != nil || !strings.HasSuffix(name, ".json") {
			continue
		}
		rec, err := in.readRecord(vmid)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// readRecord reads and validates a record; a missing one wraps fs.ErrNotExist.
func (in *Installer) readRecord(vmid int) (applianceRecord, error) {
	raw, err := in.d.Files.ReadFile(recordPath(vmid))
	if errors.Is(err, fs.ErrNotExist) {
		return applianceRecord{}, err
	}
	if err != nil {
		return applianceRecord{}, failWrap(ExitConfiguration, "read the appliance record for "+strconv.Itoa(vmid), err)
	}
	var rec applianceRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, failWrap(ExitConfiguration, "the appliance record "+recordPath(vmid)+" is unreadable", err)
	}
	if rec.VMID != vmid || !reInstallID.MatchString(rec.InstallID) {
		return rec, fail(ExitConfiguration, "the appliance record %s does not describe VMID %d with a valid install id", recordPath(vmid), vmid)
	}
	return rec, nil
}

// guestOwnership reads the container's marks. owned is false for a container
// that exists but does not carry this record's install id and the supermgmt
// tag; a container that is gone is neither owned nor an error.
func (in *Installer) guestOwnership(ctx context.Context, rec applianceRecord) (st GuestState, owned bool, err error) {
	pve := in.d.PVE
	if st, err = pve.State(ctx, rec.VMID); err != nil {
		return st, false, failWrap(ExitPrerequisite, "look up container "+strconv.Itoa(rec.VMID), err)
	}
	if !st.Exists {
		return st, false, nil
	}
	cfg, err := pve.Config(ctx, rec.VMID)
	if err != nil {
		return st, false, failWrap(ExitPrerequisite, "read the configuration of container "+strconv.Itoa(rec.VMID), err)
	}
	return st, strings.Contains(cfg.Description, ownershipMark(rec.InstallID)) && contains(cfg.Tags, applianceTag), nil
}

// proveGuest refuses a container that exists without the proof of ownership.
func (in *Installer) proveGuest(ctx context.Context, rec applianceRecord) (GuestState, error) {
	st, owned, err := in.guestOwnership(ctx, rec)
	if err == nil && st.Exists && !owned {
		err = fail(ExitPrerequisite, "container %d does not carry install id %s and the %s tag; it is not touched", rec.VMID, rec.InstallID, applianceTag)
	}
	return st, err
}

// ---- upgrade from the host ----

// delegateUpgrade pushes the verified binary into the appliance and runs the
// upgrade there, once the record and the container's own marks agree.
func (in *Installer) delegateUpgrade(ctx context.Context, o Options, rec applianceRecord) error {
	d := in.d
	st, err := in.proveGuest(ctx, rec)
	if err != nil {
		return err
	}
	switch {
	case !st.Exists:
		return fail(ExitPrerequisite, "container %d no longer exists", rec.VMID)
	case st.Status != "running":
		return fail(ExitPrerequisite, "container %d is %s; start it (pct start %d) and rerun", rec.VMID, st.Status, rec.VMID)
	}
	bin := firstNonEmpty(o.UpgradeBinary, o.Binary)
	if err := validPath(bin); err != nil {
		return failWrap(ExitInvalid, "the new sm binary", err)
	}
	want, err := d.Files.Hash(bin)
	if err != nil {
		return failWrap(ExitInvalid, "hash the new sm binary", err)
	}
	in.say("upgrading the appliance in container %d (install %s)", rec.VMID, rec.InstallID)
	if err := pushStaged(ctx, d.PVE, rec.VMID, bin, want); err != nil {
		return err
	}
	defer in.unstageOwned(context.WithoutCancel(ctx), rec)
	argv := []string{stagedBinary, "install", "upgrade", "--binary", stagedBinary}
	if o.AllowDowngrade {
		argv = append(argv, "--allow-downgrade")
	}
	out, err := d.PVE.Exec(ctx, rec.VMID, "", argv, nil, false)
	_, _ = d.Out.Write(bytes.TrimRight(out, "\n"))
	_, _ = d.Out.Write([]byte("\n"))
	if err != nil {
		return delegatedFailure(err)
	}
	return nil
}

// pushStaged puts bin in a directory that did not exist a moment ago and that only root can
// enter, then proves the bytes that arrived: root runs that file next, so nothing but root may be
// able to replace it between the check and the run. A leftover directory is removed first; the
// installer lock serializes runs, so a directory that appears between the removal and the
// creation belongs to somebody else and the creation refuses it.
func pushStaged(ctx context.Context, pve PVE, vmid int, bin, wantSHA string) error {
	for _, step := range []struct {
		what string
		argv []string
	}{
		{"clear an earlier staging directory", []string{"/usr/bin/rm", "-rf", stageDir}},
		{"create the staging directory", []string{"/usr/bin/mkdir", "-m", "0700", stageDir}},
	} {
		if _, err := pve.Exec(ctx, vmid, "", step.argv, nil, false); err != nil {
			return failWrap(ExitConfiguration, step.what, err)
		}
	}
	if out, err := pve.Exec(ctx, vmid, "", []string{"/usr/bin/stat", "-c", "%U:%a", stageDir}, nil, false); err != nil || strings.TrimSpace(string(out)) != "root:700" {
		return fail(ExitConfiguration, "%s inside the container is not a private root directory", stageDir)
	}
	if err := pve.Push(ctx, vmid, bin, stagedBinary, Owner{User: "root", Group: "root"}, 0o755); err != nil {
		return failWrap(ExitConfiguration, "push sm into the container", err)
	}
	out, err := pve.Exec(ctx, vmid, "", []string{"/usr/bin/sha256sum", stagedBinary}, nil, false)
	if err != nil {
		return failWrap(ExitConfiguration, "verify the pushed sm", err)
	}
	if got, _, _ := strings.Cut(strings.TrimSpace(string(out)), " "); got != wantSHA {
		return fail(ExitConfiguration, "the pushed sm does not match the new binary (sha256 %s, want %s)", got, wantSHA)
	}
	return nil
}

func unstage(ctx context.Context, pve PVE, vmid int) error {
	_, err := pve.Exec(ctx, vmid, "", []string{"/usr/bin/rm", "-rf", stageDir}, nil, false)
	return err
}

// unstageOwned removes the staging directory, unless the VMID no longer belongs to rec.
func (in *Installer) unstageOwned(ctx context.Context, rec applianceRecord) {
	if st, owned, err := in.guestOwnership(ctx, rec); err == nil && st.Exists && owned {
		_ = unstage(ctx, in.d.PVE, rec.VMID)
	}
}

// delegatedFailure keeps the exit code the upgrade inside the container ended with.
func delegatedFailure(err error) error {
	var status *ExitStatus
	if errors.As(err, &status) && status.Code >= ExitInvalid && status.Code <= ExitCancelled {
		return &Error{Code: status.Code, Err: fmt.Errorf("upgrade inside the container: %w", err)}
	}
	return failWrap(ExitConfiguration, "upgrade inside the container", err)
}
