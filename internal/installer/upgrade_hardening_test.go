package installer

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"strings"
	"testing"
)

// reboot is what the machine does at boot: it starts every enabled unit that is not running.
func (h *uhost) reboot() {
	if h.enabled && !h.running {
		_ = usvc{h}.Start(context.Background(), Unit{Name: UnitName})
	}
}

// Canonical resolves a configured symlinked directory the way the daemon would.
func (h *uhost) Canonical(p string) (string, error) {
	if real, ok := h.symlinks[path.Dir(p)]; ok {
		return path.Join(real, path.Base(p)), nil
	}
	return p, nil
}

// seedUpgrade leaves an unfinished upgrade the way a crash would: the state file, sm.new and sm.prev.
func (h *uhost) seedUpgrade(t *testing.T, st upgradeState, newContent string) {
	t.Helper()
	l := applianceLayout()
	st.OldSHA256, st.NewSHA256 = sha256Hex([]byte(binV1)), sha256Hex([]byte(newContent))
	st.FromVersion, st.ToVersion, st.SchemaBefore, st.UpdatedAt = "1.0.0", "1.1.0", 3, testNow
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	h.put(l.DataDir+"/"+upgradeStateFile, string(raw))
	h.put("/usr/local/src/sm-new", newContent)
	h.inodes[l.Binary+".prev"] = h.inodes[l.Binary]
	h.prevOld = true
}

func TestUpgrade_FailedUpgradeCannotBeStartedByAReboot(t *testing.T) {
	h := newUHost(t)
	h.put("/usr/local/src/sm-new", binV2+";boot=fail-migrated")
	if err := h.upgrade(defaultHooks()); ExitCode(err) != ExitRestore {
		t.Fatalf("err = %v", err)
	}
	h.reboot()
	if h.running || h.enabled {
		t.Errorf("a reboot started the failed version (running %t, enabled %t)", h.running, h.enabled)
	}
}

func TestUpgrade_RerunOfAFailedUpgradeStopsTheServiceAgain(t *testing.T) {
	h := newUHost(t)
	h.put("/usr/local/src/sm-new", binV2+";boot=fail-migrated")
	_ = h.upgrade(defaultHooks())
	h.running, h.enabled = true, true // somebody started it meanwhile
	h.events = nil
	if err := h.upgrade(defaultHooks()); ExitCode(err) != ExitRestore {
		t.Fatalf("err = %v", err)
	}
	if h.running || h.enabled {
		t.Errorf("the failed version was left running (running %t, enabled %t)", h.running, h.enabled)
	}
	if h.index("waitstopped ") < 0 {
		t.Error("the stop was not verified")
	}
}

func TestUpgrade_RevertNeverRestoresTheOldBinaryOverAMigratedDatabase(t *testing.T) {
	h := newUHost(t)
	h.running = false
	failed := binV2 + ";boot=fail"
	l := applianceLayout()
	h.seedUpgrade(t, upgradeState{Phase: upReverting, Archive: "/x/pre.tar.zst"}, failed)
	h.put(l.Binary, failed) // the failed version is live; a boot after the crash migrated the database
	h.dbSchema = 4
	err := h.upgrade(defaultHooks())
	if ExitCode(err) != ExitRestore {
		t.Fatalf("err = %v", err)
	}
	if h.live() != failed {
		t.Errorf("the old binary was put over a database it cannot read: live %q", h.live())
	}
	if st, ok := h.state(); !ok || st.Phase != upFailed {
		t.Errorf("state = %+v", st)
	}
	if h.running || !strings.Contains(h.out.String(), "backup restore --offline") {
		t.Errorf("running %t, output:\n%s", h.running, h.out.String())
	}
	if h.index("start ") >= 0 {
		t.Error("a version was started")
	}
}

func TestUpgrade_BuildMetadataAloneIsNotADowngrade(t *testing.T) {
	h := newUHost(t)
	h.oldContent = "sm;version=1.0.0+build.2;schema=3"
	h.put(applianceLayout().Binary, h.oldContent)
	h.startedAs = h.oldContent
	h.put("/usr/local/src/sm-new", "sm;version=1.0.0+build.1;schema=3")
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.live() != "sm;version=1.0.0+build.1;schema=3" {
		t.Errorf("live = %q", h.live())
	}
}

func TestUpgrade_DatabaseLockIsTakenOnTheCanonicalPath(t *testing.T) {
	h := newUHost(t)
	l := applianceLayout()
	h.symlinks = map[string]string{l.DataDir: "/srv/real"}
	_ = h.RemoveAll(l.DataDir + "/supermgmt.db.lock")
	h.put("/srv/real/supermgmt.db.lock", "")
	h.lockHeld = true
	err := h.upgrade(defaultHooks())
	if ExitCode(err) != ExitRestore || !strings.Contains(err.Error(), "still in use") {
		t.Fatalf("err = %v", err)
	}
	if h.live() != binV1 || h.index("run "+l.Binary+".new backup") != -1 {
		t.Error("the upgrade went on while the database was held")
	}
}

func TestUpgrade_TheDatabaseLockIsHeldAcrossTheSwap(t *testing.T) {
	h := newUHost(t)
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatal(err)
	}
	if !h.renamedUnderDBLock {
		t.Error("the binary was swapped without holding the database lock")
	}
}

// ---- appliance: the installer lock covers selection through cleanup ----

func TestUpgradeAppliance_RecordIsSelectedAndUpgradedUnderTheInstallerLock(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.recordReads = nil
	if err := p.run(p.upgradeOpts(), fastHooks(), false); err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	if len(p.recordReads) == 0 || slices.Contains(p.recordReads, false) {
		t.Errorf("appliance records were read without the installer lock: %v", p.recordReads)
	}
	if len(p.lockedInside) != 1 || !p.lockedInside[0] {
		t.Errorf("the upgrade inside the container ran without the installer lock: %v", p.lockedInside)
	}
	if p.locked {
		t.Error("the lock was not released")
	}
}

func TestAppliance_AnotherInstallerHoldingTheLockStopsUpgradeAndUninstallBeforeAnyLookup(t *testing.T) {
	for name, o := range map[string]Options{
		"upgrade":   {Mode: ModeUpgrade, Binary: "/usr/local/src/sm2", Yes: true},
		"uninstall": {Mode: ModeUninstall, Yes: true},
		"purge":     {Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPVEWrap(t)
			p.mustInstall(t)
			p.recordReads, p.locked = nil, true
			err := p.run(o, fastHooks(), false)
			if exitCodeOf(t, err) != ExitPrerequisite || !strings.Contains(err.Error(), "another SuperMgmt installer") {
				t.Fatalf("err = %v", err)
			}
			if len(p.recordReads) != 0 || len(p.upgrades) != 0 || len(p.guests) != 1 {
				t.Errorf("work started without the lock: reads %v, upgrades %d, guests %d", p.recordReads, len(p.upgrades), len(p.guests))
			}
		})
	}
}

func TestUninstallAppliance_RecordIsSelectedUnderTheInstallerLock(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.recordReads = nil
	if err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900}, fastHooks(), false); err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	if len(p.recordReads) == 0 || slices.Contains(p.recordReads, false) {
		t.Errorf("appliance records were read without the installer lock: %v", p.recordReads)
	}
}

func TestUninstallAppliance_PurgeDestroysNothingWhenTheVMIDChangesHandsDuringTheConfirmation(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.answers = []string{"900"}
	p.onAsk = func() { // the operator's container is replaced while the prompt waits
		p.guests[900] = &fakeGuest{desc: "somebody else's", status: "stopped", foreign: true, tags: []string{"prod"}}
	}
	err := p.run(Options{Mode: ModeUninstall, PurgeData: true}, fastHooks(), true)
	if exitCodeOf(t, err) != ExitPrerequisite || !strings.Contains(err.Error(), "changed while waiting") {
		t.Fatalf("err = %v", err)
	}
	if len(p.violations) > 0 || p.guests[900] == nil {
		t.Errorf("a container that was not confirmed was destroyed: %v", p.violations)
	}
	if len(p.oursLeft()) == 0 || !p.Exists(recordPath(900)) {
		t.Error("the identities or the record were removed after the refusal")
	}
}
