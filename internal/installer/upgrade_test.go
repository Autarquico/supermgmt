package installer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestUpgrade_StopsBacksUpReplacesAndStarts(t *testing.T) {
	h := newUHost(t)
	l := applianceLayout()
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.out.String())
	}
	if h.live() != binV2 || h.content(l.Binary+".prev") != binV1 {
		t.Errorf("live = %q, prev = %q", h.live(), h.content(l.Binary+".prev"))
	}
	if h.dbSchema != 4 || !h.running || h.startedAs != binV2 {
		t.Errorf("schema %d running %t started as %q", h.dbSchema, h.running, h.startedAs)
	}
	order := []string{"stop ", "waitstopped ", "run " + l.Binary + ".new backup create --offline --json", "rename " + l.Binary + ".new " + l.Binary, "start ", "ready"}
	last := -1
	for _, step := range order {
		i := h.index(step)
		if i <= last {
			t.Errorf("%q is out of order (event %d after %d): %v", step, i, last, h.events)
		}
		last = i
	}
	st, ok := h.state()
	if !ok || st.Phase != upDone || st.OldSHA256 != sha256Hex([]byte(binV1)) || st.NewSHA256 != sha256Hex([]byte(binV2)) ||
		st.SchemaBefore != 3 || !strings.Contains(st.Archive, "pre-1-20260101T000000Z.tar.zst") || st.FromVersion != "1.0.0" || st.ToVersion != "1.1.0" {
		t.Errorf("state = %+v", st)
	}
	h.noViolations(t)
	if h.index("remove "+l.Binary+".new") != -1 {
		t.Error("the staged binary was removed instead of renamed into place")
	}
}

func TestUpgrade_BackupRunsAsServiceUserWithTheNewBinary(t *testing.T) {
	h := newUHost(t)
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatal(err)
	}
	var backup *Command
	for i, c := range h.runs {
		if c.Args[0] == "backup" {
			backup = &h.runs[i]
		}
	}
	if backup == nil || backup.User != ServiceUser || backup.Name != applianceLayout().Binary+".new" {
		t.Fatalf("backup command = %+v", backup)
	}
	if got := strings.Join(backup.Args, " "); !strings.Contains(got, "--offline") || !strings.Contains(got, "--json") {
		t.Errorf("args = %s", got)
	}
}

func TestUpgrade_ThePreviousBinaryIsAHardLinkAndTheLiveOneIsNeverMissing(t *testing.T) {
	h := newUHost(t)
	l := applianceLayout()
	before := h.inodes[l.Binary]
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatal(err)
	}
	if h.inodes[l.Binary+".prev"] != before {
		t.Error("sm.prev is not the old inode (a copy, not a link)")
	}
	h.noViolations(t)
}

func TestUpgrade_ReplacesAnOlderPreviousAtomically(t *testing.T) {
	h := newUHost(t)
	l := applianceLayout()
	h.put(l.Binary+".prev", "sm;version=0.9.0;schema=2")
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatal(err)
	}
	if h.content(l.Binary+".prev") != binV1 {
		t.Errorf("prev = %q", h.content(l.Binary+".prev"))
	}
	if h.has("remove " + l.Binary + ".prev") {
		t.Errorf("sm.prev was removed before being replaced: %v", h.events)
	}
	h.noViolations(t)
}

func TestUpgrade_SameBuildDoesNothing(t *testing.T) {
	h := newUHost(t)
	h.put("/usr/local/src/sm-new", binV1)
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatal(err)
	}
	if h.index("stop ") != -1 || h.index("write ") != -1 {
		t.Errorf("an identical build touched the system: %v", h.events)
	}
}

func TestUpgrade_DowngradeIsRefusedUnlessAllowed(t *testing.T) {
	tests := []struct {
		name        string
		old, new    string
		allow       bool
		wantCode    int
		wantRecords bool
	}{
		{"lower version", binV2, binV1, false, ExitInvalid, false},
		{"lower version allowed", binV2, binV1, true, 0, true},
		{"unorderable versions", "sm;version=dev;schema=3", "sm;version=nightly;schema=3", false, ExitInvalid, false},
		{"unorderable but allowed", "sm;version=dev;schema=3", "sm;version=nightly;schema=3", true, 0, true},
		{"prerelease is lower than its release", "sm;version=1.1.0;schema=3", "sm;version=1.1.0-rc.1;schema=3", false, ExitInvalid, false},
		{"release is higher than its prerelease", "sm;version=1.1.0-rc.1;schema=3", "sm;version=1.1.0;schema=3", false, 0, false},
		{"v prefix", "sm;version=v1.2.0;schema=3", "sm;version=v1.10.0;schema=3", false, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newUHost(t)
			h.oldContent = tc.old
			h.put(applianceLayout().Binary, tc.old)
			h.put("/usr/local/src/sm-new", tc.new)
			o := h.upgradeOpts()
			o.AllowDowngrade = tc.allow
			err := New(h.deps()).upgrade(context.Background(), o, defaultHooks())
			if tc.wantCode != 0 {
				if exitCodeOf(t, err) != tc.wantCode {
					t.Fatalf("err = %v", err)
				}
				if h.live() != tc.old || h.index("stop ") != -1 || h.index("remove "+applianceLayout().Binary+".new") == -1 {
					t.Errorf("a refused downgrade left traces: live %q, events %v", h.live(), h.events)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st, _ := h.state(); st.AllowDowngrade != tc.wantRecords {
				t.Errorf("allow_downgrade recorded = %t, want %t", st.AllowDowngrade, tc.wantRecords)
			}
		})
	}
}

func TestUpgrade_BackupFailureRestartsTheOldService(t *testing.T) {
	cases := map[string]func(*uhost){
		"backup command fails":       func(h *uhost) { h.backupErr = errors.New("disk full") },
		"archive has another schema": func(h *uhost) { h.backupSchema = 2 },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newUHost(t)
			setup(h)
			err := h.upgrade(defaultHooks())
			if exitCodeOf(t, err) != ExitRestore {
				t.Fatalf("err = %v", err)
			}
			l := applianceLayout()
			if h.live() != binV1 || !h.running || h.startedAs != binV1 || h.dbSchema != 3 {
				t.Errorf("live %q running %t started as %q schema %d", h.live(), h.running, h.startedAs, h.dbSchema)
			}
			if h.Exists(l.Binary+".new") || func() bool { _, ok := h.state(); return ok }() {
				t.Error("the aborted upgrade left sm.new or its state behind")
			}
			if h.index("rename "+l.Binary+".new") != -1 {
				t.Error("the binary was replaced after a failed backup")
			}
			if !strings.Contains(err.Error(), "running again") {
				t.Errorf("message does not say the old version runs again: %v", err)
			}
			h.noViolations(t)
		})
	}
}

func TestUpgrade_ServiceThatWillNotStopRestartsTheOldOne(t *testing.T) {
	h := newUHost(t)
	h.stopErr = errors.New("systemctl stop failed")
	err := h.upgrade(defaultHooks())
	if exitCodeOf(t, err) != ExitRestore || h.live() != binV1 || h.index("run "+applianceLayout().Binary+".new backup") != -1 {
		t.Fatalf("err = %v, live %q", err, h.live())
	}
}

func TestUpgrade_DatabaseHeldBySomeoneElseStopsBeforeTheBackup(t *testing.T) {
	h := newUHost(t)
	h.lockHeld = true
	err := h.upgrade(defaultHooks())
	if exitCodeOf(t, err) != ExitRestore || !strings.Contains(err.Error(), "still in use") {
		t.Fatalf("err = %v", err)
	}
	if h.index("run "+applianceLayout().Binary+".new backup") != -1 || h.live() != binV1 {
		t.Error("the upgrade went on while the database was held")
	}
}

func TestUpgrade_HealthFailureWithUnchangedSchemaRestoresThePreviousBinary(t *testing.T) {
	h := newUHost(t)
	h.put("/usr/local/src/sm-new", binV2+";boot=fail")
	l := applianceLayout()
	err := h.upgrade(defaultHooks())
	if exitCodeOf(t, err) != ExitRestore {
		t.Fatalf("err = %v", err)
	}
	if h.live() != binV1 || !h.running || h.startedAs != binV1 || h.dbSchema != 3 {
		t.Errorf("live %q running %t started as %q schema %d", h.live(), h.running, h.startedAs, h.dbSchema)
	}
	if h.content(l.Binary+".prev") != binV1 {
		t.Error("sm.prev did not survive the revert")
	}
	if _, ok := h.state(); ok {
		t.Error("state left after a completed revert")
	}
	if !strings.Contains(err.Error(), "reverted") {
		t.Errorf("err = %v", err)
	}
	h.noViolations(t)
}

func TestUpgrade_HealthFailureAfterMigrationLeavesTheServiceStoppedAndPrintsTheRestore(t *testing.T) {
	h := newUHost(t)
	h.put("/usr/local/src/sm-new", binV2+";boot=fail-migrated")
	l := applianceLayout()
	err := h.upgrade(defaultHooks())
	if exitCodeOf(t, err) != ExitRestore {
		t.Fatalf("err = %v", err)
	}
	if h.running || h.live() != binV2+";boot=fail-migrated" {
		t.Errorf("running %t live %q: the binary must not be reverted automatically", h.running, h.live())
	}
	st, ok := h.state()
	if !ok || st.Phase != upFailed {
		t.Fatalf("state = %+v", st)
	}
	out := h.out.String()
	for _, want := range []string{st.Archive, l.Binary + ".prev", "backup restore --offline " + st.Archive, "STOPPED"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	startsBefore := h.count("start ")

	// A rerun repeats the instructions and starts nothing.
	h.out.Reset()
	if err := h.upgrade(defaultHooks()); exitCodeOf(t, err) != ExitRestore {
		t.Fatalf("rerun err = %v", err)
	}
	if h.count("start ") != startsBefore || !strings.Contains(h.out.String(), "backup restore --offline") {
		t.Error("the rerun started the service or lost the instructions")
	}
	h.noViolations(t)
}

func TestUpgrade_UnreadableSchemaCountsAsAdvanced(t *testing.T) {
	h := newUHost(t)
	h.put("/usr/local/src/sm-new", binV2+";boot=fail;doctor=broken")
	err := h.upgrade(defaultHooks())
	if exitCodeOf(t, err) != ExitRestore {
		t.Fatalf("err = %v", err)
	}
	if h.running {
		t.Error("the service was started although the schema could not be read")
	}
}

func TestUpgrade_NotEnoughDiskIsRefusedBeforeAnyChange(t *testing.T) {
	h := newUHost(t)
	h.freeBytes = 1 << 20
	err := h.upgrade(defaultHooks())
	if exitCodeOf(t, err) != ExitPrerequisite || h.index("stop ") != -1 || h.Exists(applianceLayout().Binary+".new") {
		t.Fatalf("err = %v, events %v", err, h.events)
	}
}

func TestUpgrade_HostThatCannotReportDiskIsRefused(t *testing.T) {
	h := newUHost(t)
	h.noDisk = true
	if err := h.upgrade(defaultHooks()); exitCodeOf(t, err) != ExitPrerequisite {
		t.Fatalf("err = %v", err)
	}
}

func TestUpgrade_NothingInstalled(t *testing.T) {
	h := newUHost(t)
	_ = h.RemoveAll(applianceLayout().Binary)
	_ = h.RemoveAll(applianceLayout().UnitPath)
	h.uid, h.home = 1000, "/home/alex"
	if err := h.upgrade(defaultHooks()); exitCodeOf(t, err) != ExitPrerequisite {
		t.Fatalf("err = %v", err)
	}
}

func TestUpgrade_ServerNeedsRoot(t *testing.T) {
	h := newUHost(t)
	h.uid = 1000
	if err := h.upgrade(defaultHooks()); exitCodeOf(t, err) != ExitPrerequisite {
		t.Fatalf("err = %v", err)
	}
}

func TestUpgrade_LocalInstallReplacesTheBinaryWithoutAService(t *testing.T) {
	h := newUHost(t)
	h.uid, h.home = 1000, "/home/alex"
	ul := Options{}.userLayout(h.deps().Host)
	h.dirs[ul.BinDir], h.dirs[ul.DataDir], h.dirs[ul.ConfigDir] = true, true, true
	h.put(ul.Binary, binV1)
	_ = h.RemoveAll(applianceLayout().Binary)
	_ = h.RemoveAll(applianceLayout().UnitPath)
	h.violations = nil
	h.oldContent = binV1
	err := New(h.deps()).upgrade(context.Background(), h.upgradeOpts(), defaultHooks())
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.content(ul.Binary) != binV2 || h.content(ul.Binary+".prev") != binV1 {
		t.Errorf("live %q prev %q", h.content(ul.Binary), h.content(ul.Binary+".prev"))
	}
	if h.index("stop ") != -1 || h.index("start ") != -1 {
		t.Errorf("a local install without a resident daemon touched a service: %v", h.events)
	}
}

func TestUpgrade_ServerUsesTheReadinessEndpointOfItsConfiguration(t *testing.T) {
	h := newUHost(t)
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatal(err)
	}
	if len(h.probes) != 1 || h.probes[0].URL != "http://127.0.0.1:8787/health/ready" {
		t.Errorf("probes = %+v", h.probes)
	}
}

func TestUpgrade_AnotherInstallerRunningIsRefused(t *testing.T) {
	h := newUHost(t)
	d := h.deps()
	d.Files = lockedFiles{d.Files}
	err := New(d).upgrade(context.Background(), h.upgradeOpts(), defaultHooks())
	if exitCodeOf(t, err) != ExitPrerequisite {
		t.Fatalf("err = %v", err)
	}
}

type lockedFiles struct{ Files }

func (lockedFiles) Lock(string) (func(), error) { return nil, errors.New("locked") }

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.2.3", "1.2.3", 0, true},
		{"v1.2.3", "1.2.4", -1, true},
		{"1.10.0", "1.9.0", 1, true},
		{"1.2.3-rc.1", "1.2.3", -1, true},
		{"1.2.3-rc.2", "1.2.3-rc.10", -1, true},
		{"1.2.3-alpha", "1.2.3-1", 1, true},
		{"1.2.3+build5", "1.2.3", 0, true},
		{"dev", "1.2.3", 0, false},
		{"1.2", "1.2.3", 0, false},
		{"1.2.3-", "1.2.3", 0, false},
	}
	for _, tc := range tests {
		got, ok := compareVersions(tc.a, tc.b)
		if ok != tc.ok || (ok && sign(got) != tc.want) {
			t.Errorf("compare(%q, %q) = %d, %t; want %d, %t", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
