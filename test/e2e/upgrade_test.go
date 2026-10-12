//go:build e2e

package e2e_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Spec docs/specs/m3-proxmox-installer.md (upgrade) and ADR-0027, PLAN §9 row "Upgrade N-1 -> N".
// N-1 is the M2 merge commit built as v0.2.0 (schema 3); N is the tree under test built as v0.3.0
// (schema 4). The failure boundaries use a stand-in for the new release (faultWrapper) that is the
// real build except where a test injects a fault.

const (
	exitInvalid = 2
	exitRestore = 9
)

// TestM3_UpgradeNMinus1ToN
//
// Then: the service runs the new version and the schema moved 3 -> 4, the data made before is
// intact, the automatic pre-upgrade archive has schema 3 and restores with the previous release,
// the previous binary is kept, and rerunning or downgrading changes nothing.
func TestM3_UpgradeNMinus1ToN(t *testing.T) {
	h := newPreviousServer(t)
	h.stageNext()
	if got := h.schema(prevBinary); got != 3 {
		t.Fatalf("%s starts at schema %d, want 3", prevVersion, got)
	}
	prevSHA := h.sha(prevBinary)

	res := h.upgrade(nextBinary)
	if res.Code != 0 {
		t.Fatalf("sm install upgrade exited %d\n%s", res.Code, res.Output())
	}
	archive, archiveSchema := preUpgradeArchive(t, res.Output())
	h.srv.WaitReady(h.ctx())

	t.Run("the service runs the new version on schema 4", func(t *testing.T) {
		if got := h.installedVersion(h.ctx()); got != nextVersion {
			t.Errorf("installed version %q, want %s", got, nextVersion)
		}
		if got := h.schema(harness.ServerBinary); got != 4 {
			t.Errorf("schema %d after the upgrade, want 4", got)
		}
	})

	t.Run("data made before the upgrade is intact", h.assertDataIntact)

	t.Run("the previous binary is kept next to the new one", func(t *testing.T) {
		if got := h.sha(harness.ServerBinary + ".prev"); got != prevSHA {
			t.Errorf("sm.prev does not hold the previous release (%s != %s)", got, prevSHA)
		}
	})

	t.Run("the pre-upgrade archive has schema 3 and restores with the previous release", func(t *testing.T) {
		if archiveSchema != 3 {
			t.Fatalf("the installer reports the archive at schema %d, want 3", archiveSchema)
		}
		c := h.srv.C
		c.MustExec(h.ctx(), "systemctl", "stop", "supermgmt")
		restored := c.Exec(h.ctx(), "", "runuser", "-u", "supermgmt", "--", prevBinary, "backup", "restore", "--offline", archive,
			"--config", harness.ServerConfig)
		if restored.Code != 0 {
			t.Fatalf("%s backup restore exited %d\n%s", prevVersion, restored.Code, restored.Output())
		}
		if got := h.schema(prevBinary); got != 3 {
			t.Errorf("restored database is at schema %d, want 3", got)
		}
	})
}

// TestM3_UpgradeIsIdempotentAndRefusesDowngrade
//
// Then: upgrading to the build that already runs does nothing, and a lower version is refused
// (exit 2) unless --allow-downgrade is given; the refusal leaves the service running.
func TestM3_UpgradeIsIdempotentAndRefusesDowngrade(t *testing.T) {
	h := newPreviousServer(t)
	h.stageNext()
	if res := h.upgrade(nextBinary); res.Code != 0 {
		t.Fatalf("upgrade exited %d\n%s", res.Code, res.Output())
	}
	h.srv.WaitReady(h.ctx())

	again := h.upgrade(nextBinary)
	if again.Code != 0 || !strings.Contains(again.Output(), "already is this build") {
		t.Errorf("rerunning the same upgrade: exit %d, want 0 and 'already is this build'\n%s", again.Code, again.Output())
	}

	down := h.srv.C.Env(h.ctx(), "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, nextBinary, "install", "upgrade", "--binary", prevBinary, "--yes")
	if down.Code != exitInvalid || !strings.Contains(down.Output(), "refusing to downgrade") {
		t.Errorf("downgrade: exit %d, want %d and a refusal\n%s", down.Code, exitInvalid, down.Output())
	}
	if !h.serviceActive() || h.installedVersion(h.ctx()) != nextVersion {
		t.Errorf("the refused downgrade changed the running service")
	}
	h.assertDataIntact(t)
}

// TestM3_UpgradeFailedBackupKeepsOldServiceRunning
//
// Given the pre-upgrade backup fails. Then: nothing was replaced, the previous version runs again
// with its data and its schema, and no unfinished-upgrade state is left.
func TestM3_UpgradeFailedBackupKeepsOldServiceRunning(t *testing.T) {
	h := newPreviousServer(t)
	h.stageNext()
	h.setFault("backup:fail")
	prevSHA := h.sha(harness.ServerBinary)

	res := h.upgrade(wrapperBinary)
	if res.Code != exitRestore || !strings.Contains(res.Output(), "upgrade aborted before the binary was replaced") {
		t.Fatalf("upgrade with a failing backup: exit %d, want %d and an abort message\n%s", res.Code, exitRestore, res.Output())
	}
	h.srv.WaitReady(h.ctx())
	if got := h.sha(harness.ServerBinary); got != prevSHA {
		t.Errorf("the installed binary changed although the backup failed")
	}
	if got := h.installedVersion(h.ctx()); got != prevVersion {
		t.Errorf("installed version %q, want %s", got, prevVersion)
	}
	if got := h.schema(harness.ServerBinary); got != 3 {
		t.Errorf("schema %d, want 3", got)
	}
	if h.fileExists(harness.ServerData + "/upgrade.json") {
		t.Error("upgrade.json is left behind after a clean abort")
	}
	if h.fileExists(harness.ServerBinary + ".new") {
		t.Error("the staged binary is left behind after a clean abort")
	}
	h.assertDataIntact(t)
}

// TestM3_UpgradeFailedHealthWithSchemaUnchangedRestoresOldBinary
//
// Given the new service never becomes ready and never touched the schema. Then: the previous
// binary is put back automatically and runs, exit 9.
func TestM3_UpgradeFailedHealthWithSchemaUnchangedRestoresOldBinary(t *testing.T) {
	h := newPreviousServer(t)
	h.stageNext()
	h.setFault("server:never-ready")
	prevSHA := h.sha(harness.ServerBinary)

	res := h.upgrade(wrapperBinary)
	if res.Code != exitRestore || !strings.Contains(res.Output(), "was reverted") {
		t.Fatalf("upgrade whose service never starts: exit %d, want %d and 'reverted'\n%s", res.Code, exitRestore, res.Output())
	}
	h.srv.WaitReady(h.ctx())
	if got := h.sha(harness.ServerBinary); got != prevSHA {
		t.Errorf("the previous binary was not put back")
	}
	if got := h.schema(harness.ServerBinary); got != 3 {
		t.Errorf("schema %d, want 3", got)
	}
	h.assertDataIntact(t)
}

var printedStep = regexp.MustCompile(`(?m)^  (\d)\. (.+)$`)

// TestM3_UpgradeFailedMigrationStaysStoppedWithInstructions
//
// Given the new service migrated the schema and then fails its health check. Then: the service is
// left stopped, the installer exits 9 and prints the restore commands, and running them exactly as
// printed brings the previous release back on schema 3 with the data.
func TestM3_UpgradeFailedMigrationStaysStoppedWithInstructions(t *testing.T) {
	h := newPreviousServer(t)
	h.stageNext()
	h.setFault("server:migrate-then-unreachable")

	res := h.upgrade(wrapperBinary)
	if res.Code != exitRestore || !strings.Contains(res.Output(), "left STOPPED") {
		t.Fatalf("upgrade with a failed health check after the migration: exit %d, want %d and 'left STOPPED'\n%s", res.Code, exitRestore, res.Output())
	}
	if h.serviceActive() {
		t.Error("the service runs although the schema advanced and nothing was restored")
	}
	if got := h.schema(harness.ServerBinary); got != 4 {
		t.Errorf("schema %d, want 4 (the migration ran)", got)
	}

	steps := printedStep.FindAllStringSubmatch(res.Output(), -1)
	if len(steps) != 3 {
		t.Fatalf("expected 3 printed restore steps, found %d\n%s", len(steps), res.Output())
	}
	for _, step := range steps {
		if out := h.srv.C.Exec(h.ctx(), "", "sh", "-c", step[2]); out.Code != 0 {
			t.Fatalf("printed step %s (%s) exited %d\n%s", step[1], step[2], out.Code, out.Output())
		}
	}
	h.srv.WaitReady(h.ctx())
	if got := h.installedVersion(h.ctx()); got != prevVersion {
		t.Errorf("installed version %q after the printed commands, want %s", got, prevVersion)
	}
	if got := h.schema(harness.ServerBinary); got != 3 {
		t.Errorf("schema %d after the printed commands, want 3", got)
	}
	if h.fileExists(harness.ServerData + "/upgrade.json") {
		t.Error("upgrade.json is left after the printed commands")
	}
}

// TestM3_UpgradeKilledAtEachPhase
//
// Given the installer is killed (SIGKILL) at a phase. Then: rerunning the upgrade converges to the
// new version with data intact and no unfinished state.
func TestM3_UpgradeKilledAtEachPhase(t *testing.T) {
	converged := func(t *testing.T, h *upgradeHost) {
		t.Helper()
		res := h.upgrade(wrapperBinary)
		if res.Code != 0 {
			t.Fatalf("rerun after the kill exited %d\n%s", res.Code, res.Output())
		}
		h.srv.WaitReady(h.ctx())
		if got := h.installedVersion(h.ctx()); got != nextVersion {
			t.Errorf("installed version %q after the rerun, want %s", got, nextVersion)
		}
		if got := h.schema(harness.ServerBinary); got != 4 {
			t.Errorf("schema %d after the rerun, want 4", got)
		}
		if phase := h.upgradePhase(); phase != "done" && phase != "" {
			t.Errorf("upgrade state %q after the rerun, want done", phase)
		}
		h.assertDataIntact(t)
	}

	t.Run("while the pre-upgrade backup runs (service stopped)", func(t *testing.T) {
		h := newPreviousServer(t)
		h.stageNext()
		h.setFault("backup:hold")
		h.setHold(true)
		done := h.startUpgrade(wrapperBinary)
		h.waitFor("the backup to start", time.Minute, func() bool { return h.fileExists(faultDir + "/at-backup") })
		if phase := h.upgradePhase(); phase != "stopped" {
			t.Fatalf("killed in phase %q, want stopped", phase)
		}
		h.killInstaller(done)
		if h.serviceActive() {
			t.Fatal("the service runs in the middle of the backup")
		}
		h.setFault("")
		h.setHold(false)
		converged(t, h)
	})

	t.Run("while the new service starts (binary replaced)", func(t *testing.T) {
		h := newPreviousServer(t)
		h.stageNext()
		h.setFault("server:hang")
		done := h.startUpgrade(wrapperBinary)
		h.waitFor("the new service to start", time.Minute, func() bool {
			return h.fileExists(serverMarker) && h.upgradePhase() == "started"
		})
		h.killInstaller(done)
		h.setFault("")
		h.srv.C.MustExec(h.ctx(), "systemctl", "restart", "supermgmt")
		converged(t, h)
	})
}
