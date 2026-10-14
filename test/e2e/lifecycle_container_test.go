//go:build e2e

package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Spec docs/specs/m6-hardening.md (clean-machine lifecycle, server mode), ADR-0035 (hold) and
// PLAN T20: the Debian 13 server lifecycle, container-verified (a systemd container, not a VM),
// on whichever architecture Docker runs. One host walks through every operation in order; each
// step asserts the doctor report and that the data made before it survived.

// lifecycleDoctorFailures lists the doctor checks of the installed server that report "fail".
func lifecycleDoctorFailures(t *testing.T, h *upgradeHost) []string {
	t.Helper()
	res := h.srv.C.Exec(h.ctx(), "", harness.ServerBinary, "--json", "doctor", "--config", harness.ServerConfig)
	var report struct {
		Checks []struct{ Name, Status string } `json:"checks"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &report); err != nil {
		t.Fatalf("sm doctor gave no JSON report (exit %d): %v\n%s", res.Code, err, res.Output())
	}
	var failed []string
	for _, c := range report.Checks {
		if c.Status == "fail" {
			failed = append(failed, c.Name)
		}
	}
	return failed
}

func lifecycleAssertHealthy(t *testing.T, h *upgradeHost) {
	t.Helper()
	h.srv.WaitReady(h.ctx())
	if failed := lifecycleDoctorFailures(t, h); len(failed) > 0 {
		t.Errorf("doctor reports failing checks: %v", failed)
	}
}

// TestM6_LifecycleServerContainer
//
// Given a clean Debian systemd host with the previous release installed and data in it.
// Then: upgrade, backup, restore, uninstall and purge each leave the host in the state their
// contract names, and a manual start is refused while the upgrade is unfinished.
func TestM6_LifecycleServerContainer(t *testing.T) {
	h := newPreviousServer(t)
	h.stageNext()
	h.setFault("backup:hold")
	h.setHold(true)

	t.Run("the previous release is installed, healthy and holds the seeded data", func(t *testing.T) {
		lifecycleAssertHealthy(t, h)
		h.assertDataIntact(t)
	})

	t.Run("upgrade: a manual start is refused mid-upgrade, then the new release runs with the data", func(t *testing.T) {
		done := h.startUpgrade(wrapperBinary)
		h.waitFor("the pre-upgrade backup to start", time.Minute, func() bool { return h.fileExists(faultDir + "/at-backup") })
		h.assertHeld()
		h.setHold(false)

		var res harness.Result
		select {
		case res = <-done:
		case <-time.After(3 * time.Minute):
			t.Fatal("the upgrade did not finish after the hold was released")
		}
		if res.Code != 0 {
			t.Fatalf("sm install upgrade exited %d\n%s", res.Code, res.Output())
		}
		h.setFault("")
		lifecycleAssertHealthy(t, h)
		if got := h.installedVersion(h.ctx()); got != nextVersion {
			t.Errorf("installed version %q, want %s", got, nextVersion)
		}
		if got := h.schema(harness.ServerBinary); got != latestSchema(t) {
			t.Errorf("schema %d after the upgrade, want %d", got, latestSchema(t))
		}
		h.assertDataIntact(t)
	})

	api := h.srv.Typed(h.token)
	var archive wire.Backup
	t.Run("backup: a backup job succeeds and the archive lands in the data directory", func(t *testing.T) {
		var submitted wire.Submission
		h.admin.JSON(h.ctx(), "", &submitted, "backup", "create")
		harness.WaitJob(h.ctx(), t, api, jobOf(t, submitted), domain.JobSucceeded)
		var listed wire.Page[wire.Backup]
		h.admin.JSON(h.ctx(), "", &listed, "backup", "list")
		if len(listed.Items) == 0 {
			t.Fatal("backup list is empty after a succeeded backup job")
		}
		archive = listed.Items[0]
		if !h.fileExists(harness.ServerData + "/backups/" + archive.Name) {
			t.Fatalf("archive %s is not in %s/backups", archive.Name, harness.ServerData)
		}
	})

	t.Run("restore: state made after the backup is gone, the service is healthy again", func(t *testing.T) {
		if archive.Name == "" {
			t.Skip("no archive from the backup step")
		}
		issued, err := api.CreateToken(h.ctx(), wire.CreateTokenRequest{Name: "after-backup", ExpiresAt: harness.Now().Add(24 * time.Hour)})
		if err != nil {
			t.Fatalf("create the token that must not survive the restore: %v", err)
		}
		c := h.srv.C
		c.MustExec(h.ctx(), "systemctl", "stop", "supermgmt")
		restored := c.Exec(h.ctx(), "", "runuser", "-u", "supermgmt", "--", harness.ServerBinary, "backup", "restore", "--offline",
			harness.ServerData+"/backups/"+archive.Name, "--config", harness.ServerConfig)
		if restored.Code != 0 {
			t.Fatalf("sm backup restore --offline exited %d\n%s", restored.Code, restored.Output())
		}
		c.MustExec(h.ctx(), "systemctl", "start", "supermgmt")
		lifecycleAssertHealthy(t, h)
		if _, err := h.srv.Typed(issued.Value).Me(h.ctx()); err == nil {
			t.Error("a token created after the backup is still accepted after the restore")
		}
		if got := h.schema(harness.ServerBinary); got != latestSchema(t) {
			t.Errorf("schema %d after the restore, want %d", got, latestSchema(t))
		}
	})

	t.Run("uninstall: the software and the unit go, configuration, database and backups stay", func(t *testing.T) {
		res := h.srv.C.Env(h.ctx(), "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, nextBinary, "install", "uninstall", "--yes")
		if res.Code != 0 {
			t.Fatalf("sm install uninstall exited %d\n%s", res.Code, res.Output())
		}
		for _, path := range []string{harness.ServerBinary, unitFile} {
			if h.fileExists(path) {
				t.Errorf("%s is still there after the uninstall", path)
			}
		}
		if h.serviceActive() {
			t.Error("the service still runs after the uninstall")
		}
		for _, path := range []string{harness.ServerConfig, harness.ServerData + "/supermgmt.db", harness.ServerData + "/backups/" + archive.Name} {
			if !h.fileExists(path) {
				t.Errorf("%s was removed by an uninstall that did not ask to purge data", path)
			}
		}
		if !strings.Contains(res.Output(), "--purge-data") {
			t.Errorf("the uninstall does not tell how to delete the data:\n%s", res.Output())
		}
	})

	t.Run("purge: --purge-data removes the data and the configuration that were kept", func(t *testing.T) {
		res := h.srv.C.Env(h.ctx(), "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, nextBinary, "install", "uninstall", "--purge-data", "--yes")
		if res.Code != 0 {
			t.Fatalf("sm install uninstall --purge-data exited %d\n%s", res.Code, res.Output())
		}
		for _, path := range []string{harness.ServerData, "/etc/supermgmt"} {
			if h.fileExists(path) {
				t.Errorf("%s survived --purge-data", path)
			}
		}
	})
}
