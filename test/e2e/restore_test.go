//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

const keyPassphrase = "correct horse battery staple"

// TestM2_BackupRestoreFreshHost
//
// Criterion S3 (docs/specs/m2-server-auth-release.md, "backup y restore"; PLAN §9 row 7): a backup
// of server A, restored with `sm install restore` on a fresh host B together with the exported
// master key, gives a consistent state that starts in restore hold; credentials of A are dead,
// work awaiting approval is neutralized, writes are refused, and `sm admin restore-complete`
// lifts the hold so jobs run again.
//
// "Crash injected at every journal step" is not repeated here: it is
// TestRestoreCrashAtEveryJournalStep and the TestRestorePhaseA_* family in internal/backup
// (go test -tags crashpoints ./internal/backup/..., part of `make test`).
func TestM2_BackupRestoreFreshHost(t *testing.T) {
	ctx := context.Background()
	net := harness.NewNetwork(t)
	ca := harness.NewCA(t)

	// ---- server A, with some history ----
	a := harness.StartServer(t, net, ca, harness.ServerOptions{Mode: harness.Direct})
	a.AllowSelfApproval(ctx)
	adminA := harness.NewClient(t)
	adminA.AddProfile(ctx, "ops", a.URL, a.CAFile)
	tokenA := a.BootstrapAdmin(ctx, adminA, "admin of A")
	apiA := a.Typed(tokenA)

	issued, err := apiA.CreateToken(ctx, wire.CreateTokenRequest{Name: "automation", ExpiresAt: harness.Now().Add(30 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("create the token that must not survive the restore: %v", err)
	}
	var stored wire.Direct[wire.SecretVersion]
	adminA.JSON(ctx, "a secret worth keeping\n", &stored, "secrets", "import", "--name", "app/credential")
	approved := stored.Pending.Job.ID
	harness.ApproveJob(ctx, t, apiA, approved)
	harness.WaitJob(ctx, t, apiA, approved, domain.JobSucceeded)
	var parked wire.Direct[wire.SecretVersion]
	adminA.JSON(ctx, "never approved\n", &parked, "secrets", "import", "--name", "app/parked")
	parkedJob := parked.Pending.Job.ID
	sshA, err := apiA.SSHKey(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var backup wire.Submission
	adminA.JSON(ctx, "", &backup, "backup", "create")
	harness.WaitJob(ctx, t, apiA, jobOf(t, backup), domain.JobSucceeded)
	var listed wire.Page[wire.Backup]
	adminA.JSON(ctx, "", &listed, "backup", "list")
	if len(listed.Items) == 0 || len(listed.Items[0].KEKIDs) == 0 {
		t.Fatalf("the backup does not say which master key it needs: %+v", listed)
	}
	archive := listed.Items[0]
	var keys wire.Page[wire.MasterKey]
	adminA.JSON(ctx, "", &keys, "secrets", "keys")
	var kek domain.ID
	for _, k := range keys.Items {
		if k.Active {
			kek = k.ID
		}
	}
	if kek == "" || kek != archive.KEKIDs[0] {
		t.Fatalf("the active master key %q is not the one the backup needs (%v)", kek, archive.KEKIDs)
	}

	// ---- carry the archive and the exported key to the new host ----
	scratch := t.TempDir()
	archivePath := filepath.Join(scratch, archive.Name)
	harness.MustDocker(t, "cp", a.C.Name+":"+harness.ServerData+"/backups/"+archive.Name, archivePath)

	// Criterion "no secret leaks" (PLAN §9): neither the database, its log, the journal nor the
	// archive of a server that handled these secrets holds one in plaintext.
	evidence := a.Evidence(ctx)
	members, content := a.C.ArchiveEvidence(ctx, harness.ServerData+"/backups/"+archive.Name)
	evidence["archive content"] = content
	if strings.Contains(members, ".key") {
		t.Errorf("the archive carries a master key file:\n%s", members)
	}
	harness.AssertNoPlaintext(t, evidence, map[string]string{
		"the imported secret": "a secret worth keeping", "the parked secret": "never approved",
		"the admin API token": tokenA, "an issued API token": issued.Value, "the key passphrase": keyPassphrase,
	})
	a.C.MustExec(ctx, "systemctl", "stop", "supermgmt")
	export := a.C.Exec(ctx, keyPassphrase+"\n", "runuser", "-u", "supermgmt", "--", harness.ServerBinary, "secrets", "export-key",
		string(kek), "--offline", "--out", harness.ServerData+"/kek.export", "--config", harness.ServerConfig)
	if export.Code != 0 {
		t.Fatalf("export-key --offline exited %d\n%s", export.Code, export.Output())
	}
	exportPath := filepath.Join(scratch, "kek.export")
	harness.MustDocker(t, "cp", a.C.Name+":"+harness.ServerData+"/kek.export", exportPath)

	// ---- server B: a fresh host, restored before its first start ----
	b := harness.NewServerHost(t, net, ca, harness.ServerOptions{Mode: harness.Direct})
	b.C.InstallSM(ctx, t, "/root/sm")
	// The offline steps run as the service user, so the files cannot stay under /root.
	b.C.MustExec(ctx, "mkdir", "-p", "/srv/restore")
	b.C.CopyRoot(ctx, archivePath, "/srv/restore/"+archive.Name)
	b.C.CopyRoot(ctx, exportPath, "/srv/restore/kek.export")
	b.C.MustExec(ctx, "chmod", "-R", "a+rX", "/srv/restore")
	restored := b.C.Env(ctx, keyPassphrase+"\n", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, "/root/sm", "install", "restore",
		"--archive", "/srv/restore/"+archive.Name, "--key-export", "/srv/restore/kek.export",
		"--tls", "direct", "--tls-cert", "/opt/tls/server.crt", "--tls-key", "/opt/tls/server.key",
		"--public-url", b.URL, "--listen", "0.0.0.0:8443", "--yes")
	if restored.Code != 0 {
		t.Fatalf("sm install restore exited %d\n%s", restored.Code, restored.Output())
	}
	b.WaitReady(ctx)

	t.Run("the service starts in restore hold", func(t *testing.T) {
		out := b.Sm(ctx, "", "--json", "doctor", "--config", harness.ServerConfig)
		if out.Code != 0 {
			t.Fatalf("sm doctor exited %d\n%s", out.Code, out.Output())
		}
		var report struct {
			Checks []struct{ Name, Status string } `json:"checks"`
		}
		if err := json.Unmarshal([]byte(out.Stdout), &report); err != nil {
			t.Fatalf("decode doctor output: %v\n%s", err, out.Stdout)
		}
		held := false
		for _, c := range report.Checks {
			held = held || (c.Name == "restore_hold" && c.Status == "warn")
		}
		if !held {
			t.Fatalf("the restored server is not in restore hold:\n%s", out.Stdout)
		}
	})

	t.Run("credentials of the old server do not work", func(t *testing.T) {
		for name, token := range map[string]string{"the admin session": tokenA, "an API token": issued.Value} {
			if _, err := b.Typed(token).Me(ctx); err == nil {
				t.Errorf("%s of A is still accepted on B", name)
			}
		}
	})

	adminB := harness.NewClient(t)
	adminB.AddProfile(ctx, "ops", b.URL, b.CAFile)
	tokenB := b.BootstrapAdmin(ctx, adminB, "admin of B") // accepted during hold although an admin exists
	apiB := b.Typed(tokenB)

	t.Run("state is consistent: the instance identity and the secrets came across", func(t *testing.T) {
		sshB, err := apiB.SSHKey(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sshB.FingerprintSHA256 != sshA.FingerprintSHA256 {
			t.Fatalf("instance SSH key differs after restore: %s != %s", sshB.FingerprintSHA256, sshA.FingerprintSHA256)
		}
	})

	t.Run("work that was waiting for approval does not run", func(t *testing.T) {
		job, err := apiB.GetJob(ctx, parkedJob)
		if err != nil {
			t.Fatal(err)
		}
		if job.Job.State != domain.JobFailed {
			t.Fatalf("job %s that awaited approval on A is %s on B, want failed", parkedJob, job.Job.State)
		}
	})

	t.Run("writes are refused during the hold", func(t *testing.T) {
		res := adminB.Run(ctx, "", "backup", "create")
		if res.Code == 0 || !strings.Contains(res.Output(), "restore hold") {
			t.Fatalf("backup create during the hold: exit %d, want a restore-hold refusal\n%s", res.Code, res.Output())
		}
	})

	t.Run("restore-complete lifts the hold and jobs run again", func(t *testing.T) {
		if done := b.Sm(ctx, "", "admin", "restore-complete", "--config", harness.ServerConfig); done.Code != 0 {
			t.Fatalf("restore-complete exited %d\n%s", done.Code, done.Output())
		}
		var submitted wire.Submission
		adminB.JSON(ctx, "", &submitted, "backup", "create")
		harness.WaitJob(ctx, t, apiB, jobOf(t, submitted), domain.JobSucceeded)
	})
}
