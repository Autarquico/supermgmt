//go:build e2e

package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Spec docs/specs/m6-hardening.md, ADR-0035 "Crash hook" and "Recovery per point" (frozen table).
//
// The installer under test is a real process built with -tags crashpoints. SUPERMGMT_CRASH_AT=<point>
// makes it exit with code 86 at that point, which is the closest a test gets to a power cut that is
// still deterministic. Each test then reruns `sm install upgrade` and checks the outcome the ADR
// promises for that point. The service binary is the fault wrapper of the M3 upgrade tests.

const (
	crashPointEnv = "SUPERMGMT_CRASH_AT"
	crashExitCode = 86
	crashNextKey  = "next-crashpoints"
	crashDownKey  = "next-lower-version"
	crashDownVer  = "v0.2.9"
	crashDownBin  = "/opt/sm-down"
	// crashRerunDelay is the operator noticing the crash: archive names have second resolution.
	crashRerunDelay = 2 * time.Second
	crashPortProbe  = "exec 3<>/dev/tcp/127.0.0.1/9999"
)

// crashBuild is the tree under test built as version, with the given build tags, for the containers.
func crashBuild(t testing.TB, key, version, tags string) string {
	t.Helper()
	arch := harness.DockerArch(t)
	path, err := m3Once(key, func() (string, error) {
		out := filepath.Join(harness.WorkDir(), "sm-"+key+"-"+arch)
		env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
		args := []string{"build", "-trimpath", "-ldflags", "-X " + versionPackage + ".Version=" + version}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		res, err := harness.Run(context.Background(), harness.RepoRoot(), env, "", "go", append(args, "-o", out, "./cmd/sm")...)
		if e := commandFailure("go build "+out, res, err); e != nil {
			return "", e
		}
		return out, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// newCrashHost is the previous release running as a server, with the crashpoints build of the new
// release at nextBinary (it runs the installer) and the fault wrapper at wrapperBinary (it is what
// gets installed).
func newCrashHost(t *testing.T) *upgradeHost {
	t.Helper()
	h := newPreviousServer(t)
	c := h.srv.C
	c.CopyRoot(h.ctx(), crashBuild(t, crashNextKey, nextVersion, "crashpoints"), nextBinary)
	c.MustExec(h.ctx(), "chmod", "0755", nextBinary)
	c.MustExec(h.ctx(), "install", "-d", "-m", "0777", faultDir)
	c.WriteFile(h.ctx(), wrapperBinary, []byte(faultWrapper), "0755")
	h.setFault("")
	return h
}

// crashAt runs the upgrade with extra arguments until the hook ends the installer at point.
func (h *upgradeHost) crashAt(point, binary string, extra ...string) harness.Result {
	h.t.Helper()
	env := map[string]string{"SUPERMGMT_NONINTERACTIVE": "1", crashPointEnv: point}
	res := h.srv.C.Env(h.ctx(), "", env, append(upgradeArgs(binary), extra...)...)
	if res.Code != crashExitCode {
		h.t.Fatalf("crash at %s: the installer exited %d, want %d (is the point reached?)\n%s", point, res.Code, crashExitCode, res.Output())
	}
	time.Sleep(crashRerunDelay)
	return res
}

func (h *upgradeHost) upgradeWith(binary string, extra ...string) harness.Result {
	h.t.Helper()
	return h.srv.C.Env(h.ctx(), "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, append(upgradeArgs(binary), extra...)...)
}

// assertLiveSM fails when the installed sm is missing or is neither of the two releases.
func (h *upgradeHost) assertLiveSM() {
	h.t.Helper()
	if got := h.installedVersion(h.ctx()); got != prevVersion && got != nextVersion {
		h.t.Fatalf("the installed sm reports %q, want %s or %s", got, prevVersion, nextVersion)
	}
}

// assertConvergedToNext is the end state of every forward-resume row.
func (h *upgradeHost) assertConvergedToNext(t *testing.T) {
	t.Helper()
	h.srv.WaitReady(h.ctx())
	if got := h.installedVersion(h.ctx()); got != nextVersion {
		t.Errorf("installed version %q after the rerun, want %s", got, nextVersion)
	}
	if got := h.schema(harness.ServerBinary); got != latestSchema(t) {
		t.Errorf("schema %d after the rerun, want %d", got, latestSchema(t))
	}
	if phase := h.upgradePhase(); phase != "done" && phase != "" {
		t.Errorf("upgrade state %q after the rerun, want done", phase)
	}
	if !h.serviceActive() {
		t.Error("the service is not running after the rerun")
	}
	h.assertDataIntact(t)
}

// assertRestoredPrevious is the end state of every automatic-revert row.
func (h *upgradeHost) assertRestoredPrevious(t *testing.T, prevSHA string) {
	t.Helper()
	h.srv.WaitReady(h.ctx())
	if got := h.sha(harness.ServerBinary); got != prevSHA {
		t.Error("the previous binary was not put back")
	}
	if got := h.schema(harness.ServerBinary); got != 3 {
		t.Errorf("schema %d, want 3", got)
	}
	if h.fileExists(harness.ServerData + "/upgrade.json") {
		t.Error("upgrade.json is left behind after the revert")
	}
	h.assertDataIntact(t)
}

// waitMigratedServer waits until the wrapper's migrating server accepts connections: the schema has advanced.
func (h *upgradeHost) waitMigratedServer() {
	h.t.Helper()
	h.waitFor("the migrated server to listen", time.Minute, func() bool {
		return h.srv.C.Exec(h.ctx(), "", "bash", "-c", crashPortProbe).Code == 0
	})
}

// assertHeld fails when the service can be started by hand while the upgrade is unfinished.
func (h *upgradeHost) assertHeld() {
	h.t.Helper()
	if h.srv.C.Exec(h.ctx(), "", "systemctl", "start", "supermgmt").Code == 0 {
		h.t.Error("a manual start succeeded in the middle of the upgrade: the hold is not in place")
	}
	if h.serviceActive() {
		h.t.Error("the service runs in the middle of the upgrade")
	}
}

// ---- crash before the new binary is started: forward resume ----

// TestM6_CrashUpgrade_ResumesForwardFromEveryPoint
//
// Given the installer is ended at a point between staging and the done record, the schema unchanged.
// Then: `sm` is never missing, rerunning the upgrade converges to the new version with the data intact.
func TestM6_CrashUpgrade_ResumesForwardFromEveryPoint(t *testing.T) {
	heldFrom, heldTo := "U:stopped:applied", "U:swapped:recorded"
	points := []string{
		"U:staged", "U:prev-linked", "U:prepared:recorded",
		"U:hold:applied", "U:stopped:applied", "U:stopped:recorded", "U:backed_up:applied", "U:backed_up:recorded",
		"U:swap:before", "U:swap:renamed", "U:swapped:recorded",
		"U:started:applied", "U:started:recorded", "U:done:recorded",
	}
	held := points[slices.Index(points, heldFrom) : slices.Index(points, heldTo)+1]
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			h := newCrashHost(t)
			h.crashAt(point, wrapperBinary)
			h.assertLiveSM()
			if slices.Contains(held, point) {
				h.assertHeld()
			}
			res := h.upgrade(wrapperBinary)
			if res.Code != 0 {
				t.Fatalf("rerun after the crash at %s exited %d\n%s", point, res.Code, res.Output())
			}
			h.assertLiveSM()
			h.assertConvergedToNext(t)
		})
	}
}

// TestM6_CrashUpgrade_AbandonRestoresTheOldService
//
// Given the installer is ended after the upgrade was prepared. Then: rerunning with the old binary
// abandons the upgrade and the old service runs again, nothing left behind.
func TestM6_CrashUpgrade_AbandonRestoresTheOldService(t *testing.T) {
	h := newCrashHost(t)
	h.crashAt("U:prepared:recorded", wrapperBinary)
	res := h.upgrade(prevBinary)
	if res.Code != 0 || !strings.Contains(res.Output(), "abandoning the unfinished upgrade") {
		t.Fatalf("rerun with the old binary: exit %d, want 0 and an abandon notice\n%s", res.Code, res.Output())
	}
	h.srv.WaitReady(h.ctx())
	if got := h.installedVersion(h.ctx()); got != prevVersion {
		t.Errorf("installed version %q, want %s", got, prevVersion)
	}
	if h.fileExists(harness.ServerData+"/upgrade.json") || h.fileExists(harness.ServerBinary+".new") {
		t.Error("the abandoned upgrade left its state or its staged binary behind")
	}
	h.assertDataIntact(t)
}

// TestM6_CrashUpgrade_RetakesTheArchiveOfAnUnfinishedUpgrade
//
// Given the installer is ended after the backup was recorded and then again right after the retake.
// Then: the rerun converges and only the newest pre-upgrade archive remains.
func TestM6_CrashUpgrade_RetakesTheArchiveOfAnUnfinishedUpgrade(t *testing.T) {
	h := newCrashHost(t)
	first := h.crashAt("U:backed_up:recorded", wrapperBinary)
	firstArchive, _ := preUpgradeArchive(t, first.Output())
	h.crashAt("U:backup:retaken", wrapperBinary)
	res := h.upgrade(wrapperBinary)
	if res.Code != 0 {
		t.Fatalf("rerun exited %d\n%s", res.Code, res.Output())
	}
	h.assertConvergedToNext(t)
	if h.fileExists(firstArchive) {
		t.Errorf("the superseded archive %s was not removed", firstArchive)
	}
	if archive, _ := preUpgradeArchive(t, res.Output()); !h.fileExists(archive) {
		t.Errorf("the archive the rerun reports (%s) is missing", archive)
	}
}

// TestM6_CrashUpgrade_AfterAFailedBackupResumesForward
//
// Given the backup failed, the installer restarted the old service and was ended right there.
// Then: once the cause is gone, the rerun converges to the new version.
func TestM6_CrashUpgrade_AfterAFailedBackupResumesForward(t *testing.T) {
	h := newCrashHost(t)
	h.setFault("backup:fail")
	h.crashAt("U:abort:restarted", wrapperBinary)
	h.assertLiveSM()
	h.setFault("")
	if res := h.upgrade(wrapperBinary); res.Code != 0 {
		t.Fatalf("rerun exited %d\n%s", res.Code, res.Output())
	}
	h.assertConvergedToNext(t)
}

// ---- the new binary fails, schema unchanged: automatic revert ----

// TestM6_CrashUpgrade_RevertsAutomaticallyWhenTheNewBinaryFailsAndSchemaIsUnchanged
//
// Given the installer is ended after the new service was started and the new binary never becomes ready.
// Then: the rerun puts the previous binary back (exit 9) and the old version runs on schema 3.
func TestM6_CrashUpgrade_RevertsAutomaticallyWhenTheNewBinaryFailsAndSchemaIsUnchanged(t *testing.T) {
	for _, point := range []string{"U:started:applied", "U:started:recorded"} {
		t.Run(point, func(t *testing.T) {
			h := newCrashHost(t)
			h.setFault("server:never-ready")
			prevSHA := h.sha(harness.ServerBinary)
			h.crashAt(point, wrapperBinary)
			h.assertLiveSM()
			res := h.upgrade(wrapperBinary)
			if res.Code != exitRestore || !strings.Contains(res.Output(), "was reverted") {
				t.Fatalf("rerun: exit %d, want %d and 'reverted'\n%s", res.Code, exitRestore, res.Output())
			}
			h.assertLiveSM()
			h.assertRestoredPrevious(t, prevSHA)
		})
	}
}

// ---- the new binary fails, schema advanced: no automatic rollback ----

// TestM6_CrashUpgrade_NeverRollsBackAfterTheSchemaAdvanced
//
// Given the installer is ended around the start of a new binary that migrated the schema and then fails.
// Then: the rerun leaves the service stopped on the new binary, exits 9 and prints the restore commands;
// a further rerun says the same.
func TestM6_CrashUpgrade_NeverRollsBackAfterTheSchemaAdvanced(t *testing.T) {
	for _, point := range []string{"U:started:applied", "U:started:recorded"} {
		t.Run(point, func(t *testing.T) {
			h := newCrashHost(t)
			h.setFault("server:migrate-then-unreachable")
			prevSHA := h.sha(harness.ServerBinary)
			h.crashAt(point, wrapperBinary)
			h.waitMigratedServer()
			h.assertLiveSM()
			h.assertStoppedWithRestoreCommands(t, prevSHA)
			h.assertStoppedWithRestoreCommands(t, prevSHA)
		})
	}
}

// assertStoppedWithRestoreCommands reruns the upgrade and checks the schema-advanced outcome.
func (h *upgradeHost) assertStoppedWithRestoreCommands(t *testing.T, prevSHA string) {
	t.Helper()
	res := h.upgrade(wrapperBinary)
	if res.Code != exitRestore || !strings.Contains(res.Output(), "left STOPPED") {
		t.Fatalf("rerun: exit %d, want %d and 'left STOPPED'\n%s", res.Code, exitRestore, res.Output())
	}
	if n := len(printedStep.FindAllStringSubmatch(res.Output(), -1)); n != 3 {
		t.Errorf("printed %d restore steps, want 3\n%s", n, res.Output())
	}
	if !strings.Contains(res.Output(), "backup restore --offline") {
		t.Errorf("the restore command is not printed\n%s", res.Output())
	}
	h.assertLiveSM()
	if h.serviceActive() {
		t.Error("the service runs although the schema advanced and nothing was restored")
	}
	if h.sha(harness.ServerBinary) == prevSHA {
		t.Error("the previous binary was put back automatically after the schema advanced")
	}
	if got := h.schema(harness.ServerBinary); got != latestSchema(t) {
		t.Errorf("schema %d, want %d", got, latestSchema(t))
	}
}

// ---- crash during a failure already under way ----

// TestM6_CrashUpgrade_RevertResumesAndConverges
//
// Given the new binary fails with the schema unchanged and the installer is ended during the revert.
// Then: the rerun finishes the revert (exit 9) and the old version runs.
func TestM6_CrashUpgrade_RevertResumesAndConverges(t *testing.T) {
	for _, point := range []string{"U:reverting:recorded", "U:revert:renamed", "U:revert:started"} {
		t.Run(point, func(t *testing.T) {
			h := newCrashHost(t)
			h.setFault("server:never-ready")
			prevSHA := h.sha(harness.ServerBinary)
			h.crashAt(point, wrapperBinary)
			h.assertLiveSM()
			res := h.upgrade(wrapperBinary)
			if res.Code != exitRestore || !strings.Contains(res.Output(), "was reverted") {
				t.Fatalf("rerun: exit %d, want %d and 'reverted'\n%s", res.Code, exitRestore, res.Output())
			}
			h.assertLiveSM()
			h.assertRestoredPrevious(t, prevSHA)
		})
	}
}

// TestM6_CrashUpgrade_FailedRecordIsHonouredByTheRerun
//
// Given the new binary migrated the schema, failed, and the installer is ended right after recording
// the failure. Then: the rerun keeps the service stopped and prints the restore commands.
func TestM6_CrashUpgrade_FailedRecordIsHonouredByTheRerun(t *testing.T) {
	h := newCrashHost(t)
	h.setFault("server:migrate-then-unreachable")
	prevSHA := h.sha(harness.ServerBinary)
	h.crashAt("U:failed:recorded", wrapperBinary)
	h.assertLiveSM()
	h.assertStoppedWithRestoreCommands(t, prevSHA)
}

// ---- downgrade audit ----

// TestM6_CrashUpgrade_DowngradeRecordIsImportedOnceAfterTheDowngrade
//
// Given a server at N is downgraded with --allow-downgrade to N' and the installer is ended before the swap.
// Then: one pending record exists after the crash; after the rerun N' runs, the record is imported exactly
// once as instance.downgrade_authorized, the transition is audited as a downgrade, and no record is left.
func TestM6_CrashUpgrade_DowngradeRecordIsImportedOnceAfterTheDowngrade(t *testing.T) {
	h := newCrashHost(t)
	if res := h.upgrade(nextBinary); res.Code != 0 {
		t.Fatalf("upgrade to %s exited %d\n%s", nextVersion, res.Code, res.Output())
	}
	h.srv.WaitReady(h.ctx())

	c := h.srv.C
	c.CopyRoot(h.ctx(), crashBuild(t, crashDownKey, crashDownVer, ""), crashDownBin)
	c.MustExec(h.ctx(), "chmod", "0755", crashDownBin)
	pendingDir := harness.ServerData + "/audit-pending"

	h.crashAt("U:swap:before", crashDownBin, "--allow-downgrade")
	if got := strings.Fields(c.Exec(h.ctx(), "", "ls", pendingDir).Stdout); len(got) != 1 {
		t.Fatalf("pending audit records after the crash = %v, want exactly one", got)
	}

	res := h.upgradeWith(crashDownBin, "--allow-downgrade")
	if res.Code != 0 {
		t.Fatalf("downgrade rerun exited %d\n%s", res.Code, res.Output())
	}
	h.srv.WaitReady(h.ctx())
	if got := h.installedVersion(h.ctx()); got != crashDownVer {
		t.Fatalf("installed version %q, want %s", got, crashDownVer)
	}

	events := h.allEvents(t)
	authorized := eventsNamed(events, "instance.downgrade_authorized")
	if len(authorized) != 1 {
		for _, e := range authorized {
			t.Logf("event %s seq %d data %v", e.EventID, e.Seq, e.Data)
		}
		t.Fatalf("instance.downgrade_authorized events = %d, want 1", len(authorized))
	}
	if d := authorized[0].Data; d["from"] != nextVersion || d["to"] != crashDownVer {
		t.Errorf("downgrade event data = %v, want from %s to %s", d, nextVersion, crashDownVer)
	}
	changed := eventsNamed(events, "instance.version_changed")
	if len(changed) == 0 || changed[len(changed)-1].Data["direction"] != "downgrade" {
		t.Errorf("version_changed events = %v, want the last one to be a downgrade", changed)
	}
	if left := strings.Fields(c.Exec(h.ctx(), "", "ls", pendingDir).Stdout); len(left) != 0 {
		t.Errorf("pending audit records left after the daemon started: %v", left)
	}
	h.assertDataIntact(t)
}

func (h *upgradeHost) allEvents(t *testing.T) []wire.Event {
	t.Helper()
	api := h.srv.Typed(h.token)
	var all []wire.Event
	q := wire.EventQuery{PageQuery: wire.PageQuery{Limit: 200}}
	for {
		page, err := api.ListEvents(h.ctx(), q)
		if err != nil {
			t.Fatalf("list events: %v", err)
		}
		all = append(all, page.Items...)
		if page.NextCursor == "" {
			return all
		}
		q.Cursor = page.NextCursor
	}
}

func eventsNamed(events []wire.Event, action string) []wire.Event {
	var out []wire.Event
	for _, e := range events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}
