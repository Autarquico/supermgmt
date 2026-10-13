//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/test/e2e/harness"
	"github.com/autarquico/supermgmt/test/e2e/pvesim"
)

// Spec docs/specs/m6-hardening.md and ADR-0035: the appliance lifecycle across a release boundary.
// The previous milestone's own installer builds the appliance on the simulated Proxmox host
// (pvesim); the tree under test then upgrades it from the host (delegated into the container),
// backs up and restores inside it, and uninstalls and purges it.

const (
	lifecycleJournalRoot = "/var/lib/supermgmt-installer/journals"
	lifecycleHostPrev    = "/root/sm-prev"
	lifecycleHostNext    = "/root/sm-next"
	lifecycleVMID        = "900"
)

// lifecyclePrevious is the newest milestone merged on main: the N-1 of the tree under test.
func lifecyclePrevious(t testing.TB) milestone {
	t.Helper()
	for i := len(milestones) - 1; i >= 0; i-- {
		if milestones[i].merged() {
			return milestones[i]
		}
	}
	t.Fatal("no milestone is merged yet")
	return milestone{}
}

// lifecycleNextVersion orders after every milestone build.
func lifecycleNextVersion() string { return fmt.Sprintf("v0.%d.0", len(milestones)+1) }

// lifecyclePreviousBuild builds the sm of the milestone's merge commit (exported with git archive,
// the working tree is untouched) as its synthetic version, for the PVE host.
func lifecyclePreviousBuild(t testing.TB, m milestone) string {
	t.Helper()
	arch := hostArch(t)
	path, err := m3Once("lifecycle-"+m.name+"-"+arch, func() (string, error) {
		src := filepath.Join(harness.WorkDir(), "lifecycle-src-"+m.name)
		if err := os.MkdirAll(src, 0o755); err != nil {
			return "", err
		}
		tarball := src + ".tar"
		ctx := context.Background()
		res, err := harness.Run(ctx, harness.RepoRoot(), nil, "", "git", "archive", "--format=tar", "--output", tarball, m.commit)
		if e := commandFailure("git archive "+m.commit+" (CI needs fetch-depth: 0)", res, err); e != nil {
			return "", e
		}
		res, err = harness.Run(ctx, "", nil, "", "tar", "-xf", tarball, "-C", src)
		if e := commandFailure("extract "+m.commit, res, err); e != nil {
			return "", e
		}
		return buildVersioned(src, filepath.Join(harness.WorkDir(), "sm-lifecycle-"+m.name+"-"+arch), arch, m.version)
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// lifecycleSM runs `sm <args>` on the PVE host with the binary staged at path.
func (w *pveWorld) lifecycleSM(path string, env map[string]string, args ...string) harness.Result {
	w.t.Helper()
	merged := map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}
	for k, v := range env {
		merged[k] = v
	}
	return w.Host.Env(context.Background(), "", merged, append([]string{path}, args...)...)
}

// inAppliance runs a command inside the appliance container, through the host's pct.
func (w *pveWorld) inAppliance(argv ...string) harness.Result {
	w.t.Helper()
	return w.pve("pct", append([]string{"exec", lifecycleVMID, "--"}, argv...)...)
}

func (w *pveWorld) mustInAppliance(argv ...string) string {
	w.t.Helper()
	res := w.inAppliance(argv...)
	if res.Code != 0 {
		w.t.Fatalf("%s in the appliance exited %d\n%s", strings.Join(argv, " "), res.Code, res.Output())
	}
	return res.Stdout
}

func (w *pveWorld) applianceVersion() string {
	w.t.Helper()
	var v struct{ Version string }
	if err := json.Unmarshal([]byte(w.mustInAppliance(harness.ServerBinary, "version", "--json")), &v); err != nil {
		w.t.Fatal(err)
	}
	return v.Version
}

// withServiceStopped runs fn while the appliance's service is down (offline commands need the database lock).
func (w *pveWorld) withServiceStopped(fn func()) {
	w.t.Helper()
	w.mustInAppliance("systemctl", "stop", "supermgmt")
	defer w.waitApplianceReady()
	defer w.mustInAppliance("systemctl", "start", "supermgmt")
	fn()
}

// waitApplianceReady polls the appliance's online doctor, which needs the running service.
func (w *pveWorld) waitApplianceReady() {
	w.t.Helper()
	for range 60 {
		if w.inAppliance(harness.ServerBinary, "doctor", "--json").Code == 0 {
			return
		}
		time.Sleep(time.Second)
	}
	w.t.Fatal("the appliance's service did not become ready")
}

// applianceSchema is the schema version the offline doctor of the appliance's sm reports.
func (w *pveWorld) applianceSchema() int {
	w.t.Helper()
	schema := 0
	w.withServiceStopped(func() {
		out := w.mustInAppliance("runuser", "-u", "supermgmt", "--", harness.ServerBinary, "doctor", "--offline", "--json", "--config", harness.ServerConfig)
		var report struct {
			Checks []struct{ Name, Detail string } `json:"checks"`
		}
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			w.t.Fatalf("the appliance's offline doctor gave no report: %v\n%s", err, out)
		}
		for _, c := range report.Checks {
			if m := schemaDetail.FindStringSubmatch(c.Detail); c.Name == "schema" && m != nil {
				schema, _ = strconv.Atoi(m[1])
			}
		}
	})
	if schema == 0 {
		w.t.Fatal("the appliance's offline doctor reports no schema version")
	}
	return schema
}

// installApplianceWith is installAppliance for the sm staged at path.
func (w *pveWorld) installApplianceWith(path string) applianceInstall {
	w.t.Helper()
	res := w.lifecycleSM(path, nil, "install", "proxmox-lxc", "--yes")
	out := applianceInstall{Result: res}
	if m := accessURL.FindStringSubmatch(res.Output()); m != nil {
		out.URL = m[1]
	}
	if m := accessCode.FindStringSubmatch(res.Output()); m != nil {
		out.Code = m[1]
	}
	if m := accessCA.FindStringSubmatch(res.Output()); m != nil {
		out.CAPEM = m[1] + "\n"
	}
	return out
}

// TestM6_ApplianceLifecycleAcrossAReleaseBoundary
//
// Given an appliance built by the previous milestone's installer. Then: the new installer upgrades
// it from the host (pre-upgrade backup, new version and schema in the container, session intact,
// the host's own guests untouched); a backup taken inside restores and the service comes back; the
// default uninstall keeps the container and its identities; --purge-data removes this install's
// container, record and identities and nothing else.
func TestM6_ApplianceLifecycleAcrossAReleaseBoundary(t *testing.T) {
	prev := lifecyclePrevious(t)
	w := startPVEWorld(t, pveOptions{})
	w.seedHost()
	before := w.state()
	ctx := context.Background()

	w.Host.CopyRoot(ctx, lifecyclePreviousBuild(t, prev), lifecycleHostPrev)
	w.Host.MustExec(ctx, "chmod", "0755", lifecycleHostPrev)
	a := w.installApplianceWith(lifecycleHostPrev)
	a.mustSucceed(t)
	l := w.newLaptop()
	l.signIn(a)
	if got := w.applianceVersion(); got != prev.version {
		t.Fatalf("the N-1 appliance runs %q, want %s", got, prev.version)
	}
	if got := w.applianceSchema(); got != prev.schema {
		t.Fatalf("the N-1 appliance is at schema %d, want %d", got, prev.schema)
	}

	next := lifecycleNextVersion()
	w.installHostSMVersion(w.Host, lifecycleHostNext, next)
	upgrade := w.lifecycleSM(lifecycleHostNext, nil, "install", "upgrade", "--yes")
	if upgrade.Code != 0 {
		t.Fatalf("sm install upgrade on the host exited %d\n%s", upgrade.Code, upgrade.Output())
	}

	t.Run("the container runs the new version on the latest schema with the pre-upgrade backup taken", func(t *testing.T) {
		if _, archiveSchema := preUpgradeArchive(t, upgrade.Output()); archiveSchema != prev.schema {
			t.Errorf("the pre-upgrade archive is at schema %d, want %d", archiveSchema, prev.schema)
		}
		if got := w.applianceVersion(); got != next {
			t.Errorf("the appliance runs %q after the upgrade, want %s", got, next)
		}
		if got := w.applianceSchema(); got != latestSchema(t) {
			t.Errorf("the appliance is at schema %d after the upgrade, want %d", got, latestSchema(t))
		}
	})

	t.Run("the laptop's session still sees the appliance and the host's own guests are untouched", func(t *testing.T) {
		if tree := l.mustSM("", "nodes", "list", "--tree"); !strings.Contains(tree, "lxc/"+lifecycleVMID) {
			t.Errorf("the session no longer sees the appliance:\n%s", tree)
		}
		if list := w.mustPVE("pct", "list"); !strings.Contains(list, "legacy") {
			t.Errorf("the host's own container is gone:\n%s", list)
		}
	})

	t.Run("a backup taken inside restores and the service comes back healthy", func(t *testing.T) {
		w.withServiceStopped(func() {
			out := w.mustInAppliance("runuser", "-u", "supermgmt", "--", harness.ServerBinary, "backup", "create", "--offline", "--json", "--config", harness.ServerConfig)
			var report struct{ Name string }
			if err := json.Unmarshal([]byte(out), &report); err != nil || report.Name == "" {
				t.Fatalf("the offline backup reported no archive (%v):\n%s", err, out)
			}
			w.mustInAppliance("runuser", "-u", "supermgmt", "--", harness.ServerBinary, "backup", "restore", "--offline",
				harness.ServerData+"/backups/"+report.Name, "--config", harness.ServerConfig)
		})
		if got := w.applianceSchema(); got != latestSchema(t) {
			t.Errorf("the restored appliance is at schema %d, want %d", got, latestSchema(t))
		}
		if res := w.inAppliance("systemctl", "is-active", "supermgmt"); res.Code != 0 {
			t.Errorf("the service is not active after the restore:\n%s", res.Output())
		}
	})

	t.Run("the default uninstall keeps the container and the Proxmox identities", func(t *testing.T) {
		res := w.lifecycleSM(lifecycleHostNext, nil, "install", "uninstall", "--yes")
		if res.Code != 0 {
			t.Fatalf("sm install uninstall exited %d\n%s", res.Code, res.Output())
		}
		if list := w.mustPVE("pct", "list"); !regexp.MustCompile(lifecycleVMID + `\s+stopped`).MatchString(list) {
			t.Errorf("the container is not stopped and kept:\n%s", list)
		}
		if users := w.mustPVE("pveum", "user", "list", "--output-format", "json"); !strings.Contains(users, `"userid":"sm-`) {
			t.Errorf("the identities of the install were removed without --purge-data:\n%s", users)
		}
	})

	t.Run("purge removes this install's container, record and identities and nothing else", func(t *testing.T) {
		res := w.lifecycleSM(lifecycleHostNext, map[string]string{"SUPERMGMT_YES": "1"}, "install", "uninstall", "--purge-data", "--vmid", lifecycleVMID, "--yes")
		if res.Code != 0 {
			t.Fatalf("purge exited %d\n%s", res.Code, res.Output())
		}
		w.assertStateEquals(before)
		after := w.state()
		for _, own := range []string{`"userid":"sm-`, `SMAudit-`, `SMPower-`} {
			if all := after["pveum user list"] + after["pveum role list"]; strings.Contains(all, own) {
				t.Errorf("an identity of the install (%s) survived the purge:\n%s", own, all)
			}
		}
		if left := w.Host.Exec(ctx, "", "sh", "-c", "ls /var/lib/supermgmt-installer/appliances/*.json 2>/dev/null"); strings.TrimSpace(left.Stdout) != "" {
			t.Errorf("the appliance record survived the purge: %s", left.Stdout)
		}
	})
}

// TestM6_ApplianceJournalLivesInTheRootOnlyRoot
//
// Given an install that fails and whose rollback also fails. Then: the journal is kept under the
// root-only journalRoot (0700, root), nothing is left in the shared /var/tmp, and a rerun without
// a terminal refuses to go on until the journal is recovered.
func TestM6_ApplianceJournalLivesInTheRootOnlyRoot(t *testing.T) {
	w := startPVEWorld(t, pveOptions{})
	w.seedHost()
	ctx := context.Background()
	w.Sim.Inject(pvesim.Fault{Tool: "pct", Contains: "secrets import"})
	w.Sim.Inject(pvesim.Fault{Tool: "pct", Contains: "destroy " + lifecycleVMID})

	failed := w.installAppliance(nil)
	if failed.Result.Code == 0 || !strings.Contains(failed.Result.Output(), "NOT fully rolled back") {
		t.Fatalf("expected a failed install that could not roll back, got exit %d\n%s", failed.Result.Code, failed.Result.Output())
	}
	root := w.Host.Exec(ctx, "", "stat", "-c", "%a %U", lifecycleJournalRoot)
	if strings.TrimSpace(root.Stdout) != "700 root" {
		t.Errorf("%s is %q, want \"700 root\" (%s)", lifecycleJournalRoot, strings.TrimSpace(root.Stdout), root.Output())
	}
	journals := strings.Fields(w.Host.Exec(ctx, "", "sh", "-c", "ls "+lifecycleJournalRoot).Stdout)
	if len(journals) != 1 || !strings.Contains(failed.Result.Output(), lifecycleJournalRoot+"/"+journals[0]) {
		t.Errorf("journals under %s: %v; the report must name the one kept\n%s", lifecycleJournalRoot, journals, failed.Result.Output())
	}
	if tmp := w.Host.Exec(ctx, "", "sh", "-c", "ls -d /var/tmp/supermgmt-installer-* 2>/dev/null"); strings.TrimSpace(tmp.Stdout) != "" {
		t.Errorf("a journal or staged token was left in the shared /var/tmp: %s", tmp.Stdout)
	}

	rerun := w.installAppliance(nil)
	if rerun.Result.Code == 0 || !strings.Contains(rerun.Result.Output(), lifecycleJournalRoot+"/"+journals[0]) {
		t.Errorf("a rerun without a terminal must refuse and name the kept journal, got exit %d\n%s", rerun.Result.Code, rerun.Result.Output())
	}
	if still := strings.Fields(w.Host.Exec(ctx, "", "sh", "-c", "ls "+lifecycleJournalRoot).Stdout); len(still) != 1 || still[0] != journals[0] {
		t.Errorf("the refused rerun changed the journals: %v, want [%s]", still, journals[0])
	}
}
