//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/test/e2e/harness"
	"github.com/autarquico/supermgmt/test/e2e/pvesim"
)

// Spec docs/specs/m3-proxmox-installer.md and PLAN §9: `sm install proxmox-lxc` on a simulated
// Proxmox host (pvesim): the appliance is a systemd container on the test network, the Proxmox
// tools are shims, the Proxmox API is the fake. The "laptop" is a container on the same network
// (the appliance address is private), running the same `sm`.
//
// On an arm64 machine run these with SM_E2E_PVE_HOST_PLATFORM=linux/amd64 (see pvesim_test.go).

const (
	hostSM     = "/root/sm"
	laptopHome = "/root/laptop"
	legacyVMID = "800" // a container that exists before the install and must survive it
)

// applianceInstall is the outcome of `sm install proxmox-lxc`.
type applianceInstall struct {
	Result harness.Result
	URL    string
	CAPEM  string
	Code   string
}

var (
	accessURL  = regexp.MustCompile(`--url (https://\S+) --ca-file`)
	accessCode = regexp.MustCompile(`Bootstrap code \(shown once, single use\): (\S+)`)
	accessCA   = regexp.MustCompile(`(?s)(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)`)
)

// installHostSM puts the sm of the tree (version nextVersion), built for the PVE host container, at path.
func (w *pveWorld) installHostSM(c *harness.Container, path string) {
	w.t.Helper()
	w.installHostSMVersion(c, path, nextVersion)
}

func (w *pveWorld) installHostSMVersion(c *harness.Container, path, version string) {
	w.t.Helper()
	arch := hostArch(w.t)
	bin, err := m3Once("sm-host-"+version+"-"+arch, func() (string, error) {
		return buildVersioned(harness.RepoRoot(), filepath.Join(harness.WorkDir(), "sm-host-"+version+"-"+arch), arch, version)
	})
	if err != nil {
		w.t.Fatal(err)
	}
	ctx := context.Background()
	c.CopyRoot(ctx, bin, path)
	c.MustExec(ctx, "chmod", "0755", path)
}

// runInstaller runs `sm <args>` on the PVE host as root without a terminal.
func (w *pveWorld) runInstaller(env map[string]string, args ...string) harness.Result {
	w.t.Helper()
	ctx := context.Background()
	if w.Host.Exec(ctx, "", "test", "-x", hostSM).Code != 0 {
		w.installHostSM(w.Host, hostSM)
	}
	merged := map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}
	for k, v := range env {
		merged[k] = v
	}
	return w.Host.Env(ctx, "", merged, append([]string{hostSM}, args...)...)
}

// installAppliance runs `sm install proxmox-lxc --yes` on the PVE host.
func (w *pveWorld) installAppliance(env map[string]string) applianceInstall {
	w.t.Helper()
	res := w.runInstaller(env, "install", "proxmox-lxc", "--yes")
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

func (a applianceInstall) mustSucceed(t *testing.T) {
	t.Helper()
	if a.Result.Code != 0 || a.URL == "" || a.Code == "" || a.CAPEM == "" {
		t.Fatalf("sm install proxmox-lxc exited %d (url %q, code found %t, ca found %t)\n%s",
			a.Result.Code, a.URL, a.Code != "", a.CAPEM != "", a.Result.Output())
	}
}

// laptop is a container on the PVE network with `sm` and its own HOME, like a workstation.
type laptop struct {
	t *testing.T
	c *harness.Container
}

func (w *pveWorld) newLaptop() *laptop {
	w.t.Helper()
	ctx := context.Background()
	c := harness.Start(w.t, harness.RunOptions{Image: harness.Image(w.t), Network: w.Network, Cmd: []string{"sleep", "infinity"}})
	c.InstallSM(ctx, w.t, "/usr/local/bin/sm")
	c.MustExec(ctx, "mkdir", "-p", laptopHome)
	return &laptop{t: w.t, c: c}
}

// sm runs the laptop's sm with HOME set and no OS keychain, so sessions live in a 0600 file.
func (l *laptop) sm(stdin string, args ...string) harness.Result {
	l.t.Helper()
	env := map[string]string{
		"HOME": laptopHome, "XDG_CONFIG_HOME": laptopHome + "/config", "XDG_DATA_HOME": laptopHome + "/data",
		"XDG_STATE_HOME": laptopHome + "/state", "XDG_RUNTIME_DIR": laptopHome, "NO_COLOR": "1", "SUPERMGMT_NO_AUTOSTART": "1",
		"PATH": "/usr/local/bin:/usr/bin:/bin",
	}
	return l.c.Env(context.Background(), stdin, env, append([]string{"/usr/local/bin/sm"}, args...)...)
}

func (l *laptop) mustSM(stdin string, args ...string) string {
	l.t.Helper()
	res := l.sm(stdin, args...)
	if res.Code != 0 {
		l.t.Fatalf("sm %s exited %d\n%s", strings.Join(args, " "), res.Code, res.Output())
	}
	return res.Stdout
}

// signIn adds the profile with the printed CA and signs in with the bootstrap code.
func (l *laptop) signIn(a applianceInstall) {
	l.t.Helper()
	l.c.WriteFile(context.Background(), laptopHome+"/supermgmt-ca.pem", []byte(a.CAPEM), "0644")
	l.mustSM("", "profile", "add", "supermgmt", "--url", a.URL, "--ca-file", laptopHome+"/supermgmt-ca.pem", "--use")
	l.mustSM(a.Code+"\n", "login", "--bootstrap", "--display-name", "pve admin")
}

// hostState is what the Proxmox host holds, as the tools report it: the guests, the access
// control and the Docker containers behind the guests.
type hostState map[string]string

func (w *pveWorld) state() hostState {
	w.t.Helper()
	st := hostState{"pct list": w.mustPVE("pct", "list")}
	for _, argv := range [][]string{{"user", "list"}, {"role", "list"}, {"acl", "list"}} {
		st["pveum "+strings.Join(argv, " ")] = w.mustPVE("pveum", append(argv, "--output-format", "json")...)
	}
	st["pveum token list legacy"] = w.mustPVE("pveum", "user", "token", "list", "legacy@pve", "--output-format", "json")
	names := strings.Fields(harness.MustDocker(w.t, "ps", "--all", "--filter", "label="+pveSweepKV, "--format", "{{.Names}}"))
	sort.Strings(names)
	st["containers"] = strings.Join(names, " ")
	return st
}

func (w *pveWorld) assertStateEquals(want hostState) {
	w.t.Helper()
	got := w.state()
	for key, before := range want {
		if got[key] != before {
			w.t.Errorf("%s changed:\nbefore: %s\nafter:  %s", key, before, got[key])
		}
	}
}

// seedHost gives the host something of its own that no install may touch: a stopped container,
// a user with a token, a role, an ACL, and the downloaded template.
func (w *pveWorld) seedHost() {
	w.t.Helper()
	w.mustPVE("pveam", "download", "local", debianTemplate)
	w.mustPVE("pct", "create", legacyVMID, "local:vztmpl/"+debianTemplate, "--hostname", "legacy", "--rootfs", "local-lvm:8",
		"--net0", "name=eth0,bridge=vmbr0,ip=dhcp", "--tags", "mine")
	w.mustPVE("pveum", "user", "add", "legacy@pve", "--comment", "pre-existing")
	w.mustPVE("pveum", "role", "add", "LegacyRole", "--privs", "VM.Audit")
	w.mustPVE("pveum", "acl", "modify", "/", "--roles", "LegacyRole", "--users", "legacy@pve")
	w.mustPVE("pveum", "user", "token", "add", "legacy@pve", "keep", "--output-format", "json")
}

// addFakeCluster puts guests into the fake Proxmox that the tools did not create.
func (w *pveWorld) addFakeCluster() {
	w.t.Helper()
	ctx := context.Background()
	for _, g := range []pvesim.FakeGuest{{VMID: 901, Name: "web", Status: "stopped"}, {VMID: 902, Name: "db", Status: "running"}} {
		if err := w.admin.PutGuest(ctx, g); err != nil {
			w.t.Fatal(err)
		}
	}
}

func indexOfCall(calls []string, fragment string) int {
	for i, c := range calls {
		if strings.Contains(c, fragment) {
			return i
		}
	}
	return -1
}

// assertNoSecretOnHost searches the places an installer could leave a file.
func (w *pveWorld) assertNoSecretOnHost(secrets []string) {
	w.t.Helper()
	for _, secret := range secrets {
		res := w.Host.Exec(context.Background(), "", "grep", "-rIlF", "-e", secret, "/root", "/var", "/tmp", "/etc", "/run", "/opt", "/srv")
		if strings.TrimSpace(res.Stdout) != "" {
			w.t.Errorf("a file on the Proxmox host holds the token: %s", res.Stdout)
		}
	}
}

// TestM3_ApplianceInstallDiscoversAndLogsIn
//
// Criterion: fresh PVE -> one command -> unprivileged LXC with the service -> discovered -> the
// laptop signs in with the printed CA and bootstrap code, sees the cluster and powers a guest.
func TestM3_ApplianceInstallDiscoversAndLogsIn(t *testing.T) {
	w := startPVEWorld(t, pveOptions{})
	w.seedHost()
	w.addFakeCluster()
	before := w.state()

	a := w.installAppliance(nil)
	a.mustSucceed(t)

	t.Run("the container is unprivileged, unmounted and tagged", func(t *testing.T) {
		conf := w.mustPVE("pct", "config", "900")
		for _, want := range []string{"unprivileged: 1", "features: nesting=0,keyctl=0", "onboot: 1", "tags: supermgmt"} {
			if !strings.Contains(conf, want) {
				t.Errorf("pct config lacks %q:\n%s", want, conf)
			}
		}
		if regexp.MustCompile(`(?m)^(mp\d+|lxc\.)`).MatchString(conf) {
			t.Errorf("the container has mounts or raw lxc keys:\n%s", conf)
		}
	})

	t.Run("the service is enabled only after the token was imported", func(t *testing.T) {
		calls := w.Sim.Calls()
		imported, enabled := indexOfCall(calls, "secrets import"), indexOfCall(calls, "systemctl enable")
		if imported < 0 || enabled < 0 || imported > enabled {
			t.Fatalf("secrets import at %d, systemctl enable at %d; want the import first\n%s", imported, enabled, strings.Join(calls, "\n"))
		}
	})

	t.Run("no Proxmox command line and no host file carries the token", func(t *testing.T) {
		secrets := w.Sim.TokenSecrets()
		if len(secrets) == 0 {
			t.Fatal("the simulation minted no token")
		}
		for _, call := range w.Sim.Calls() {
			for _, secret := range secrets {
				if strings.Contains(call, secret) {
					t.Errorf("a command line carries the token: %s", strings.ReplaceAll(call, secret, "<token>"))
				}
			}
		}
		if out := w.Host.Exec(context.Background(), "", "sh", "-c", "ls -d /var/tmp/supermgmt-installer-* 2>/dev/null"); strings.TrimSpace(out.Stdout) != "" {
			t.Errorf("the install left a journal or a staged token on the host: %s", out.Stdout)
		}
		w.assertNoSecretOnHost(secrets)
	})

	t.Run("the Proxmox identities of the install exist and the host's own are untouched", func(t *testing.T) {
		after := w.state()
		if !strings.Contains(after["pveum user list"], `"userid":"sm-`) {
			t.Errorf("no per-install user:\n%s", after["pveum user list"])
		}
		for _, role := range []string{`"roleid":"SMAudit-`, `"roleid":"SMPower-`} {
			if !strings.Contains(after["pveum role list"], role) {
				t.Errorf("no per-install role %s:\n%s", role, after["pveum role list"])
			}
		}
		for _, legacy := range []string{"legacy@pve", "LegacyRole"} {
			if !strings.Contains(after["pveum user list"]+after["pveum role list"], legacy) {
				t.Errorf("pre-existing %s is gone", legacy)
			}
		}
		if after["pveum token list legacy"] != before["pveum token list legacy"] {
			t.Error("the pre-existing token changed")
		}
		if !strings.Contains(after["pct list"], "legacy") {
			t.Errorf("the pre-existing container is gone:\n%s", after["pct list"])
		}
	})

	l := w.newLaptop()
	l.signIn(a)

	t.Run("discovery shows the cluster node and its guests", func(t *testing.T) {
		tree := l.mustSM("", "nodes", "list", "--tree")
		for _, want := range []string{"pve", "supermgmt", "lxc/900", "web", "lxc/901", "db", "lxc/902"} {
			if !strings.Contains(tree, want) {
				t.Errorf("the tree lacks %q:\n%s", want, tree)
			}
		}
	})

	t.Run("a guest is powered on through the CLI", func(t *testing.T) {
		if tree := l.mustSM("", "nodes", "list", "--tree"); !regexp.MustCompile(`web\s+lxc/901\s+stopped`).MatchString(tree) {
			t.Fatalf("guest web is not stopped before the power action:\n%s", tree)
		}
		res := l.sm("", "nodes", "power", "web", "start", "--wait", "--yes")
		if res.Code != 0 {
			t.Fatalf("sm nodes power web start --wait exited %d\n%s", res.Code, res.Output())
		}
		running := regexp.MustCompile(`web\s+lxc/901\s+running`)
		var tree string
		for range 90 {
			if tree = l.mustSM("", "nodes", "list", "--tree"); running.MatchString(tree) {
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("the tree never shows guest web running after the power action:\n%s", tree)
	})
}

// ---- rollback ----

// TestM3_ApplianceRollbackLeavesHostClean
//
// Criterion: a failure at a step undoes what this install created and nothing else. Each case
// breaks one step; afterwards the guests, users, roles, ACLs and containers are as they were
// (the downloaded template stays: it is a shared cache), no record or journal remains and the
// token is nowhere on the host.
func TestM3_ApplianceRollbackLeavesHostClean(t *testing.T) {
	apiDown := []pvesim.InjectRequest{
		{Method: "GET", PathSuffix: "/version", Times: 1000, Kind: "respond", Code: 500, Body: `{"data":null,"message":"injected\n"}`},
		{Method: "GET", PathSuffix: "/cluster/resources", Times: 1000, Kind: "respond", Code: 500, Body: `{"data":null,"message":"injected\n"}`},
	}
	cases := []struct {
		name  string
		fault pvesim.Fault
		api   []pvesim.InjectRequest
		exit  int
	}{
		{
			name: "S7 the container is created and then the tool fails", exit: 6,
			fault: pvesim.Fault{Tool: "pct", Contains: "create 900", After: true},
		},
		{
			name: "S12f the token cannot be pushed into the container", exit: 7,
			fault: pvesim.Fault{Tool: "pct", Contains: "push 900 /var/tmp/supermgmt-installer-"},
		},
		{
			name: "S13 the offline import of the token fails", exit: 7,
			fault: pvesim.Fault{Tool: "pct", Contains: "secrets import"},
		},
		{
			name: "S15b enabling the service fails", exit: 7,
			fault: pvesim.Fault{Tool: "pct", Contains: "systemctl enable"},
		},
		{name: "S15a the Proxmox API fails the provider check", exit: 8, api: apiDown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := startPVEWorld(t, pveOptions{})
			w.seedHost()
			before := w.state()
			if tc.fault.Tool != "" {
				w.Sim.Inject(tc.fault)
			}
			for _, rule := range tc.api {
				if err := w.admin.Inject(context.Background(), rule); err != nil {
					t.Fatal(err)
				}
			}

			a := w.installAppliance(nil)
			if a.Result.Code != tc.exit {
				t.Fatalf("exit %d, want %d\n%s", a.Result.Code, tc.exit, a.Result.Output())
			}
			if !strings.Contains(a.Result.Output(), "rolled back") {
				t.Errorf("the installer does not say it rolled back:\n%s", a.Result.Output())
			}

			w.assertStateEquals(before)
			if !strings.Contains(w.mustPVE("pveam", "list", "local"), debianTemplate) {
				t.Error("the template cache was deleted")
			}
			leftovers := "ls -d /var/tmp/supermgmt-installer-* /var/lib/supermgmt-installer/appliances/*.json 2>/dev/null"
			if res := w.Host.Exec(context.Background(), "", "sh", "-c", leftovers); strings.TrimSpace(res.Stdout) != "" {
				t.Errorf("the failed install left a journal, a staged file or a record on the host:\n%s", res.Stdout)
			}
			w.assertNoSecretOnHost(w.Sim.TokenSecrets())
		})
	}
}

// ---- upgrade and uninstall from the Proxmox host ----

// TestM3_ApplianceUpgradeFromTheHostDelegatesIntoTheContainer
//
// Then: `sm install upgrade` on the host proves the container (record and marks), pushes the new
// build, upgrades inside, and the appliance keeps serving with the same sessions; other containers
// are left alone.
func TestM3_ApplianceUpgradeFromTheHostDelegatesIntoTheContainer(t *testing.T) {
	w := startPVEWorld(t, pveOptions{})
	w.seedHost()
	a := w.installAppliance(nil)
	a.mustSucceed(t)
	l := w.newLaptop()
	l.signIn(a)
	ctx := context.Background()

	w.installHostSMVersion(w.Host, "/root/sm-next", "v0.4.0")
	res := w.Host.Env(ctx, "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, "/root/sm-next", "install", "upgrade", "--yes")
	if res.Code != 0 {
		t.Fatalf("sm install upgrade on the host exited %d\n%s", res.Code, res.Output())
	}
	if !strings.Contains(res.Output(), "pre-upgrade backup") {
		t.Errorf("no pre-upgrade backup in the output:\n%s", res.Output())
	}
	out := w.mustPVE("pct", "exec", "900", "--", "/usr/local/bin/sm", "version", "--json")
	var v struct{ Version string }
	if err := json.Unmarshal([]byte(out), &v); err != nil || v.Version != "v0.4.0" {
		t.Errorf("the appliance runs %q after the upgrade (%v), want v0.4.0", v.Version, err)
	}
	if tree := l.mustSM("", "nodes", "list", "--tree"); !strings.Contains(tree, "lxc/900") {
		t.Errorf("the laptop's session no longer sees the appliance:\n%s", tree)
	}
	if list := w.mustPVE("pct", "list"); !strings.Contains(list, "legacy") {
		t.Errorf("the host's own container is gone:\n%s", list)
	}
}

// TestM3_ApplianceUninstallKeepsTheContainerUntilPurged
//
// Then: the default uninstall removes the software and stops the container, keeping it and the
// Proxmox identities; --purge-data --vmid destroys the container and removes the identities of
// this install only, leaving the host as it was before the install.
func TestM3_ApplianceUninstallKeepsTheContainerUntilPurged(t *testing.T) {
	w := startPVEWorld(t, pveOptions{})
	w.seedHost()
	before := w.state()
	a := w.installAppliance(nil)
	a.mustSucceed(t)

	res := w.runInstaller(nil, "install", "uninstall", "--yes")
	if res.Code != 0 {
		t.Fatalf("sm install uninstall on the host exited %d\n%s", res.Code, res.Output())
	}
	if list := w.mustPVE("pct", "list"); !regexp.MustCompile(`900\s+stopped`).MatchString(list) {
		t.Errorf("the container is not stopped and kept after the default uninstall:\n%s", list)
	}
	if users := w.mustPVE("pveum", "user", "list", "--output-format", "json"); !strings.Contains(users, `"userid":"sm-`) {
		t.Errorf("the Proxmox identities of the install were removed without --purge-data:\n%s", users)
	}

	refused := w.runInstaller(nil, "install", "uninstall", "--purge-data", "--yes")
	if refused.Code != 2 {
		t.Errorf("--purge-data without --vmid and SUPERMGMT_YES=1: exit %d, want 2\n%s", refused.Code, refused.Output())
	}
	if list := w.mustPVE("pct", "list"); !strings.Contains(list, "900") {
		t.Fatalf("a refused purge destroyed the container:\n%s", list)
	}

	purged := w.runInstaller(map[string]string{"SUPERMGMT_YES": "1"}, "install", "uninstall", "--purge-data", "--vmid", "900", "--yes")
	if purged.Code != 0 {
		t.Fatalf("purge exited %d\n%s", purged.Code, purged.Output())
	}
	w.assertStateEquals(before)
	if res := w.Host.Exec(context.Background(), "", "sh", "-c", "ls /var/lib/supermgmt-installer/appliances/*.json 2>/dev/null"); strings.TrimSpace(res.Stdout) != "" {
		t.Errorf("the appliance record survived the purge: %s", res.Stdout)
	}
}
