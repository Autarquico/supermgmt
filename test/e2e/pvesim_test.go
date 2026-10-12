//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/test/e2e/harness"
	"github.com/autarquico/supermgmt/test/e2e/pvesim"
)

// The simulated Proxmox host (package pvesim): a Debian systemd container whose pct, pvesh, pveum,
// pvesm, pveam and pveversion are shims for a Sim in the test process, guests that are Docker
// containers, and the fake PVE API in a container of its own. The appliance tests (T10b) start it
// with startPVEWorld and run `sm install proxmox-lxc` on its Host.

const (
	pveSubnet  = "10.77.0.0/24" // the fake API's certificate is valid for 10.77.0.1 only
	pveAPIIP   = "10.77.0.1"
	pveSweepKV = "sm-e2e-pvesim=1"
)

// pveWorld is a simulated PVE host and everything it needs.
type pveWorld struct {
	t        *testing.T
	Network  string
	Host     *harness.Container // where the installer runs: the "PVE host"
	API      *harness.Container // the fake PVE API
	Sim      *pvesim.Sim
	Topology pvesim.Topology
	CAPEM    []byte // the CA of the API, also at /etc/pve/pve-root-ca.pem on Host
	admin    *pvesim.AdminClient
}

// pveOptions let a test shape the host before it starts.
type pveOptions struct {
	Topology func(*pvesim.Topology)
}

// The appliance installer supports linux/amd64 only. On an arm64 machine run the suite with
// SM_E2E_PVE_HOST_PLATFORM=linux/amd64: the PVE host container (where the installer runs, plain
// processes only) is then an emulated amd64 container and the guests stay native, running the
// amd64 sm the installer pushes through the emulation of user binaries. Where Docker is amd64
// (CI) nothing needs setting.
func pveHostPlatform() string { return os.Getenv("SM_E2E_PVE_HOST_PLATFORM") }

// hostArch is the architecture of the binaries that run on the PVE host container.
func hostArch(t testing.TB) string {
	t.Helper()
	if pveHostPlatform() == "linux/amd64" {
		return "amd64"
	}
	return harness.DockerArch(t)
}

// hostImage is the Debian image of the PVE host container.
func hostImage(t testing.TB) string {
	t.Helper()
	if pveHostPlatform() == "" {
		return harness.Image(t)
	}
	tag := harness.HostImage + "-" + strings.ReplaceAll(pveHostPlatform(), "/", "-")
	if _, err := m3Once("host-image-"+tag, func() (string, error) {
		res, err := harness.Docker(context.Background(), "", "build", "--quiet", "--platform", pveHostPlatform(), "--tag", tag,
			filepath.Join(harness.RepoRoot(), "test", "e2e", "image"))
		return tag, commandFailure("build "+tag, res, err)
	}); err != nil {
		t.Fatal(err)
	}
	return tag
}

// buildTool builds a Go tool for the containers (keys starting with "host-": for the PVE host's).
func buildTool(t *testing.T, key, pkg string) string {
	t.Helper()
	arch := harness.DockerArch(t)
	if strings.HasPrefix(key, "host-") {
		arch = hostArch(t)
	}
	path, err := m3Once(key, func() (string, error) {
		out := filepath.Join(harness.WorkDir(), key+"-"+arch)
		env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
		res, err := harness.Run(context.Background(), harness.RepoRoot(), env, "", "go", "build", "-trimpath", "-o", out, pkg)
		return out, commandFailure("go build "+pkg, res, err)
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func startPVEWorld(t *testing.T, opts pveOptions) *pveWorld {
	t.Helper()
	ctx := context.Background()
	w := &pveWorld{t: t, Topology: pvesim.DefaultTopology()}
	if opts.Topology != nil {
		opts.Topology(&w.Topology)
	}
	w.Network = "sm-e2e-pve-" + harness.Suffix()
	if res, err := harness.Docker(ctx, "", "network", "create", "--subnet", pveSubnet, "--gateway", "10.77.0.254", w.Network); err != nil || res.Code != 0 {
		t.Fatalf("create the PVE network %s (the fake API must sit at %s, so only one simulated host can run at a time): %v\n%s", pveSubnet, pveAPIIP, err, res.Output())
	}
	t.Cleanup(func() { _, _ = harness.Docker(ctx, "", "network", "rm", w.Network) })

	engine := pvesim.DockerEngine{Image: harness.Image(t), Network: w.Network, Label: pveSweepKV}
	if pveHostPlatform() != "" {
		// Rosetta cannot run a service with MemoryDenyWriteExecute: relax it for the emulated sm.
		engine.AfterStart = [][]string{{"sh", "-c", "mkdir -p /etc/systemd/system/supermgmt.service.d && " +
			"printf '[Service]\\nMemoryDenyWriteExecute=no\\n' > /etc/systemd/system/supermgmt.service.d/emulation.conf"}}
	}
	t.Cleanup(func() { engine.RemoveLabelled(ctx) })

	w.startAPI()
	w.startHost(engine)
	return w
}

func (w *pveWorld) startAPI() {
	t, ctx := w.t, context.Background()
	topo, err := json.Marshal(w.Topology)
	if err != nil {
		t.Fatal(err)
	}
	topoFile := harness.WriteHostFile(t, t.TempDir(), "topology.json", topo, 0o644)
	w.API = harness.Start(t, harness.RunOptions{
		Image: harness.Image(t), Cmd: []string{"/fakeapi"}, Publish: []string{"8007"},
		Files: map[string]string{"/fakeapi": buildTool(t, "fakeapi", "./test/e2e/pvesim/fakeapi"), "/topology.json": topoFile},
	})
	harness.MustDocker(t, "network", "connect", "--ip", pveAPIIP, "--alias", "pve-api", w.Network, w.API.Name)
	w.admin = pvesim.NewAdminClient(fmt.Sprintf("http://127.0.0.1:%d", w.API.HostPort("8007")))
	deadline := time.Now().Add(30 * time.Second)
	for !w.admin.Ready(ctx) {
		if time.Now().After(deadline) {
			t.Fatalf("the fake PVE API did not start\n%s", w.API.Logs())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if w.CAPEM, err = w.admin.CA(ctx); err != nil || len(w.CAPEM) == 0 {
		t.Fatalf("read the CA of the fake PVE API: %v", err)
	}
}

func (w *pveWorld) startHost(engine pvesim.DockerEngine) {
	t, ctx := w.t, context.Background()
	name := "sm-e2e-pvehost-" + harness.Suffix()
	create := []string{"create", "--name", name}
	if pveHostPlatform() != "" {
		create = append(create, "--platform", pveHostPlatform())
	}
	harness.MustDocker(t, append(create, "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock",
		"--network", w.Network, "--hostname", w.Topology.Node, "--add-host", "host.docker.internal:host-gateway", hostImage(t))...)
	t.Cleanup(func() { _, _ = harness.Docker(ctx, "", "rm", "--force", "--volumes", name) })
	w.Host = harness.Adopt(t, name)
	harness.MustDocker(t, "start", name)
	w.Host.WaitSystemd(ctx)

	w.Sim = pvesim.New(w.Topology, engine, w.admin, name)
	token := harness.Suffix() + harness.Suffix()
	url := w.serveSim(token)

	c := w.Host
	shim := buildTool(t, "host-pvesim-shim", "./test/e2e/pvesim/shim")
	c.MustExec(ctx, "mkdir", "-p", "/usr/local/lib/pvesim", "/etc/pvesim", "/etc/pve")
	c.CopyRoot(ctx, shim, "/usr/local/lib/pvesim/shim")
	c.MustExec(ctx, "chmod", "0755", "/usr/local/lib/pvesim/shim")
	for path := range map[string]bool{
		"/usr/sbin/pct": true, "/usr/sbin/pveam": true, "/usr/sbin/pveum": true, "/usr/sbin/pvesm": true,
		"/usr/bin/pvesh": true, "/usr/bin/pveversion": true,
	} {
		c.MustExec(ctx, "ln", "-s", "/usr/local/lib/pvesim/shim", path)
	}
	controller, _ := json.Marshal(map[string]string{"url": url, "token": token})
	c.WriteFile(ctx, "/etc/pvesim/controller.json", controller, "0600")
	c.WriteFile(ctx, "/etc/pve/pve-root-ca.pem", w.CAPEM, "0644")
	if got := c.MustExec(ctx, "/usr/bin/pveversion"); !strings.HasPrefix(got, "pve-manager/"+w.Topology.Version+"/") {
		t.Fatalf("pveversion on the simulated host printed %q", got)
	}
}

// serveSim serves the Sim on every interface of the test machine and returns the URL the shims
// use to reach it from inside the PVE host container.
func (w *pveWorld) serveSim(token string) string {
	t := w.t
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: w.Sim.Handler(token), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return fmt.Sprintf("http://host.docker.internal:%d", ln.Addr().(*net.TCPAddr).Port)
}

// pve runs a Proxmox tool on the host the way the installer does: by absolute path with a clean
// environment.
func (w *pveWorld) pve(tool string, args ...string) harness.Result {
	w.t.Helper()
	path := map[string]string{
		"pct": "/usr/sbin/pct", "pveam": "/usr/sbin/pveam", "pveum": "/usr/sbin/pveum", "pvesm": "/usr/sbin/pvesm",
		"pvesh": "/usr/bin/pvesh", "pveversion": "/usr/bin/pveversion",
	}[tool]
	argv := append([]string{"env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", path}, args...)
	return w.Host.Exec(context.Background(), "", argv...)
}

func (w *pveWorld) mustPVE(tool string, args ...string) string {
	w.t.Helper()
	res := w.pve(tool, args...)
	if res.Code != 0 {
		w.t.Fatalf("%s %v exited %d\n%s", tool, args, res.Code, res.Output())
	}
	return res.Stdout
}

// ---- the harness tests (they run with the appliance job) ----

const debianTemplate = "debian-13-standard_13.1-1_amd64.tar.zst"

// TestM3_ApplianceHarnessShimRejectsWhatPVERejects
//
// The fidelity contract of the simulated host: an option the real tool does not have, a malformed
// value or a missing argument fails with exit 255 and a message, and changes nothing.
func TestM3_ApplianceHarnessShimRejectsWhatPVERejects(t *testing.T) {
	w := startPVEWorld(t, pveOptions{})
	cases := map[string][]string{
		"pct create --bogus":                {"pct", "create", "900", "local:vztmpl/" + debianTemplate, "--bogus", "1"},
		"pct start with a stray option":     {"pct", "start", "900", "--now"},
		"pct without a subcommand":          {"pct"},
		"pveum role with a bogus privilege": {"pveum", "role", "add", "r", "--privs", "Bogus.Priv"},
		"pvesh --bogus":                     {"pvesh", "get", "/cluster/nextid", "--bogus", "1"},
		"pveam download of an unknown name": {"pveam", "download", "local", "no-such-template.tar.zst"},
		"pvesm status --bogus":              {"pvesm", "status", "--bogus", "1"},
		"pveversion --bogus":                {"pveversion", "--bogus"},
	}
	for name, argv := range cases {
		t.Run(name, func(t *testing.T) {
			res := w.pve(argv[0], argv[1:]...)
			if res.Code != 255 || strings.TrimSpace(res.Stderr) == "" {
				t.Fatalf("exit %d, stderr %q; want 255 and a message", res.Code, res.Stderr)
			}
		})
	}
	if list := w.mustPVE("pct", "list"); strings.Count(list, "\n") != 1 {
		t.Errorf("refused commands changed the host:\n%s", list)
	}
}

// TestM3_ApplianceHarnessGuestIsADockerContainer
//
// pct create/start/exec/push/stop/destroy drive a systemd container on the test network; the
// installer's `pct create` vector is accepted and read back as unprivileged without mounts.
func TestM3_ApplianceHarnessGuestIsADockerContainer(t *testing.T) {
	w := startPVEWorld(t, pveOptions{})
	w.mustPVE("pveam", "download", "local", debianTemplate)
	w.mustPVE("pct", "create", "900", "local:vztmpl/"+debianTemplate,
		"--hostname", "supermgmt", "--cores", "2", "--memory", "2048", "--swap", "512", "--rootfs", "local-lvm:16",
		"--net0", "name=eth0,bridge=vmbr0,ip=dhcp", "--unprivileged", "1", "--features", "nesting=0,keyctl=0", "--onboot", "1",
		"--tags", "supermgmt;appliance", "--description", "SuperMgmt appliance")
	conf := w.mustPVE("pct", "config", "900")
	for _, want := range []string{"unprivileged: 1", "features: nesting=0,keyctl=0", "tags: supermgmt;appliance"} {
		if !strings.Contains(conf, want) {
			t.Errorf("pct config lacks %q:\n%s", want, conf)
		}
	}

	if res := w.pve("pct", "exec", "900", "--", "/bin/true"); res.Code == 0 {
		t.Error("pct exec on a stopped guest succeeded")
	}
	w.mustPVE("pct", "start", "900")
	if list := w.mustPVE("pct", "list"); !strings.Contains(list, "900") || !strings.Contains(list, "running") {
		t.Errorf("pct list after start:\n%s", list)
	}
	if got := strings.TrimSpace(w.mustPVE("pct", "exec", "900", "--", "/usr/bin/systemctl", "is-system-running")); got != "running" && got != "degraded" {
		t.Errorf("systemd in the guest is %q", got)
	}
	if res := w.pve("pct", "exec", "900", "--", "/bin/sh", "-c", "exit 7"); res.Code != 7 {
		t.Errorf("pct exec of a failing command exited %d, want its status 7", res.Code)
	}

	w.mustPVE("pct", "push", "900", "/etc/pve/pve-root-ca.pem", "/root/pve-ca.pem", "--perms", "0640", "--user", "root", "--group", "adm")
	if got := strings.TrimSpace(w.mustPVE("pct", "exec", "900", "--", "/usr/bin/stat", "-c", "%a %U:%G", "/root/pve-ca.pem")); got != "640 root:adm" {
		t.Errorf("pushed file has mode/owner %q, want 640 root:adm", got)
	}
	if got := w.mustPVE("pct", "exec", "900", "--", "/bin/cat", "/root/pve-ca.pem"); got != string(w.CAPEM) {
		t.Error("the pushed file differs from the source")
	}

	if res := w.pve("pct", "destroy", "900"); res.Code != 255 {
		t.Errorf("destroying a running guest: exit %d, want 255", res.Code)
	}
	w.mustPVE("pct", "stop", "900")
	w.mustPVE("pct", "destroy", "900")
	left := harness.MustDocker(t, "ps", "--all", "--quiet", "--filter", "label="+pveSweepKV)
	if left != "" {
		t.Errorf("the destroyed guest left a container behind: %s", left)
	}
}

// TestM3_ApplianceHarnessTokenPrivilegesReachTheAPI
//
// A token made with pveum authenticates against the fake PVE API at the host's bridge address,
// from the host and from inside a guest, and sees guests only through the ACLs pveum granted.
func TestM3_ApplianceHarnessTokenPrivilegesReachTheAPI(t *testing.T) {
	w := startPVEWorld(t, pveOptions{})
	ctx := context.Background()

	bridges := w.mustPVE("pvesh", "get", "/nodes/"+w.Topology.Node+"/network", "--type", "any_bridge", "--output-format", "json")
	if !strings.Contains(bridges, `"address":"`+pveAPIIP+`"`) {
		t.Fatalf("the bridge does not report the API address %s:\n%s", pveAPIIP, bridges)
	}

	w.mustPVE("pveam", "download", "local", debianTemplate)
	w.mustPVE("pct", "create", "900", "local:vztmpl/"+debianTemplate, "--hostname", "supermgmt", "--rootfs", "local-lvm:8",
		"--net0", "name=eth0,bridge=vmbr0,ip=dhcp", "--unprivileged", "1", "--tags", "supermgmt")
	w.mustPVE("pct", "start", "900")

	w.mustPVE("pveum", "user", "add", "smaudit-1@pve", "--comment", "SuperMgmt")
	w.mustPVE("pveum", "role", "add", "SMAudit-1", "--privs", "VM.Audit,Sys.Audit,Datastore.Audit,Pool.Audit")
	out := w.mustPVE("pveum", "user", "token", "add", "smaudit-1@pve", "supermgmt", "--privsep", "1", "--output-format", "json")
	var token struct{ Value string }
	if err := json.Unmarshal([]byte(out), &token); err != nil || token.Value == "" {
		t.Fatalf("token reply %q: %v", out, err)
	}
	header := "Authorization: PVEAPIToken=smaudit-1@pve!supermgmt=" + token.Value
	get := func(c *harness.Container, path string) harness.Result {
		return c.Exec(ctx, "", "curl", "-sS", "--max-time", "10", "--cacert", "/etc/pve/pve-root-ca.pem", "-H", header,
			"-w", "\n%{http_code}", "https://"+pveAPIIP+":8006/api2/json"+path)
	}

	version := get(w.Host, "/version")
	if !strings.HasSuffix(strings.TrimSpace(version.Stdout), "200") {
		t.Fatalf("GET /version with the new token from the host: %s", version.Output())
	}
	if res := get(w.Host, "/cluster/resources?type=vm"); strings.Contains(res.Stdout, `"vmid":900`) {
		t.Errorf("a token without ACLs sees the guest:\n%s", res.Stdout)
	}

	w.mustPVE("pveum", "acl", "modify", "/", "--roles", "SMAudit-1", "--users", "smaudit-1@pve")
	w.mustPVE("pveum", "acl", "modify", "/", "--roles", "SMAudit-1", "--tokens", "smaudit-1@pve!supermgmt")
	if res := get(w.Host, "/cluster/resources?type=vm"); !strings.Contains(res.Stdout, `"vmid":900`) {
		t.Errorf("a token granted VM.Audit does not see the guest:\n%s", res.Output())
	}

	w.mustPVE("pct", "push", "900", "/etc/pve/pve-root-ca.pem", "/etc/pve-ca.pem", "--perms", "0644")
	inside := w.mustPVE("pct", "exec", "900", "--", "/usr/bin/curl", "-sS", "--max-time", "10", "--cacert", "/etc/pve-ca.pem",
		"-H", header, "-o", "/dev/null", "-w", "%{http_code}", "https://"+pveAPIIP+":8006/api2/json/version")
	if strings.TrimSpace(inside) != "200" {
		t.Errorf("GET /version from inside the guest: HTTP %s", inside)
	}

	w.mustPVE("pveum", "user", "token", "remove", "smaudit-1@pve", "supermgmt")
	if res := get(w.Host, "/cluster/resources?type=vm"); strings.Contains(res.Stdout, `"vmid":900`) {
		t.Errorf("a removed token still sees the guest:\n%s", res.Stdout)
	}
}
