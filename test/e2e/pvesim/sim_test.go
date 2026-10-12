package pvesim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// memEngine is a container runtime in memory: files written by exec are not modelled, commands
// succeed, and the calls are recorded.
type memEngine struct {
	calls   []string
	files   map[string][]byte // path -> content, for `cat` in the host container
	failing map[string]bool   // call verb that fails
}

func (m *memEngine) record(verb, name string) error {
	m.calls = append(m.calls, verb+" "+name)
	if m.failing[verb] {
		return fmt.Errorf("injected %s failure", verb)
	}
	return nil
}

func (m *memEngine) Create(_ context.Context, name string, _ ContainerSpec) error {
	return m.record("create", name)
}
func (m *memEngine) Start(_ context.Context, name string) error  { return m.record("start", name) }
func (m *memEngine) Stop(_ context.Context, name string) error   { return m.record("stop", name) }
func (m *memEngine) Remove(_ context.Context, name string) error { return m.record("remove", name) }
func (m *memEngine) Exec(_ context.Context, name string, argv []string, _ []byte) (ExecResult, error) {
	m.calls = append(m.calls, "exec "+name+" "+strings.Join(argv, " "))
	if argv[0] == "cat" {
		data, ok := m.files[argv[1]]
		if !ok {
			return ExecResult{Code: 1}, nil
		}
		return ExecResult{Stdout: data}, nil
	}
	return ExecResult{}, nil
}

// recordingAPI keeps what the tools mirrored into the fake API.
type recordingAPI struct {
	guests map[int]FakeGuest
	grants map[string]bool // subject|path|role
	roles  map[string][]string
	tokens map[string]bool
}

func newRecordingAPI() *recordingAPI {
	return &recordingAPI{guests: map[int]FakeGuest{}, grants: map[string]bool{}, roles: map[string][]string{}, tokens: map[string]bool{}}
}

func (a *recordingAPI) PutGuest(_ context.Context, g FakeGuest) error {
	a.guests[g.VMID] = g
	return nil
}

func (a *recordingAPI) RemoveGuest(_ context.Context, id int) error { delete(a.guests, id); return nil }

func (a *recordingAPI) SetRole(_ context.Context, n string, p []string) error {
	a.roles[n] = p
	return nil
}

func (a *recordingAPI) AddToken(_ context.Context, u, id string, _ bool) (string, error) {
	a.tokens[u+"!"+id] = true
	return "s3cret-" + id, nil
}

func (a *recordingAPI) Grant(_ context.Context, s, p, r string, _ bool) error {
	a.grants[s+"|"+p+"|"+r] = true
	return nil
}

func (a *recordingAPI) Revoke(_ context.Context, s, p, r string) error {
	delete(a.grants, s+"|"+p+"|"+r)
	return nil
}

type rig struct {
	sim *Sim
	eng *memEngine
	api *recordingAPI
}

func newRig() *rig {
	eng := &memEngine{files: map[string][]byte{"/root/ca.pem": []byte("pem")}, failing: map[string]bool{}}
	api := newRecordingAPI()
	return &rig{sim: New(DefaultTopology(), eng, api, "pvehost"), eng: eng, api: api}
}

func (r *rig) run(tool string, args ...string) Response {
	return r.sim.Run(context.Background(), Request{Tool: tool, Args: args})
}

func (r *rig) mustRun(t *testing.T, tool string, args ...string) string {
	t.Helper()
	res := r.run(tool, args...)
	if res.Code != 0 {
		t.Fatalf("%s %v exited %d: %s", tool, args, res.Code, res.Stderr)
	}
	return string(res.Stdout)
}

const debian = "debian-13-standard_13.1-1_amd64.tar.zst"

// createArgs is the argument vector of the installer's `pct create` (ADR-0026 "Container shape").
func createArgs(vmid string, extra ...string) []string {
	return append([]string{
		"create", vmid, "local:vztmpl/" + debian,
		"--hostname", "supermgmt", "--cores", "2", "--memory", "2048", "--swap", "512",
		"--rootfs", "local-lvm:16", "--net0", "name=eth0,bridge=vmbr0,ip=dhcp",
		"--unprivileged", "1", "--features", "nesting=0,keyctl=0", "--onboot", "1",
		"--tags", "supermgmt;appliance", "--description", "SuperMgmt appliance",
	}, extra...)
}

func (r *rig) createGuest(t *testing.T, vmid string, extra ...string) {
	t.Helper()
	r.mustRun(t, "pveam", "download", "local", debian)
	r.mustRun(t, "pct", createArgs(vmid, extra...)...)
}

func TestToolsRejectUnknownOptionsAndSubcommands(t *testing.T) {
	r := newRig()
	r.createGuest(t, "900")
	cases := []struct {
		name string
		tool string
		args []string
	}{
		{"pct create unknown option", "pct", createArgs("901", "--bogus", "1")},
		{"pct create one dash", "pct", createArgs("901", "-x", "1")},
		{"pct start unknown option", "pct", []string{"start", "900", "--now"}},
		{"pct unknown subcommand", "pct", []string{"reboot", "900"}},
		{"pct config unknown option", "pct", []string{"config", "900", "--json"}},
		{"pct push unknown option", "pct", []string{"push", "900", "/root/ca.pem", "/tmp/ca.pem", "--mode", "0644"}},
		{"pct push malformed perms", "pct", []string{"push", "900", "/root/ca.pem", "/tmp/ca.pem", "--perms", "rw-r--r--"}},
		{"pct missing argument", "pct", []string{"start"}},
		{"pct extra argument", "pct", []string{"start", "900", "901"}},
		{"pveum unknown option", "pveum", []string{"user", "add", "u@pve", "--bogus", "x"}},
		{"pveum role with unknown privilege", "pveum", []string{"role", "add", "r", "--privs", "VM.Audit,Bogus.Priv"}},
		{"pveum acl without roles", "pveum", []string{"acl", "modify", "/", "--users", "root@pam"}},
		{"pveum bad realm", "pveum", []string{"user", "add", "u@ldap"}},
		{"pveum unknown subcommand", "pveum", []string{"user", "frobnicate"}},
		{"pvesh unknown option", "pvesh", []string{"get", "/cluster/nextid", "--bogus", "1"}},
		{"pvesh vmid out of range", "pvesh", []string{"get", "/cluster/nextid", "--vmid", "5"}},
		{"pvesh unknown path", "pvesh", []string{"get", "/cluster/bogus"}},
		{"pvesh network type outside the enumeration", "pvesh", []string{"get", "/nodes/pve/network", "--type", "wifi"}},
		{"pvesm unknown option", "pvesm", []string{"status", "--bogus", "1"}},
		{"pveam unknown option", "pveam", []string{"available", "--bogus", "x"}},
		{"pveversion unknown option", "pveversion", []string{"--bogus"}},
		{"unknown tool", "qm", []string{"list"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := r.run(tc.tool, tc.args...)
			if res.Code != 255 || len(res.Stderr) == 0 {
				t.Fatalf("exit %d, stderr %q; want 255 and a message", res.Code, res.Stderr)
			}
			if strings.Contains(tc.name, "unknown option") && !strings.Contains(strings.ToLower(string(res.Stderr)), "unknown option") {
				t.Fatalf("refused for another reason than the unknown option: %q", res.Stderr)
			}
		})
	}
}

func TestPctCreateRefusesWhatPVERefuses(t *testing.T) {
	r := newRig()
	r.mustRun(t, "pveam", "download", "local", debian)
	t.Run("template that was never downloaded", func(t *testing.T) {
		res := r.run("pct", "create", "900", "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", "--hostname", "x")
		if res.Code != 255 || !strings.Contains(string(res.Stderr), "does not exist") {
			t.Fatalf("exit %d: %s", res.Code, res.Stderr)
		}
	})
	t.Run("rootfs on a storage without rootdir content", func(t *testing.T) {
		args := createArgs("900")
		args[indexOf(args, "--rootfs")+1] = "local:8"
		if res := r.run("pct", args...); res.Code != 255 || !strings.Contains(string(res.Stderr), "container directories") {
			t.Fatalf("exit %d: %s", res.Code, res.Stderr)
		}
	})
	t.Run("a bridge that does not exist", func(t *testing.T) {
		args := createArgs("900")
		args[indexOf(args, "--net0")+1] = "name=eth0,bridge=vmbr9,ip=dhcp"
		if res := r.run("pct", args...); res.Code != 255 || !strings.Contains(string(res.Stderr), "bridge") {
			t.Fatalf("exit %d: %s", res.Code, res.Stderr)
		}
	})
	t.Run("an unknown network property", func(t *testing.T) {
		args := createArgs("900")
		args[indexOf(args, "--net0")+1] = "name=eth0,bridge=vmbr0,speed=fast"
		if res := r.run("pct", args...); res.Code != 255 {
			t.Fatalf("exit %d: %s", res.Code, res.Stderr)
		}
	})
	t.Run("an unknown feature", func(t *testing.T) {
		args := createArgs("900")
		args[indexOf(args, "--features")+1] = "nesting=0,telepathy=1"
		if res := r.run("pct", args...); res.Code != 255 {
			t.Fatalf("exit %d: %s", res.Code, res.Stderr)
		}
	})
	t.Run("an existing VMID", func(t *testing.T) {
		r.mustRun(t, "pct", createArgs("900")...)
		if res := r.run("pct", createArgs("900")...); res.Code != 255 || !strings.Contains(string(res.Stderr), "already exists") {
			t.Fatalf("exit %d: %s", res.Code, res.Stderr)
		}
	})
	if got := len(r.eng.calls); got != 1 {
		t.Errorf("a refused create reached the container runtime: %v", r.eng.calls)
	}
}

func indexOf(list []string, v string) int {
	for i, e := range list {
		if e == v {
			return i
		}
	}
	return -1
}

func TestGuestLifecycleFollowsPVEStateMachine(t *testing.T) {
	r := newRig()
	r.createGuest(t, "900")

	if got := r.mustRun(t, "pct", "list"); !strings.Contains(got, "stopped") || !strings.Contains(got, "supermgmt") {
		t.Errorf("pct list after create:\n%s", got)
	}
	if res := r.run("pct", "stop", "900"); res.Code != 255 {
		t.Errorf("stopping a stopped guest: exit %d, want 255", res.Code)
	}
	r.mustRun(t, "pct", "start", "900")
	if res := r.run("pct", "start", "900"); res.Code != 255 {
		t.Errorf("starting a running guest: exit %d, want 255", res.Code)
	}
	if res := r.run("pct", "destroy", "900"); res.Code != 255 || !strings.Contains(string(res.Stderr), "running") {
		t.Errorf("destroying a running guest: exit %d: %s", res.Code, res.Stderr)
	}
	if got := r.api.guests[900].Status; got != "running" {
		t.Errorf("the fake API lists the guest as %q, want running", got)
	}
	r.mustRun(t, "pct", "stop", "900")
	r.mustRun(t, "pct", "destroy", "900")
	if _, still := r.api.guests[900]; still {
		t.Error("the fake API still lists the destroyed guest")
	}
	if res := r.run("pct", "config", "900"); res.Code != 255 {
		t.Errorf("config of a destroyed guest: exit %d, want 255", res.Code)
	}
}

func TestPctConfigReadbackShowsWhatWasCreated(t *testing.T) {
	r := newRig()
	r.createGuest(t, "900")
	conf := r.mustRun(t, "pct", "config", "900")
	for _, want := range []string{"unprivileged: 1", "features: nesting=0,keyctl=0", "onboot: 1", "tags: supermgmt;appliance", "hostname: supermgmt", "description: SuperMgmt appliance"} {
		if !strings.Contains(conf, want) {
			t.Errorf("pct config lacks %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "\nmp") || strings.Contains(conf, "lxc.") {
		t.Errorf("pct config shows mounts or raw lxc keys nobody asked for:\n%s", conf)
	}

	r.createGuest(t, "901", "--mp0", "/srv/data,mp=/data")
	if conf := r.mustRun(t, "pct", "config", "901"); !strings.Contains(conf, "mp0: ") {
		t.Errorf("a mount passed to pct create must be visible in pct config:\n%s", conf)
	}
}

func TestNextIDSkipsGuestsInUse(t *testing.T) {
	r := newRig()
	r.createGuest(t, "900")
	if res := r.run("pvesh", "get", "/cluster/nextid", "--vmid", "900"); res.Code != 255 {
		t.Errorf("nextid for a VMID in use: exit %d, want 255", res.Code)
	}
	if got := strings.TrimSpace(r.mustRun(t, "pvesh", "get", "/cluster/nextid", "--vmid", "901")); got != "901" {
		t.Errorf("nextid for a free VMID printed %q", got)
	}
}

func TestBridgesReportTheAddressOfTheAPI(t *testing.T) {
	r := newRig()
	out := r.mustRun(t, "pvesh", "get", "/nodes/pve/network", "--type", "any_bridge", "--output-format", "json")
	var rows []struct{ Iface, Address string }
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(rows) != 1 || rows[0].Iface != "vmbr0" || rows[0].Address != "10.77.0.1" {
		t.Errorf("bridges %+v, want vmbr0 at 10.77.0.1 only", rows)
	}
}

func TestTemplatesAreListedOnlyAfterDownload(t *testing.T) {
	r := newRig()
	if got := r.mustRun(t, "pveam", "list", "local"); strings.Contains(got, debian) {
		t.Errorf("a template that was never downloaded is listed:\n%s", got)
	}
	if res := r.run("pveam", "download", "local", "debian-99-standard_99.0-1_amd64.tar.zst"); res.Code != 255 {
		t.Errorf("downloading a template that is not on offer: exit %d, want 255", res.Code)
	}
	if res := r.run("pveam", "download", "local-lvm", debian); res.Code != 255 {
		t.Errorf("downloading to a storage without vztmpl content: exit %d, want 255", res.Code)
	}
	r.mustRun(t, "pveam", "download", "local", debian)
	if got := r.mustRun(t, "pveam", "list", "local"); !strings.Contains(got, "local:vztmpl/"+debian) {
		t.Errorf("the downloaded template is not listed:\n%s", got)
	}
	if got := r.mustRun(t, "pveam", "available", "--section", "system"); !strings.Contains(got, "system") || !strings.Contains(got, debian) {
		t.Errorf("pveam available:\n%s", got)
	}
}

func TestPushCopiesFromTheHostWithOwnerAndMode(t *testing.T) {
	r := newRig()
	r.createGuest(t, "900")
	if res := r.run("pct", "push", "900", "/root/ca.pem", "/tmp/ca.pem"); res.Code != 255 {
		t.Errorf("push to a stopped guest: exit %d, want 255", res.Code)
	}
	r.mustRun(t, "pct", "start", "900")
	if res := r.run("pct", "push", "900", "/root/missing", "/tmp/x"); res.Code != 255 {
		t.Errorf("push of a file that is not on the host: exit %d, want 255", res.Code)
	}
	r.mustRun(t, "pct", "push", "900", "/root/ca.pem", "/tmp/ca.pem", "--perms", "0640", "--user", "root", "--group", "adm")
	joined := strings.Join(r.eng.calls, "\n")
	for _, want := range []string{"chmod 0640 /tmp/ca.pem", "chown root:adm /tmp/ca.pem"} {
		if !strings.Contains(joined, want) {
			t.Errorf("push did not run %q; calls:\n%s", want, joined)
		}
	}
}

func TestPveumTokensAreMirroredAsGrants(t *testing.T) {
	r := newRig()
	r.mustRun(t, "pveum", "user", "add", "smaudit-1@pve", "--comment", "SuperMgmt")
	r.mustRun(t, "pveum", "role", "add", "SMAudit-1", "--privs", "VM.Audit,Sys.Audit")
	out := r.mustRun(t, "pveum", "user", "token", "add", "smaudit-1@pve", "sm", "--privsep", "1", "--output-format", "json")
	var token struct {
		Value string `json:"value"`
		Full  string `json:"full-tokenid"`
	}
	if err := json.Unmarshal([]byte(out), &token); err != nil || token.Value == "" || token.Full != "smaudit-1@pve!sm" {
		t.Fatalf("token reply %q: %v", out, err)
	}
	r.mustRun(t, "pveum", "acl", "modify", "/", "--roles", "SMAudit-1", "--tokens", "smaudit-1@pve!sm")
	r.mustRun(t, "pveum", "acl", "modify", "/", "--roles", "SMAudit-1", "--users", "smaudit-1@pve")
	if !r.api.grants["smaudit-1@pve!sm|/|SMAudit-1"] || !r.api.grants["smaudit-1@pve|/|SMAudit-1"] {
		t.Fatalf("grants not mirrored: %v", r.api.grants)
	}

	list := r.mustRun(t, "pveum", "acl", "list", "--output-format", "json")
	if !strings.Contains(list, `"ugid":"smaudit-1@pve!sm"`) || !strings.Contains(list, `"type":"token"`) {
		t.Errorf("acl list:\n%s", list)
	}
	if res := r.run("pveum", "acl", "list"); res.Code != 255 {
		t.Errorf("acl list without --output-format json: exit %d, want 255 (tables are not drawn)", res.Code)
	}

	r.mustRun(t, "pveum", "user", "token", "remove", "smaudit-1@pve", "sm")
	if r.api.grants["smaudit-1@pve!sm|/|SMAudit-1"] {
		t.Error("removing the token left its grant in the fake API")
	}
	r.mustRun(t, "pveum", "user", "delete", "smaudit-1@pve")
	if len(r.api.grants) != 0 {
		t.Errorf("deleting the user left grants: %v", r.api.grants)
	}
	if res := r.run("pveum", "user", "delete", "smaudit-1@pve"); res.Code != 255 {
		t.Errorf("deleting a user twice: exit %d, want 255", res.Code)
	}
}

func TestPveumRefusesDanglingReferences(t *testing.T) {
	r := newRig()
	r.mustRun(t, "pveum", "user", "add", "u@pve")
	cases := map[string][]string{
		"acl for a role that does not exist":   {"acl", "modify", "/", "--roles", "Nope", "--users", "u@pve"},
		"acl for a user that does not exist":   {"acl", "modify", "/", "--roles", "PVEAuditor", "--users", "ghost@pve"},
		"acl for a token that does not exist":  {"acl", "modify", "/", "--roles", "PVEAuditor", "--tokens", "u@pve!ghost"},
		"acl on a path PVE does not have":      {"acl", "modify", "/etc", "--roles", "PVEAuditor", "--users", "u@pve"},
		"token for a user that does not exist": {"user", "token", "add", "ghost@pve", "t", "--output-format", "json"},
		"deleting a built-in role":             {"role", "delete", "Administrator"},
		"creating a role twice":                {"role", "add", "PVEAuditor", "--privs", "VM.Audit"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if res := r.run("pveum", args...); res.Code != 255 {
				t.Fatalf("exit %d, want 255: %s", res.Code, res.Stderr)
			}
		})
	}
}

func TestPveversionPrintsTheManagerVersion(t *testing.T) {
	r := newRig()
	if got := r.mustRun(t, "pveversion"); !strings.HasPrefix(got, "pve-manager/9.0.3/") {
		t.Errorf("pveversion printed %q", got)
	}
}

func TestNodeStorageFiltersByContent(t *testing.T) {
	r := newRig()
	out := r.mustRun(t, "pvesh", "get", "/nodes/pve/storage", "--content", "rootdir", "--output-format", "json")
	if !strings.Contains(out, `"storage":"local-lvm"`) || strings.Contains(out, `"storage":"local"`) {
		t.Errorf("GET /nodes/pve/storage --content rootdir:\n%s", out)
	}
}

func TestNodeStorageRefusesAnotherNode(t *testing.T) {
	r := newRig()
	if res := r.run("pvesh", "get", "/nodes/other/storage", "--output-format", "json"); res.Code != 255 {
		t.Errorf("exit %d, want 255", res.Code)
	}
}

// The real pvesm has no JSON output: it prints a table and rejects --output-format.
func TestPvesmStatusHasNoJSONOutput(t *testing.T) {
	r := newRig()
	if res := r.run("pvesm", "status", "--output-format", "json"); res.Code != 255 || !strings.Contains(strings.ToLower(string(res.Stderr)), "unknown option") {
		t.Errorf("pvesm status --output-format json: exit %d, stderr %q; want 255 and unknown option", res.Code, res.Stderr)
	}
	table := r.mustRun(t, "pvesm", "status")
	if !strings.HasPrefix(table, "Name") || !strings.Contains(table, "local-lvm") {
		t.Errorf("pvesm status:\n%s", table)
	}
}

func TestFailingRuntimeFailsTheCommandAndLeavesNoGuest(t *testing.T) {
	r := newRig()
	r.eng.failing["create"] = true
	r.mustRun(t, "pveam", "download", "local", debian)
	if res := r.run("pct", createArgs("900")...); res.Code != 255 {
		t.Fatalf("create with a failing runtime: exit %d, want 255", res.Code)
	}
	if got := r.mustRun(t, "pct", "list"); strings.Contains(got, "900") {
		t.Errorf("a failed create left a guest:\n%s", got)
	}
	if len(r.api.guests) != 0 {
		t.Errorf("a failed create reached the fake API: %v", r.api.guests)
	}
}

func TestInjectedFaultsFailMatchingRunsBeforeOrAfterTheWork(t *testing.T) {
	r := newRig()
	r.mustRun(t, "pveam", "download", "local", debian)
	r.sim.Inject(Fault{Tool: "pct", Contains: "create 900", After: true, Stderr: "boom"})
	res := r.run("pct", createArgs("900")...)
	if res.Code != 255 || !strings.Contains(string(res.Stderr), "boom") {
		t.Fatalf("exit %d: %s", res.Code, res.Stderr)
	}
	if got := r.mustRun(t, "pct", "list"); !strings.Contains(got, "900") {
		t.Errorf("an After fault must leave the work done:\n%s", got)
	}

	r.sim.Inject(Fault{Tool: "pct", Contains: "start 900"})
	if res := r.run("pct", "start", "900"); res.Code != 255 {
		t.Fatalf("exit %d", res.Code)
	}
	if got := r.mustRun(t, "pct", "status", "900"); !strings.Contains(got, "stopped") {
		t.Errorf("a fault without After must not run the command:\n%s", got)
	}
	r.mustRun(t, "pct", "start", "900") // the fault was spent
	if calls := r.sim.Calls(); len(calls) == 0 || !strings.HasPrefix(calls[0], "pveam download") {
		t.Errorf("calls %v", calls)
	}
}
