package installer

import (
	"context"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func (w *aw) install(h provisionHooks) error {
	return New(w.deps(false)).provision(context.Background(), w.opts(), h)
}

// recoverStale runs the start of a later interactive run: stale journals only.
func (w *aw) recoverStale() error {
	w.failAt = 0
	p, err := New(w.deps(true)).newProvision(w.opts(), fastHooks())
	if err != nil {
		return err
	}
	return p.recoverStale(context.Background())
}

func (w *aw) opIndex(prefix string) int {
	return slices.IndexFunc(w.opLog, func(op string) bool { return strings.HasPrefix(op, prefix) })
}

func (w *aw) mustInstall(t *testing.T) {
	t.Helper()
	if err := w.install(fastHooks()); err != nil {
		t.Fatalf("install: %v\noutput:\n%s", err, w.out.String())
	}
}

func (w *aw) oursLeft() []string {
	var left []string
	for id, g := range w.guests {
		if !g.foreign {
			left = append(left, "guest "+strconv.Itoa(id))
		}
	}
	for k, v := range w.users {
		if v == "ours" {
			left = append(left, "user "+k)
		}
	}
	for k, v := range w.roles {
		if v == "ours" {
			left = append(left, "role "+k)
		}
	}
	for k, v := range w.tokens {
		if v == "ours" {
			left = append(left, "token "+k)
		}
	}
	for a := range w.acls {
		if strings.HasPrefix(a.User, "sm-") || strings.HasPrefix(a.Token, "sm-") {
			left = append(left, "acl "+aclName(a))
		}
	}
	return left
}

func TestProxmoxLXC_InstallsAndCommits(t *testing.T) {
	w := newAW(t)
	w.mustInstall(t)

	if len(w.oursLeft()) != 1+1+2+1+4 { // guest, user, 2 roles, token, 4 ACLs
		t.Fatalf("created resources: %v", w.oursLeft())
	}
	if got := w.hostPaths("/var/tmp/supermgmt-installer-"); len(got) != 0 {
		t.Errorf("journal left behind: %v", got)
	}
	if got := w.hostPaths(appliancesDir + "/"); len(got) != 1 {
		t.Errorf("appliance records: %v", got)
	}
	if !w.ct.enabled || !w.ct.imported {
		t.Errorf("enabled=%t imported=%t", w.ct.enabled, w.ct.imported)
	}
	out := w.out.String()
	for _, want := range []string{"BOOT-1234", "BEGIN CERTIFICATE", "sha256", "sm profile add"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if len(w.violations) > 0 {
		t.Errorf("violations: %v", w.violations)
	}
	if leaks := w.leaks(); len(leaks) > 0 {
		t.Errorf("token leaked: %v", leaks)
	}
	if w.lastProbe.ServerName != w.ct.ip.String() || len(w.lastProbe.RootPEM) == 0 {
		t.Errorf("readiness probe %+v", w.lastProbe)
	}
	w.checkBoot()
	if len(w.violations) > 0 {
		t.Errorf("violations: %v", w.violations)
	}
}

func TestProxmoxLXC_PowerOffOmitsThePowerRole(t *testing.T) {
	w := newAW(t)
	o := w.opts()
	o.Appliance.Power = false
	if err := New(w.deps(false)).provision(context.Background(), o, fastHooks()); err != nil {
		t.Fatal(err)
	}
	for r := range w.roles {
		if strings.HasPrefix(r, "SMPower-") {
			t.Errorf("power role %s created with power disabled", r)
		}
	}
	if len(w.oursLeft()) != 1+1+1+1+2 {
		t.Errorf("created: %v", w.oursLeft())
	}
}

func TestProxmoxLXC_PowerRoleRepeatsAuditBecauseDeeperACLsReplaceInherited(t *testing.T) {
	w := newAW(t)
	w.mustInstall(t)
	var power, audit string
	for _, op := range w.opLog {
		switch {
		case strings.HasPrefix(op, "pve.createrole SMPower-"):
			power = op
		case strings.HasPrefix(op, "pve.createrole SMAudit-"):
			audit = op
		}
	}
	if !strings.HasSuffix(power, " VM.Audit,VM.PowerMgmt") || !strings.HasSuffix(audit, " VM.Audit,Sys.Audit,Datastore.Audit,Pool.Audit") {
		t.Fatalf("roles: %q / %q", audit, power)
	}
	for a := range w.acls {
		if strings.HasPrefix(a.Role, "SMPower-") && a.Path != "/vms" || strings.HasPrefix(a.Role, "SMAudit-") && a.Path != "/" {
			t.Errorf("ACL %+v on the wrong path", a)
		}
	}
}

func TestProxmoxLXC_StepOrderKeepsTheUnitDisabledUntilTheCredentialIsIn(t *testing.T) {
	w := newAW(t)
	w.mustInstall(t)
	order := []string{
		"pve.create", "ct.exec /usr/bin/mkdir -m 0700 " + stageDir, "pve.push " + stagedBinary, "ct.exec " + stagedBinary + " install server", "ct.exec /usr/local/bin/sm server init",
		"ct.exec /usr/bin/stat -f", "ct.exec /usr/bin/install -d", "ct.exec /usr/local/bin/sm providers check --offline --tls-only",
		"pve.createuser", "pve.addtoken", "host.write", "pve.push /run/supermgmt-bootstrap/pve-token",
		"ct.exec /usr/local/bin/sm secrets import", "ct.exec /usr/bin/tee /etc/supermgmt/config.yaml",
		"ct.exec /usr/local/bin/sm providers check --offline pve", "ct.exec /usr/bin/systemctl enable --now",
	}
	cursor := 0
	for _, prefix := range order {
		i := slices.IndexFunc(w.opLog[cursor:], func(op string) bool { return strings.HasPrefix(op, prefix) })
		if i < 0 {
			t.Fatalf("%q missing or out of order after op %d", prefix, cursor)
		}
		cursor += i + 1
	}
	enables := 0
	for _, op := range w.opLog {
		if strings.Contains(op, "systemctl enable") {
			enables++
		}
	}
	if enables != 1 {
		t.Errorf("systemctl enable ran %d times", enables)
	}
}

func TestProxmoxLXC_NoTokenBeforeBootstrapDirIsVerified(t *testing.T) {
	w := newAW(t)
	w.mustInstall(t)
	token := w.opIndex("pve.addtoken")
	for _, before := range []string{"ct.exec /usr/bin/stat -f -c %T /run", "ct.exec /usr/bin/id -u supermgmt", "ct.exec /usr/bin/install -d -m 0700 -o supermgmt", "ct.exec /usr/local/bin/sm providers check --offline --tls-only"} {
		if i := w.opIndex(before); i < 0 || i > token {
			t.Errorf("%q (op %d) must precede the token (op %d)", before, i, token)
		}
	}
}

func TestProxmoxLXC_TmpfsMissingRefusesBeforeAnyToken(t *testing.T) {
	w := newAW(t)
	err := w.installWithoutRunTmpfs()
	if exitCodeOf(t, err) != ExitConfiguration {
		t.Fatalf("err = %v", err)
	}
	if w.opIndex("pve.addtoken") >= 0 || len(w.oursLeft()) != 0 {
		t.Errorf("token created or resources left: %v", w.oursLeft())
	}
}

func (w *aw) installWithoutRunTmpfs() error {
	d := w.deps(false)
	d.PVE = notTmpfs{w}
	return New(d).provision(context.Background(), w.opts(), fastHooks())
}

type notTmpfs struct{ *aw }

func (n notTmpfs) Exec(ctx context.Context, vmid int, user string, argv []string, stdin io.Reader, sensitive bool) ([]byte, error) {
	if len(argv) > 1 && argv[1] == "-f" {
		return []byte("ext4\n"), nil
	}
	return n.aw.Exec(ctx, vmid, user, argv, stdin, sensitive)
}

func TestProxmoxLXC_CreateIsUnprivilegedWithoutMounts(t *testing.T) {
	args, err := createArgs(GuestSpec{
		VMID: 900, Hostname: "supermgmt", Template: "local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst", Storage: "local-lvm",
		DiskGiB: 16, Cores: 2, MemoryMiB: 2048, SwapMiB: 512, Network: GuestNetwork{Bridge: "vmbr0", DHCP: true},
		Tags: []string{"supermgmt"}, Description: "supermgmt install ab12cd34",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" --unprivileged 1 ", " --features nesting=0,keyctl=0 ", " --onboot 1 ", " --tags supermgmt ", " --net0 name=eth0,bridge=vmbr0,ip=dhcp "} {
		if !strings.Contains(joined, want) {
			t.Errorf("create argv lacks %q: %s", want, joined)
		}
	}
	for _, banned := range []string{" --mp", "lxc.", " --privileged"} {
		if strings.Contains(joined, banned) {
			t.Errorf("create argv has %q: %s", banned, joined)
		}
	}
}

func TestProxmoxLXC_ReadbackMismatchRollsBack(t *testing.T) {
	shapes := map[string]func(*fakeGuest){
		"privileged": func(g *fakeGuest) { g.unpriv = false },
		"nesting":    func(g *fakeGuest) { g.features["nesting"] = "1" },
		"mount":      func(g *fakeGuest) { g.mounts = []string{"mp0"} },
		"raw lxc":    func(g *fakeGuest) { g.raw = []string{"lxc.cgroup2.devices.allow"} },
		"no tag":     func(g *fakeGuest) { g.tags = nil },
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			w := newAW(t)
			w.createShape = shape
			err := w.install(fastHooks())
			if exitCodeOf(t, err) != ExitCreation || !strings.Contains(err.Error(), "does not match the plan") {
				t.Fatalf("err = %v", err)
			}
			if left := w.oursLeft(); len(left) != 0 {
				t.Errorf("left: %v", left)
			}
		})
	}
}

func TestProxmoxLXC_OfflineCommandsRunAsTheServiceUser(t *testing.T) {
	w := newAW(t)
	w.mustInstall(t)
	for _, e := range w.execs {
		if e.argv[0] == "/usr/local/bin/sm" && e.user != ServiceUser {
			t.Errorf("%v ran as %q", e.argv, e.user)
		}
	}
	for p, m := range w.ct.meta {
		if strings.HasPrefix(p, "/var/lib/supermgmt/") && m.owner != "supermgmt:supermgmt" {
			t.Errorf("%s owned by %s", p, m.owner)
		}
	}
}

func TestProxmoxLXC_PushOwnerFallbackFixesTheTokenFile(t *testing.T) {
	w := newAW(t)
	w.pushIgnoresOwn = true
	w.mustInstall(t)
	if w.opIndex("ct.exec /usr/bin/chown supermgmt:supermgmt /run/supermgmt-bootstrap/pve-token") < 0 {
		t.Error("no chown fallback")
	}
	if !w.ct.imported {
		t.Error("not imported")
	}
}

func TestProxmoxLXC_ImportRunsInSensitiveMode(t *testing.T) {
	w := newAW(t)
	w.mustInstall(t)
	found := false
	for _, e := range w.execs {
		if len(e.argv) > 2 && e.argv[1] == "secrets" {
			found = true
			if !e.sensitive {
				t.Error("secrets import is not Sensitive")
			}
		}
	}
	if !found {
		t.Error("no import ran")
	}
}

func TestProxmoxLXC_FirstDiscoveryNeverConfirmedRollsBack(t *testing.T) {
	w := newAW(t)
	w.doctorOKAfter = 1000
	err := w.install(fastHooks())
	if exitCodeOf(t, err) != ExitConnectivity {
		t.Fatalf("err = %v", err)
	}
	if len(w.oursLeft()) != 0 {
		t.Errorf("left: %v", w.oursLeft())
	}
}

func TestProxmoxLXC_UntrustedEndpointRefusesBeforeAnyToken(t *testing.T) {
	w := newAW(t)
	w.pveTrusted = false
	err := w.install(fastHooks())
	if exitCodeOf(t, err) != ExitConnectivity || !strings.Contains(err.Error(), "8006") {
		t.Fatalf("err = %v", err)
	}
	if w.opIndex("pve.addtoken") >= 0 || w.opIndex("pve.createuser") >= 0 {
		t.Error("identities were created before the endpoint was trusted")
	}
	if len(w.oursLeft()) != 0 {
		t.Errorf("left: %v", w.oursLeft())
	}
}
