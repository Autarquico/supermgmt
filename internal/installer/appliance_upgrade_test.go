package installer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// pveWrap is T5's in-memory Proxmox host with the two commands the container's
// own sm answers during upgrade and uninstall.
type pveWrap struct {
	*aw
	upgradeErr   error
	uninstallErr error
	corruptPush  bool
	upgrades     []execRecord
	uninstalls   int
}

func newPVEWrap(t *testing.T) *pveWrap {
	t.Helper()
	p := &pveWrap{aw: newAW(t)}
	p.files["/usr/local/src/sm2"] = []byte("the new sm binary")
	return p
}

func (p *pveWrap) depsWith(interactive bool) Deps {
	d := p.deps(interactive)
	d.PVE = p
	return d
}

func (p *pveWrap) run(o Options, hooks provisionHooks, interactive bool) error {
	ctx := context.Background()
	if o.Mode == ModeUninstall {
		return New(p.depsWith(interactive)).uninstall(ctx, o, hooks)
	}
	return New(p.depsWith(interactive)).upgrade(ctx, o, hooks)
}

func (p *pveWrap) installAppliance(t *testing.T, vmid int) {
	t.Helper()
	o := p.opts()
	o.Appliance.VMID = vmid
	if err := New(p.deps(false)).provision(context.Background(), o, fastHooks()); err != nil {
		t.Fatalf("install %d: %v\n%s", vmid, err, p.out.String())
	}
}

func (p *pveWrap) Push(ctx context.Context, vmid int, src, dst string, owner Owner, mode fs.FileMode) error {
	if err := p.aw.Push(ctx, vmid, src, dst, owner, mode); err != nil {
		return err
	}
	if p.corruptPush && dst == stagedBinary {
		p.ct.files[dst] = []byte("tampered")
	}
	return nil
}

func (p *pveWrap) Exec(ctx context.Context, vmid int, user string, argv []string, stdin io.Reader, sensitive bool) ([]byte, error) {
	bin := applianceLayout().Binary
	switch {
	case len(argv) > 2 && argv[0] == stagedBinary && argv[1] == "install" && argv[2] == "upgrade":
		p.upgrades = append(p.upgrades, execRecord{user: user, argv: append([]string{strconv.Itoa(vmid)}, argv...)})
		return []byte("upgraded inside\n"), p.upgradeErr
	case len(argv) == 3 && argv[0] == "/usr/bin/test" && argv[1] == "-x":
		if _, ok := p.ct.files[argv[2]]; ok {
			return nil, nil
		}
		return nil, exitStatus(1)
	case len(argv) == 3 && argv[0] == bin && argv[1] == "install" && argv[2] == "uninstall":
		p.uninstalls++
		if p.uninstallErr != nil {
			return nil, p.uninstallErr
		}
		delete(p.ct.files, bin)
		p.ct.unit, p.ct.enabled = false, false
		return []byte("removed the software\n"), nil
	}
	return p.aw.Exec(ctx, vmid, user, argv, stdin, sensitive)
}

func (p *pveWrap) record(t *testing.T, vmid int) applianceRecord {
	t.Helper()
	raw, ok := p.files[recordPath(vmid)]
	if !ok {
		t.Fatalf("no record for %d", vmid)
	}
	var rec applianceRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func (p *pveWrap) upgradeOpts() Options {
	return Options{Mode: ModeUpgrade, Binary: "/usr/local/src/sm2", Yes: true}
}

func TestUpgradeAppliance_PushesTheVerifiedBinaryAndRunsTheUpgradeInside(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	err := p.run(p.upgradeOpts(), fastHooks(), false)
	if err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	if len(p.upgrades) != 1 {
		t.Fatalf("upgrades = %+v", p.upgrades)
	}
	want := []string{"900", stagedBinary, "install", "upgrade", "--binary", stagedBinary}
	if !slices.Equal(p.upgrades[0].argv, want) || p.upgrades[0].user != "" {
		t.Errorf("exec = %+v, want root running %v", p.upgrades[0], want)
	}
	if _, left := p.ct.files[stagedBinary]; left {
		t.Error("the staged binary stayed in the container")
	}
	if !strings.Contains(p.out.String(), "upgraded inside") {
		t.Errorf("the container's output was swallowed:\n%s", p.out.String())
	}
	if len(p.violations) > 0 {
		t.Errorf("violations: %v", p.violations)
	}
}

func TestUpgradeAppliance_ForwardsAllowDowngrade(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	o := p.upgradeOpts()
	o.AllowDowngrade = true
	if err := p.run(o, fastHooks(), false); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.upgrades[0].argv, "--allow-downgrade") {
		t.Errorf("argv = %v", p.upgrades[0].argv)
	}
}

func TestUpgradeAppliance_RefusesWithoutProofOfOwnership(t *testing.T) {
	tests := []struct {
		name     string
		tamper   func(*pveWrap)
		opts     func(*Options)
		wantCode int
	}{
		{"container description is not ours", func(p *pveWrap) { p.guests[900].desc = "somebody else's" }, nil, ExitPrerequisite},
		{"description carries another install id", func(p *pveWrap) { p.guests[900].desc = ownershipMark("deadbeef") }, nil, ExitPrerequisite},
		{"supermgmt tag missing", func(p *pveWrap) { p.guests[900].tags = []string{"other"} }, nil, ExitPrerequisite},
		{"container is gone", func(p *pveWrap) { delete(p.guests, 900) }, nil, ExitPrerequisite},
		{"container is stopped", func(p *pveWrap) { p.guests[900].status = "stopped" }, nil, ExitPrerequisite},
		{"record was replaced by one for another install", func(p *pveWrap) {
			rec := p.record(t, 900)
			rec.InstallID = "deadbeef"
			raw, _ := json.Marshal(rec)
			p.files[recordPath(900)] = raw
		}, nil, ExitPrerequisite},
		{"VMID has no record", nil, func(o *Options) { o.VMID = 950 }, ExitInvalid},
		{"record is damaged", func(p *pveWrap) { p.files[recordPath(900)] = []byte("{") }, nil, ExitConfiguration},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newPVEWrap(t)
			p.mustInstall(t)
			if tc.tamper != nil {
				tc.tamper(p)
			}
			o := p.upgradeOpts()
			if tc.opts != nil {
				tc.opts(&o)
			}
			pushes := p.opIndex("pve.push /tmp/supermgmt-sm")
			if err := p.run(o, fastHooks(), false); exitCodeOf(t, err) != tc.wantCode {
				t.Fatalf("err = %v", err)
			}
			if len(p.upgrades) != 0 || p.opIndex("pve.push /tmp/supermgmt-sm") != pushes {
				t.Error("something was pushed or run although ownership was not proven")
			}
		})
	}
}

func TestUpgradeAppliance_HostWithoutRecordsIsNotAnApplianceHost(t *testing.T) {
	p := newPVEWrap(t)
	err := p.run(p.upgradeOpts(), fastHooks(), false)
	if exitCodeOf(t, err) != ExitPrerequisite || len(p.upgrades) != 0 || p.opIndex("pve.push") != -1 {
		t.Fatalf("err = %v", err)
	}
}

func TestUpgradeAppliance_SeveralAppliancesNeedAVMID(t *testing.T) {
	p := newPVEWrap(t)
	p.installAppliance(t, 900)
	p.installAppliance(t, 901)
	err := p.run(p.upgradeOpts(), fastHooks(), false)
	if exitCodeOf(t, err) != ExitInvalid || !strings.Contains(err.Error(), "--vmid") || len(p.upgrades) != 0 {
		t.Fatalf("err = %v", err)
	}
	o := p.upgradeOpts()
	o.VMID = 901
	if err := p.run(o, fastHooks(), false); err != nil {
		t.Fatal(err)
	}
	if len(p.upgrades) != 1 || p.upgrades[0].argv[0] != "901" {
		t.Errorf("upgrades = %+v", p.upgrades)
	}
}

func TestUpgradeAppliance_PropagatesTheExitCodeOfTheUpgradeInside(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.upgradeErr = &ExitStatus{Command: "pct", Code: ExitRestore}
	err := p.run(p.upgradeOpts(), fastHooks(), false)
	if exitCodeOf(t, err) != ExitRestore {
		t.Fatalf("err = %v", err)
	}
	if _, left := p.ct.files[stagedBinary]; left {
		t.Error("the staged binary stayed in the container after a failed upgrade")
	}
}

func TestUpgradeAppliance_RefusesABinaryThatChangedOnTheWay(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.corruptPush = true
	err := p.run(p.upgradeOpts(), fastHooks(), false)
	if exitCodeOf(t, err) != ExitConfiguration || len(p.upgrades) != 0 {
		t.Fatalf("err = %v", err)
	}
}

func TestVMIDOutsideAProxmoxHostIsUnsupported(t *testing.T) {
	p := newPVEWrap(t)
	for _, mode := range []Mode{ModeUpgrade, ModeUninstall} {
		d := p.deps(false)
		d.PVE = nil
		err := New(d).Run(context.Background(), Options{Mode: mode, VMID: 900, Binary: "/usr/local/src/sm2"})
		if exitCodeOf(t, err) != ExitUnsupported {
			t.Errorf("%s: err = %v", mode, err)
		}
	}
}

// ---- uninstall ----

// identitiesOf lists what a record's install owns on the Proxmox side.
func (p *pveWrap) identitiesOf(t *testing.T, vmid int) (present, absent []string) {
	t.Helper()
	rec := p.record(t, vmid)
	user := userIDFor(rec.InstallID)
	check := func(kind, name string, ok bool) {
		if ok {
			present = append(present, kind+" "+name)
		} else {
			absent = append(absent, kind+" "+name)
		}
	}
	_, hasGuest := p.guests[vmid]
	check("guest", strconv.Itoa(vmid), hasGuest)
	check("user", user, p.users[user] != "")
	check("token", user+"!"+pveTokenID, p.tokens[user+"!"+pveTokenID] != "")
	for _, r := range rec.Roles {
		check("role", r, p.roles[r] != "")
	}
	hasACL := false
	for a := range p.acls {
		hasACL = hasACL || a.User == user || strings.HasPrefix(a.Token, user+"!")
	}
	check("acl", user, hasACL)
	return present, absent
}

func TestUninstallAppliance_DefaultKeepsTheContainerAndItsIdentities(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	if err := p.run(Options{Mode: ModeUninstall, Yes: true}, fastHooks(), false); err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	if p.uninstalls != 1 || p.ct.unit || p.ct.enabled {
		t.Errorf("uninstalls %d, unit %t, enabled %t", p.uninstalls, p.ct.unit, p.ct.enabled)
	}
	if g := p.guests[900]; g == nil || g.status != "stopped" {
		t.Fatalf("the container must stay, stopped: %+v", g)
	}
	_, absent := p.identitiesOf(t, 900)
	if len(absent) != 0 {
		t.Errorf("default uninstall removed %v", absent)
	}

	// A rerun converges: it finds the software gone and only makes sure the container is stopped.
	if err := p.run(Options{Mode: ModeUninstall, Yes: true}, fastHooks(), false); err != nil {
		t.Fatal(err)
	}
	if p.uninstalls != 1 || p.guests[900].status != "stopped" {
		t.Errorf("rerun: uninstalls %d, status %s", p.uninstalls, p.guests[900].status)
	}
	if len(p.violations) > 0 {
		t.Errorf("violations: %v", p.violations)
	}
}

func TestUninstallAppliance_FailureInsideLeavesTheContainerRunning(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.uninstallErr = &ExitStatus{Command: "pct", Code: ExitConfiguration}
	if err := p.run(Options{Mode: ModeUninstall, Yes: true}, fastHooks(), false); exitCodeOf(t, err) != ExitConfiguration {
		t.Fatalf("err = %v", err)
	}
	if p.guests[900].status != "running" {
		t.Error("the container was stopped although the software is still there")
	}
}

func TestUninstallAppliance_PurgeNeedsTheTypedVMID(t *testing.T) {
	t.Run("no terminal and no explicit VMID", func(t *testing.T) {
		p := newPVEWrap(t)
		p.mustInstall(t)
		err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true}, fastHooks(), false)
		if exitCodeOf(t, err) != ExitInvalid || p.guests[900] == nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no terminal and no yes", func(t *testing.T) {
		p := newPVEWrap(t)
		p.mustInstall(t)
		err := p.run(Options{Mode: ModeUninstall, PurgeData: true, VMID: 900}, fastHooks(), false)
		if exitCodeOf(t, err) != ExitInvalid || p.guests[900] == nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a wrong VMID typed", func(t *testing.T) {
		p := newPVEWrap(t)
		p.mustInstall(t)
		p.answers = []string{"901"}
		err := p.run(Options{Mode: ModeUninstall, PurgeData: true}, fastHooks(), true)
		if exitCodeOf(t, err) != ExitCancelled || p.guests[900] == nil {
			t.Fatalf("err = %v", err)
		}
		if present, absent := p.identitiesOf(t, 900); len(absent) != 0 || len(present) == 0 {
			t.Errorf("a cancelled purge removed %v", absent)
		}
	})
	t.Run("the right VMID typed", func(t *testing.T) {
		p := newPVEWrap(t)
		p.mustInstall(t)
		rec := p.record(t, 900)
		p.answers = []string{"900"}
		if err := p.run(Options{Mode: ModeUninstall, PurgeData: true}, fastHooks(), true); err != nil {
			t.Fatalf("%v\n%s", err, p.out.String())
		}
		assertPurged(t, p, rec)
	})
	t.Run("explicit vmid and yes without a terminal", func(t *testing.T) {
		p := newPVEWrap(t)
		p.mustInstall(t)
		rec := p.record(t, 900)
		if err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900}, fastHooks(), false); err != nil {
			t.Fatalf("%v\n%s", err, p.out.String())
		}
		assertPurged(t, p, rec)
	})
}

func assertPurged(t *testing.T, p *pveWrap, rec applianceRecord) {
	t.Helper()
	user := userIDFor(rec.InstallID)
	if _, ok := p.guests[rec.VMID]; ok {
		t.Error("container still exists")
	}
	if p.users[user] != "" || p.tokens[user+"!"+pveTokenID] != "" {
		t.Errorf("user %q or token left", user)
	}
	for _, r := range rec.Roles {
		if p.roles[r] != "" {
			t.Errorf("role %s left", r)
		}
	}
	for a := range p.acls {
		if a.User == user || strings.HasPrefix(a.Token, user+"!") {
			t.Errorf("ACL %+v left", a)
		}
	}
	if _, ok := p.files[recordPath(rec.VMID)]; ok {
		t.Error("record left")
	}
	if len(p.violations) > 0 {
		t.Errorf("violations: %v", p.violations)
	}
}

func TestUninstallAppliance_PurgeLeavesTheOtherApplianceAndForeignIdentitiesAlone(t *testing.T) {
	p := newPVEWrap(t)
	p.users["ops@pve"], p.roles["PVEAuditor"], p.tokens["ops@pve!ci"] = "foreign", "foreign", "foreign"
	p.acls[ACL{Path: "/", Role: "PVEAuditor", User: "ops@pve"}] = true
	p.guests[100] = &fakeGuest{desc: "someone's vm", status: "running", foreign: true}
	p.installAppliance(t, 900)
	p.installAppliance(t, 901)
	first, second := p.record(t, 900), p.record(t, 901)
	if first.InstallID == second.InstallID {
		t.Fatal("two installs share an id")
	}
	othersBefore, absent := p.identitiesOf(t, 901)
	if len(absent) != 0 {
		t.Fatalf("second appliance is incomplete: %v", absent)
	}
	foreignBefore := snapshotForeign(p)

	err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900}, fastHooks(), false)
	if err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	assertPurged(t, p, first)
	if present, absent := p.identitiesOf(t, 901); !slices.Equal(present, othersBefore) || len(absent) != 0 {
		t.Errorf("the other appliance changed: present %v absent %v (was %v)", present, absent, othersBefore)
	}
	if got := snapshotForeign(p); !slices.Equal(got, foreignBefore) {
		t.Errorf("foreign resources changed:\n got %v\nwant %v", got, foreignBefore)
	}
	if p.guests[901].status != "running" {
		t.Error("the other container was stopped")
	}
}

func snapshotForeign(p *pveWrap) []string {
	var out []string
	for id, g := range p.guests {
		if g.foreign {
			out = append(out, "guest "+strconv.Itoa(id)+" "+g.status)
		}
	}
	for k, v := range p.users {
		if v == "foreign" {
			out = append(out, "user "+k)
		}
	}
	for k, v := range p.roles {
		if v == "foreign" {
			out = append(out, "role "+k)
		}
	}
	for k, v := range p.tokens {
		if v == "foreign" {
			out = append(out, "token "+k)
		}
	}
	for a := range p.acls {
		if a.User == "ops@pve" {
			out = append(out, "acl "+aclName(a))
		}
	}
	slices.Sort(out)
	return out
}

func TestUninstallAppliance_PurgeNeverDestroysAContainerThatIsNotOurs(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	rec := p.record(t, 900)
	// The appliance was destroyed by hand and the VMID reused by somebody else.
	p.guests[900] = &fakeGuest{desc: "somebody else's", status: "running", foreign: true, tags: []string{"other"}}
	if err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900}, fastHooks(), false); err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	if g := p.guests[900]; g == nil || g.status != "running" {
		t.Error("the foreign container was touched")
	}
	delete(p.guests, 900)
	assertPurged(t, p, rec)
}

func TestUninstallAppliance_PurgeAfterTheContainerIsGoneStillRemovesTheIdentities(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	rec := p.record(t, 900)
	delete(p.guests, 900)
	if err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900}, fastHooks(), false); err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	assertPurged(t, p, rec)
}

func TestUninstallAppliance_APurgeFollowsADefaultUninstall(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	rec := p.record(t, 900)
	if err := p.run(Options{Mode: ModeUninstall, Yes: true}, fastHooks(), false); err != nil {
		t.Fatal(err)
	}
	if err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900}, fastHooks(), false); err != nil {
		t.Fatal(err)
	}
	assertPurged(t, p, rec)
}

func TestUninstallAppliance_RefusesARecordThatNamesSomebodyElsesIdentities(t *testing.T) {
	tests := map[string]func(*applianceRecord){
		"user":  func(r *applianceRecord) { r.User = "root@pam" },
		"token": func(r *applianceRecord) { r.Token = "root@pam!ops" },
		"role":  func(r *applianceRecord) { r.Roles = append(r.Roles, "Administrator") },
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPVEWrap(t)
			p.mustInstall(t)
			rec := p.record(t, 900)
			p.users["root@pam"], p.roles["Administrator"] = "foreign", "foreign"
			tamper(&rec)
			raw, _ := json.Marshal(rec)
			p.files[recordPath(900)] = raw
			err := p.run(Options{Mode: ModeUninstall, PurgeData: true, Yes: true, VMID: 900}, fastHooks(), false)
			if exitCodeOf(t, err) != ExitConfiguration {
				t.Fatalf("err = %v", err)
			}
			if p.guests[900] == nil || p.users["root@pam"] == "" || p.roles["Administrator"] == "" {
				t.Error("something was removed on the strength of a tampered record")
			}
		})
	}
}

func TestUninstallAppliance_SeveralAppliancesNeedAVMID(t *testing.T) {
	p := newPVEWrap(t)
	p.installAppliance(t, 900)
	p.installAppliance(t, 901)
	err := p.run(Options{Mode: ModeUninstall, Yes: true}, fastHooks(), false)
	if exitCodeOf(t, err) != ExitInvalid || p.uninstalls != 0 {
		t.Fatalf("err = %v", err)
	}
}

func TestUninstallAppliance_ErrNotExistIsHandledForMissingRecords(t *testing.T) {
	p := newPVEWrap(t)
	_, err := New(p.depsWith(false)).readRecord(900)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}
