package installer

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

type scenario struct {
	name      string
	setup     func(*aw)
	opts      func(*Options)
	alwaysErr bool // the install refuses by design (a name collision)
}

func foreignHost(w *aw) {
	w.guests[900] = &fakeGuest{desc: "someone's vm", status: "running", foreign: true, tags: []string{"prod"}}
	w.guests[901] = &fakeGuest{desc: "someone else's", status: "stopped", foreign: true}
	w.users["ops@pve"] = "foreign"
	w.roles["PVEAdmin"] = "foreign"
	w.acls[ACL{Path: "/", Role: "PVEAdmin", User: "ops@pve"}] = true
	w.tokens["ops@pve!ci"] = "foreign"
	w.tplLocal = []string{"local:vztmpl/alpine-3.20-default_20240908_amd64.tar.xz"}
}

var scenarios = []scenario{
	{name: "fresh host, template downloaded"},
	{name: "existing template", setup: func(w *aw) {
		w.tplLocal = []string{"local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst"}
	}},
	{name: "pre-existing guests and identities", setup: foreignHost},
	{name: "explicit VMID", setup: foreignHost, opts: func(o *Options) { o.Appliance.VMID = 950 }},
	{name: "power disabled", opts: func(o *Options) { o.Appliance.Power = false }},
	{name: "colliding user", alwaysErr: true, setup: func(w *aw) { w.collide["user"] = true }},
	{name: "colliding audit role", alwaysErr: true, setup: func(w *aw) { w.collide["auditrole"] = true }},
	{name: "colliding power role", alwaysErr: true, setup: func(w *aw) { w.collide["powerrole"] = true }},
	{name: "colliding token", alwaysErr: true, setup: func(w *aw) { w.collide["token"] = true }},
}

func (sc scenario) world(t *testing.T) (*aw, Options) {
	w := newAW(t)
	if sc.setup != nil {
		sc.setup(w)
	}
	o := w.opts()
	if sc.opts != nil {
		sc.opts(&o)
	}
	return w, o
}

func (w *aw) foreignState() []string {
	var lines []string
	for id, g := range w.guests {
		if g.foreign {
			lines = append(lines, fmt.Sprintf("guest %d %s %s", id, g.desc, g.status))
		}
	}
	for k, v := range w.users {
		if v == "foreign" {
			lines = append(lines, "user "+k)
		}
	}
	for k, v := range w.roles {
		if v == "foreign" {
			lines = append(lines, "role "+k)
		}
	}
	for k, v := range w.tokens {
		if v == "foreign" {
			lines = append(lines, "token "+k)
		}
	}
	for a := range w.acls {
		if !strings.HasPrefix(a.User, "sm-") && !strings.HasPrefix(a.Token, "sm-") {
			lines = append(lines, "acl "+aclName(a))
		}
	}
	sort.Strings(lines)
	return lines
}

func subset(small, big []string) []string {
	have := map[string]bool{}
	for _, l := range big {
		have[l] = true
	}
	var missing []string
	for _, l := range small {
		if !have[l] {
			missing = append(missing, l)
		}
	}
	return missing
}

// assertRolledBack: the undo set equals the created set. Everything this
// install made is gone, everything that was there is untouched, no secret
// survives, and what is left of the journal holds nothing to undo.
func assertRolledBack(t *testing.T, w *aw, label string, baseline []string) {
	t.Helper()
	assertClean(t, w, label, baseline)
	if err := w.recoverStale(); err != nil {
		t.Errorf("%s: recovery of leftovers: %v", label, err)
	}
	if got := w.hostPaths("/var/tmp/supermgmt-installer-"); len(got) > 0 {
		t.Errorf("%s: journal debris after recovery: %v", label, got)
	}
}

// assertRolledBackLater is for a failure inside the rollback itself: the
// journal keeps what is left and a later run finishes the job.
func assertRolledBackLater(t *testing.T, w *aw, label string, baseline []string) {
	t.Helper()
	if err := w.recoverStale(); err != nil {
		t.Errorf("%s: recovery after a failed rollback: %v", label, err)
	}
	assertClean(t, w, label, baseline)
	if got := w.hostPaths("/var/tmp/supermgmt-installer-"); len(got) > 0 {
		t.Errorf("%s: journal debris after recovery: %v", label, got)
	}
}

func assertClean(t *testing.T, w *aw, label string, baseline []string) {
	t.Helper()
	if left := w.oursLeft(); len(left) > 0 {
		t.Errorf("%s: created resources left behind: %v", label, left)
	}
	if missing := subset(baseline, w.foreignState()); len(missing) > 0 {
		t.Errorf("%s: pre-existing resources changed or removed: %v", label, missing)
	}
	if len(w.violations) > 0 {
		t.Errorf("%s: violations: %v", label, w.violations)
	}
	if leaks := w.leaks(); len(leaks) > 0 {
		t.Errorf("%s: token leaked: %v", label, leaks)
	}
	if got := w.hostPaths(appliancesDir + "/"); len(got) > 0 {
		t.Errorf("%s: appliance record for a rolled-back install: %v", label, got)
	}
	for _, dir := range w.hostPaths("/var/tmp/supermgmt-installer-") {
		if strings.HasSuffix(dir, "/stage") || strings.HasSuffix(dir, "pve-token") {
			t.Errorf("%s: host temp left behind: %s", label, dir)
		}
		if j, err := openJournal(w, dir); err == nil && len(j.toUndo()) > 0 {
			t.Errorf("%s: journal still lists resources: %v", label, j.toUndo())
		}
	}
}

func TestProxmoxLXC_FailureAtEveryStepUndoesOnlyCreated(t *testing.T) {
	for _, sc := range scenarios {
		for _, applied := range []bool{false, true} {
			name := sc.name + map[bool]string{false: " / op fails", true: " / op applies then reports failure"}[applied]
			t.Run(name, func(t *testing.T) {
				probe, o := sc.world(t)
				err := New(probe.deps(false)).provision(t.Context(), o, fastHooks())
				if sc.alwaysErr != (err != nil) {
					t.Fatalf("baseline run: err = %v, want error=%t", err, sc.alwaysErr)
				}
				total := probe.ops
				t.Logf("%d operations", total)
				for k := 1; k <= total; k++ {
					w, o := sc.world(t)
					baseline := w.foreignState()
					w.failAt, w.applyOnInject = k, applied
					label := fmt.Sprintf("failure at op %d (%s)", k, probe.opLog[k-1])
					err := New(w.deps(false)).provision(t.Context(), o, fastHooks())
					if err == nil {
						assertInstalled(t, w, label) // a polled read recovered by itself
						continue
					}
					if len(w.hostPaths(appliancesDir+"/")) > 0 {
						assertInstalledAfterCommit(t, w, label)
						continue
					}
					if probe.rollbackStart != 0 && k >= probe.rollbackStart {
						assertRolledBackLater(t, w, label, baseline)
						continue
					}
					assertRolledBack(t, w, label, baseline)
				}
			})
		}
	}
}

func assertInstalled(t *testing.T, w *aw, label string) {
	t.Helper()
	if len(w.hostPaths(appliancesDir+"/")) != 1 || !w.ct.enabled || !w.ct.imported {
		t.Errorf("%s: run succeeded but the appliance is not installed", label)
	}
	if len(w.violations) > 0 || len(w.leaks()) > 0 {
		t.Errorf("%s: violations %v leaks %v", label, w.violations, w.leaks())
	}
}

// assertInstalledAfterCommit: once the record exists the install is never rolled
// back; a later run only finishes the journal cleanup.
func assertInstalledAfterCommit(t *testing.T, w *aw, label string) {
	t.Helper()
	if len(w.oursLeft()) != 1+1+2+1+4 && len(w.oursLeft()) != 1+1+1+1+2 {
		t.Errorf("%s: a committed install lost resources: %v", label, w.oursLeft())
	}
	if err := w.recoverStale(); err != nil {
		t.Errorf("%s: finishing cleanup: %v", label, err)
	}
	if got := w.hostPaths("/var/tmp/supermgmt-installer-"); len(got) > 0 {
		t.Errorf("%s: journal not cleaned: %v", label, got)
	}
	if len(w.leaks()) > 0 || len(w.violations) > 0 {
		t.Errorf("%s: leaks %v violations %v", label, w.leaks(), w.violations)
	}
}

func TestProxmoxLXC_CollisionsFailWithoutTouchingTheOtherResource(t *testing.T) {
	for _, sc := range scenarios {
		if !sc.alwaysErr {
			continue
		}
		t.Run(sc.name, func(t *testing.T) {
			w, o := sc.world(t)
			err := New(w.deps(false)).provision(t.Context(), o, fastHooks())
			if exitCodeOf(t, err) != ExitCreation || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("err = %v", err)
			}
			if len(w.foreignState()) == 0 {
				t.Error("the colliding resource disappeared")
			}
			assertRolledBack(t, w, sc.name, nil)
		})
	}
}

func TestProxmoxLXC_ExistingTemplateIsUsedAndNothingIsDownloaded(t *testing.T) {
	w, o := scenarios[1].world(t)
	if err := New(w.deps(false)).provision(t.Context(), o, fastHooks()); err != nil {
		t.Fatal(err)
	}
	if w.opIndex("pve.download") >= 0 {
		t.Error("downloaded although a Debian 13 template exists")
	}
}

func TestProxmoxLXC_DownloadedTemplateSurvivesRollback(t *testing.T) {
	w := newAW(t)
	w.doctorOKAfter = 1000
	if err := w.install(fastHooks()); err == nil {
		t.Fatal("want a failure")
	}
	want := "local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst"
	if len(w.tplLocal) != 1 || w.tplLocal[0] != want {
		t.Errorf("templates after rollback: %v, want [%s]", w.tplLocal, want)
	}
	if !strings.Contains(w.out.String(), "kept template") {
		t.Errorf("rollback did not report the kept template:\n%s", w.out.String())
	}
}

func TestProxmoxLXC_ExplicitVMIDInUseIsRefusedUntouched(t *testing.T) {
	w := newAW(t)
	foreignHost(w)
	o := w.opts()
	o.Appliance.VMID = 900
	err := New(w.deps(false)).provision(t.Context(), o, fastHooks())
	if exitCodeOf(t, err) != ExitInvalid || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("err = %v", err)
	}
	if w.opIndex("pve.create") >= 0 || len(w.hostPaths("/var/tmp/supermgmt-installer-")) != 0 {
		t.Error("side effects before the refusal")
	}
	if w.guests[900].status != "running" {
		t.Error("the pre-existing guest was touched")
	}
}

func TestProxmoxLXC_VMIDTakenAtCreateIsKeptForManualRecovery(t *testing.T) {
	w := newAW(t)
	w.raceAtCreate = true
	err := w.install(fastHooks())
	if exitCodeOf(t, err) != ExitConfiguration || !strings.Contains(err.Error(), "manual recovery") {
		t.Fatalf("err = %v", err)
	}
	if len(w.violations) > 0 {
		t.Errorf("violations: %v", w.violations)
	}
	if len(w.foreignState()) != 1 {
		t.Errorf("the foreign guest was changed: %v", w.foreignState())
	}
	if len(w.hostPaths("/var/tmp/supermgmt-installer-")) == 0 {
		t.Error("journal removed although a resource is kept")
	}
}
