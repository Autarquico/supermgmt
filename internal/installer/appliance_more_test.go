package installer

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestProxmoxLXC_RollbackWaitsForADelayedCreateTask(t *testing.T) {
	probe := newAW(t)
	probe.mustInstall(t)
	createOp := probe.opIndex("pve.create") + 1

	w := newAW(t)
	w.failAt, w.applyOnInject, w.lockDelay = createOp, true, 3 // the CLI died, the task still runs
	if err := w.install(fastHooks()); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	assertRolledBack(t, w, "delayed create task", nil)
}

func TestProxmoxLXC_RollbackStillPendingKeepsTheJournalAndExits6(t *testing.T) {
	probe := newAW(t)
	probe.mustInstall(t)

	w := newAW(t)
	w.failAt, w.applyOnInject, w.lockDelay = probe.opIndex("pve.create")+1, true, 1000
	err := w.install(fastHooks())
	if exitCodeOf(t, err) != ExitCreation || !strings.Contains(err.Error(), "pending recovery") {
		t.Fatalf("err = %v", err)
	}
	if len(w.guests) != 1 || len(w.hostPaths("/var/tmp/supermgmt-installer-")) == 0 {
		t.Fatal("the locked guest or the journal was dropped")
	}
	// A later run, once the task is done, finishes the rollback.
	for _, g := range w.guests {
		g.lock, g.lockPolls = "", 0
	}
	if err := w.recoverStale(); err != nil {
		t.Fatal(err)
	}
	assertClean(t, w, "after the task finished", nil)
	if len(w.hostPaths("/var/tmp/supermgmt-installer-")) != 0 {
		t.Error("journal left")
	}
}

func TestProxmoxLXC_StaleJournalNeedsATerminalToRollBack(t *testing.T) {
	probe := newAW(t)
	probe.mustInstall(t)
	w := newAW(t)
	w.failAt, w.applyOnInject, w.lockDelay = probe.opIndex("pve.create")+1, true, 1000
	_ = w.install(fastHooks())
	w.failAt = 0
	err := w.install(fastHooks()) // non-interactive
	if exitCodeOf(t, err) != ExitConfiguration || !strings.Contains(err.Error(), "from a terminal") {
		t.Fatalf("err = %v", err)
	}
	w.confirmYes = false
	if err := w.recoverStale(); exitCodeOf(t, err) != ExitCancelled {
		t.Fatalf("declined: %v", err)
	}
}

func TestProxmoxLXC_PreflightRefusals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*aw, *Deps, *Options)
		code  int
	}{
		{"not a Proxmox host", func(_ *aw, d *Deps, _ *Options) { d.PVE = nil }, ExitUnsupported},
		{"arm64", func(_ *aw, d *Deps, _ *Options) { d.Host.GOARCH = "arm64" }, ExitUnsupported},
		{"not root", func(_ *aw, d *Deps, _ *Options) { d.Host.UID = 1000 }, ExitPrerequisite},
		{"PVE 8", func(w *aw, _ *Deps, _ *Options) { w.version = "8.4.1" }, ExitUnsupported},
		{"ambiguous storage", func(w *aw, _ *Deps, _ *Options) {
			w.storages = append(w.storages, PVEStorage{ID: "tank", Content: []string{"rootdir"}, Active: true})
		}, ExitInvalid},
		{"ambiguous bridge", func(w *aw, _ *Deps, _ *Options) { w.bridges = []string{"vmbr1", "vmbr2"} }, ExitInvalid},
		{"unknown storage", func(_ *aw, _ *Deps, o *Options) { o.Appliance.Storage = "nope" }, ExitInvalid},
		{"storage with a separator", func(_ *aw, _ *Deps, o *Options) { o.Appliance.Storage = "local,mp0=/" }, ExitInvalid},
		{"bad hostname", func(_ *aw, _ *Deps, o *Options) { o.Appliance.Hostname = "-x" }, ExitInvalid},
		{"static without gateway", func(_ *aw, _ *Deps, o *Options) { o.Appliance.Network, o.Appliance.IP = "static", "10.0.0.5/24" }, ExitInvalid},
		{"bad endpoint", func(_ *aw, _ *Deps, o *Options) { o.Appliance.PVEEndpoint = "http://pve:8006" }, ExitInvalid},
		{"bad CA path", func(_ *aw, _ *Deps, o *Options) { o.Appliance.PVECAFile = "../ca.pem" }, ExitInvalid},
		{"CA is not a certificate", func(w *aw, _ *Deps, _ *Options) { w.files[defaultPVECAFile] = []byte("nope") }, ExitInvalid},
		{"no Debian 13 template", func(w *aw, _ *Deps, _ *Options) { w.tplAvail = []string{"debian-12-standard_12.7-1_amd64.tar.zst"} }, ExitPrerequisite},
		{"no TTY, several things unset", func(w *aw, _ *Deps, _ *Options) { w.bridges = []string{} }, ExitPrerequisite},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newAW(t)
			d, o := w.deps(false), w.opts()
			tc.setup(w, &d, &o)
			err := New(d).provision(context.Background(), o, fastHooks())
			if exitCodeOf(t, err) != tc.code {
				t.Fatalf("err = %v, want exit %d", err, tc.code)
			}
			if len(w.hostPaths("/var/tmp/supermgmt-installer-")) != 0 || w.opIndex("pve.create") >= 0 {
				t.Error("a side effect happened before the refusal")
			}
		})
	}
}

func TestProxmoxLXC_StaticNetworkAndSizing(t *testing.T) {
	w := newAW(t)
	w.ct.ip = netip.MustParseAddr("192.168.1.60")
	o := w.opts()
	o.Appliance = Appliance{Power: true, Network: "static", IP: "192.168.1.60/24", Gateway: "192.168.1.1", DNS: "1.1.1.1,9.9.9.9", Cores: 4, MemoryMiB: 4096, DiskGiB: 32, Hostname: "mgmt", VMID: 777}
	if err := New(w.deps(false)).provision(context.Background(), o, fastHooks()); err != nil {
		t.Fatal(err)
	}
	if w.guests[777] == nil {
		t.Fatal("explicit VMID not used")
	}
	if !strings.Contains(w.out.String(), "static 192.168.1.60/24 via 192.168.1.1") || !strings.Contains(w.out.String(), "https://192.168.1.60:8443") {
		t.Errorf("output:\n%s", w.out.String())
	}
}

func TestProxmoxLXC_InteractiveChoosesAmbiguousStorage(t *testing.T) {
	w := newAW(t)
	w.storages = append(w.storages, PVEStorage{ID: "tank", Content: []string{"rootdir"}, Active: true})
	w.answers = []string{"tank"}
	o := w.opts()
	o.Yes = false
	if err := New(w.deps(true)).provision(context.Background(), o, fastHooks()); err != nil {
		t.Fatal(err)
	}
	if len(w.asked) < 2 || !strings.Contains(w.asked[0], "storage") || w.asked[len(w.asked)-1] != "Proceed? [y/N]" && !strings.Contains(strings.Join(w.asked, "|"), "Proceed?") {
		t.Errorf("questions: %v", w.asked)
	}
}

func TestProxmoxLXC_DecliningThePlanChangesNothing(t *testing.T) {
	w := newAW(t)
	w.confirmYes = false
	o := w.opts()
	o.Yes = false
	err := New(w.deps(true)).provision(context.Background(), o, fastHooks())
	if exitCodeOf(t, err) != ExitCancelled || w.opIndex("host.mkdir") >= 0 {
		t.Fatalf("err = %v, ops %v", err, w.opLog)
	}
}

func TestProxmoxLXC_InstallerLockIsExclusive(t *testing.T) {
	w := newAW(t)
	w.locked = true
	if err := w.install(fastHooks()); exitCodeOf(t, err) != ExitPrerequisite {
		t.Fatalf("err = %v", err)
	}
}

func TestProxmoxLXC_TokenNeverInArgvEnvOutputLogsJournal(t *testing.T) {
	probe := newAW(t)
	probe.mustInstall(t)
	// A clean run and a failure at every point after the token exists.
	for k := probe.opIndex("pve.addtoken"); k < len(probe.opLog); k++ {
		w := newAW(t)
		w.failAt, w.applyOnInject = k+1, k%2 == 0
		_ = w.install(fastHooks())
		if leaks := w.leaks(); len(leaks) > 0 {
			t.Fatalf("failure at op %d (%s): token leaked: %v", k+1, probe.opLog[k], leaks)
		}
		for _, p := range w.hostPaths("/var/tmp/supermgmt-installer-") {
			if strings.HasSuffix(p, "pve-token") {
				t.Fatalf("failure at op %d: host temp left: %s", k+1, p)
			}
		}
	}
}

func TestAutoMode(t *testing.T) {
	t.Run("PVE host creates the appliance", func(t *testing.T) {
		w := newAW(t)
		o := w.opts()
		o.Mode = ModeAuto
		if err := New(w.deps(false)).Run(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if len(w.guests) != 1 || !strings.Contains(w.out.String(), "auto: installing in proxmox-lxc mode") {
			t.Errorf("output:\n%s", w.out.String())
		}
	})
	t.Run("desktop installs locally", func(t *testing.T) {
		for _, env := range []map[string]string{{"DISPLAY": ":0"}, {"WAYLAND_DISPLAY": "wayland-0"}, {"XDG_CURRENT_DESKTOP": "GNOME"}} {
			w := newWorld()
			d, out := w.deps("linux", 1000, false)
			d.Host.Env = env
			if err := New(d).Run(context.Background(), Options{Mode: ModeAuto, Binary: "/tmp/sm", Yes: true}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "auto: installing in local mode") {
				t.Errorf("%v: %s", env, out.String())
			}
		}
	})
	t.Run("macOS installs locally", func(t *testing.T) {
		w := newWorld()
		d, out := w.deps("darwin", 501, false)
		if err := New(d).Run(context.Background(), Options{Mode: ModeAuto, Binary: "/tmp/sm", Yes: true}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "local mode") {
			t.Errorf("output: %s", out.String())
		}
	})
	t.Run("server without a terminal asks for SUPERMGMT_MODE", func(t *testing.T) {
		w := newWorld()
		d, _ := w.deps("linux", 0, false)
		err := New(d).Run(context.Background(), Options{Mode: ModeAuto, Binary: "/tmp/sm"})
		if exitCodeOf(t, err) != ExitInvalid || !strings.Contains(err.Error(), "SUPERMGMT_MODE") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("server prompt declined", func(t *testing.T) {
		w := newWorld()
		w.confirmYes = false
		d, _ := w.deps("linux", 0, true)
		err := New(d).Run(context.Background(), Options{Mode: ModeAuto, Binary: "/tmp/sm"})
		if exitCodeOf(t, err) != ExitCancelled {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("server prompt accepted", func(t *testing.T) {
		w := newWorld()
		d, out := w.deps("linux", 0, true)
		_ = New(d).Run(context.Background(), Options{Mode: ModeAuto, Binary: "/tmp/sm", Yes: true, PublicURL: "https://mgmt.example.com"})
		if !strings.Contains(out.String(), "auto: installing in server mode") {
			t.Errorf("output: %s", out.String())
		}
	})
}
