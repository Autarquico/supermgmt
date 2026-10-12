package installer

import (
	"context"
	"strings"
	"testing"
)

func (h *uhost) uninstallOpts() Options { return Options{Mode: ModeUninstall, Yes: true} }

func (h *uhost) uninstall(o Options, hooks provisionHooks) error {
	return New(h.deps()).uninstall(context.Background(), o, hooks)
}

// keepers are the paths an uninstall without --purge-data must not touch.
func (h *uhost) seedUserData() []string {
	l := applianceLayout()
	paths := []string{l.DataDir + "/supermgmt.db", l.BackupsDir + "/old.tar.zst", l.KeysDir + "/k1.key", l.ConfigFile, l.ConfigDir + "/tls/ca.pem"}
	for _, p := range paths {
		if p != l.ConfigFile {
			h.put(p, "x")
		}
	}
	return paths
}

func TestUninstall_ServerKeepsConfigurationDataAndBackups(t *testing.T) {
	h := newUHost(t)
	keep := h.seedUserData()
	l := applianceLayout()
	if err := h.uninstall(h.uninstallOpts(), defaultHooks()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	for _, p := range keep {
		if !h.Exists(p) {
			t.Errorf("%s was deleted", p)
		}
	}
	for _, p := range []string{l.Binary, l.Binary + ".prev", l.UnitPath} {
		if h.Exists(p) {
			t.Errorf("%s is still there", p)
		}
	}
	if h.running || h.enabled {
		t.Errorf("running %t enabled %t", h.running, h.enabled)
	}
	order := []string{"stop ", "waitstopped ", "disable ", "remove " + l.UnitPath, "reload ", "remove " + l.Binary}
	last := -1
	for _, step := range order {
		i := h.index(step)
		if i <= last {
			t.Errorf("%q out of order: %v", step, h.events)
		}
		last = i
	}
}

func TestUninstall_YesAloneNeverDeletesData(t *testing.T) {
	h := newUHost(t)
	keep := h.seedUserData()
	o := h.uninstallOpts()
	o.Yes = true
	if err := h.uninstall(o, defaultHooks()); err != nil {
		t.Fatal(err)
	}
	for _, p := range keep {
		if !h.Exists(p) {
			t.Errorf("%s was deleted by an uninstall without --purge-data", p)
		}
	}
}

func TestUninstall_PurgeNeedsASeparateConfirmation(t *testing.T) {
	tests := []struct {
		name     string
		yes      bool
		answers  []string
		wantCode int
		deleted  bool
	}{
		{"no terminal, no yes", false, nil, ExitInvalid, false},
		{"no terminal, yes", true, nil, 0, true},
		{"terminal, wrong phrase", false, []string{"yes"}, ExitCancelled, false},
		{"terminal, right phrase", false, []string{purgePhrase}, 0, true},
		{"terminal, yes does not replace the phrase", true, []string{"no"}, ExitCancelled, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newUHost(t)
			keep := h.seedUserData()
			h.answers, h.yes = tc.answers, tc.yes || len(tc.answers) == 0
			o := Options{Mode: ModeUninstall, PurgeData: true, Yes: tc.yes}
			err := h.uninstall(o, defaultHooks())
			if tc.wantCode != 0 {
				if exitCodeOf(t, err) != tc.wantCode {
					t.Fatalf("err = %v", err)
				}
			} else if err != nil {
				t.Fatalf("%v\n%s", err, h.out.String())
			}
			for _, p := range keep {
				if h.Exists(p) == tc.deleted {
					t.Errorf("%s: exists = %t, deleted wanted = %t", p, h.Exists(p), tc.deleted)
				}
			}
			if !tc.deleted && !h.Exists(applianceLayout().Binary) {
				t.Error("a cancelled purge still removed the software")
			}
		})
	}
}

func TestUninstall_PurgeRefusesSystemDirectories(t *testing.T) {
	for _, dir := range []string{"/var/lib", "/etc", "/", "/root"} {
		t.Run(dir, func(t *testing.T) {
			h := newUHost(t)
			o := Options{Mode: ModeUninstall, PurgeData: true, Yes: true, DataDir: dir}
			if err := h.uninstall(o, defaultHooks()); exitCodeOf(t, err) != ExitInvalid {
				t.Fatalf("err = %v", err)
			}
			if !h.Exists(applianceLayout().Binary) {
				t.Error("the software was removed before the refusal")
			}
		})
	}
}

func TestSafeToDelete(t *testing.T) {
	tests := []struct {
		path string
		ok   bool
	}{
		{"/var/lib/supermgmt", true},
		{"/etc/supermgmt", true},
		{"/home/alex/.local/share/supermgmt", true},
		{"/var/lib", false},
		{"/home/alex", false},
		{"/home", false},
		{"relative/dir", false},
		{"/var/lib/supermgmt/../x", false},
	}
	for _, tc := range tests {
		if err := safeToDelete(tc.path, "/home/alex"); (err == nil) != tc.ok {
			t.Errorf("safeToDelete(%q) = %v, want ok=%t", tc.path, err, tc.ok)
		}
	}
}

func TestUninstall_PurgeAfterAnEarlierUninstallRemovesTheLeftovers(t *testing.T) {
	h := newUHost(t)
	keep := h.seedUserData()
	if err := h.uninstall(h.uninstallOpts(), defaultHooks()); err != nil {
		t.Fatal(err)
	}
	if err := h.uninstall(h.uninstallOpts(), defaultHooks()); exitCodeOf(t, err) != ExitPrerequisite {
		t.Fatalf("a second plain uninstall: err = %v", err)
	}
	if err := h.uninstall(Options{Mode: ModeUninstall, PurgeData: true, Yes: true}, defaultHooks()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	for _, p := range keep {
		if h.Exists(p) {
			t.Errorf("%s survived the purge", p)
		}
	}
}

func TestUninstall_LocalInstallKeepsClientProfilesOnPurge(t *testing.T) {
	h := newUHost(t)
	h.uid, h.home = 1000, "/home/alex"
	ul := Options{}.userLayout(h.deps().Host)
	_ = h.RemoveAll(applianceLayout().Binary)
	_ = h.RemoveAll(applianceLayout().UnitPath)
	for p, c := range map[string]string{ul.Binary: binV1, ul.ConfigFile: "x", ul.ProfileFile: "p", ul.DataDir + "/supermgmt.db": "db"} {
		h.put(p, c)
	}
	h.oldContent = ""
	if err := h.uninstall(Options{Mode: ModeUninstall, PurgeData: true, Yes: true}, defaultHooks()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.Exists(ul.Binary) || h.Exists(ul.ConfigFile) || h.Exists(ul.DataDir+"/supermgmt.db") {
		t.Error("local files survived the purge")
	}
	if !h.Exists(ul.ProfileFile) {
		t.Error("the client profiles were deleted with the server data")
	}
	if h.index("stop ") != -1 {
		t.Error("a local install without a resident daemon stopped a service")
	}
}

func TestUninstall_ServerNeedsRoot(t *testing.T) {
	h := newUHost(t)
	h.uid = 1000
	if err := h.uninstall(h.uninstallOpts(), defaultHooks()); exitCodeOf(t, err) != ExitPrerequisite {
		t.Fatalf("err = %v", err)
	}
}

func TestUninstall_DamagedConfigurationDoesNotBlockIt(t *testing.T) {
	h := newUHost(t)
	h.put(applianceLayout().ConfigFile, "not: [valid")
	if err := h.uninstall(h.uninstallOpts(), defaultHooks()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.Exists(applianceLayout().Binary) {
		t.Error("the binary is still there")
	}
}

func TestUninstall_ServiceThatWillNotStopKeepsEverything(t *testing.T) {
	h := newUHost(t)
	h.stopErr = context.DeadlineExceeded
	err := h.uninstall(h.uninstallOpts(), defaultHooks())
	if exitCodeOf(t, err) != ExitConfiguration || !h.Exists(applianceLayout().Binary) || !h.Exists(applianceLayout().UnitPath) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "stop") {
		t.Errorf("err = %v", err)
	}
}
