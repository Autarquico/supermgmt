package installer

import (
	"context"
	"strings"
	"testing"
)

func restoreOpts(stdin string) Options {
	o := serverOpts()
	o.Mode = ModeRestore
	o.Archive, o.KeyExport = "/backup/a.tar.zst", "/backup/key.smkey"
	o.Stdin = strings.NewReader(stdin)
	return o
}

func restoreWorld() *world {
	w := newWorld()
	w.files["/backup/a.tar.zst"], w.files["/backup/key.smkey"] = []byte("a"), []byte("k")
	return w
}

func TestRestoreRunsTheFrozenOfflineCommandsBeforeStarting(t *testing.T) {
	w := restoreWorld()
	d, out := w.deps("linux", 0, false)
	o := restoreOpts("passphrase\n")
	if err := New(d).Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	importKey := w.index("run /usr/local/bin/sm secrets import-key")
	restore := w.index("run /usr/local/bin/sm backup restore")
	start := w.index("start")
	if w.index("register") >= importKey || importKey >= restore || restore >= start {
		t.Fatalf("order wrong: %v", w.events)
	}
	if w.index("run /usr/local/bin/sm admin") >= 0 {
		t.Error("restore must not issue a bootstrap code")
	}
	wantArgs := map[int][]string{
		0: {"secrets", "import-key", "--offline", "--from", "/backup/key.smkey", "--config", "/etc/supermgmt/config.yaml"},
		1: {"backup", "restore", "--offline", "/backup/a.tar.zst", "--config", "/etc/supermgmt/config.yaml"},
	}
	for i, want := range wantArgs {
		c := w.commands[i]
		if strings.Join(c.Args, " ") != strings.Join(want, " ") || c.User != ServiceUser || c.Stdin != o.Stdin {
			t.Errorf("command %d = %+v", i, c)
		}
	}
	if !strings.Contains(out.String(), "restore-complete") {
		t.Errorf("hold instructions missing:\n%s", out)
	}
}

func TestRestoreFailureCodes(t *testing.T) {
	cases := []struct {
		name string
		step string
		code int
		want int
	}{
		{"restore failure", "backup restore", 9, ExitRestore},
		{"restore invalid input", "backup restore", 2, ExitInvalid},
		{"restore prerequisite", "backup restore", 4, ExitPrerequisite},
		{"restore other status", "backup restore", 1, ExitRestore},
		{"import-key wrong passphrase", "secrets import-key", 9, ExitRestore},
		{"import-key prerequisite", "secrets import-key", 4, ExitPrerequisite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := restoreWorld()
			w.runErr["/usr/local/bin/sm "+tc.step] = &ExitStatus{Command: "sm", Code: tc.code}
			d, _ := w.deps("linux", 0, false)
			err := New(d).Run(context.Background(), restoreOpts(""))
			if got := exitCodeOf(t, err); got != tc.want {
				t.Fatalf("exit %d (%v), want %d", got, err, tc.want)
			}
			if w.index("start") >= 0 {
				t.Error("service started after a failed restore")
			}
		})
	}
}

func TestRestoreSkipsRestoreWhenKeyImportFails(t *testing.T) {
	w := restoreWorld()
	w.runErr["/usr/local/bin/sm secrets import-key"] = &ExitStatus{Command: "sm", Code: 9}
	d, _ := w.deps("linux", 0, false)
	_ = New(d).Run(context.Background(), restoreOpts(""))
	if w.index("run /usr/local/bin/sm backup restore") >= 0 {
		t.Error("restore ran after key import failed")
	}
}

func TestRestoreRequiresExistingInputs(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"no archive":      func(o *Options) { o.Archive = "" },
		"no key export":   func(o *Options) { o.KeyExport = "" },
		"archive missing": func(o *Options) { o.Archive = "/nope" },
	} {
		t.Run(name, func(t *testing.T) {
			w := restoreWorld()
			d, _ := w.deps("linux", 0, false)
			o := restoreOpts("")
			mutate(&o)
			if got := exitCodeOf(t, New(d).Run(context.Background(), o)); got != ExitInvalid {
				t.Fatalf("exit %d, want %d", got, ExitInvalid)
			}
			if w.index("useradd") >= 0 {
				t.Error("changes made before input validation")
			}
		})
	}
}

func TestRestoreHealthFailure(t *testing.T) {
	w := restoreWorld()
	w.healthErr = context.DeadlineExceeded
	d, _ := w.deps("linux", 0, false)
	if got := exitCodeOf(t, New(d).Run(context.Background(), restoreOpts(""))); got != ExitConnectivity {
		t.Fatalf("exit %d, want %d", got, ExitConnectivity)
	}
}

func TestLocalInstallWritesBinaryAndConfig(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 1000, false)
	if err := New(d).Run(context.Background(), Options{Mode: ModeLocal, Binary: "/tmp/sm"}); err != nil {
		t.Fatal(err)
	}
	if string(w.files["/home/alex/.local/bin/sm"]) != "binary" || w.modes["/home/alex/.local/bin/sm"] != 0o755 {
		t.Error("binary not installed to ~/.local/bin")
	}
	cfg := w.files["/home/alex/.config/supermgmt/config.yaml"]
	if !strings.Contains(string(cfg), "mode: local") || strings.Contains(string(cfg), "resident") {
		t.Errorf("config:\n%s", cfg)
	}
	if w.index("user-") >= 0 {
		t.Error("no resident unit was requested")
	}
}

func TestLocalInstallHonorsInstallDir(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 1000, false)
	if err := New(d).Run(context.Background(), Options{Mode: ModeLocal, Binary: "/tmp/sm", InstallDir: "/opt/bin"}); err != nil {
		t.Fatal(err)
	}
	if !w.Exists("/opt/bin/sm") {
		t.Fatal("binary not in SUPERMGMT_INSTALL_DIR")
	}
}

func TestLocalResidentUnit(t *testing.T) {
	cases := []struct {
		goos string
		unit string
		want string
	}{
		{"linux", "/home/alex/.config/systemd/user/supermgmt.service", "ExecStart=/home/alex/.local/bin/sm daemon --config /home/alex/.config/supermgmt/config.yaml"},
		{"darwin", "/home/alex/Library/LaunchAgents/dev.supermgmt.daemon.plist", "<string>/home/alex/.local/bin/sm</string>"},
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			w := newWorld()
			d, _ := w.deps(tc.goos, 1000, false)
			if err := New(d).Run(context.Background(), Options{Mode: ModeLocal, Binary: "/tmp/sm", Resident: true}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(w.files[tc.unit]), tc.want) {
				t.Errorf("unit %s:\n%s", tc.unit, w.files[tc.unit])
			}
			if w.index("user-register") < 0 || w.index("user-start") < w.index("user-register") {
				t.Errorf("resident unit not registered then started: %v", w.events)
			}
		})
	}
}

func TestLocalResidentNeedsSystemdOnLinux(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 1000, false)
	d.Host.HasSystemd = false
	err := New(d).Run(context.Background(), Options{Mode: ModeLocal, Binary: "/tmp/sm", Resident: true})
	if got := exitCodeOf(t, err); got != ExitUnsupported {
		t.Fatalf("exit %d", got)
	}
}

func TestLocalUnsupportedOS(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("windows", 1000, false)
	if got := exitCodeOf(t, New(d).Run(context.Background(), Options{Mode: ModeLocal, Binary: "/tmp/sm"})); got != ExitUnsupported {
		t.Fatalf("exit %d", got)
	}
}

func TestLocalExistingInstallFailsWithoutATerminal(t *testing.T) {
	w := newWorld()
	w.files["/home/alex/.local/bin/sm"] = []byte("old")
	d, _ := w.deps("linux", 1000, false)
	err := New(d).Run(context.Background(), Options{Mode: ModeLocal, Binary: "/tmp/sm"})
	if got := exitCodeOf(t, err); got != ExitPrerequisite {
		t.Fatalf("exit %d (%v)", got, err)
	}
	if string(w.files["/home/alex/.local/bin/sm"]) != "old" {
		t.Error("existing binary replaced")
	}
}

func TestClientInstallWritesBinaryAndEmptyProfileOnly(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 1000, false)
	if err := New(d).Run(context.Background(), Options{Mode: ModeClient, Binary: "/tmp/sm"}); err != nil {
		t.Fatal(err)
	}
	if !w.Exists("/home/alex/.local/bin/sm") || !w.Exists("/home/alex/.config/supermgmt/profiles.yaml") {
		t.Fatalf("client files missing: %v", w.events)
	}
	if w.modes["/home/alex/.config/supermgmt/profiles.yaml"] != 0o600 {
		t.Error("profile must be 0600")
	}
	for _, e := range w.events {
		if strings.HasPrefix(e, "useradd") || strings.HasPrefix(e, "run") || strings.Contains(e, "register") {
			t.Errorf("client mode touched the system: %s", e)
		}
	}
}

func TestClientReinstallKeepsProfile(t *testing.T) {
	w := newWorld()
	w.files["/home/alex/.config/supermgmt/profiles.yaml"] = []byte("mine")
	w.files["/home/alex/.local/bin/sm"] = []byte("old")
	d, _ := w.deps("linux", 1000, false)
	if err := New(d).Run(context.Background(), Options{Mode: ModeClient, Binary: "/tmp/sm"}); err != nil {
		t.Fatal(err)
	}
	if string(w.files["/home/alex/.config/supermgmt/profiles.yaml"]) != "mine" || string(w.files["/home/alex/.local/bin/sm"]) != "binary" {
		t.Error("profile must be kept and the binary refreshed")
	}
}
