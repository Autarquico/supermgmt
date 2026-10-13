package installer

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"strings"
	"testing"
)

type recordingRunner struct {
	cmds   []Command
	answer func(Command) ([]byte, error)
}

func (r *recordingRunner) Run(_ context.Context, c Command) ([]byte, error) {
	r.cmds = append(r.cmds, c)
	if r.answer != nil {
		return r.answer(c)
	}
	return nil, nil
}

func newRecordedPVE() (execPVE, *recordingRunner) {
	r := &recordingRunner{}
	return newExecPVE(r), r
}

var bg = context.Background()

// Every value that could become an option, a second argument or a path
// traversal is refused before any command runs.
func TestPVE_ArgvValidation(t *testing.T) {
	goodSpec := GuestSpec{
		VMID: 900, Hostname: "supermgmt", Template: "local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst", Storage: "local-lvm",
		DiskGiB: 16, Cores: 2, MemoryMiB: 2048, SwapMiB: 512, Network: GuestNetwork{Bridge: "vmbr0", DHCP: true},
		Tags: []string{"supermgmt"}, Description: "supermgmt install ab12cd34",
	}
	with := func(edit func(*GuestSpec)) GuestSpec { s := goodSpec; edit(&s); return s }
	calls := map[string]func(p execPVE) error{
		"vmid below range":      func(p execPVE) error { return p.Start(bg, 99) },
		"vmid negative":         func(p execPVE) error { return p.Stop(bg, -1) },
		"vmid above range":      func(p execPVE) error { return p.Destroy(bg, 1_000_000_000) },
		"storage leading dash":  func(p execPVE) error { _, err := p.Templates(bg, "-x"); return err },
		"storage space":         func(p execPVE) error { _, err := p.Templates(bg, "a b"); return err },
		"storage separator":     func(p execPVE) error { _, err := p.Templates(bg, "a,mp0=/"); return err },
		"storage semicolon":     func(p execPVE) error { _, err := p.Templates(bg, "a;b"); return err },
		"template traversal":    func(p execPVE) error { return p.DownloadTemplate(bg, "local", "../x.tar.zst") },
		"template leading dash": func(p execPVE) error { return p.DownloadTemplate(bg, "local", "-evil") },
		"push relative src":     func(p execPVE) error { return p.Push(bg, 900, "sm", "/tmp/x", Owner{}, 0o600) },
		"push dash src":         func(p execPVE) error { return p.Push(bg, 900, "-x", "/tmp/x", Owner{}, 0o600) },
		"push traversal dst":    func(p execPVE) error { return p.Push(bg, 900, "/tmp/a", "/run/../etc/x", Owner{}, 0o600) },
		"push space dst":        func(p execPVE) error { return p.Push(bg, 900, "/tmp/a", "/run/x y", Owner{}, 0o600) },
		"push unclean dst":      func(p execPVE) error { return p.Push(bg, 900, "/tmp/a", "/run//x", Owner{}, 0o600) },
		"push dash owner":       func(p execPVE) error { return p.Push(bg, 900, "/tmp/a", "/tmp/b", Owner{User: "-x"}, 0o600) },
		"exec relative command": func(p execPVE) error { _, err := p.Exec(bg, 900, "", []string{"sm"}, nil, false); return err },
		"exec dash command":     func(p execPVE) error { _, err := p.Exec(bg, 900, "", []string{"-sm"}, nil, false); return err },
		"exec traversal command": func(p execPVE) error {
			_, err := p.Exec(bg, 900, "", []string{"/usr/../bin/sh"}, nil, false)
			return err
		},
		"exec empty": func(p execPVE) error { _, err := p.Exec(bg, 900, "", nil, nil, false); return err },
		"exec NUL argument": func(p execPVE) error {
			_, err := p.Exec(bg, 900, "", []string{"/bin/true", "a\x00b"}, nil, false)
			return err
		},
		"exec dash user":          func(p execPVE) error { _, err := p.Exec(bg, 900, "-u", []string{"/bin/true"}, nil, false); return err },
		"exec spaced user":        func(p execPVE) error { _, err := p.Exec(bg, 900, "a b", []string{"/bin/true"}, nil, false); return err },
		"user without realm":      func(p execPVE) error { return p.CreateUser(bg, "alice", "c") },
		"user with separator":     func(p execPVE) error { return p.CreateUser(bg, "a@pve --enable 0", "c") },
		"comment leading dash":    func(p execPVE) error { return p.CreateUser(bg, "a@pve", "--x") },
		"comment newline":         func(p execPVE) error { return p.CreateUser(bg, "a@pve", "a\nb") },
		"role dash":               func(p execPVE) error { return p.CreateRole(bg, "-r", []string{"VM.Audit"}) },
		"privilege list injected": func(p execPVE) error { return p.CreateRole(bg, "r", []string{"VM.Audit,Sys.Modify"}) },
		"role without privileges": func(p execPVE) error { return p.CreateRole(bg, "r", nil) },
		"acl path traversal":      func(p execPVE) error { return p.AddACL(bg, ACL{Path: "/vms/../", Role: "r", User: "a@pve"}) },
		"acl role list":           func(p execPVE) error { return p.AddACL(bg, ACL{Path: "/", Role: "a,b", User: "a@pve"}) },
		"acl both subjects":       func(p execPVE) error { return p.AddACL(bg, ACL{Path: "/", Role: "r", User: "a@pve", Token: "a@pve!t"}) },
		"acl no subject":          func(p execPVE) error { return p.RemoveACL(bg, ACL{Path: "/", Role: "r"}) },
		"acl bad token":           func(p execPVE) error { return p.AddACL(bg, ACL{Path: "/", Role: "r", Token: "a@pve"}) },
		"token id dash":           func(p execPVE) error { _, err := p.AddToken(bg, "a@pve", "-x"); return err },
		"create hostname dash":    func(p execPVE) error { return p.Create(bg, with(func(s *GuestSpec) { s.Hostname = "-bad" })) },
		"create hostname dots":    func(p execPVE) error { return p.Create(bg, with(func(s *GuestSpec) { s.Hostname = "a..b" })) },
		"create description dash": func(p execPVE) error { return p.Create(bg, with(func(s *GuestSpec) { s.Description = "--x" })) },
		"create template path": func(p execPVE) error {
			return p.Create(bg, with(func(s *GuestSpec) { s.Template = "local:vztmpl/../x" }))
		},
		"create bridge list": func(p execPVE) error {
			return p.Create(bg, with(func(s *GuestSpec) { s.Network.Bridge = "vmbr0,firewall=0" }))
		},
		"create tag separator": func(p execPVE) error { return p.Create(bg, with(func(s *GuestSpec) { s.Tags = []string{"a;b"} })) },
		"create static no gw": func(p execPVE) error {
			return p.Create(bg, with(func(s *GuestSpec) { s.Network = GuestNetwork{Bridge: "vmbr0"} }))
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			p, r := newRecordedPVE()
			if err := call(p); !errors.Is(err, errInvalidArgument) {
				t.Fatalf("err = %v, want an invalid argument", err)
			}
			if len(r.cmds) != 0 {
				t.Errorf("a command ran: %v", r.cmds)
			}
		})
	}
}

func TestPVE_RunsToolsByAbsolutePathWithACleanEnvironment(t *testing.T) {
	t.Setenv("PATH", "/tmp/evil")
	p, r := newRecordedPVE()
	_ = p.Start(bg, 900)
	_, _ = p.Version(bg)
	_, _ = p.UserExists(bg, "a@pve")
	_, _ = p.AvailableTemplates(bg)
	for _, c := range r.cmds {
		if c.Name != "/usr/bin/env" || len(c.Args) < 4 || c.Args[0] != "-i" || c.Args[1] != "PATH=/usr/sbin:/usr/bin:/sbin:/bin" || c.Args[2] != "LC_ALL=C" {
			t.Fatalf("not run with a clean environment: %v %v", c.Name, c.Args)
		}
		if !strings.HasPrefix(c.Args[3], "/usr/") {
			t.Errorf("tool %q is not an absolute path", c.Args[3])
		}
	}
	if got := r.cmds[0].Args[3:]; strings.Join(got, " ") != "/usr/sbin/pct start 900" {
		t.Errorf("start argv = %v", got)
	}
}

func TestPVE_ExecNeverUsesAShellAndSeparatesOptions(t *testing.T) {
	p, r := newRecordedPVE()
	_, _ = p.Exec(bg, 900, ServiceUser, []string{"/usr/local/bin/sm", "server", "init", "--config", "/etc/x; rm -rf /"}, nil, true)
	c := r.cmds[0]
	got := strings.Join(c.Args[3:], "\x1f")
	want := strings.Join([]string{"/usr/sbin/pct", "exec", "900", "--", "/usr/sbin/runuser", "-u", "supermgmt", "--", "/usr/local/bin/sm", "server", "init", "--config", "/etc/x; rm -rf /"}, "\x1f")
	if got != want || !c.Sensitive {
		t.Errorf("argv = %q (sensitive %t)", got, c.Sensitive)
	}
	for _, a := range c.Args {
		if a == "sh" || a == "-c" || strings.HasSuffix(a, "/sh") || strings.HasSuffix(a, "/bash") {
			t.Errorf("shell in argv: %v", c.Args)
		}
	}
}

func TestPVE_AddTokenIsSensitiveAndNeverEchoesOutput(t *testing.T) {
	p, r := newRecordedPVE()
	r.answer = func(Command) ([]byte, error) { return []byte(`{"full-tokenid":"a@pve!sm","value":"SECRET-1"}`), nil }
	secret, err := p.AddToken(bg, "a@pve", "sm")
	if err != nil || secret.Reveal() != "SECRET-1" {
		t.Fatalf("secret %v err %v", secret, err)
	}
	if !r.cmds[0].Sensitive || strings.Contains(strings.Join(r.cmds[0].Args, " "), "SECRET-1") {
		t.Errorf("command %+v", r.cmds[0])
	}
	for name, answer := range map[string]func(Command) ([]byte, error){
		"command fails": func(Command) ([]byte, error) { return []byte("SECRET-1"), errors.New("SECRET-1 exploded") },
		"garbage":       func(Command) ([]byte, error) { return []byte("SECRET-1 not json"), nil },
		"empty value":   func(Command) ([]byte, error) { return []byte(`{"value":""}`), nil },
	} {
		r.answer = answer
		if _, err := p.AddToken(bg, "a@pve", "sm"); err == nil || strings.Contains(err.Error(), "SECRET-1") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPVE_CreateArgvIsTheFrozenShape(t *testing.T) {
	p, r := newRecordedPVE()
	spec := GuestSpec{
		VMID: 901, Hostname: "mgmt", Template: "local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst", Storage: "tank", DiskGiB: 8,
		Cores: 1, MemoryMiB: 1024, SwapMiB: 0,
		Network: GuestNetwork{Bridge: "vmbr1", Address: netip.MustParsePrefix("10.0.0.5/24"), Gateway: netip.MustParseAddr("10.0.0.1"), DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")}},
		Tags:    []string{"supermgmt"}, Description: "supermgmt install ab12cd34",
	}
	if err := p.Create(bg, spec); err != nil {
		t.Fatal(err)
	}
	want := "/usr/sbin/pct create 901 local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst --hostname mgmt --cores 1 --memory 1024 --swap 0 " +
		"--rootfs tank:8 --net0 name=eth0,bridge=vmbr1,ip=10.0.0.5/24,gw=10.0.0.1 --unprivileged 1 --features nesting=0,keyctl=0 --onboot 1 " +
		"--tags supermgmt --description supermgmt install ab12cd34 --nameserver 1.1.1.1 9.9.9.9"
	if got := strings.Join(r.cmds[0].Args[3:], " "); got != want {
		t.Errorf("argv:\n got %s\nwant %s", got, want)
	}
}

func TestPVE_Parsers(t *testing.T) {
	p, r := newRecordedPVE()
	r.answer = func(c Command) ([]byte, error) {
		if c.Args[3] == "/usr/bin/hostname" {
			return []byte("pve\n"), nil
		}
		switch c.Args[4] {
		case "list":
			if c.Args[3] == "/usr/sbin/pct" {
				return []byte("VMID       Status     Lock         Name\n900        running                 supermgmt\n901        stopped    create       other\n"), nil
			}
		case "config":
			return []byte("arch: amd64\ndescription: supermgmt install ab12cd34\nfeatures: nesting=0,keyctl=0\nlock: create\nmp0: /a,mp=/b\nlxc.cgroup2.x: 1\ntags: supermgmt\nunprivileged: 1\n"), nil
		case "get":
			return []byte(`[{"storage":"local","type":"dir","content":"vztmpl,iso","active":1},{"storage":"off","type":"dir","content":"rootdir","active":0}]`), nil
		}
		return nil, nil
	}
	if st, _ := p.State(bg, 900); !st.Exists || st.Status != "running" || st.Lock != "" {
		t.Errorf("state 900 = %+v", st)
	}
	if st, _ := p.State(bg, 901); st.Lock != "create" || st.Status != "stopped" {
		t.Errorf("state 901 = %+v", st)
	}
	if st, _ := p.State(bg, 902); st.Exists {
		t.Errorf("state 902 = %+v", st)
	}
	cfg, _ := p.Config(bg, 900)
	if !cfg.Unprivileged || cfg.Features["nesting"] != "0" || cfg.Lock != "create" || len(cfg.Mounts) != 1 || len(cfg.RawLXC) != 1 || cfg.Tags[0] != "supermgmt" || !strings.Contains(cfg.Description, "ab12cd34") {
		t.Errorf("config = %+v", cfg)
	}
	stores, _ := p.Storages(bg)
	last := r.cmds[len(r.cmds)-1]
	if got := strings.Join(last.Args[3:], " "); got != "/usr/bin/pvesh get /nodes/pve/storage --output-format json" {
		t.Errorf("storages ran %q; pvesm status has no JSON output", got)
	}
	if len(stores) != 2 || !stores[0].Active || stores[1].Active || stores[0].Content[0] != "vztmpl" {
		t.Errorf("storages = %+v", stores)
	}
}

func TestPVE_VersionAndTemplatesAndNextID(t *testing.T) {
	p, r := newRecordedPVE()
	r.answer = func(c Command) ([]byte, error) {
		switch c.Args[3] {
		case "/usr/bin/pveversion":
			return []byte("pve-manager/9.0.3/025864202ebb6109 (running kernel: 6.14.8-2-pve)\n"), nil
		case "/usr/sbin/pveam":
			if c.Args[4] == "list" {
				return []byte("NAME                                                         SIZE\nlocal:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst         120.00MB\n"), nil
			}
			return []byte("system          debian-13-standard_13.1-1_amd64.tar.zst\nsystem          debian-12-standard_12.7-1_amd64.tar.zst\nturnkeylinux    x\n"), nil
		case "/usr/bin/pvesh":
			if c.Args[7] == "900" || c.Args[7] == "901" {
				return nil, &ExitStatus{Command: "pvesh", Code: 255}
			}
		}
		return nil, nil
	}
	if v, err := p.Version(bg); err != nil || v != "9.0.3" {
		t.Errorf("version %q %v", v, err)
	}
	if vols, _ := p.Templates(bg, "local"); len(vols) != 1 || !strings.HasPrefix(vols[0], "local:vztmpl/debian-13") {
		t.Errorf("templates %v", vols)
	}
	if names, _ := p.AvailableTemplates(bg); len(names) != 2 {
		t.Errorf("available %v", names)
	}
	if id, err := p.NextID(bg, 900); err != nil || id != 902 {
		t.Errorf("nextid %d %v", id, err)
	}
}

func TestPVE_NextIDStopsOnAToolFailure(t *testing.T) {
	p, r := newRecordedPVE()
	r.answer = func(Command) ([]byte, error) { return nil, errors.New("cannot start pvesh") }
	if _, err := p.NextID(bg, 900); err == nil || len(r.cmds) != 1 {
		t.Fatalf("err %v after %d commands", err, len(r.cmds))
	}
}

func TestHighestTemplatePicksTheNewestDebian13(t *testing.T) {
	names := []string{
		"debian-13-standard_13.0-1_amd64.tar.zst", "debian-13-standard_13.10-1_amd64.tar.zst", "debian-13-standard_13.2-1_amd64.tar.zst",
		"debian-12-standard_12.9-1_amd64.tar.zst", "debian-13-standard_13.9-1_arm64.tar.zst",
	}
	if got := highestTemplate(names, func(s string) string { return s }); got != "debian-13-standard_13.10-1_amd64.tar.zst" {
		t.Errorf("highest = %s", got)
	}
	if highestTemplate(nil, func(s string) string { return s }) != "" {
		t.Error("empty list must give no template")
	}
}

func TestParseACLNameRoundTrips(t *testing.T) {
	for _, a := range []ACL{{Path: "/", Role: "R", User: "a@pve"}, {Path: "/vms", Role: "R", Token: "a@pve!sm"}} {
		if got, ok := parseACLName(aclName(a)); !ok || got != a {
			t.Errorf("%+v -> %+v %t", a, got, ok)
		}
	}
	if _, ok := parseACLName("garbage"); ok {
		t.Error("garbage parsed")
	}
}

func TestPVE_TokenIsOursOnlyWithTheInstallComment(t *testing.T) {
	const user = "sm-abc123@pve"
	tests := map[string]struct {
		listing string
		want    bool
	}{
		"our comment":     {`[{"tokenid":"sm","comment":"supermgmt install abc123"}]`, true},
		"no comment":      {`[{"tokenid":"sm"}]`, false},
		"foreign comment": {`[{"tokenid":"sm","comment":"made by hand"}]`, false},
		"another install": {`[{"tokenid":"sm","comment":"supermgmt install zzz"}]`, false},
		"other token id":  {`[{"tokenid":"other","comment":"supermgmt install abc123"}]`, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, r := newRecordedPVE()
			r.answer = func(Command) ([]byte, error) { return []byte(tc.listing), nil }
			got, err := p.TokenExists(bg, user, "sm")
			if err != nil || got != tc.want {
				t.Errorf("TokenExists = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestPVE_AddTokenCarriesTheInstallComment(t *testing.T) {
	p, r := newRecordedPVE()
	r.answer = func(Command) ([]byte, error) { return []byte(`{"value":"S"}`), nil }
	if _, err := p.AddToken(bg, "sm-abc123@pve", "sm"); err != nil {
		t.Fatal(err)
	}
	if args := strings.Join(r.cmds[0].Args, " "); !strings.Contains(args, "--comment supermgmt install abc123") {
		t.Errorf("argv = %q", args)
	}
}

var _ = fs.ErrNotExist
