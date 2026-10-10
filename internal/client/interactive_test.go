package client_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func hostKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key))) + " root@node-comment"
}

func connectInfo(t *testing.T) wire.ConnectInfo {
	t.Helper()
	node := domain.UUIDv7Generator{}.NewID()
	return wire.ConnectInfo{
		NodeID: node, Host: "203.0.113.7", Port: 2222, User: "alex",
		HostPublicKey: hostKeyLine(t), HostKeyAlias: "sm-" + string(node),
	}
}

func TestInteractiveCommandIsolatesOpenSSHFromEveryConfiguration(t *testing.T) {
	info := connectInfo(t)
	kh := "/tmp/sm-kh-x/kh"
	tests := []struct {
		tool wire.Tool
		tail []string
	}{
		{wire.ToolShell, []string{"--", "203.0.113.7"}},
		{wire.ToolLazydocker, []string{"-t", "--", "203.0.113.7", "lazydocker"}},
		{wire.ToolBtop, []string{"-t", "--", "203.0.113.7", "btop"}},
		{wire.ToolTmux, []string{"-t", "--", "203.0.113.7", "tmux"}},
	}
	for _, tt := range tests {
		t.Run(string(tt.tool), func(t *testing.T) {
			argv, err := client.InteractiveCommand(info, tt.tool, kh)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{
				"ssh", "-F", "/dev/null",
				"-o", "HostKeyAlias=" + info.HostKeyAlias,
				"-o", "UserKnownHostsFile=" + kh,
				"-o", "GlobalKnownHostsFile=/dev/null",
				"-o", "StrictHostKeyChecking=yes",
				"-o", "UpdateHostKeys=no",
				"-o", "CheckHostIP=no",
				"-o", "ProxyCommand=none",
				"-o", "ProxyJump=none",
				"-o", "KnownHostsCommand=none",
				"-o", "ControlMaster=no",
				"-o", "ControlPath=none",
				"-o", "PermitLocalCommand=no",
				"-p", "2222", "-l", "alex",
			}
			want = append(want, tt.tail...)
			if !slices.Equal(argv, want) {
				t.Errorf("argv:\n%q\nwant:\n%q", argv, want)
			}
		})
	}
}

func TestInteractiveCommandRejectsAnythingThatCouldBecomeAnSSHOption(t *testing.T) {
	good := connectInfo(t)
	tests := map[string]func(*wire.ConnectInfo){
		"host option":         func(i *wire.ConnectInfo) { i.Host = "-oProxyCommand=touch_pwned" },
		"host with space":     func(i *wire.ConnectInfo) { i.Host = "a b" },
		"host with newline":   func(i *wire.ConnectInfo) { i.Host = "a\nProxyCommand x" },
		"empty host":          func(i *wire.ConnectInfo) { i.Host = "" },
		"port zero":           func(i *wire.ConnectInfo) { i.Port = 0 },
		"port too large":      func(i *wire.ConnectInfo) { i.Port = 65536 },
		"user option":         func(i *wire.ConnectInfo) { i.User = "-oProxyCommand=x" },
		"user with semicolon": func(i *wire.ConnectInfo) { i.User = "root;id" },
		"empty user":          func(i *wire.ConnectInfo) { i.User = "" },
		"alias mismatch":      func(i *wire.ConnectInfo) { i.HostKeyAlias = "sm-other" },
		"alias injection":     func(i *wire.ConnectInfo) { i.HostKeyAlias = "x\n@cert-authority * " + i.HostPublicKey },
		"garbage key":         func(i *wire.ConnectInfo) { i.HostPublicKey = "not a key" },
		"empty key":           func(i *wire.ConnectInfo) { i.HostPublicKey = "" },
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			info := good
			corrupt(&info)
			if argv, err := client.InteractiveCommand(info, wire.ToolShell, "/tmp/kh"); err == nil {
				t.Errorf("accepted %+v as %q", info, argv)
			}
		})
	}
	if _, err := client.InteractiveCommand(good, "rm", "/tmp/kh"); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("unknown tool: got %v", err)
	}
	for _, path := range []string{"relative/kh", "/tmp/a b/kh", "/tmp/%d/kh", "/tmp/\"q\"/kh"} {
		if _, err := client.InteractiveCommand(good, wire.ToolShell, path); err == nil {
			t.Errorf("accepted known_hosts path %q", path)
		}
	}
}

// sessionDaemon serves the session routes and records the end request.
func sessionDaemon(t *testing.T, info wire.ConnectInfo) *fakeDaemon {
	t.Helper()
	return startFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sessions"):
			respond(w, 201, wire.SessionOpened{
				Session:     wire.Session{ID: domain.UUIDv7Generator{}.NewID(), NodeID: info.NodeID, State: wire.SessionIssued},
				ConnectInfo: info,
			})
		case strings.HasSuffix(r.URL.Path, "/end"):
			respond(w, 200, wire.Session{State: wire.SessionEnded})
		default:
			http.NotFound(w, r)
		}
	})
}

func endRequest(t *testing.T, d *fakeDaemon) (wire.EndSessionRequest, received) {
	t.Helper()
	var ends []received
	for _, r := range d.Requests() {
		if strings.HasSuffix(r.Path, "/end") {
			ends = append(ends, r)
		}
	}
	if len(ends) != 1 {
		t.Fatalf("daemon saw %d session ends, want exactly 1", len(ends))
	}
	var body wire.EndSessionRequest
	if err := json.Unmarshal(ends[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	return body, ends[0]
}

func TestOpenSessionWritesOnePinnedLineAndDoneCleansUpAndReportsTheExit(t *testing.T) {
	info := connectInfo(t)
	d := sessionDaemon(t, info)
	tmp := shortDir(t)
	c := d.client(client.Options{TempDir: tmp})

	h, err := c.OpenSession(context.Background(), info.NodeID, "shell")
	if err != nil {
		t.Fatal(err)
	}
	khPath := valueOf(t, h.Cmd.Args, "UserKnownHostsFile=")
	if info, err := os.Stat(filepath.Dir(khPath)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("known_hosts dir: %v, %v; want mode 0700", info, err)
	}
	got, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(strings.TrimSpace(string(got)))
	if len(fields) != 3 || fields[0] != info.HostKeyAlias || strings.Contains(string(got), "root@node-comment") {
		t.Errorf("known_hosts = %q, want exactly '<alias> <type> <key>' without the comment", got)
	}

	h.Done(3, nil)
	h.Done(3, nil) // the second call must change nothing

	if _, err := os.Stat(filepath.Dir(khPath)); !os.IsNotExist(err) {
		t.Errorf("known_hosts dir still exists: %v", err)
	}
	end, req := endRequest(t, d)
	if end.Reason != wire.EndExited || end.ExitCode == nil || *end.ExitCode != 3 {
		t.Errorf("end = %+v", end)
	}
	if req.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Error("session end has no Idempotency-Key")
	}
}

func TestDoneAfterALaunchFailureReportsLaunchFailedAndCleansUp(t *testing.T) {
	info := connectInfo(t)
	d := sessionDaemon(t, info)
	tmp := shortDir(t)
	h, err := d.client(client.Options{TempDir: tmp}).OpenSession(context.Background(), info.NodeID, "shell")
	if err != nil {
		t.Fatal(err)
	}
	h.Done(0, exec.ErrNotFound)

	end, _ := endRequest(t, d)
	if end.Reason != wire.EndLaunchFailed || end.ExitCode != nil {
		t.Errorf("end = %+v", end)
	}
	assertEmptyDir(t, tmp)
}

func TestHostileConnectInfoFromTheDaemonEndsTheSessionAndLeavesNothingBehind(t *testing.T) {
	info := connectInfo(t)
	info.Host = "-oProxyCommand=touch_pwned"
	d := sessionDaemon(t, info)
	tmp := shortDir(t)
	if _, err := d.client(client.Options{TempDir: tmp}).OpenSession(context.Background(), info.NodeID, "shell"); err == nil {
		t.Fatal("expected an error")
	}
	end, _ := endRequest(t, d)
	if end.Reason != wire.EndLaunchFailed {
		t.Errorf("end = %+v", end)
	}
	assertEmptyDir(t, tmp)
}

func TestOpenInteractiveUserOverrideIsValidatedBeforeAnythingIsIssued(t *testing.T) {
	info := connectInfo(t)
	d := sessionDaemon(t, info)
	c := d.client(client.Options{TempDir: shortDir(t)})
	_, err := c.OpenInteractive(context.Background(), client.Interactive{Node: info.NodeID, Tool: wire.ToolShell, User: "-oProxyCommand=x"})
	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("got %v", err)
	}
	if n := len(d.Requests()); n != 0 {
		t.Errorf("daemon saw %d requests, want 0", n)
	}

	h, err := c.OpenInteractive(context.Background(), client.Interactive{Node: info.NodeID, Tool: wire.ToolShell, User: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Done(0, nil)
	if got := valueAfter(t, h.Cmd.Args, "-l"); got != "deploy" {
		t.Errorf("-l = %q, want the override", got)
	}
}

func TestUnknownToolIsRefusedBeforeAnyRequest(t *testing.T) {
	info := connectInfo(t)
	d := sessionDaemon(t, info)
	if _, err := d.client(client.Options{}).OpenSession(context.Background(), info.NodeID, "rm -rf"); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("got %v", err)
	}
	if n := len(d.Requests()); n != 0 {
		t.Errorf("daemon saw %d requests, want 0", n)
	}
}

// TestHostileUserConfigDoesNotReachTheEffectiveSSHConfiguration asks the
// system OpenSSH what it would use (ssh -G, no connection is made) with a
// HOME whose ~/.ssh/config tries ProxyCommand and KnownHostsCommand.
func TestHostileUserConfigDoesNotReachTheEffectiveSSHConfiguration(t *testing.T) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh on PATH")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	hostile := "Host *\n  ProxyCommand touch " + filepath.Join(home, "pwned") + "\n  KnownHostsCommand /bin/false\n  UserKnownHostsFile /dev/null\n  StrictHostKeyChecking no\n  ControlMaster auto\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(hostile), 0o600); err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(shortDir(t), "kh")
	argv, err := client.InteractiveCommand(connectInfo(t), wire.ToolShell, kh)
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-G"}, argv[1:]...)
	cmd := exec.CommandContext(t.Context(), sshPath, args...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh -G: %v", err)
	}
	effective := out.String()
	for _, want := range []string{"userknownhostsfile " + kh, "stricthostkeychecking true", "controlmaster false"} {
		if !strings.Contains(effective, want) {
			t.Errorf("effective config lacks %q", want)
		}
	}
	for _, forbidden := range []string{"touch", "/bin/false"} {
		if strings.Contains(effective, forbidden) {
			t.Errorf("effective config contains hostile %q:\n%s", forbidden, effective)
		}
	}
}

func valueOf(t *testing.T, args []string, prefix string) string {
	t.Helper()
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, prefix); ok {
			return v
		}
	}
	t.Fatalf("no %q in %q", prefix, args)
	return ""
}

func valueAfter(t *testing.T, args []string, flag string) string {
	t.Helper()
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("no %q in %q", flag, args)
	}
	return args[i+1]
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%s still holds %d entries", dir, len(entries))
	}
}
