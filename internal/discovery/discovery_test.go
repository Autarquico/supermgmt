package discovery

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const linuxProbe = `@@probe 1
@@uname
Linux 6.12.43-amd64 x86_64
@@os
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
ID=debian
@@hostname
node-a
@@uptime
12345.67 9999.00
@@cpu
4
cpu  1000 0 500 8000 500 0 0 0 0 0
cpu  1100 0 600 8100 500 0 0 0 0 0
@@loadavg
0.52 0.40 0.30 1/200 999
@@memory
MemTotal:        8000000 kB
MemFree:         1000000 kB
MemAvailable:    5000000 kB
@@disk
Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/vda1         50000000 20000000  30000000      40% /
@@pkgmgr
apt-get
@@systemd
active
/usr/bin/systemctl
systemd 257 (257.9-1)
@@docker
path=/usr/bin/docker
server=26.1.5
compose=2.29.1
@@tools
btop
tmux
@@sudo
yes
@@setup
user=admin
home=absent
markers=absent
@@addresses
1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0
2: eth0    inet 203.0.113.9/32 scope global eth0
2: eth0    inet6 fe80::1/64 scope link
2: eth0    inet6 2001:db8::5/64 scope global
2: eth0    inet6 fd00::5/64 scope global
`

func TestParseLinuxProbe(t *testing.T) {
	s, err := Parse([]byte(linuxProbe))
	if err != nil {
		t.Fatal(err)
	}
	if s.Kernel != "Linux 6.12.43-amd64 x86_64" || s.Hostname != "node-a" || s.OS != (OSInfo{ID: "debian", Name: "Debian GNU/Linux 13 (trixie)", Version: "13"}) {
		t.Errorf("identity = %+v", s)
	}
	if s.Uptime != time.Duration(12345.67*float64(time.Second)) {
		t.Errorf("uptime = %v", s.Uptime)
	}
	if s.CPU.Cores != 4 || !s.CPU.UsageKnown || math.Abs(s.CPU.UsagePercent-200.0/3) > 0.001 {
		t.Errorf("cpu = %+v (busy 200 of 300 ticks)", s.CPU)
	}
	if s.Load != [3]float64{0.52, 0.40, 0.30} || s.Memory != (Memory{TotalKB: 8000000, AvailableKB: 5000000}) || s.Disk != (Disk{50000000, 20000000, 30000000}) {
		t.Errorf("metrics = %+v %+v %+v", s.Load, s.Memory, s.Disk)
	}
	if len(s.PackageManagers) != 1 || s.PackageManagers[0] != "apt-get" {
		t.Errorf("pkgmgr = %v", s.PackageManagers)
	}
	if s.Systemd != (Systemd{Active: true, SystemctlPath: "/usr/bin/systemctl", Version: "257"}) {
		t.Errorf("systemd = %+v", s.Systemd)
	}
	if s.Docker != (Docker{Path: "/usr/bin/docker", ServerVersion: "26.1.5", ComposeVersion: "2.29.1"}) || !s.Docker.Reachable() {
		t.Errorf("docker = %+v", s.Docker)
	}
	if s.Tools != (Tools{Btop: true, Tmux: true}) || !s.PasswordlessSudo {
		t.Errorf("tools = %+v sudo = %v", s.Tools, s.PasswordlessSudo)
	}
	if s.Probed != (ProbedAs{User: "admin"}) || s.Setup != nil {
		t.Errorf("setup = %+v / %+v", s.Probed, s.Setup)
	}
	want := []Address{
		{"127.0.0.1", "ipv4", "loopback"},
		{"10.0.0.5", "ipv4", "private"},
		{"203.0.113.9", "ipv4", "global"},
		{"fe80::1", "ipv6", "link"},
		{"2001:db8::5", "ipv6", "global"},
		{"fd00::5", "ipv6", "private"},
	}
	if len(s.Addresses) != len(want) {
		t.Fatalf("addresses = %+v", s.Addresses)
	}
	for i := range want {
		if s.Addresses[i] != want[i] {
			t.Errorf("address %d = %+v, want %+v", i, s.Addresses[i], want[i])
		}
	}
}

func TestParseTreatsEmptySectionsAsUnknownNotFalse(t *testing.T) {
	var b strings.Builder
	b.WriteString("@@probe 1\n")
	for _, name := range templates.ProbeSections {
		b.WriteString("@@" + name + "\n")
	}
	s, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if s.CPU.UsageKnown || s.Memory.TotalKB != 0 || s.Uptime != 0 || s.Docker.Reachable() || s.Systemd.Active || s.PasswordlessSudo {
		t.Errorf("snapshot = %+v", s)
	}
	caps := byName(Capabilities(s, false))
	if !caps["node.read"].Available || caps["node.metrics"].Available || caps["docker.read"].Available {
		t.Error("unknown values must not become capabilities")
	}
}

func TestParseSurvivesAMalformedSection(t *testing.T) {
	broken := strings.Replace(linuxProbe, "cpu  1100 0 600 8100 500 0 0 0 0 0", "cpu  garbage", 1)
	broken = strings.Replace(broken, "MemTotal:        8000000 kB", "MemTotal: lots", 1)
	s, err := Parse([]byte(broken))
	if err != nil {
		t.Fatal(err)
	}
	if s.CPU.UsageKnown || s.CPU.Cores != 4 || s.Memory.TotalKB != 0 || s.Disk.TotalKB == 0 || !s.Systemd.Active {
		t.Errorf("one bad section affected others: %+v", s)
	}
}

func TestParseIgnoresForgedHeadersAndUnknownFormats(t *testing.T) {
	forged := strings.Replace(linuxProbe, "node-a\n", "node-a\n@@sudo\nyes\n@@evil\n", 1)
	forged = strings.Replace(forged, "@@sudo\nyes\n@@setup", "@@sudo\nno\n@@setup", 1)
	s, err := Parse([]byte(forged))
	if err != nil {
		t.Fatal(err)
	}
	if s.PasswordlessSudo {
		t.Error("a forged @@sudo header inside another section was honored")
	}
	for _, bad := range []string{"", "garbage", "@@probe 2\n@@uname\nLinux\n", "@@uname\nLinux\n"} {
		if _, err := Parse([]byte(bad)); smerr.CodeOf(err) != smerr.CodeProviderError {
			t.Errorf("Parse(%q): %v", bad, err)
		}
	}
}

func TestParseMacOSProbe(t *testing.T) {
	body := map[string]string{
		"uname": "Darwin 24.1.0 arm64", "os": "ProductName:\t\tmacOS\nProductVersion:\t\t15.1",
		"cpu": "10\nCPU usage: 9.39% user, 6.40% sys, 84.19% idle ",
		"memory": "17179869184\nMach Virtual Memory Statistics: (page size of 16384 bytes)\n" +
			"Pages free:                                    22198.\nPages active:                                 411945.\n" +
			"Pages inactive:                               403328.\nPages speculative:                              7992.\n" +
			"Pages throttled:                                   0.\nPages wired down:                             259671.",
		"pkgmgr": "brew", "systemd": "absent", "docker": "path=",
		"addresses": "lo0: flags=8049\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255",
	}
	probe := "@@probe 1\n"
	for _, name := range templates.ProbeSections {
		probe += "@@" + name + "\n" + body[name] + "\n"
	}
	s, err := Parse([]byte(probe))
	if err != nil {
		t.Fatal(err)
	}
	if s.OS.Name != "macOS 15.1" || s.CPU.Cores != 10 || s.Memory.TotalKB != 16*1024*1024 || s.Systemd.Active || len(s.Addresses) != 2 {
		t.Errorf("snapshot = %+v", s)
	}
}

func TestTopIdlePercentRefusesWhatIsNotAPercentage(t *testing.T) {
	for _, line := range []string{"CPU usage: NaN% idle", "CPU usage: +Inf% idle", "CPU usage: 150% idle", "CPU usage: -1% idle", "CPU usage: 5% user"} {
		if idle, ok := topIdlePercent(line); ok {
			t.Errorf("topIdlePercent(%q) = %v, accepted", line, idle)
		}
	}
}

func TestParseMacOSProbeReadsUsageNotJustTotals(t *testing.T) {
	probe := "@@probe 1\n"
	for _, name := range templates.ProbeSections {
		body := map[string]string{
			"cpu":    "10\nCPU usage: 9.39% user, 6.40% sys, 84.19% idle ",
			"memory": "17179869184\nMach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 1000.\nPages inactive: 2000.\nPages speculative: 100.\nPages wired down: 9999.",
		}[name]
		probe += "@@" + name + "\n" + body + "\n"
	}
	s, err := Parse([]byte(probe))
	if err != nil {
		t.Fatal(err)
	}
	if !s.CPU.UsageKnown || math.Abs(s.CPU.UsagePercent-15.81) > 0.001 {
		t.Errorf("cpu = %+v, want 15.81%% busy (100 - idle)", s.CPU)
	}
	if want := uint64(3100 * 16); s.Memory.AvailableKB != want {
		t.Errorf("available = %d KiB, want free+inactive+speculative pages = %d", s.Memory.AvailableKB, want)
	}
}

func byName(caps []database.NodeCapability) map[string]database.NodeCapability {
	m := map[string]database.NodeCapability{}
	for _, c := range caps {
		m[c.Capability] = c
	}
	return m
}

func TestReadCapabilitiesNeverDependOnSetup(t *testing.T) {
	s, _ := Parse([]byte(linuxProbe))
	s.TakenAt = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	caps := byName(Capabilities(s, false))
	for _, name := range []string{"node.read", "node.metrics", "node.ssh", "node.exec.template", "node.packages.read", "service.read", "service.logs", "docker.read", "docker.logs", "tool.btop", "tool.tmux"} {
		c, ok := caps[name]
		if !ok || !c.Available || !c.CheckedAt.Equal(s.TakenAt) {
			t.Errorf("%s = %+v", name, c)
		}
	}
	if caps["tool.lazydocker"].Available {
		t.Error("lazydocker absent but advertised")
	}
	if caps["service.logs"].Metadata["mode"] != runtimes.LogsJournalGroup {
		t.Errorf("logs mode = %v", caps["service.logs"].Metadata["mode"])
	}
	if _, ok := caps["node.setup"]; ok {
		t.Error("node.setup is the setup job's to write")
	}
}

func TestMutatingCapabilitiesNeedSSHAndSetup(t *testing.T) {
	s, _ := Parse([]byte(linuxProbe))
	mutating := []string{"service.start", "service.stop", "service.restart"}
	available := func(caps map[string]database.NodeCapability) []string {
		var out []string
		for _, n := range mutating {
			c, ok := caps[n]
			if !ok {
				t.Fatalf("%s is not reported", n)
			}
			if c.Available {
				out = append(out, n)
			}
		}
		return out
	}

	if got := available(byName(Capabilities(s, false))); len(got) != 0 {
		t.Errorf("without setup: %v", got)
	}

	s.Setup = &runtimes.SetupMeta{
		SetupVersion: 1, SystemctlPath: "/usr/bin/systemctl", LogsMode: runtimes.LogsBroker,
		Units: []runtimes.UnitGrant{{Unit: "app.service", Verbs: []domain.ServiceVerb{domain.VerbRestart, domain.VerbStop}}},
	}
	caps := byName(Capabilities(s, false))
	if got := available(caps); strings.Join(got, ",") != "service.stop,service.restart" {
		t.Errorf("with setup: %v", got)
	}
	if units := caps["service.restart"].Metadata["units"].([]string); len(units) != 1 || units[0] != "app.service" {
		t.Errorf("units = %v", units)
	}
	if caps["service.logs"].Metadata["mode"] != runtimes.LogsBroker {
		t.Error("broker mode not reported")
	}

	if got := available(byName(Capabilities(s, true))); len(got) != 0 {
		t.Errorf("local provider advertised %v", got)
	}
	if byName(Capabilities(s, true))["node.ssh"].Available {
		t.Error("local node advertises ssh")
	}

	s.Setup.DockerAccess = true
	if got := available(byName(Capabilities(s, false))); len(got) != 3 {
		t.Errorf("docker_access should enable all verbs on containers: %v", got)
	}
	s.Docker.ServerVersion = ""
	if got := available(byName(Capabilities(s, false))); len(got) != 2 {
		t.Errorf("unreachable docker still advertised: %v", got)
	}
	s.Systemd.Active = false
	if got := available(byName(Capabilities(s, false))); len(got) != 0 {
		t.Errorf("no systemd, no docker: %v", got)
	}
}

type probeExec struct {
	out  string
	rans int
}

func (p *probeExec) Run(_ context.Context, c templates.Command) (transport.Result, error) {
	p.rans++
	return transport.Result{Stdout: []byte(p.out)}, nil
}

func TestProbeRunsOneSession(t *testing.T) {
	ex := &probeExec{out: linuxProbe}
	s, err := Probe(context.Background(), ex)
	if err != nil || ex.rans != 1 || s.Hostname != "node-a" {
		t.Errorf("snapshot = %+v, sessions = %d, err = %v", s, ex.rans, err)
	}
}

func composeDeployNode(t *testing.T) Snapshot {
	t.Helper()
	probe := strings.Replace(linuxProbe, "compose=2.29.1", "compose=5.5.1", 1)
	probe = strings.Replace(probe, "@@tools\nbtop\ntmux", "@@tools\nbtop\ntmux\ncurl\nbash\ntimeout\nflock\njq\nss\nsha256sum\nbase64\ndf", 1)
	s, err := Parse([]byte(probe))
	if err != nil {
		t.Fatal(err)
	}
	s.Setup = &runtimes.SetupMeta{SetupVersion: 2, DockerAccess: true}
	return s
}

func TestParseDeploymentTools(t *testing.T) {
	s := composeDeployNode(t)
	want := Tools{Btop: true, Tmux: true, Curl: true, Bash: true, Timeout: true, Flock: true, Jq: true, Ss: true, Sha256sum: true, Base64: true, Df: true}
	if s.Tools != want {
		t.Errorf("tools = %+v", s.Tools)
	}
}

func TestComposeDeployCapability(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Snapshot)
		local      bool
		wantReason string
	}{
		{"all requirements met", func(*Snapshot) {}, false, ""},
		{"no setup recorded", func(s *Snapshot) { s.Setup = nil }, false, "node.setup version 2 required"},
		{"v1 node", func(s *Snapshot) { s.Setup.SetupVersion = 1 }, false, "node.setup version 2 required"},
		{"no docker access", func(s *Snapshot) { s.Setup.DockerAccess = false }, false, "docker access required"},
		{"daemon unreachable", func(s *Snapshot) { s.Docker.ServerVersion = "" }, false, "docker access required"},
		{"wrong compose version", func(s *Snapshot) { s.Docker.ComposeVersion = "2.29.1" }, false, "unsupported compose version 2.29.1"},
		{"v-prefixed compose version", func(s *Snapshot) { s.Docker.ComposeVersion = "v5.5.1" }, false, "unsupported compose version v5.5.1"},
		{"flock missing", func(s *Snapshot) { s.Tools.Flock = false }, false, "flock missing"},
		{"jq missing", func(s *Snapshot) { s.Tools.Jq = false }, false, "jq missing"},
		{"bash missing", func(s *Snapshot) { s.Tools.Bash = false }, false, "bash missing"},
		{"timeout missing", func(s *Snapshot) { s.Tools.Timeout = false }, false, "timeout missing"},
		{"ss missing", func(s *Snapshot) { s.Tools.Ss = false }, false, "ss missing"},
		{"sha256sum missing", func(s *Snapshot) { s.Tools.Sha256sum = false }, false, "sha256sum missing"},
		{"base64 missing", func(s *Snapshot) { s.Tools.Base64 = false }, false, "base64 missing"},
		{"df missing", func(s *Snapshot) { s.Tools.Df = false }, false, "df missing"},
		{"local provider", func(*Snapshot) {}, true, "ssh node required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := composeDeployNode(t)
			tt.mutate(&s)
			c, ok := byName(Capabilities(s, tt.local))["docker.compose.deploy"]
			if !ok {
				t.Fatal("docker.compose.deploy is not reported")
			}
			reason, _ := c.Metadata["reason"].(string)
			if c.Available != (tt.wantReason == "") || reason != tt.wantReason {
				t.Errorf("available = %v, reason = %q, want reason %q", c.Available, reason, tt.wantReason)
			}
		})
	}
}

func TestHealthCapabilitiesFollowTools(t *testing.T) {
	tests := []struct {
		name      string
		tools     Tools
		http, tcp bool
	}{
		{"none", Tools{}, false, false},
		{"curl only", Tools{Curl: true}, true, false},
		{"bash without timeout", Tools{Bash: true}, false, false},
		{"bash and timeout", Tools{Bash: true, Timeout: true}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := byName(Capabilities(Snapshot{Tools: tt.tools}, false))
			if caps["health.http"].Available != tt.http || caps["health.tcp"].Available != tt.tcp {
				t.Errorf("http = %v, tcp = %v", caps["health.http"].Available, caps["health.tcp"].Available)
			}
		})
	}
}
