package systemd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func ref(unit string) runtimes.ServiceRef {
	return runtimes.ServiceRef{Kind: domain.ServiceSystemdUnit, NativeID: unit, Name: unit}
}

const unitList = `  ssh.service                       loaded    active   running OpenBSD Secure Shell server
  systemd-journald.service          loaded    active   running Journal Service
  getty@tty1.service                loaded    active   running Getty on tty1
  sm-demo.service                   loaded    active   running SuperMgmt demo
● broken.service                    loaded    failed   failed  A broken one
  ghost.service                     not-found inactive dead    ghost.service
  user@1000.service                 loaded    active   running User Manager
`

func discoverNode(t *testing.T) *fakeNode {
	return newFakeNode(t).reply("systemd.version", "systemd 257 (257.9-1)\n+PAM +AUDIT\n").reply("systemd.list_units", unitList)
}

func names(d runtimes.Discovered) []string {
	var out []string
	for _, s := range d.Services {
		out = append(out, s.Name)
	}
	return out
}

func TestDiscoverDefaultSelectionHidesSystemMachinery(t *testing.T) {
	d, err := New().Discover(context.Background(), discoverNode(t), runtimes.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(names(d), ","), "ssh.service,sm-demo.service,broken.service"; got != want {
		t.Errorf("services = %s, want %s", got, want)
	}
	if d.Runtime.Type != domain.RuntimeSystemd || d.Runtime.Version != "257" {
		t.Errorf("runtime = %+v", d.Runtime)
	}
	broken := d.Services[2]
	if broken.Kind != domain.ServiceSystemdUnit || broken.NativeID != "broken.service" || broken.Status != "failed" || broken.Metadata["sub_state"] != "failed" {
		t.Errorf("broken = %+v", broken)
	}
}

func TestDiscoverIncludeReplacesDefaultsAndExcludeWins(t *testing.T) {
	tests := []struct {
		name   string
		filter runtimes.Filter
		want   string
	}{
		{"include system unit", runtimes.Filter{Include: []string{"systemd-*"}}, "systemd-journald.service"},
		{"include without suffix", runtimes.Filter{Include: []string{"sm-*"}}, "sm-demo.service"},
		{"include with suffix", runtimes.Filter{Include: []string{"s*.service"}}, "ssh.service,systemd-journald.service,sm-demo.service"},
		{"exclude wins", runtimes.Filter{Include: []string{"s*"}, Exclude: []string{"systemd-*", "ssh"}}, "sm-demo.service"},
		{"exclude on defaults", runtimes.Filter{Exclude: []string{"broken"}}, "ssh.service,sm-demo.service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New().Discover(context.Background(), discoverNode(t), tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(names(d), ","); got != tt.want {
				t.Errorf("services = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDiscoverFailures(t *testing.T) {
	if _, err := New().Discover(context.Background(), discoverNode(t), runtimes.Filter{Include: []string{"[a"}}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("bad pattern: %v", err)
	}
	absent := newFakeNode(t).fail("systemd.version", 127)
	if _, err := New().Discover(context.Background(), absent, runtimes.Filter{}); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("no systemd: %v", err)
	}
	garbage := newFakeNode(t).reply("systemd.version", "not systemd\n")
	if _, err := New().Discover(context.Background(), garbage, runtimes.Filter{}); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("garbage version: %v", err)
	}
}

func TestLogsAreSanitizedBoundedAndModeAware(t *testing.T) {
	node := newFakeNode(t).on("systemd.logs_group", func(templates.Command) transport.Result {
		return transport.Result{Stdout: []byte("2026-01-01T00:00:00+0000 h u[1]: \x1b[31mred\x1b[0m\x07 \xff end\n\x1b]0;title\x07second\r\n"), Truncated: true}
	})
	chunk, err := New().Logs(context.Background(), node, ref("sm-demo.service"), runtimes.LogQuery{Lines: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(chunk.Lines) != 2 || chunk.Lines[0] != "2026-01-01T00:00:00+0000 h u[1]: red � end" || chunk.Lines[1] != "second" || !chunk.Truncated {
		t.Errorf("chunk = %+v", chunk)
	}
	if line := node.calls[0].Line; !strings.Contains(line, "SYSTEMD_PAGER= PAGER=cat journalctl --no-pager") || !strings.Contains(line, "-n '50'") {
		t.Errorf("line = %s", line)
	}

	broker := newFakeNode(t).reply("systemd.logs_broker", "line\n")
	if _, err := New().Logs(context.Background(), broker, ref("sm-demo.service"), runtimes.LogQuery{Lines: 10, Mode: runtimes.LogsBroker}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(broker.calls[0].Line, "sudo -n /usr/local/libexec/supermgmt/unit-logs 'sm-demo.service' '10'") {
		t.Errorf("broker line = %s", broker.calls[0].Line)
	}
}

func TestLogsRejectBadQueries(t *testing.T) {
	node := newFakeNode(t)
	for _, lines := range []int{0, -1, runtimes.MaxLogLines + 1} {
		if _, err := New().Logs(context.Background(), node, ref("a.service"), runtimes.LogQuery{Lines: lines}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("lines %d: %v", lines, err)
		}
	}
	if _, err := New().Logs(context.Background(), node, ref("a;b.service"), runtimes.LogQuery{Lines: 1}); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("bad unit: %v", err)
	}
	if _, err := New().Logs(context.Background(), node, runtimes.ServiceRef{Kind: domain.ServiceDockerContainer, NativeID: "a.service"}, runtimes.LogQuery{Lines: 1}); err == nil {
		t.Error("docker ref accepted")
	}
	if len(node.calls) != 0 {
		t.Errorf("rejected queries still reached the node: %v", node.ran())
	}
	denied := newFakeNode(t).fail("systemd.logs_broker", 1)
	if _, err := New().Logs(context.Background(), denied, ref("a.service"), runtimes.LogQuery{Lines: 1, Mode: runtimes.LogsBroker}); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("denied: %v", err)
	}
}

func TestMutateNeedsAGrantAndWrapsInTheMarkerProtocol(t *testing.T) {
	setup := runtimes.SetupMeta{SystemctlPath: testSystemctl, Units: []runtimes.UnitGrant{{Unit: "a.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}}}}
	cmd, err := New().Mutate(ref("a.service"), domain.VerbRestart, "0190-m1", setup)
	if err != nil {
		t.Fatal(err)
	}
	if !cmd.Mutating || cmd.Deadline != 2*time.Minute || !strings.HasPrefix(cmd.Line, ": > /var/lib/supermgmt/markers/0190-m1 && { timeout --kill-after=10s 120s sudo -n '/usr/bin/systemctl' restart 'a.service'") {
		t.Errorf("cmd = %+v", cmd)
	}
	for name, call := range map[string]func() error{
		"verb not granted": func() error { _, err := New().Mutate(ref("a.service"), domain.VerbStop, "m1", setup); return err },
		"unit not granted": func() error { _, err := New().Mutate(ref("b.service"), domain.VerbRestart, "m1", setup); return err },
		"no setup": func() error {
			_, err := New().Mutate(ref("a.service"), domain.VerbRestart, "m1", runtimes.SetupMeta{})
			return err
		},
		"unknown verb": func() error { _, err := New().Mutate(ref("a.service"), "reload", "m1", setup); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func showReply(invocation, active, sub string) string {
	return "Id=a.service\nLoadState=loaded\nActiveState=" + active + "\nSubState=" + sub + "\nInvocationID=" + invocation + "\n"
}

func TestPreStateRecordsTheInvocationID(t *testing.T) {
	node := newFakeNode(t).reply("systemd.show", showReply("inv-1", "active", "running"))
	pre, err := New().PreState(context.Background(), node, ref("a.service"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pre) != `{"invocation_id":"inv-1","active_state":"active","sub_state":"running"}` {
		t.Errorf("pre = %s", pre)
	}
}

func TestObserveMapsEvidence(t *testing.T) {
	const pre = `{"invocation_id":"inv-1","active_state":"active","sub_state":"running"}`
	tests := []struct {
		name string
		verb domain.ServiceVerb
		show string
		want jobs.Classification
	}{
		{"restart new invocation active", domain.VerbRestart, showReply("inv-2", "active", "running"), jobs.ClassComplete},
		{"restart unchanged invocation", domain.VerbRestart, showReply("inv-1", "active", "running"), jobs.ClassNotStarted},
		{"restart new invocation not active", domain.VerbRestart, showReply("inv-2", "failed", "failed"), jobs.ClassUnknown},
		{"restart new invocation activating", domain.VerbRestart, showReply("inv-2", "activating", "auto-restart"), jobs.ClassUnknown},
		{"start new invocation active", domain.VerbStart, showReply("inv-2", "active", "running"), jobs.ClassComplete},
		{"start unchanged invocation", domain.VerbStart, showReply("inv-1", "active", "running"), jobs.ClassNotStarted},
		{"stop inactive", domain.VerbStop, showReply("inv-1", "inactive", "dead"), jobs.ClassComplete},
		{"stop still active", domain.VerbStop, showReply("inv-1", "active", "running"), jobs.ClassNotStarted},
		{"stop deactivating", domain.VerbStop, showReply("inv-1", "deactivating", "stop-sigterm"), jobs.ClassUnknown},
		{"stop failed", domain.VerbStop, showReply("inv-1", "failed", "failed"), jobs.ClassUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := newFakeNode(t).reply("systemd.list_jobs", "77 other.service start running\n").reply("systemd.show", tt.show)
			o, err := observe(context.Background(), node, ref("a.service"), tt.verb, json.RawMessage(pre))
			if err != nil {
				t.Fatal(err)
			}
			if o.Classification != tt.want || o.Proof != ProofNoJobs || string(o.Pre) != pre {
				t.Errorf("observation = %+v", o)
			}
			var fp unitState
			if err := json.Unmarshal(o.Fingerprint, &fp); err != nil || fp.ActiveState == "" {
				t.Errorf("fingerprint = %s (%v)", o.Fingerprint, err)
			}
			ev, err := New().Observe(context.Background(), node, ref("a.service"), tt.verb, "m1", json.RawMessage(pre), time.Time{})
			if err != nil || !ev.Proven() || ev.Classification != tt.want {
				t.Errorf("evidence = %+v, %v", ev, err)
			}
		})
	}
}

func TestObserveFingerprintChangesWithTheInvocationID(t *testing.T) {
	fingerprint := func(invocation string) string {
		node := newFakeNode(t).reply("systemd.list_jobs", "").reply("systemd.show", showReply(invocation, "active", "running"))
		o, err := observe(context.Background(), node, ref("a.service"), domain.VerbRestart, json.RawMessage(`{"invocation_id":"old"}`))
		if err != nil {
			t.Fatal(err)
		}
		return string(o.Fingerprint)
	}
	if fingerprint("inv-2") == fingerprint("inv-3") {
		t.Error("two invocations share a fingerprint, so a pair of samples would wrongly agree")
	}
}

func TestObserveWhileSystemdHasAJobIsNoEvidence(t *testing.T) {
	node := newFakeNode(t).reply("systemd.list_jobs", "12 a.service restart running\n99 b.service start waiting\n")
	_, err := New().Observe(context.Background(), node, ref("a.service"), domain.VerbRestart, "m1", json.RawMessage(`{}`), time.Time{})
	if err == nil || !strings.Contains(err.Error(), ErrSettling.Error()) {
		t.Fatalf("got %v, want ErrSettling", err)
	}
	if node.count("systemd.show") != 0 {
		t.Error("state was sampled while a job was still queued")
	}
}

func TestObserveUnreachableAndBadPreState(t *testing.T) {
	node := newFakeNode(t).fail("systemd.list_jobs", 1)
	if _, err := New().Observe(context.Background(), node, ref("a.service"), domain.VerbRestart, "m1", json.RawMessage(`{}`), time.Time{}); err == nil {
		t.Error("failing list-jobs counted as evidence")
	}
	if _, err := New().Observe(context.Background(), newFakeNode(t), ref("a.service"), domain.VerbRestart, "m1", json.RawMessage(`nope`), time.Time{}); err == nil {
		t.Error("undecodable pre-state counted as evidence")
	}
}
