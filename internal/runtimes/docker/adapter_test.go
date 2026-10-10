package docker

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

type fakeNode struct {
	t        *testing.T
	handlers map[string]transport.Result
	calls    []templates.Command
}

func newFakeNode(t *testing.T) *fakeNode {
	return &fakeNode{t: t, handlers: map[string]transport.Result{}}
}

func (f *fakeNode) reply(template, stdout string) *fakeNode {
	f.handlers[template] = transport.Result{Stdout: []byte(stdout)}
	return f
}

func (f *fakeNode) fail(template string, status int) *fakeNode {
	f.handlers[template] = transport.Result{ExitStatus: status}
	return f
}

func (f *fakeNode) Run(_ context.Context, c templates.Command) (transport.Result, error) {
	f.calls = append(f.calls, c)
	r, ok := f.handlers[c.Template]
	if !ok {
		f.t.Fatalf("unexpected template %s", c.Template)
	}
	return r, nil
}

func ref(id string) runtimes.ServiceRef {
	return runtimes.ServiceRef{Kind: domain.ServiceDockerContainer, NativeID: id, Name: "web"}
}

const dockerVersion = `Client: Docker Engine - Community
 Version:           26.1.5
 API version:       1.45

Server: Docker Engine - Community
 Engine:
  Version:          26.1.5
  API version:      1.45 (minimum version 1.24)
`

const inspectAll = `[
 {"Id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Name":"/sm-demo-web","Image":"sha256:1234",
  "Config":{"Image":"nginx:1.27","Labels":{"com.docker.compose.project":"demo","note":"hi\u001b[31m"}},
  "State":{"Status":"running","Running":true,"StartedAt":"2026-10-10T10:00:00.5Z","Health":{"Status":"healthy"}},
  "NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}],"443/tcp":null}}},
 {"Id":"bbbb","Name":"/job-runner","Image":"sha256:5678","Config":{"Image":"alpine","Labels":null},
  "State":{"Status":"exited","Running":false,"StartedAt":"2026-10-09T10:00:00Z"},"NetworkSettings":{"Ports":{}}}
]`

func discoverNode(t *testing.T) *fakeNode {
	return newFakeNode(t).reply("docker.version", dockerVersion).reply("docker.compose_version", "2.29.1\n").reply("docker.inspect_all", inspectAll)
}

func TestDiscoverReportsEngineAndContainers(t *testing.T) {
	d, err := New().Discover(context.Background(), discoverNode(t), runtimes.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Runtime.Type != domain.RuntimeDocker || d.Runtime.Version != "26.1.5" || d.Runtime.Metadata["compose_version"] != "2.29.1" {
		t.Errorf("runtime = %+v", d.Runtime)
	}
	if len(d.Services) != 2 {
		t.Fatalf("services = %+v", d.Services)
	}
	web := d.Services[0]
	if web.Kind != domain.ServiceDockerContainer || web.Name != "sm-demo-web" || web.Status != "running" || web.Health != "healthy" || web.NativeID[:4] != "aaaa" {
		t.Errorf("web = %+v", web)
	}
	if web.Metadata["compose_project"] != "demo" || web.Metadata["image"] != "nginx:1.27" || web.Metadata["ports"].([]string)[0] != "0.0.0.0:8080->80/tcp" {
		t.Errorf("metadata = %+v", web.Metadata)
	}
	if labels := web.Metadata["labels"].(map[string]any); labels["note"] != "hi" {
		t.Errorf("label not sanitized: %q", labels["note"])
	}
	if job := d.Services[1]; job.Status != "exited" || job.Health != "" {
		t.Errorf("job = %+v", job)
	}
}

func TestDiscoverFilterAndFailures(t *testing.T) {
	d, err := New().Discover(context.Background(), discoverNode(t), runtimes.Filter{Include: []string{"sm-*", "job-*"}, Exclude: []string{"job-*"}})
	if err != nil || len(d.Services) != 1 || d.Services[0].Name != "sm-demo-web" {
		t.Errorf("filtered = %+v, %v", d.Services, err)
	}
	if _, err := New().Discover(context.Background(), discoverNode(t), runtimes.Filter{Exclude: []string{"[x"}}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("bad pattern: %v", err)
	}
	noServer := newFakeNode(t).reply("docker.version", "Client:\n Version: 26.1.5\n")
	if _, err := New().Discover(context.Background(), noServer, runtimes.Filter{}); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("no server: %v", err)
	}
	empty := discoverNode(t).reply("docker.inspect_all", "")
	if d, err := New().Discover(context.Background(), empty, runtimes.Filter{}); err != nil || len(d.Services) != 0 {
		t.Errorf("no containers: %+v, %v", d, err)
	}
	broken := discoverNode(t).reply("docker.inspect_all", "[{")
	if _, err := New().Discover(context.Background(), broken, runtimes.Filter{}); err == nil {
		t.Error("unreadable inspect output accepted")
	}
	noCompose := discoverNode(t).fail("docker.compose_version", 1)
	if d, err := New().Discover(context.Background(), noCompose, runtimes.Filter{}); err != nil || d.Runtime.Metadata["compose_version"] != "" {
		t.Errorf("no compose: %+v, %v", d.Runtime, err)
	}
}

func TestLogsAreSanitizedAndBounded(t *testing.T) {
	node := newFakeNode(t).reply("docker.logs", "2026-10-10T10:00:00Z \x1b[1mhello\x1b[0m\x00\n2026-10-10T10:00:01Z bye\n")
	chunk, err := New().Logs(context.Background(), node, ref("sm-demo-web"), runtimes.LogQuery{Lines: 20})
	if err != nil || len(chunk.Lines) != 2 || chunk.Lines[0] != "2026-10-10T10:00:00Z hello" {
		t.Fatalf("chunk = %+v, %v", chunk, err)
	}
	if want := "docker logs --timestamps --tail '20' -- 'sm-demo-web' 2>&1"; node.calls[0].Line != want {
		t.Errorf("line = %s", node.calls[0].Line)
	}
	for _, lines := range []int{0, runtimes.MaxLogLines + 1} {
		if _, err := New().Logs(context.Background(), node, ref("x"), runtimes.LogQuery{Lines: lines}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("lines %d: %v", lines, err)
		}
	}
	for _, id := range []string{"-rf", "a b", "a;b", "$(id)", ""} {
		if _, err := New().Logs(context.Background(), node, ref(id), runtimes.LogQuery{Lines: 1}); err == nil {
			t.Errorf("container %q accepted", id)
		}
	}
}

func TestMutateRequiresDockerAccess(t *testing.T) {
	cmd, err := New().Mutate(ref("sm-demo-web"), domain.VerbRestart, "0190-m1", runtimes.SetupMeta{DockerAccess: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd.Line, "timeout --kill-after=10s 120s docker restart -- 'sm-demo-web'; rc=$?") || !cmd.Mutating {
		t.Errorf("line = %s", cmd.Line)
	}
	if _, err := New().Mutate(ref("sm-demo-web"), domain.VerbRestart, "m1", runtimes.SetupMeta{}); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("without docker_access: %v", err)
	}
	if _, err := New().Mutate(ref("a;b"), domain.VerbStop, "m1", runtimes.SetupMeta{DockerAccess: true}); err == nil {
		t.Error("injection accepted")
	}
}

func inspectOne(started string, running bool) string {
	state := `{"Status":"running","Running":` + map[bool]string{true: "true", false: "false"}[running] + `,"StartedAt":"` + started + `"}`
	return `[{"Id":"aaaa","Name":"/web","Config":{"Image":"x"},"State":` + state + `}]`
}

func TestPreStateRecordsStartedAt(t *testing.T) {
	pre, err := New().PreState(context.Background(), newFakeNode(t).reply("docker.inspect", inspectOne("2026-10-10T10:00:00Z", true)), ref("web"))
	if err != nil || string(pre) != `{"started_at":"2026-10-10T10:00:00Z","running":true,"status":"running"}` {
		t.Errorf("pre = %s, %v", pre, err)
	}
	if _, err := New().PreState(context.Background(), newFakeNode(t).fail("docker.inspect", 1), ref("web")); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("missing container: %v", err)
	}
}

func TestObserveMapsEvidence(t *testing.T) {
	dispatched := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	const pre = `{"started_at":"2026-10-10T09:00:00Z","running":true}`
	tests := []struct {
		name    string
		verb    domain.ServiceVerb
		done    string
		doneErr int
		inspect string
		want    jobs.Classification
		noProof bool
	}{
		{"restart started after dispatch", domain.VerbRestart, "0\n", 0, inspectOne("2026-10-10T10:00:03.25Z", true), jobs.ClassComplete, false},
		{"start started after dispatch", domain.VerbStart, "0\n", 0, inspectOne("2026-10-10T10:00:03Z", true), jobs.ClassComplete, false},
		{"restart not restarted", domain.VerbRestart, "0\n", 0, inspectOne("2026-10-10T09:00:00Z", true), jobs.ClassUnknown, false},
		{"restart started but stopped", domain.VerbRestart, "0\n", 0, inspectOne("2026-10-10T10:00:03Z", false), jobs.ClassUnknown, false},
		{"start at exactly dispatch time", domain.VerbStart, "0\n", 0, inspectOne("2026-10-10T10:00:00Z", true), jobs.ClassUnknown, false},
		{"stop stopped", domain.VerbStop, "0\n", 0, inspectOne("2026-10-10T09:00:00Z", false), jobs.ClassComplete, false},
		{"stop still running", domain.VerbStop, "0\n", 0, inspectOne("2026-10-10T09:00:00Z", true), jobs.ClassUnknown, false},
		{"done file missing", domain.VerbRestart, "", 1, inspectOne("2026-10-10T10:00:03Z", true), "", true},
		{"done file nonzero", domain.VerbRestart, "1\n", 0, inspectOne("2026-10-10T10:00:03Z", true), "", true},
		{"done file garbage", domain.VerbRestart, "ok\n", 0, inspectOne("2026-10-10T10:00:03Z", true), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := newFakeNode(t).reply("docker.inspect", tt.inspect)
			node.handlers["docker.done_file"] = transport.Result{Stdout: []byte(tt.done), ExitStatus: tt.doneErr}
			ev, err := New().Observe(context.Background(), node, ref("web"), tt.verb, "0190-m1", json.RawMessage(pre), dispatched)
			if tt.noProof {
				if err == nil {
					t.Fatalf("got evidence %+v without a completion proof", ev)
				}
				if len(node.calls) != 1 {
					t.Errorf("state was inspected without proof: %d calls", len(node.calls))
				}
				return
			}
			if err != nil || !ev.Proven() || ev.Classification != tt.want {
				t.Errorf("evidence = %+v, %v", ev, err)
			}
			if got := node.calls[0].Line; got != "cat '/var/lib/supermgmt/markers/0190-m1.done'" {
				t.Errorf("done file read = %s", got)
			}
			o, _ := observe(context.Background(), node, ref("web"), tt.verb, "0190-m1", json.RawMessage(pre), dispatched)
			if o.Proof != ProofDoneFile || string(o.Pre) != pre || !strings.Contains(string(o.Fingerprint), `"started_at"`) {
				t.Errorf("observation = %+v", o)
			}
		})
	}
}

func TestObserveRejectsAnUnsafeMarker(t *testing.T) {
	node := newFakeNode(t)
	if _, err := New().Observe(context.Background(), node, ref("web"), domain.VerbStop, "../etc/passwd", json.RawMessage(`{}`), time.Time{}); err == nil {
		t.Error("path traversal marker accepted")
	}
	if len(node.calls) != 0 {
		t.Error("node contacted")
	}
}
