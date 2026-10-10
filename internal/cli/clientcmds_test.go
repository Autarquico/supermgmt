package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

func newTestID() domain.ID { return domain.UUIDv7Generator{}.NewID() }

func TestAPICommandsFailWithThePrerequisiteExitWhenNoDaemonRuns(t *testing.T) {
	f := newFakeAPI(t, nil)
	r := f.run("status")
	if r.code != exitPrerequisite || !strings.Contains(r.stderr, "daemon is not reachable") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
}

func TestNodesListShowsStateAndForwardsFilters(t *testing.T) {
	node := wire.Node{
		ID: newTestID(), Name: "web-1", Environment: "production", ManagementState: "managed",
		Reachability: "unreachable", Stale: true, Connection: wire.Connection{State: wire.ConnBackoff},
		Endpoint: wire.Endpoint{Host: "203.0.113.7", Port: 22, AdminUser: "alex"},
	}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{node}, NextCursor: "c2"})
		},
	}))
	r := f.run("nodes", "list", "--environment", "production", "--tag", "db", "--limit", "5")
	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{string(node.ID), "web-1", "unreachable (stale)", "backoff", "alex@203.0.113.7:22", "more results: --cursor c2"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	if q := f.Requests()[0].Query; q != "environment=production&limit=5&tag=db" {
		t.Errorf("query = %q", q)
	}
}

func TestNodesListJSONIsThePage(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{Name: "n"}}})
		},
	}))
	r := f.run("nodes", "list", "--json")
	var page wire.Page[wire.Node]
	if err := json.Unmarshal([]byte(r.stdout), &page); err != nil || len(page.Items) != 1 || page.Items[0].Name != "n" {
		t.Fatalf("stdout = %q, err = %v", r.stdout, err)
	}
}

func TestNodesListRejectsAnUnknownReachabilityBeforeAnyRequest(t *testing.T) {
	f := newFakeAPI(t, router(nil))
	if r := f.run("nodes", "list", "--reachability", "sideways"); r.code != exitUsage {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("daemon saw %d requests", n)
	}
}

func TestNodeReferenceResolvesByNameAndRefusesAmbiguity(t *testing.T) {
	web, dup1, dup2 := newTestID(), newTestID(), newTestID()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{ID: web, Name: "web"}, {ID: dup1, Name: "db"}, {ID: dup2, Name: "db"}}})
		},
		"GET " + wire.Path(wire.PathNode, string(web)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Node{ID: web, Name: "web"})
		},
	}))
	if r := f.run("nodes", "get", "web"); r.code != 0 || !strings.Contains(r.stdout, string(web)) {
		t.Errorf("get web: code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if r := f.run("nodes", "get", "db"); r.code != exitInternal || !strings.Contains(r.stderr, "use the id") {
		t.Errorf("get db: code=%d err=%q", r.code, r.stderr)
	}
	if r := f.run("nodes", "get", "nope"); !strings.Contains(r.stderr, `no node named "nope"`) {
		t.Errorf("get nope: err=%q", r.stderr)
	}
}

func scannedKey(t *testing.T) wire.HostKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return wire.HostKey{
		AuthorizedKey: strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key))), Type: "ssh-ed25519",
		FingerprintSHA256: cryptossh.FingerprintSHA256(key),
	}
}

func addNodeAPI(t *testing.T, key wire.HostKey) *fakeAPI {
	t.Helper()
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.PathNodesSSHHostKey: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, key) },
		"POST " + wire.PathNodesSSH: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 201, wire.Direct[wire.Node]{Applied: &wire.Node{ID: newTestID(), Name: "web-1"}})
		},
	}))
}

var addArgs = []string{"nodes", "add", "--name", "web-1", "--host", "203.0.113.7", "--admin-user", "alex", "--environment", "staging", "--tag", "a", "--tag", "b"}

func TestNodesAddPinsTheKeyTheUserConfirmedByFingerprint(t *testing.T) {
	key := scannedKey(t)
	f := addNodeAPI(t, key)
	r := f.run(append(addArgs, "--fingerprint", key.FingerprintSHA256)...)
	if r.code != 0 || !strings.Contains(r.stdout, "added node web-1") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	var sent wire.AddSSHNodeRequest
	adds := f.Mutations()
	if len(adds) != 1 || json.Unmarshal([]byte(adds[0].Body), &sent) != nil {
		t.Fatalf("mutations = %+v", adds)
	}
	if sent.HostPublicKey != key.AuthorizedKey || sent.Port != 22 || sent.AdminUser != "alex" || len(sent.Tags) != 2 || sent.Environment != "staging" {
		t.Errorf("request = %+v", sent)
	}
	if !strings.Contains(r.stderr, key.FingerprintSHA256) {
		t.Errorf("the scanned fingerprint was not shown: %q", r.stderr)
	}
}

func TestNodesAddRefusesAKeyThatDiffersFromTheExpectedFingerprint(t *testing.T) {
	f := addNodeAPI(t, scannedKey(t))
	r := f.run(append(addArgs, "--fingerprint", "SHA256:somethingelse")...)
	if r.code != exitInternal || !strings.Contains(r.stderr, "SSH_HOST_KEY_MISMATCH") && !strings.Contains(r.stderr, "not the expected") {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
	if n := len(f.Mutations()); n != 0 {
		t.Errorf("the node was added anyway (%d mutations)", n)
	}
}

func TestNodesAddNeedsTheUserToTypeYes(t *testing.T) {
	key := scannedKey(t)
	for stdin, wantAdded := range map[string]bool{"yes\n": true, "y\n": false, "\n": false, "": false, "no\n": false} {
		f := addNodeAPI(t, key)
		r := f.runCtx(context.Background(), stdin, addArgs...)
		if added := len(f.Mutations()) == 1; added != wantAdded {
			t.Errorf("stdin %q: added=%v, want %v (code=%d err=%q)", stdin, added, wantAdded, r.code, r.stderr)
		}
		if !wantAdded && r.code != exitUsage {
			t.Errorf("stdin %q: code=%d, want %d", stdin, r.code, exitUsage)
		}
	}
}

func TestNodesAddRequiresNameHostAndAdminUserBeforeScanning(t *testing.T) {
	f := addNodeAPI(t, scannedKey(t))
	if r := f.run("nodes", "add", "--host", "h"); r.code != exitUsage {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("daemon saw %d requests", n)
	}
}

func TestNodesAddReportsAPendingJobWhenApprovalIsRequired(t *testing.T) {
	key := scannedKey(t)
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.PathNodesSSHHostKey: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, key) },
		"POST " + wire.PathNodesSSH: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, wire.Direct[wire.Node]{Pending: &wire.Submission{
				Job: wire.Job{ID: newTestID(), Type: "control_plane.apply", State: domain.JobAwaitingApproval}, Policy: wire.Policy{ApprovalRequired: true, Quorum: 1},
			}})
		},
	}))
	r := f.run(append(addArgs, "--fingerprint", key.FingerprintSHA256)...)
	if r.code != 0 || !strings.Contains(r.stdout, "awaiting_approval; approval required (quorum 1)") {
		t.Errorf("code=%d out=%q", r.code, r.stdout)
	}
}

func TestNodesRemoveSendsTheRevisionItReadAndAsksFirst(t *testing.T) {
	id := newTestID()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathNode, string(id)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Node{ID: id, Name: "web-1", SpecRevision: 9})
		},
		"DELETE " + wire.Path(wire.PathNode, string(id)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Direct[wire.Node]{Applied: &wire.Node{ID: id, Name: "web-1"}})
		},
	}))
	if r := f.runCtx(context.Background(), "no\n", "nodes", "remove", string(id)); r.code != exitUsage || len(f.Mutations()) != 0 {
		t.Errorf("declined: code=%d mutations=%d", r.code, len(f.Mutations()))
	}
	r := f.run("nodes", "remove", string(id), "--yes")
	if r.code != 0 || !strings.Contains(r.stdout, "retired node web-1") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	del := f.Mutations()[0]
	if del.Header.Get(wire.HeaderIfMatch) != "9" || del.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("delete headers = %v", del.Header)
	}
}

func TestServiceRestartSubmitsAJobAndSaysWhenApprovalIsNeeded(t *testing.T) {
	id := newTestID()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.Path(wire.PathServiceRestart, string(id)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, wire.Submission{
				Job:    wire.Job{ID: newTestID(), Type: "service.restart", State: domain.JobAwaitingApproval},
				Policy: wire.Policy{ApprovalRequired: true, Quorum: 1},
			})
		},
	}))
	r := f.run("services", "restart", string(id))
	if r.code != 0 || !strings.Contains(r.stdout, "service.restart) is awaiting_approval; approval required") {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if r := f.run("services", "restart", "web"); r.code != exitUsage {
		t.Errorf("non-id: code=%d", r.code)
	}
}

func TestServicesLogsPrintsLinesAndFlagsTruncation(t *testing.T) {
	id := newTestID()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathServiceLogs, string(id)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.LogChunk{Lines: []string{"one", "two"}, Truncated: true})
		},
	}))
	r := f.run("services", "logs", string(id), "--lines", "2")
	if r.stdout != "one\ntwo\n" || !strings.Contains(r.stderr, "truncated") {
		t.Errorf("out=%q err=%q", r.stdout, r.stderr)
	}
	if q := f.Requests()[0].Query; q != "lines=2" {
		t.Errorf("query = %q", q)
	}
}

func TestGovernanceCommandsRequireThePlanHashBeforeAnyRequest(t *testing.T) {
	id := string(newTestID())
	f := newFakeAPI(t, router(nil))
	for _, args := range [][]string{
		{"jobs", "approve", id},
		{"jobs", "reject", id, "--reason", "no"},
		{"jobs", "cancel", id},
		{"jobs", "resolve", id, "--outcome", "failed"},
	} {
		if r := f.run(args...); r.code != exitUsage || !strings.Contains(r.stderr, "--plan-hash") {
			t.Errorf("%v: code=%d err=%q", args, r.code, r.stderr)
		}
	}
	if r := f.run("jobs", "reject", id, "--plan-hash", "h"); r.code != exitUsage {
		t.Errorf("reject without reason: code=%d", r.code)
	}
	if r := f.run("jobs", "resolve", id, "--plan-hash", "h", "--outcome", "maybe"); r.code != exitUsage {
		t.Errorf("resolve bad outcome: code=%d", r.code)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("daemon saw %d requests", n)
	}
}

func TestJobsApproveRejectCancelResolveSendTheBoundRequests(t *testing.T) {
	id := newTestID()
	job := func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 200, wire.Job{ID: id, Type: "service.restart", State: domain.JobQueued})
	}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.Path(wire.PathJobApprove, string(id)): job,
		"POST " + wire.Path(wire.PathJobReject, string(id)):  job,
		"POST " + wire.Path(wire.PathJobCancel, string(id)):  job,
		"POST " + wire.Path(wire.PathJobResolve, string(id)): job,
	}))
	for _, args := range [][]string{
		{"jobs", "approve", string(id), "--plan-hash", "H"},
		{"jobs", "reject", string(id), "--plan-hash", "H", "--reason", "too risky"},
		{"jobs", "cancel", string(id), "--plan-hash", "H"},
		{"jobs", "resolve", string(id), "--plan-hash", "H", "--outcome", "succeeded", "--note", "checked", "--assume-quiescent"},
	} {
		if r := f.run(args...); r.code != 0 || !strings.Contains(r.stdout, "is now queued") {
			t.Errorf("%v: code=%d out=%q err=%q", args, r.code, r.stdout, r.stderr)
		}
	}
	bodies := []string{}
	for _, m := range f.Mutations() {
		bodies = append(bodies, m.Body)
	}
	want := []string{
		`{"plan_hash":"H","reason":""}`,
		`{"plan_hash":"H","reason":"too risky"}`,
		`{"plan_hash":"H"}`,
		`{"plan_hash":"H","outcome":"succeeded","note":"checked","assume_quiescent":true}`,
	}
	if strings.Join(bodies, "\n") != strings.Join(want, "\n") {
		t.Errorf("bodies:\n%s\nwant:\n%s", strings.Join(bodies, "\n"), strings.Join(want, "\n"))
	}
}

func TestJobsListFiltersByStateAndRejectsUnknownStates(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathJobs: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Job]{Items: []wire.Job{{ID: newTestID(), Type: "service.restart", State: domain.JobInterrupted, Attempts: 1, MaxAttempts: 1}}})
		},
	}))
	r := f.run("jobs", "--state", "interrupted", "--state", "queued")
	if r.code != 0 || !strings.Contains(r.stdout, "interrupted") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if q := f.Requests()[0].Query; q != "state=interrupted&state=queued" {
		t.Errorf("query = %q", q)
	}
	if r := f.run("jobs", "list", "--state", "bogus"); r.code != exitUsage {
		t.Errorf("bogus state: code=%d", r.code)
	}
}

func TestJobsWatchPrintsOnChangeHoldsPresenceAndStopsOnCancel(t *testing.T) {
	var polls atomic.Int32
	jobID := newTestID()
	var presence atomic.Int32
	state := func(n int32) domain.JobState {
		if n < 3 {
			return domain.JobQueued
		}
		return domain.JobSucceeded
	}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathPresence: func(w http.ResponseWriter, r *http.Request) {
			presence.Add(1)
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		},
		"GET " + wire.PathJobs: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Job]{Items: []wire.Job{{ID: jobID, Type: "t", State: state(polls.Add(1))}}})
		},
	}))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for polls.Load() < 5 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	done := make(chan result, 1)
	go func() { done <- f.runCtx(ctx, "", "jobs", "--watch", "--interval", "10ms", "--json") }()
	select {
	case r := <-done:
		if r.code != 0 {
			t.Fatalf("code=%d err=%q", r.code, r.stderr)
		}
		frames := strings.Count(r.stdout, "\n")
		if frames != 2 { // queued once, succeeded once; unchanged polls print nothing
			t.Errorf("printed %d frames, want 2:\n%s", frames, r.stdout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watch did not stop")
	}
	if presence.Load() == 0 {
		t.Error("watch never held presence")
	}
}

func TestApprovalsListShowsThePlanHashToApproveAgainst(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathApprovals: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Approval]{Items: []wire.Approval{{
				Job:          wire.Job{ID: newTestID(), Type: "service.restart", PlanHash: "abc123"},
				Plan:         json.RawMessage(`{"action":"service.restart"}`),
				Environments: []string{"production"}, Quorum: 1, ExpiresAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			}}})
		},
	}))
	r := f.run("approvals", "--plan")
	for _, want := range []string{"abc123", "production", "0/1", "2026-01-02T03:04:05Z", `"action": "service.restart"`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestStatusSummarizesNodesAndPendingWork(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Me{DisplayName: "local:501", ActorType: "human", Credential: "local_socket", InstanceMode: "local"})
		},
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{Reachability: "reachable"}, {Reachability: "reachable"}, {Reachability: "unreachable"}}})
		},
		"GET " + wire.PathJobs: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Job]{Items: []wire.Job{{}, {}}})
		},
	}))
	r := f.run("status")
	for _, want := range []string{"local:501", "nodes:", "reachable", "unreachable", "active jobs:", "awaiting approval:"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestEventsForwardsItsFilters(t *testing.T) {
	id := newTestID()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathEvents: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Event]{Items: []wire.Event{{Seq: 41, Action: "node.probe", CorrelationID: "c-1"}}})
		},
	}))
	r := f.run("events", "--resource-type", "node", "--resource-id", string(id), "--after-seq", "40")
	if r.code != 0 || !strings.Contains(r.stdout, "node.probe") || !strings.Contains(r.stdout, "c-1") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if q := f.Requests()[0].Query; q != "after_seq=40&resource_id="+string(id)+"&resource_type=node" {
		t.Errorf("query = %q", q)
	}
	if r := f.run("events", "--resource-type", "nonsense"); r.code != exitUsage {
		t.Errorf("bad type: code=%d", r.code)
	}
}

func TestSSHKeyShowPrintsThePublicKey(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathSSHKey: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.SSHKey{Ref: "secret://ssh/default", Version: 1, AuthorizedKey: "ssh-ed25519 AAAA", FingerprintSHA256: "SHA256:xyz"})
		},
	}))
	r := f.run("ssh-key", "show")
	if !strings.HasPrefix(r.stdout, "ssh-ed25519 AAAA\n") || !strings.Contains(r.stdout, "SHA256:xyz") {
		t.Errorf("out=%q", r.stdout)
	}
}

func TestAPIErrorsCarryTheCorrelationID(t *testing.T) {
	f := newFakeAPI(t, router(nil)) // every route 404s with a correlation id
	human := f.run("status")
	if !strings.Contains(human.stderr, "(correlation id corr-err)") {
		t.Errorf("human stderr = %q", human.stderr)
	}
	machine := f.run("status", "--json")
	var body jsonError
	if err := json.Unmarshal([]byte(machine.stderr), &body); err != nil || body.Error.Details["correlation_id"] != "corr-err" || body.Error.Code != "NOT_FOUND" {
		t.Errorf("json stderr = %q (%v)", machine.stderr, err)
	}
}

// fakeSSH puts an ssh on PATH that exits with code, and returns the dir.
func fakeSSH(t *testing.T, code string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nexit " + code + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func endBody(t *testing.T, f *fakeAPI) wire.EndSessionRequest {
	t.Helper()
	var end wire.EndSessionRequest
	for _, m := range f.Mutations() {
		if strings.HasSuffix(m.Path, "/end") {
			if err := json.Unmarshal([]byte(m.Body), &end); err != nil {
				t.Fatal(err)
			}
			return end
		}
	}
	t.Fatal("no session end was posted")
	return end
}

func sshDaemon(t *testing.T, nodeID domain.ID) *fakeAPI {
	t.Helper()
	key := scannedKey(t)
	info := wire.ConnectInfo{NodeID: nodeID, Host: "203.0.113.7", Port: 22, User: "alex", HostPublicKey: key.AuthorizedKey, HostKeyAlias: "sm-" + string(nodeID)}
	return newFakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/sessions"):
			reply(w, 201, wire.SessionOpened{Session: wire.Session{ID: newTestID(), NodeID: nodeID}, ConnectInfo: info})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/end"):
			reply(w, 200, wire.Session{State: wire.SessionEnded})
		default:
			replyError(w, 404, smerr.CodeNotFound, "", "no route")
		}
	})
}

func TestSSHExitsWithTheChildsStatusAndReportsItToTheDaemon(t *testing.T) {
	node := newTestID()
	fakeSSH(t, "7")
	f := sshDaemon(t, node)
	r := f.run("ssh", string(node))
	if r.code != 7 || r.stderr != "" {
		t.Fatalf("code=%d stderr=%q, want 7 and silence", r.code, r.stderr)
	}
	if end := endBody(t, f); end.Reason != wire.EndExited || end.ExitCode == nil || *end.ExitCode != 7 {
		t.Errorf("end = %+v", end)
	}
}

func TestSSHCleanExitIsZero(t *testing.T) {
	node := newTestID()
	fakeSSH(t, "0")
	f := sshDaemon(t, node)
	if r := f.run("ssh", string(node), "--user", "deploy"); r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	if end := endBody(t, f); end.Reason != wire.EndExited || *end.ExitCode != 0 {
		t.Errorf("end = %+v", end)
	}
}

func TestSSHMissingBinaryIsALaunchFailure(t *testing.T) {
	node := newTestID()
	t.Setenv("PATH", t.TempDir()) // no ssh anywhere
	f := sshDaemon(t, node)
	r := f.run("ssh", string(node))
	if r.code != exitInternal || !strings.Contains(r.stderr, "cannot run ssh") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	if end := endBody(t, f); end.Reason != wire.EndLaunchFailed {
		t.Errorf("end = %+v", end)
	}
}

func TestDockerHandoffExplainsAMissingLazydockerWithoutInstallingIt(t *testing.T) {
	node := newTestID()
	fakeSSH(t, "127")
	f := sshDaemon(t, node)
	r := f.run("docker", string(node))
	if r.code != 127 || !strings.Contains(r.stderr, "lazydocker is not installed") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
}

func TestKeysUnavailableIsAPrerequisiteFailure(t *testing.T) {
	err := &secrets.KeysUnavailableError{Problems: []string{"kek 0198... missing"}}
	wrapped := smerr.Wrap(err, smerr.CodeInternal, "", "start daemon")
	for _, e := range []error{err, wrapped} {
		if got := exitCode(e); got != exitPrerequisite {
			t.Errorf("exitCode(%v) = %d, want %d", e, got, exitPrerequisite)
		}
	}
}

func TestChildExitStatusIsTheProcessExitCodeAndPrintsNothing(t *testing.T) {
	err := &childExitError{code: 42}
	if exitCode(err) != 42 {
		t.Errorf("exitCode = %d", exitCode(err))
	}
	var out strings.Builder
	reportError(&out, err, false)
	reportError(&out, err, true)
	if out.Len() != 0 {
		t.Errorf("reported %q", out.String())
	}
}
