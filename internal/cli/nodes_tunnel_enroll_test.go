package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	enrollToken = "eyJhIjoiY29ubmVjdG9yLXRva2VuLWZvci10ZXN0cyJ9"
	enrollLine  = "curl -fsSL https://example.test/join.sh | sudo sh -s -- --tunnel --instance i --authorized-key 'ssh-ed25519 AAAA'"
)

// enrollmentDaemon is a daemon stand-in with one enrollment named vps1: GET answers the phases in order
// (the last one repeats), and the writes are recorded.
type enrollmentDaemon struct {
	*fakeAPI
	mu     sync.Mutex
	phases []string
	reads  int
	key    wire.HostKey
	// existing: GET answers it from the first call; otherwise the first GET is a 404 until a start.
	started bool
}

func (d *enrollmentDaemon) view() wire.TunnelEnrollment {
	d.mu.Lock()
	defer d.mu.Unlock()
	phase := d.phases[min(d.reads, len(d.phases)-1)]
	d.reads++
	v := wire.TunnelEnrollment{
		ID: newTestID(), NodeID: newTestID(), Name: "vps1", Hostname: "ssh-vps1.example.com", Phase: phase,
		ExpiresAt: domain.SystemClock{}.Now().Add(time.Hour), JoinLine: enrollLine, Tags: []string{},
	}
	if phase == "scanned" || phase == "confirmed" || phase == "committed" {
		v.HostPublicKey, v.HostKeyFingerprint = d.key.AuthorizedKey, d.key.FingerprintSHA256
	}
	return v
}

func newEnrollmentDaemon(t *testing.T, existing bool, phases ...string) *enrollmentDaemon {
	t.Helper()
	d := &enrollmentDaemon{phases: phases, key: scannedKey(t), started: existing}
	d.fakeAPI = newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathTunnelEnrollment, "vps1"): func(w http.ResponseWriter, _ *http.Request) {
			d.mu.Lock()
			started := d.started
			d.mu.Unlock()
			if !started {
				replyError(w, 404, smerr.CodeNotFound, "", "no enrollment")
				return
			}
			reply(w, 200, d.view())
		},
		"POST " + wire.PathTunnelEnrollments: func(w http.ResponseWriter, _ *http.Request) {
			d.mu.Lock()
			d.started = true
			d.mu.Unlock()
			v := d.view()
			reply(w, 201, wire.Direct[wire.TunnelEnrollment]{Applied: &v})
		},
		"GET " + wire.Path(wire.PathTunnelEnrollmentToken, "vps1"): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.TunnelEnrollmentToken{Token: enrollToken})
		},
		"POST " + wire.Path(wire.PathTunnelEnrollmentConfirm, "vps1"): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, d.view())
		},
		"POST " + wire.Path(wire.PathTunnelEnrollmentRefuse, "vps1"): func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 409, smerr.CodeSSHHostKeyMismatch, "", "the host key was not accepted")
		},
		"POST " + wire.Path(wire.PathTunnelEnrollmentCancel, "vps1"): func(w http.ResponseWriter, _ *http.Request) {
			v := d.view()
			v.Phase = "removing"
			reply(w, 200, v)
		},
	}))
	return d
}

// paths are the method and path of the requests the enrollment saw, presence holds left out.
func (d *enrollmentDaemon) paths() []string {
	var out []string
	for _, r := range d.Requests() {
		if r.Path != wire.PathPresence {
			out = append(out, r.Method+" "+r.Path)
		}
	}
	return out
}

func (d *enrollmentDaemon) sent(method, pattern string) []sentRequest {
	var out []sentRequest
	for _, r := range d.Requests() {
		if r.Method == method && r.Path == wire.Path(pattern, "vps1") {
			out = append(out, r)
		}
	}
	return out
}

func interactive(t *testing.T, yes bool) {
	t.Helper()
	old := stdinIsTerminal
	stdinIsTerminal = func(*cobra.Command) bool { return yes }
	t.Cleanup(func() { stdinIsTerminal = old })
}

var enrollArgs = []string{"nodes", "add", "--tunnel", "--name", "vps1", "--interval", "1ms"}

func TestTunnelAddPrintsTheLineAndTheTokenSeparatelyThenCommits(t *testing.T) {
	d := newEnrollmentDaemon(t, false, "started", "access_ready", "dns_created", "dns_created", "scanned", "confirmed", "committed")
	interactive(t, false)

	r := d.run(append(enrollArgs, "--fingerprint", d.key.FingerprintSHA256, "--environment", "staging", "--tag", "edge", "--expires-in", "2h")...)

	if r.code != 0 || !strings.Contains(r.stdout, "added node vps1") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, enrollLine) || !strings.Contains(r.stdout, "ssh-vps1.example.com") && !strings.Contains(r.stderr, "ssh-vps1.example.com") {
		t.Errorf("the line and the hostname must be printed:\n%s\n%s", r.stdout, r.stderr)
	}
	if strings.Count(r.stdout, enrollToken) != 1 || strings.Contains(r.stderr, enrollToken) || strings.Contains(enrollLine, enrollToken) {
		t.Errorf("the token must be printed once, on stdout, apart from the line:\n%s\n%s", r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "Paste it at the node's prompt") {
		t.Errorf("no instruction to paste the token: %q", r.stderr)
	}
	var start wire.StartTunnelEnrollmentRequest
	starts := d.sent("POST", wire.PathTunnelEnrollments)
	if len(starts) != 1 || json.Unmarshal([]byte(starts[0].Body), &start) != nil || start.Name != "vps1" ||
		start.Environment != "staging" || start.ExpiresIn != "2h0m0s" || len(start.Tags) != 1 {
		t.Errorf("start = %+v", starts)
	}
	confirms := d.sent("POST", wire.PathTunnelEnrollmentConfirm)
	var confirmed wire.ConfirmTunnelEnrollmentRequest
	if len(confirms) != 1 || json.Unmarshal([]byte(confirms[0].Body), &confirmed) != nil || confirmed.HostPublicKey != d.key.AuthorizedKey {
		t.Errorf("the confirmation must carry the exact scanned key: %+v", confirms)
	}
	if !strings.Contains(r.stderr, d.key.FingerprintSHA256) {
		t.Errorf("the fingerprint was not shown: %q", r.stderr)
	}
}

func TestTunnelAddRefusesAFingerprintThatDiffersAndEndsTheEnrollment(t *testing.T) {
	d := newEnrollmentDaemon(t, false, "dns_created", "scanned")
	interactive(t, false)

	r := d.run(append(enrollArgs, "--fingerprint", "SHA256:somethingelse")...)

	if r.code == 0 || !strings.Contains(r.stderr, "not the expected") {
		t.Fatalf("code=%d err=%q", r.code, r.stderr)
	}
	if len(d.sent("POST", wire.PathTunnelEnrollmentConfirm)) != 0 || len(d.sent("POST", wire.PathTunnelEnrollmentRefuse)) != 1 {
		t.Errorf("requests = %v", d.paths())
	}
}

func TestTunnelAddAsksAtTheTerminalAndOnlyYesConfirms(t *testing.T) {
	for stdin, want := range map[string]string{"yes\n": "confirm", "no\n": "refuse", "y\n": "refuse", "": "none"} {
		d := newEnrollmentDaemon(t, true, "scanned", "scanned", "committed")
		interactive(t, true)

		r := d.runCtx(context.Background(), stdin, enrollArgs...)

		confirms, refusals := len(d.sent("POST", wire.PathTunnelEnrollmentConfirm)), len(d.sent("POST", wire.PathTunnelEnrollmentRefuse))
		got := map[bool]string{true: "none"}[confirms+refusals == 0]
		switch {
		case confirms == 1:
			got = "confirm"
		case refusals == 1:
			got = "refuse"
		}
		if got != want {
			t.Errorf("stdin %q: %s, want %s (code=%d err=%q)", stdin, got, want, r.code, r.stderr)
		}
		if want == "confirm" && r.code != 0 {
			t.Errorf("stdin %q: code=%d err=%q", stdin, r.code, r.stderr)
		}
	}
}

func TestTunnelAddWithoutATerminalNeedsTheFingerprint(t *testing.T) {
	d := newEnrollmentDaemon(t, false, "started")
	interactive(t, false)

	r := d.run(enrollArgs...)

	if r.code != exitUsage || !strings.Contains(r.stderr, "--fingerprint is required") {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
	if n := len(d.paths()); n != 0 {
		t.Errorf("the daemon saw %v before the usage error", d.paths())
	}
}

func TestTunnelExcludesTheDirectNodeFlags(t *testing.T) {
	interactive(t, true)
	for _, flags := range [][]string{
		{"--host", "10.0.0.1"}, {"--port", "2222"}, {"--admin-user", "root"}, {"--admin-credential-ref", "ssh-agent://x"},
	} {
		d := newEnrollmentDaemon(t, false, "started")
		r := d.run(append(append([]string{}, enrollArgs...), flags...)...)
		if r.code != exitUsage || !strings.Contains(r.stderr, "--tunnel excludes "+flags[0]) {
			t.Errorf("%v: code=%d err=%q", flags, r.code, r.stderr)
		}
		if len(d.paths()) != 0 {
			t.Errorf("%v: requests = %v", flags, d.paths())
		}
	}
	d := newEnrollmentDaemon(t, false, "started")
	for _, args := range [][]string{
		{"nodes", "add", "--tunnel"},
		{"nodes", "add", "--tunnel", "--name", "vps1", "--show-token", "--cancel"},
		{"nodes", "add", "--tunnel", "--name", "vps1", "--expires-in", "48h"},
		{"nodes", "add", "--name", "vps1", "--host", "h", "--admin-user", "u", "--expires-in", "1h"},
		{"nodes", "add", "--name", "vps1", "--cancel"},
	} {
		if r := d.run(args...); r.code != exitUsage {
			t.Errorf("%v: code=%d err=%q", args, r.code, r.stderr)
		}
	}
	if len(d.paths()) != 0 {
		t.Errorf("requests = %v", d.paths())
	}
}

func TestTunnelAddReattachesToTheOpenEnrollmentWithoutStartingAnother(t *testing.T) {
	d := newEnrollmentDaemon(t, true, "dns_created", "scanned", "confirmed", "committed")
	interactive(t, false)

	r := d.run(append(enrollArgs, "--fingerprint", d.key.FingerprintSHA256)...)

	if r.code != 0 || !strings.Contains(r.stdout, "added node vps1") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if len(d.sent("POST", wire.PathTunnelEnrollments)) != 0 {
		t.Errorf("a second enrollment was started: %v", d.paths())
	}
	if strings.Contains(r.stdout, enrollToken) || strings.Contains(r.stderr, enrollToken) || len(d.sent("GET", wire.PathTunnelEnrollmentToken)) != 0 {
		t.Errorf("a reattach must not print the token again")
	}
	if !strings.Contains(r.stderr, "reattached") || !strings.Contains(r.stderr, "--show-token") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

func TestTunnelAddLeavesTheEnrollmentRunningWhenInterrupted(t *testing.T) {
	d := newEnrollmentDaemon(t, true, "dns_created")
	interactive(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	r := d.runCtx(ctx, "", append(enrollArgs, "--fingerprint", "SHA256:x")...)

	if r.code != exitUsage || !strings.Contains(r.stderr, "stays open") || !strings.Contains(r.stderr, "again to reattach") {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
	for _, m := range d.Mutations() {
		t.Errorf("an interrupted wait must change nothing: %s %s", m.Method, m.Path)
	}
}

func TestTunnelAddReportsWhenApprovalIsRequired(t *testing.T) {
	var gets int
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathTunnelEnrollment, "vps1"): func(w http.ResponseWriter, _ *http.Request) {
			gets++
			replyError(w, 404, smerr.CodeNotFound, "", "no enrollment")
		},
		"POST " + wire.PathTunnelEnrollments: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, wire.Direct[wire.TunnelEnrollment]{Pending: &wire.Submission{
				Job:    wire.Job{ID: newTestID(), Type: "control_plane.apply", State: "awaiting_approval"},
				Policy: wire.Policy{ApprovalRequired: true, Quorum: 1},
			}})
		},
	}))
	interactive(t, false)

	r := f.run(append(enrollArgs, "--fingerprint", "SHA256:x")...)

	if r.code != 0 || !strings.Contains(r.stdout, "awaiting_approval; approval required (quorum 1)") || !strings.Contains(r.stderr, "run the same command again") {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
}

func TestTunnelAddStopsWithTheReasonWhenTheEnrollmentIsHaltedOrEnded(t *testing.T) {
	for phase, want := range map[string]string{"failed": "is halted", "expired": "ended (expired)", "mismatch": "ended (SSH_HOST_KEY_MISMATCH)"} {
		d := newEnrollmentDaemon(t, true, "dns_created", phase)
		interactive(t, false)
		r := d.run(append(enrollArgs, "--fingerprint", "SHA256:x")...)
		if r.code == 0 || !strings.Contains(r.stderr, want) && !strings.Contains(r.stderr, phase) {
			t.Errorf("%s: code=%d err=%q", phase, r.code, r.stderr)
		}
	}
}

func TestTunnelAddCancelRemovesTheEnrollment(t *testing.T) {
	d := newEnrollmentDaemon(t, true, "dns_created")

	r := d.run("nodes", "add", "--tunnel", "--name", "vps1", "--cancel")

	if r.code != 0 || !strings.Contains(r.stdout, "vps1") || len(d.sent("POST", wire.PathTunnelEnrollmentCancel)) != 1 {
		t.Errorf("code=%d out=%q err=%q requests=%v", r.code, r.stdout, r.stderr, d.paths())
	}
}

func TestTunnelAddShowTokenPrintsItOnStdoutOnly(t *testing.T) {
	d := newEnrollmentDaemon(t, true, "dns_created")

	r := d.run("nodes", "add", "--tunnel", "--name", "vps1", "--show-token")

	if r.code != 0 || strings.TrimSpace(r.stdout) != enrollToken || strings.Contains(r.stderr, enrollToken) {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if len(d.Mutations()) != 0 {
		t.Errorf("showing the token must not write: %v", d.paths())
	}
}

func TestNodesListShowsTheOpenEnrollmentsWithTheirExpiry(t *testing.T) {
	expires := time.Date(2026, 11, 2, 15, 4, 5, 0, time.UTC)
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{ID: newTestID(), Name: "web-1"}}})
		},
		"GET " + wire.PathTunnelEnrollments: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.TunnelEnrollment]{Items: []wire.TunnelEnrollment{
				{Name: "vps1", Hostname: "ssh-vps1.example.com", Phase: "dns_created", ExpiresAt: expires},
			}})
		},
	}))

	human := f.run("nodes", "list")
	if human.code != 0 || !strings.Contains(human.stdout, "Open enrollments") || !strings.Contains(human.stdout, "vps1") ||
		!strings.Contains(human.stdout, expires.Local().Format(time.DateTime)) {
		t.Errorf("human = %q", human.stdout)
	}
	var out struct {
		Items             []wire.Node             `json:"items"`
		TunnelEnrollments []wire.TunnelEnrollment `json:"tunnel_enrollments"`
	}
	r := f.run("nodes", "list", "--json")
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || len(out.Items) != 1 || len(out.TunnelEnrollments) != 1 || !out.TunnelEnrollments[0].ExpiresAt.Equal(expires) {
		t.Errorf("json = %q (%v)", r.stdout, err)
	}
}

func TestNodesListWithoutEnrollmentsKeepsThePlainPage(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{Name: "n"}}})
		},
		"GET " + wire.PathTunnelEnrollments: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.TunnelEnrollment]{Items: []wire.TunnelEnrollment{}})
		},
	}))
	r := f.run("nodes", "list", "--json")
	if strings.Contains(r.stdout, "tunnel_enrollments") || strings.Contains(f.run("nodes", "list").stdout, "Open enrollments") {
		t.Errorf("stdout = %q", r.stdout)
	}
}
