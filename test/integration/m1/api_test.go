package m1

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func startedInstance(t *testing.T) *instance {
	t.Helper()
	in := newInstance(t, instanceOptions{})
	in.startDaemon()
	return in
}

var keyCounter = struct {
	sync.Mutex
	n int
}{}

// idemKey is a fresh printable-ASCII Idempotency-Key.
func idemKey(t *testing.T) string {
	t.Helper()
	keyCounter.Lock()
	defer keyCounter.Unlock()
	keyCounter.n++
	return fmt.Sprintf("m1-%s-%d-%s", strings.ReplaceAll(t.Name(), "/", "-"), keyCounter.n, rand.Text())
}

func randomHostKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(k)))
}

// Security: a caller cannot present credentials on the local socket until M5.
func TestM1Security_AuthorizationHeaderOnTheSocketIsRefused(t *testing.T) {
	in := startedInstance(t)
	for _, auth := range []string{"Bearer abc", "Basic dTpw", "Bearer "} {
		r := in.raw(t, http.MethodGet, wire.PathMe, map[string]string{"Authorization": auth}, "")
		requireCode(t, r, http.StatusUnauthorized, smerr.CodeUnauthenticated)
	}
	if r := in.raw(t, http.MethodGet, wire.PathMe, nil, ""); r.Status != http.StatusOK {
		t.Fatalf("GET /me without Authorization = %d, want 200", r.Status)
	}
}

// Security: dynamic verbs are literal routes; nothing else reaches a handler.
func TestM1Security_OnlyStartStopRestartAreServiceActionRoutes(t *testing.T) {
	in := startedInstance(t)
	id := "01a12725-6026-7df2-877e-2f05d9c4415d"
	for _, verb := range []string{"delete", "exec", "kill", "restart;id", "restart%3Bid", "..%2Fstart", "start/extra", "RESTART", ""} {
		r := in.raw(t, http.MethodPost, "/api/v1/services/"+id+"/actions/"+verb, map[string]string{"Idempotency-Key": idemKey(t)}, "{}")
		if r.Status != http.StatusNotFound && r.Status != http.StatusMethodNotAllowed && r.Status != http.StatusBadRequest {
			t.Errorf("POST .../actions/%s = %d, want 404/405/400", verb, r.Status)
		}
	}
	// A real verb on an unknown service is a clean NOT_FOUND, not a crash.
	r := in.raw(t, http.MethodPost, "/api/v1/services/"+id+"/actions/restart", map[string]string{"Idempotency-Key": idemKey(t)}, "{}")
	requireCode(t, r, http.StatusNotFound, smerr.CodeNotFound)
}

// Security: hostile API parameters never reach ssh, a shell or the database.
func TestM1Security_HostileNodeParametersAreRejected(t *testing.T) {
	in := startedInstance(t)
	canary := "/tmp/sm-m1-pwned-" + rand.Text()
	t.Cleanup(func() { _ = os.Remove(canary) })
	key := randomHostKey(t)

	hostile := []wire.AddSSHNodeRequest{
		{Name: "n", Host: "-oProxyCommand=touch " + canary, Port: 22, AdminUser: "admin", HostPublicKey: key},
		{Name: "n", Host: "127.0.0.1;touch " + canary, Port: 22, AdminUser: "admin", HostPublicKey: key},
		{Name: "n", Host: "$(touch " + canary + ")", Port: 22, AdminUser: "admin", HostPublicKey: key},
		{Name: "n", Host: "a\nb", Port: 22, AdminUser: "admin", HostPublicKey: key},
		{Name: "n", Host: "host name", Port: 22, AdminUser: "admin", HostPublicKey: key},
		{Name: "n", Host: "127.0.0.1", Port: 70000, AdminUser: "admin", HostPublicKey: key},
		{Name: "n", Host: "127.0.0.1", Port: 22, AdminUser: "root;touch " + canary, HostPublicKey: key},
		{Name: "n", Host: "127.0.0.1", Port: 22, AdminUser: "-oProxyCommand=x", HostPublicKey: key},
		{Name: "n", Host: "127.0.0.1", Port: 22, AdminUser: "a b", HostPublicKey: key},
		{Name: "n", Host: "127.0.0.1", Port: 22, AdminUser: "admin", User: "supermgmt\nroot", HostPublicKey: key},
		{Name: "n", Host: "127.0.0.1", Port: 22, AdminUser: "admin", HostPublicKey: "ssh-ed25519 not-base64 ; touch " + canary},
		{Name: "n", Host: "127.0.0.1", Port: 22, AdminUser: "admin", HostPublicKey: ""},
	}
	for i, body := range hostile {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := in.raw(t, http.MethodPost, wire.PathNodesSSH, map[string]string{"Idempotency-Key": idemKey(t)}, string(raw))
		if r.Status < 400 || r.Status >= 500 {
			t.Errorf("hostile add-node #%d %s = %d, want a 4xx", i, raw, r.Status)
		}
	}
	for _, host := range []string{"-oProxyCommand=touch " + canary, "127.0.0.1;id", "$(id)", "a\nb", ""} {
		raw, _ := json.Marshal(wire.ScanHostKeyRequest{Host: host, Port: 22})
		r := in.raw(t, http.MethodPost, wire.PathNodesSSHHostKey, nil, string(raw))
		requireCode(t, r, http.StatusBadRequest, smerr.CodeInvalidArgument)
	}

	nodes, err := in.client().ListNodes(t.Context(), wire.NodeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes.Items) != 0 {
		t.Errorf("hostile requests created %d node(s)", len(nodes.Items))
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("a hostile parameter was executed: %s exists", canary)
	}
}

// Idempotency (ADR-0014): concurrent duplicates execute once and answer alike.
func TestM1Idempotency_ConcurrentDuplicatesExecuteOnce(t *testing.T) {
	in := startedInstance(t)
	key := idemKey(t)
	const callers = 12
	responses := make([]rawResponse, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses[i] = in.raw(t, http.MethodPost, wire.PathProviders, map[string]string{"Idempotency-Key": key}, `{"type":"local"}`)
		}()
	}
	wg.Wait()

	replayed := 0
	for i, r := range responses {
		if r.Status != responses[0].Status || string(r.Body) != string(responses[0].Body) {
			t.Errorf("caller %d got %d %s, caller 0 got %d %s", i, r.Status, r.Body, responses[0].Status, responses[0].Body)
		}
		if r.Header.Get(wire.HeaderIdempotentReplayed) == "true" {
			replayed++
		}
	}
	if responses[0].Status >= 300 {
		t.Fatalf("registering the local provider = %d %s", responses[0].Status, responses[0].Body)
	}
	if replayed != callers-1 {
		t.Errorf("%d of %d duplicates were marked Idempotent-Replayed, want %d", replayed, callers, callers-1)
	}
	if got := jobCount(t, in.client()); got != 1 {
		t.Errorf("%d jobs after %d concurrent duplicates, want exactly 1", got, callers)
	}
}

// Idempotency: a key is bound to the exact request that first used it.
func TestM1Idempotency_SameKeyWithADifferentRequestIsAConflict(t *testing.T) {
	in := startedInstance(t)
	node := addUnreachableNode(t, in)
	revision := fmt.Sprint(node.SpecRevision)
	patch := `{"tags":["a"]}`

	first := in.raw(t, http.MethodPatch, "/api/v1/nodes/"+string(node.ID), map[string]string{"Idempotency-Key": "k-patch", "If-Match": revision}, patch)
	if first.Status >= 300 {
		t.Fatalf("PATCH node = %d %s", first.Status, first.Body)
	}

	cases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		body    string
	}{
		{"different body", http.MethodPatch, "/api/v1/nodes/" + string(node.ID), map[string]string{"If-Match": revision}, `{"tags":["b"]}`},
		{"different bytes of the same JSON", http.MethodPatch, "/api/v1/nodes/" + string(node.ID), map[string]string{"If-Match": revision}, `{"tags": ["a"]}`},
		{"different If-Match", http.MethodPatch, "/api/v1/nodes/" + string(node.ID), map[string]string{"If-Match": "999"}, patch},
		{"different route", http.MethodPost, wire.PathProviders, nil, `{"type":"local"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			headers := map[string]string{"Idempotency-Key": "k-patch"}
			for k, v := range c.headers {
				headers[k] = v
			}
			r := in.raw(t, c.method, c.path, headers, c.body)
			got := requireCode(t, r, http.StatusConflict, smerr.CodeConflict)
			if got.Reason() != smerr.ReasonIdempotencyMismatch {
				t.Errorf("reason = %q, want %q", got.Reason(), smerr.ReasonIdempotencyMismatch)
			}
		})
	}

	replay := in.raw(t, http.MethodPatch, "/api/v1/nodes/"+string(node.ID), map[string]string{"Idempotency-Key": "k-patch", "If-Match": revision}, patch)
	if replay.Status != first.Status || string(replay.Body) != string(first.Body) || replay.Header.Get(wire.HeaderIdempotentReplayed) != "true" {
		t.Errorf("replay = %d %s (replayed=%q), want the original %d %s", replay.Status, replay.Body, replay.Header.Get(wire.HeaderIdempotentReplayed), first.Status, first.Body)
	}
}

// Idempotency: a committed mutation whose response was lost replays byte for
// byte after a daemon crash, and is never executed twice.
func TestM1Idempotency_ResponseLostAcrossADaemonKillReplaysIdentically(t *testing.T) {
	in := startedInstance(t)
	api := in.client()
	key := idemKey(t)

	in.sendWithoutReading(t, http.MethodPost, wire.PathProviders, map[string]string{"Idempotency-Key": key}, `{"type":"local"}`)
	eventually(t, 10*time.Second, "the abandoned request to commit", func() bool {
		jobs, err := api.ListJobs(t.Context(), wire.JobQuery{})
		return err == nil && len(jobs.Items) == 1
	})
	in.killDaemon()
	in.startDaemon()

	first := in.raw(t, http.MethodPost, wire.PathProviders, map[string]string{"Idempotency-Key": key}, `{"type":"local"}`)
	second := in.raw(t, http.MethodPost, wire.PathProviders, map[string]string{"Idempotency-Key": key}, `{"type":"local"}`)
	if first.Status >= 300 {
		t.Fatalf("replay after the kill = %d %s", first.Status, first.Body)
	}
	for _, r := range []rawResponse{first, second} {
		if r.Header.Get(wire.HeaderIdempotentReplayed) != "true" {
			t.Errorf("replay after the kill lacks %s: true", wire.HeaderIdempotentReplayed)
		}
	}
	if string(first.Body) != string(second.Body) || first.Status != second.Status {
		t.Errorf("replays differ: %d %s vs %d %s", first.Status, first.Body, second.Status, second.Body)
	}
	if got := jobCount(t, api); got != 1 {
		t.Errorf("%d jobs after the replay, want 1", got)
	}
}

// jobCount counts every job: registering the local provider is gated, so each
// real execution leaves exactly one control_plane.apply job awaiting approval.
func jobCount(t *testing.T, api *client.Client) int {
	t.Helper()
	jobs, err := api.ListJobs(t.Context(), wire.JobQuery{})
	if err != nil {
		t.Fatal(err)
	}
	return len(jobs.Items)
}

// addUnreachableNode registers an SSH node nothing listens on: enough to
// exercise node mutations without a fixture.
func addUnreachableNode(t *testing.T, in *instance) wire.Node {
	t.Helper()
	added, err := in.client().AddSSHNode(t.Context(), wire.AddSSHNodeRequest{
		Name: "ghost", Host: "127.0.0.1", Port: 1, AdminUser: "admin", HostPublicKey: randomHostKey(t), Environment: "staging",
	})
	if err != nil || added.Applied == nil {
		t.Fatalf("add the unreachable node: %v %+v", err, added)
	}
	return *added.Applied
}
