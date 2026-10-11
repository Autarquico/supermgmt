package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

const joinTokenValue = "smj_0123456789abcdef"

func issuingServer(issued *wire.EnrollmentRequest) http.HandlerFunc {
	return router(map[string]http.HandlerFunc{
		"POST " + wire.PathEnrollments: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(issued)
			reply(w, 201, wire.EnrollmentIssued{ID: "0192a000-0000-7000-8000-00000000e001", Token: joinTokenValue, ExpiresAt: issued.ExpiresAt})
		},
	})
}

func TestEnrollmentsCreateSendsTheConstraintsAndPrintsTheTokenAlone(t *testing.T) {
	var got wire.EnrollmentRequest
	f := newFakeAPI(t, issuingServer(&got))

	r := f.run("enrollments", "create", "--tag", "edge", "--tag", "eu", "--max-nodes", "3", "--source-cidr", "203.0.113.0/24", "--expires-in", "2h")

	if r.code != 0 || r.stdout != joinTokenValue+"\n" {
		t.Fatalf("exit %d, stdout %q (must be the token alone), stderr %s", r.code, r.stdout, r.stderr)
	}
	if strings.Join(got.Tags, ",") != "edge,eu" || got.MaxNodes != 3 || strings.Join(got.SourceCIDRs, ",") != "203.0.113.0/24" {
		t.Errorf("request = %+v", got)
	}
	if d := time.Until(got.ExpiresAt); d < time.Hour+55*time.Minute || d > 2*time.Hour {
		t.Errorf("expires_at is %s from now, want 2h", d)
	}
	if k := f.Requests()[0].Header.Get(wire.HeaderIdempotencyKey); k != "" {
		t.Errorf("credential-issuing request carried Idempotency-Key %q", k)
	}
}

func TestEnrollmentsCreateTellsWhatToRunOnTheNodeWithoutTheTokenInIt(t *testing.T) {
	var got wire.EnrollmentRequest
	f := newFakeAPI(t, issuingServer(&got))

	r := f.run("enrollments", "create")

	for _, want := range []string{"only time", "sm join --server https://<server> --token-stdin", "join.sh --token-stdin --server https://<server>"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, joinTokenValue) {
		t.Error("the instructions repeat the token, which would put it on an argument line")
	}
	if got.MaxNodes != 1 || len(got.Tags) != 0 || got.Tags == nil {
		t.Errorf("defaults = %+v, want one node and empty (non-null) lists", got)
	}
}

func TestEnrollmentsCreateNamesTheProfileServerInTheJoinCommand(t *testing.T) {
	var got wire.EnrollmentRequest
	b := newRemoteBox(t, routes{"POST " + wire.PathEnrollments: issuingServer(&got)})
	b.useProfile()
	b.signIn(tokenOne)

	r := b.run("", "enrollments", "create")

	if r.code != 0 || !strings.Contains(r.stderr, "sm join --server "+b.srv.URL+" --token-stdin") {
		t.Fatalf("exit %d, stderr:\n%s", r.code, r.stderr)
	}
}

func TestEnrollmentsCreateJSONIsTheIssuedToken(t *testing.T) {
	var got wire.EnrollmentRequest
	f := newFakeAPI(t, issuingServer(&got))

	r := f.run("enrollments", "create", "--json")

	var issued wire.EnrollmentIssued
	if err := json.Unmarshal([]byte(r.stdout), &issued); err != nil || issued.Token != joinTokenValue {
		t.Fatalf("stdout %q: %v", r.stdout, err)
	}
}

func TestEnrollmentsCreateRefusesBadFlagsBeforeAnyRequest(t *testing.T) {
	var got wire.EnrollmentRequest
	f := newFakeAPI(t, issuingServer(&got))
	cases := [][]string{
		{"--expires-in", "25h"},
		{"--expires-in", "2d"},
		{"--expires-in", "-1h"},
		{"--expires-in", "soon"},
		{"--max-nodes", "0"},
		{"extra"},
	}
	for _, args := range cases {
		if r := f.run(append([]string{"enrollments", "create"}, args...)...); r.code != exitUsage {
			t.Errorf("%v: exit %d, %q", args, r.code, r.stderr)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

func TestEnrollmentsCreateShowsAServerRefusal(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.PathEnrollments: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 403, "POLICY_DENIED", "DEFAULT_DENY", "not allowed")
		},
	}))

	r := f.run("enrollments", "create")

	if r.code == 0 || r.stdout != "" {
		t.Errorf("exit %d, stdout %q", r.code, r.stdout)
	}
}
