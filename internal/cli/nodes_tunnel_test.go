package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// tunnelAPI answers one node (idWeb) with the given endpoint and records plans.
type tunnelAPI struct {
	*fakeAPI
	plans     []wire.CreatePlanRequest
	submitted []wire.PlanHashRequest
}

func newTunnelAPI(t *testing.T, endpoint wire.Endpoint, policy wire.Policy) *tunnelAPI {
	s := &tunnelAPI{}
	s.fakeAPI = newFakeAPI(t, router(routes{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{ID: idWeb, Name: "web-1"}}})
		},
		"GET " + wire.Path(wire.PathNode, string(idWeb)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Node{ID: idWeb, Name: "web-1", Kind: "ssh", Endpoint: endpoint})
		},
		"POST " + wire.PathPlans: func(w http.ResponseWriter, r *http.Request) {
			var req wire.CreatePlanRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.plans = append(s.plans, req)
			reply(w, 200, wire.CreatedPlan{PlanID: idPlan, PlanHash: hashOf, Policy: policy})
		},
		"POST " + wire.Path(wire.PathPlanSubmit, string(idPlan)): func(w http.ResponseWriter, r *http.Request) {
			var req wire.PlanHashRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.submitted = append(s.submitted, req)
			reply(w, 200, *awaiting("job-tunnel"))
		},
	}))
	return s
}

func TestNodesSetupTunnelSendsTheParameterAndPreviewsTheTransport(t *testing.T) {
	for name, tc := range map[string]struct {
		endpoint wire.Endpoint
		preview  string
	}{
		"hostname not known yet": {wire.Endpoint{}, "transport: cloudflare\n"},
		"hostname known":         {wire.Endpoint{Transport: domain.TransportCloudflare, TunnelHostname: "ssh-web-1.example.com"}, "transport: cloudflare via ssh-web-1.example.com\n"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTunnelAPI(t, tc.endpoint, approvalPolicy)

			r := s.run("nodes", "setup", "web-1", "--tunnel", "--yes")

			if r.code != 0 || len(s.plans) != 1 {
				t.Fatalf("exit %d, plans %d, stderr %s", r.code, len(s.plans), r.stderr)
			}
			if s.plans[0].Action != "node.setup" || s.plans[0].Parameters["tunnel"] != "true" {
				t.Errorf("plan = %+v", s.plans[0])
			}
			if !strings.Contains(r.stderr, tc.preview) {
				t.Errorf("stderr %q lacks %q", r.stderr, tc.preview)
			}
		})
	}
}

func TestNodesSetupWithoutTunnelSendsNoTunnelParameter(t *testing.T) {
	s := newTunnelAPI(t, wire.Endpoint{}, approvalPolicy)

	r := s.run("nodes", "setup", "web-1", "--yes")

	if _, sent := s.plans[0].Parameters["tunnel"]; r.code != 0 || sent || strings.Contains(r.stderr, "transport:") {
		t.Errorf("exit %d, parameters %v, stderr %q", r.code, s.plans[0].Parameters, r.stderr)
	}
}

func TestNodesTunnelDisablePlansPreviewsConfirmsAndSubmits(t *testing.T) {
	endpoint := wire.Endpoint{Transport: domain.TransportCloudflare, TunnelHostname: "ssh-web-1.example.com"}

	declined := newTunnelAPI(t, endpoint, approvalPolicy)
	if r := declined.runIn("no\n", "nodes", "tunnel", "disable", "web-1"); r.code != exitUsage || len(declined.submitted) != 0 {
		t.Errorf("declined: exit %d, %d submissions", r.code, len(declined.submitted))
	}

	s := newTunnelAPI(t, endpoint, approvalPolicy)
	r := s.run("nodes", "tunnel", "disable", "web-1", "--yes")
	if r.code != 0 || len(s.plans) != 1 || len(s.submitted) != 1 || s.submitted[0].PlanHash != hashOf {
		t.Fatalf("exit %d, plans %d, submitted %+v, stderr %s", r.code, len(s.plans), s.submitted, r.stderr)
	}
	if plan := s.plans[0]; plan.Action != "node.tunnel.disable" || plan.Targets[0].ID != idWeb || plan.Targets[0].Type != domain.ResourceNode {
		t.Errorf("plan = %+v", plan)
	}
	if !strings.Contains(r.stderr, "transport: cloudflare -> direct") || !strings.Contains(r.stdout, "job-tunnel") {
		t.Errorf("stdout %q, stderr %q", r.stdout, r.stderr)
	}
}

func TestNodesTunnelDisableRefusesAPlanPolicyDenies(t *testing.T) {
	s := newTunnelAPI(t, wire.Endpoint{}, wire.Policy{Decision: "deny", Reason: smerr.ReasonDefaultDeny})

	if r := s.run("nodes", "tunnel", "disable", "web-1", "--yes"); r.code == 0 || len(s.submitted) != 0 {
		t.Errorf("exit %d, %d submissions", r.code, len(s.submitted))
	}
}

func TestCloudflareRotateAccessTokenTargetsTheInstance(t *testing.T) {
	s := newTunnelAPI(t, wire.Endpoint{}, approvalPolicy)

	r := s.run("cloudflare", "rotate-access-token", "--yes")

	if r.code != 0 || len(s.plans) != 1 || len(s.submitted) != 1 {
		t.Fatalf("exit %d, plans %d, stderr %s", r.code, len(s.plans), r.stderr)
	}
	if plan := s.plans[0]; plan.Action != "cloudflare.access_token.rotate" || plan.Targets[0].Type != domain.ResourceInstance {
		t.Errorf("plan = %+v", plan)
	}
	declined := newTunnelAPI(t, wire.Endpoint{}, approvalPolicy)
	if r := declined.runIn("", "cloudflare", "rotate-access-token"); r.code != exitUsage || len(declined.submitted) != 0 {
		t.Errorf("unconfirmed: exit %d, %d submissions", r.code, len(declined.submitted))
	}
}

func TestWriteNodesShowsTransportOnlyWhenSomeNodeIsNotDirect(t *testing.T) {
	direct := wire.Node{ID: idWeb, Name: "web-1"}
	tunnel := wire.Node{ID: idPlan, Name: "web-2", Endpoint: wire.Endpoint{Transport: domain.TransportCloudflare}}

	var plain, mixed strings.Builder
	if err := writeNodes(&plain, wire.Page[wire.Node]{Items: []wire.Node{direct}}); err != nil {
		t.Fatal(err)
	}
	if err := writeNodes(&mixed, wire.Page[wire.Node]{Items: []wire.Node{direct, tunnel}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "TRANSPORT") {
		t.Errorf("all-direct listing grew a column:\n%s", plain.String())
	}
	lines := strings.Split(strings.TrimSpace(mixed.String()), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[0], "TRANSPORT") || !strings.HasSuffix(lines[1], "direct") || !strings.HasSuffix(lines[2], "cloudflare") {
		t.Errorf("mixed listing:\n%s", mixed.String())
	}
}

func TestWriteNodeShowsTransportAndTunnelHostname(t *testing.T) {
	var out strings.Builder
	n := wire.Node{ID: idWeb, Name: "web-1", Endpoint: wire.Endpoint{Transport: domain.TransportCloudflare, TunnelHostname: "ssh-web-1.example.com"}}
	if err := writeNode(&out, n); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cloudflare", "ssh-web-1.example.com"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}
