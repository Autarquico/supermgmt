package cli

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func appsFixture() (web, api wire.App, node wire.Node) {
	web = wire.App{
		ID: newTestID(), Name: "web", DeployedService: "app", ComposeSource: "control-plane", SpecRevision: 3,
		Repository: &wire.Repository{Owner: "acme", Name: "web"},
		Targets:    []wire.AppTarget{{ID: newTestID(), Environment: "prod", NodeID: newTestID(), ComposeProject: "sm-web-prod", DeploymentPolicy: wire.DeploymentPolicy{Rollback: "automatic"}}},
	}
	api = wire.App{ID: newTestID(), Name: "api", DeployedService: "srv"}
	node = wire.Node{ID: newTestID(), Name: "edge-1"}
	return web, api, node
}

func appsAPI(t *testing.T, apps ...wire.App) *fakeAPI {
	t.Helper()
	routes := map[string]http.HandlerFunc{
		"GET " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Page[wire.App]{Items: apps}) },
		"GET " + wire.PathAppRoutes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.AppRoute]{Items: []wire.AppRoute{}})
		},
	}
	for _, a := range apps {
		routes["GET "+wire.Path(wire.PathApp, string(a.ID))] = func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, a) }
	}
	return newFakeAPI(t, router(routes))
}

func TestAppsListShowsRepositoryServiceAndTargetCount(t *testing.T) {
	web, api, _ := appsFixture()
	f := appsAPI(t, web, api)

	r := f.run("apps", "list")

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{"web", "acme/web", "app", "api", "-"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestAppsGetResolvesByNameOrIdAndShowsTargets(t *testing.T) {
	web, api, _ := appsFixture()
	f := appsAPI(t, web, api)

	byName := f.run("apps", "get", "web")
	byID := f.run("apps", "get", string(web.ID))

	for label, r := range map[string]result{"name": byName, "id": byID} {
		if r.code != 0 {
			t.Fatalf("%s: code=%d stderr=%q", label, r.code, r.stderr)
		}
		for _, want := range []string{"spec revision:", "sm-web-prod", "prod", "automatic"} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("%s: output lacks %q:\n%s", label, want, r.stdout)
			}
		}
	}
}

func TestAppsGetRefusesAnUnknownOrAmbiguousName(t *testing.T) {
	web, _, _ := appsFixture()
	twin := web
	twin.ID = newTestID()
	f := appsAPI(t, web, twin)

	missing := f.run("apps", "get", "nope")
	ambiguous := f.run("apps", "get", "web")

	if missing.code == 0 || !strings.Contains(missing.stderr, `no app named "nope"`) {
		t.Errorf("missing: code=%d stderr=%q", missing.code, missing.stderr)
	}
	if ambiguous.code == 0 || !strings.Contains(ambiguous.stderr, "use the id") {
		t.Errorf("ambiguous: code=%d stderr=%q", ambiguous.code, ambiguous.stderr)
	}
}

func createAppAPI(t *testing.T, created wire.App) *fakeAPI {
	t.Helper()
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 201, wire.Direct[wire.App]{Applied: &created})
		},
	}))
}

func sentCreateApp(t *testing.T, f *fakeAPI) wire.CreateAppRequest {
	t.Helper()
	muts := f.Mutations()
	if len(muts) != 1 {
		t.Fatalf("mutations = %+v", muts)
	}
	var req wire.CreateAppRequest
	if err := json.Unmarshal([]byte(muts[0].Body), &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestAppsCreateSendsFlagsAndTheComposeFileAsControlPlaneSource(t *testing.T) {
	web, _, _ := appsFixture()
	f := createAppAPI(t, web)
	compose := filepath.Join(t.TempDir(), "compose.yaml")
	writeFile(t, compose, "services:\n  app:\n    image: ${image}\n")

	r := f.run("apps", "create", "--name", "web", "--deployed-service", "app", "--compose-file", compose,
		"--var", "region=eu", "--ref", "db=secret://apps/web/db", "--automation-identity")

	if r.code != 0 || !strings.Contains(r.stdout, "created app web") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	req := sentCreateApp(t, f)
	if req.Name != "web" || req.DeployedService != "app" || req.ComposeSource != "control-plane" || !strings.Contains(req.ComposeContent, "image: ${image}") {
		t.Errorf("request = %+v", req)
	}
	if req.Variables["region"] != "eu" || req.SecretRefs["db"] != "secret://apps/web/db" || !req.AutomationIdentity {
		t.Errorf("request = %+v", req)
	}
}

func TestAppsCreateFlagsOverrideTheFile(t *testing.T) {
	web, _, _ := appsFixture()
	f := createAppAPI(t, web)
	file := filepath.Join(t.TempDir(), "app.json")
	writeFile(t, file, `{"name":"from-file","deployed_service":"svc","variables":{"a":"1"}}`)

	r := f.run("apps", "create", "--file", file, "--name", "from-flag", "--var", "b=2")

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	req := sentCreateApp(t, f)
	if req.Name != "from-flag" || req.DeployedService != "svc" || req.Variables["a"] != "1" || req.Variables["b"] != "2" {
		t.Errorf("request = %+v", req)
	}
}

func TestAppsCreateRejectsBadInputBeforeAnyRequest(t *testing.T) {
	web, _, _ := appsFixture()
	f := createAppAPI(t, web)
	typo := filepath.Join(t.TempDir(), "typo.json")
	writeFile(t, typo, `{"name":"web","unknown_field":"x"}`)
	tests := map[string][]string{
		"no name":            {"apps", "create"},
		"malformed variable": {"apps", "create", "--name", "web", "--var", "novalue"},
		"unknown field":      {"apps", "create", "--file", typo},
		"missing file":       {"apps", "create", "--file", filepath.Join(t.TempDir(), "absent.json")},
		"missing compose":    {"apps", "create", "--name", "web", "--compose-file", filepath.Join(t.TempDir(), "absent.yaml")},
	}
	for name, args := range tests {
		if r := f.run(args...); r.code != exitUsage {
			t.Errorf("%s: exit %d, stderr %q", name, r.code, r.stderr)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

func TestAppsCreateErrorsCarryCodeAndReason(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 422, smerr.CodeInvalidArgument, smerr.ReasonComposeRejected, "service app: privileged is not allowed")
		},
	}))

	r := f.run("--json", "apps", "create", "--name", "web")

	var got jsonError
	if err := json.Unmarshal([]byte(r.stderr), &got); err != nil {
		t.Fatalf("stderr %q: %v", r.stderr, err)
	}
	if r.code != exitUsage || got.Error.Code != string(smerr.CodeInvalidArgument) || got.Error.Reason != string(smerr.ReasonComposeRejected) {
		t.Errorf("code=%d error=%+v", r.code, got.Error)
	}
}

func TestAppsTargetAddResolvesAppAndNodeAndSendsThePolicy(t *testing.T) {
	web, _, node := appsFixture()
	created := wire.AppTarget{ID: newTestID(), Environment: "prod", ComposeProject: "sm-web-prod"}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.App]{Items: []wire.App{web}})
		},
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{node}})
		},
		"POST " + wire.Path(wire.PathAppTargets, string(web.ID)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 201, wire.Direct[wire.AppTarget]{Applied: &created})
		},
	}))
	policy := filepath.Join(t.TempDir(), "policy.json")
	writeFile(t, policy, `{"rollback":"manual","stateful":true}`)

	r := f.run("apps", "target", "add", "web", "--environment", "prod", "--node", "edge-1",
		"--policy-file", policy, "--rollback", "automatic", "--bind-address", "127.0.0.1")

	if r.code != 0 || !strings.Contains(r.stdout, "sm-web-prod") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	muts := f.Mutations()
	if len(muts) != 1 {
		t.Fatalf("mutations = %+v", muts)
	}
	var req wire.CreateAppTargetRequest
	if err := json.Unmarshal([]byte(muts[0].Body), &req); err != nil {
		t.Fatal(err)
	}
	if req.Environment != "prod" || req.NodeID != node.ID {
		t.Errorf("request = %+v", req)
	}
	p := req.DeploymentPolicy
	if p.Rollback != "automatic" || !p.Stateful || len(p.AllowedBindAddresses) != 1 || p.AllowedBindAddresses[0] != "127.0.0.1" {
		t.Errorf("policy = %+v", p)
	}
}

func TestAppsTargetAddNeedsEnvironmentAndNodeBeforeAnyRequest(t *testing.T) {
	f := appsAPI(t)

	r := f.run("apps", "target", "add", "web", "--environment", "prod")

	if r.code != exitUsage || len(f.Requests()) != 0 {
		t.Errorf("exit %d, requests %d, stderr %q", r.code, len(f.Requests()), r.stderr)
	}
}

func TestAppsTargetAddAcceptsIDsWithoutLookingThemUp(t *testing.T) {
	appID, nodeID := newTestID(), newTestID()
	created := wire.AppTarget{ID: newTestID(), Environment: "prod", ComposeProject: "sm-web-prod"}
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.Path(wire.PathAppTargets, string(appID)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 201, wire.Direct[wire.AppTarget]{Applied: &created})
		},
	}))

	r := f.run("apps", "target", "add", string(appID), "--environment", "prod", "--node", string(nodeID))

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	if reqs := f.Requests(); len(reqs) != 1 || domain.ID(strings.Split(reqs[0].Path, "/")[4]) != appID {
		t.Errorf("requests = %+v", reqs)
	}
}
