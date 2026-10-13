package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	deploymentTestPolling = "5ms"
	deploymentTestCommit  = "0123456789abcdef0123456789abcdef01234567"
	deploymentTestDigest  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var (
	deploymentTestAt     = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	deploymentTestPlan   = "sha256:" + strings.Repeat("b", 64)
	deploymentTestDeploy = domain.ID("0199d000-0000-7000-8000-000000000001")
	deploymentTestJob    = domain.ID("0199d000-0000-7000-8000-000000000002")
	deploymentTestKnown  = domain.ID("0199d000-0000-7000-8000-000000000003")
	deploymentTestApp    = domain.ID("0199d000-0000-7000-8000-000000000004")
	deploymentTestTarget = domain.ID("0199d000-0000-7000-8000-000000000005")
	deploymentTestNode   = domain.ID("0199d000-0000-7000-8000-000000000006")
)

// runWithDeployments is fakeAPI.run with the deployment commands registered,
// which the root does at merge time.
func runWithDeployments(f *fakeAPI, args ...string) result {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true, Args: noArgs}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("json", false, "")
	root.AddCommand(deploymentCommands(f.Env)...)

	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append(append([]string{}, f.Args...), args...))
	err := root.Execute()
	if err != nil {
		asJSON, _ := root.PersistentFlags().GetBool("json")
		reportError(&errOut, err, asJSON)
	}
	return result{exitCode(err), out.String(), errOut.String()}
}

func deploymentTestApp1() wire.App {
	return wire.App{
		ID: deploymentTestApp, Name: "web", DeployedService: "app",
		Targets: []wire.AppTarget{{
			ID: deploymentTestTarget, Environment: "prod", NodeID: deploymentTestNode, ComposeProject: "sm-web-prod",
			DeploymentPolicy: wire.DeploymentPolicy{Rollback: "automatic"},
		}},
	}
}

func deploymentTestRecord(state string) wire.Deployment {
	return wire.Deployment{
		ID: deploymentTestDeploy, Kind: "deploy", AppID: deploymentTestApp, AppTargetID: deploymentTestTarget,
		CommitSHA: deploymentTestCommit, State: state, CreatedAt: deploymentTestAt, UpdatedAt: deploymentTestAt,
		Images: []wire.RequestedImage{{Service: "app", Digest: deploymentTestDigest}},
	}
}

func deploymentTestRoutes(extra map[string]http.HandlerFunc) http.HandlerFunc {
	app := deploymentTestApp1()
	routes := map[string]http.HandlerFunc{
		"GET " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.App]{Items: []wire.App{app}})
		},
		"GET " + wire.Path(wire.PathApp, string(app.ID)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, app) },
	}
	for k, v := range extra {
		routes[k] = v
	}
	return router(routes)
}

func sentDeploymentRequest(t *testing.T, f *fakeAPI) wire.CreateDeploymentRequest {
	t.Helper()
	muts := f.Mutations()
	if len(muts) != 1 {
		t.Fatalf("mutations = %+v", muts)
	}
	var req wire.CreateDeploymentRequest
	if err := json.Unmarshal([]byte(muts[0].Body), &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestDeployPrintsThePlanPreviewForTheNamedTarget(t *testing.T) {
	created := deploymentTestRecord("waiting_ci")
	f := newFakeAPI(t, deploymentTestRoutes(map[string]http.HandlerFunc{
		"POST " + wire.PathDeployments: func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, created) },
	}))

	r := runWithDeployments(f, "deploy", "web", "prod", "--commit", deploymentTestCommit, "--image", "app="+deploymentTestDigest)

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	assertGolden(t, "deploy_plan_preview.golden", r.stdout)
	req := sentDeploymentRequest(t, f)
	if req.AppTargetID != deploymentTestTarget || req.Kind != "deploy" || req.CommitSHA != deploymentTestCommit ||
		len(req.Images) != 1 || req.Images[0].Service != "app" || req.Images[0].Digest != deploymentTestDigest {
		t.Errorf("request = %+v", req)
	}
}

func TestDeployPreviewOffersApprovalOnceThePlanIsFrozen(t *testing.T) {
	frozen := deploymentTestRecord("awaiting_approval")
	frozen.PlanHash, frozen.JobID = &deploymentTestPlan, &deploymentTestJob
	f := newFakeAPI(t, deploymentTestRoutes(map[string]http.HandlerFunc{
		"POST " + wire.PathDeployments: func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, frozen) },
	}))

	r := runWithDeployments(f, "deploy", "web", "prod", "--commit", deploymentTestCommit, "--image", "app="+deploymentTestDigest)

	want := "sm jobs approve " + string(deploymentTestJob) + " --plan-hash " + deploymentTestPlan
	if r.code != 0 || !strings.Contains(r.stdout, want) {
		t.Errorf("code=%d, output lacks %q:\n%s", r.code, want, r.stdout)
	}
}

func TestDeployRejectsBadInputBeforeAnyRequest(t *testing.T) {
	f := newFakeAPI(t, deploymentTestRoutes(nil))
	image := "app=" + deploymentTestDigest
	tests := map[string][]string{
		"no commit":       {"deploy", "web", "prod", "--image", image},
		"no image":        {"deploy", "web", "prod", "--commit", deploymentTestCommit},
		"malformed image": {"deploy", "web", "prod", "--commit", deploymentTestCommit, "--image", "app"},
		"empty digest":    {"deploy", "web", "prod", "--commit", deploymentTestCommit, "--image", "app="},
	}
	for name, args := range tests {
		if r := runWithDeployments(f, args...); r.code != exitUsage {
			t.Errorf("%s: exit %d, stderr %q", name, r.code, r.stderr)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

func TestDeployRefusesAnEnvironmentTheAppDoesNotTarget(t *testing.T) {
	f := newFakeAPI(t, deploymentTestRoutes(nil))

	r := runWithDeployments(f, "deploy", "web", "staging", "--commit", deploymentTestCommit, "--image", "app="+deploymentTestDigest)

	if r.code == 0 || !strings.Contains(r.stderr, `no target in environment "staging"`) {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	if len(f.Mutations()) != 0 {
		t.Errorf("mutations = %+v", f.Mutations())
	}
}

func TestDeployErrorsCarryCodeAndReason(t *testing.T) {
	f := newFakeAPI(t, deploymentTestRoutes(map[string]http.HandlerFunc{
		"POST " + wire.PathDeployments: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 422, smerr.CodeInvalidArgument, smerr.ReasonDigestUnbound, "digest is not bound to the commit")
		},
	}))

	r := runWithDeployments(f, "--json", "deploy", "web", "prod", "--commit", deploymentTestCommit, "--image", "app="+deploymentTestDigest)

	var got jsonError
	if err := json.Unmarshal([]byte(r.stderr), &got); err != nil {
		t.Fatalf("stderr %q: %v", r.stderr, err)
	}
	if r.code != exitUsage || got.Error.Reason != string(smerr.ReasonDigestUnbound) {
		t.Errorf("code=%d error=%+v", r.code, got.Error)
	}
}

// settlingAPI answers POST /deployments with a queued deployment and then
// GET /deployments/{id} with the given states in order, repeating the last.
func settlingAPI(t *testing.T, final wire.Deployment, intermediate ...string) *fakeAPI {
	t.Helper()
	var polls atomic.Int32
	queued := deploymentTestRecord("queued")
	return newFakeAPI(t, deploymentTestRoutes(map[string]http.HandlerFunc{
		"POST " + wire.PathDeployments: func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, queued) },
		"GET " + wire.Path(wire.PathDeployment, string(queued.ID)): func(w http.ResponseWriter, _ *http.Request) {
			n := int(polls.Add(1)) - 1
			if n < len(intermediate) {
				reply(w, 200, deploymentTestRecord(intermediate[n]))
				return
			}
			reply(w, 200, final)
		},
	}))
}

func TestDeployWaitExitsZeroOnceTheDeploymentSucceeds(t *testing.T) {
	done := deploymentTestRecord("succeeded")
	done.KnownGood = true
	f := settlingAPI(t, done, "preparing", "deploying")

	r := runWithDeployments(f, "deploy", "web", "prod", "--commit", deploymentTestCommit,
		"--image", "app="+deploymentTestDigest, "--wait", "--interval", deploymentTestPolling)

	if r.code != 0 || !strings.Contains(r.stdout, "succeeded") {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
}

func TestDeployWaitFailsWithTheStateReasonWhenTheDeploymentDoesNotSucceed(t *testing.T) {
	tests := []struct {
		state  string
		code   smerr.Code
		reason smerr.Reason
	}{
		{"failed", smerr.CodeDeploymentFailed, smerr.ReasonHealthFailed},
		{"rolled_back", smerr.CodeDeploymentFailed, smerr.ReasonHealthFailed},
		{"rollback_failed", smerr.CodeRollbackFailed, smerr.ReasonRollbackUnavailable},
		{"cancelled", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			ended := deploymentTestRecord(tt.state)
			ended.StateCode, ended.StateReason = tt.code, tt.reason
			f := settlingAPI(t, ended, "deploying")

			r := runWithDeployments(f, "--json", "deploy", "web", "prod", "--commit", deploymentTestCommit,
				"--image", "app="+deploymentTestDigest, "--wait", "--interval", deploymentTestPolling)

			var got jsonError
			if err := json.Unmarshal([]byte(r.stderr), &got); err != nil {
				t.Fatalf("stderr %q: %v", r.stderr, err)
			}
			if r.code == 0 || !strings.Contains(got.Error.Message, tt.state) || got.Error.Reason != string(tt.reason) {
				t.Errorf("code=%d error=%+v", r.code, got.Error)
			}
		})
	}
}

func TestRollbackTargetsTheNewestDeploymentOfTheEnvironment(t *testing.T) {
	newest := deploymentTestRecord("failed")
	rollback := deploymentTestRecord("queued")
	rollback.Kind, rollback.RollbackOfDeploymentID = "rollback", &newest.ID
	f := newFakeAPI(t, deploymentTestRoutes(map[string]http.HandlerFunc{
		"GET " + wire.PathDeployments: func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("app_target_id"); got != string(deploymentTestTarget) {
				t.Errorf("app_target_id = %q", got)
			}
			reply(w, 200, wire.Page[wire.Deployment]{Items: []wire.Deployment{newest}})
		},
		"POST " + wire.Path(wire.PathDeploymentRollback, string(newest.ID)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, rollback)
		},
	}))

	r := runWithDeployments(f, "rollback", "web", "prod", "--to", string(deploymentTestKnown))

	if r.code != 0 || !strings.Contains(r.stdout, "rollback") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	muts := f.Mutations()
	if len(muts) != 1 || !strings.Contains(muts[0].Body, string(deploymentTestKnown)) {
		t.Errorf("mutations = %+v", muts)
	}
}

func TestRollbackWithoutAnyDeploymentIsRefusedBeforeAnyMutation(t *testing.T) {
	f := newFakeAPI(t, deploymentTestRoutes(map[string]http.HandlerFunc{
		"GET " + wire.PathDeployments: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Deployment]{})
		},
	}))

	r := runWithDeployments(f, "rollback", "web", "prod")

	if r.code == 0 || !strings.Contains(r.stderr, "no deployment to roll back") || len(f.Mutations()) != 0 {
		t.Errorf("code=%d stderr=%q mutations=%+v", r.code, r.stderr, f.Mutations())
	}
}

func timelineFixture() wire.Deployment {
	started := deploymentTestAt.Add(time.Second)
	finished := deploymentTestAt.Add(5 * time.Second)
	d := deploymentTestRecord("failed")
	d.PlanHash, d.JobID = &deploymentTestPlan, &deploymentTestJob
	d.StateCode, d.StateReason = smerr.CodeDeploymentFailed, smerr.ReasonHealthFailed
	d.FinishedAt = &finished
	d.Steps = []wire.DeploymentStep{
		{Ordinal: 1, Name: "preflight", State: "succeeded", Attempt: 1, StartedAt: &started, FinishedAt: &finished},
		{
			Ordinal: 2, Name: "health", State: "failed", Attempt: 1, StartedAt: &started, FinishedAt: &finished,
			Error: &wire.StepError{Code: smerr.CodeDeploymentFailed, Reason: smerr.ReasonHealthFailed, Cause: "HTTP_503"},
		},
	}
	return d
}

func TestDeploymentsGetShowsTheStepTimeline(t *testing.T) {
	d := timelineFixture()
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathDeployment, string(d.ID)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, d) },
	}))

	r := runWithDeployments(f, "deployments", "get", string(d.ID))

	if r.code != 0 {
		t.Fatalf("code=%d stderr=%q", r.code, r.stderr)
	}
	assertGolden(t, "deployments_timeline.golden", r.stdout)
}

func TestDeploymentsGetFollowStreamsUntilSettledAndFailsWhenItDidNotSucceed(t *testing.T) {
	final := timelineFixture()
	var polls atomic.Int32
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathDeployment, string(final.ID)): func(w http.ResponseWriter, _ *http.Request) {
			if polls.Add(1) == 1 {
				reply(w, 200, deploymentTestRecord("deploying"))
				return
			}
			reply(w, 200, final)
		},
	}))

	r := runWithDeployments(f, "deployments", "get", string(final.ID), "--follow", "--interval", deploymentTestPolling)

	if r.code == 0 || !strings.Contains(r.stderr, "health_failed") && !strings.Contains(r.stderr, "HEALTH_FAILED") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "state:") || strings.Count(r.stdout, "id:") != 2 {
		t.Errorf("expected the first view and the settled one:\n%s", r.stdout)
	}
}

func TestDeploymentsListFiltersByAppAndState(t *testing.T) {
	d := deploymentTestRecord("succeeded")
	d.KnownGood = true
	f := newFakeAPI(t, deploymentTestRoutes(map[string]http.HandlerFunc{
		"GET " + wire.PathDeployments: func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("app_id") != string(deploymentTestApp) || q.Get(wire.QueryState) != "succeeded" {
				t.Errorf("query = %v", q)
			}
			reply(w, 200, wire.Page[wire.Deployment]{Items: []wire.Deployment{d}})
		},
	}))

	r := runWithDeployments(f, "deployments", "list", "--app", "web", "--state", "succeeded")

	for _, want := range []string{string(d.ID), "succeeded", "0123456789ab", "yes"} {
		if r.code != 0 || !strings.Contains(r.stdout, want) {
			t.Errorf("code=%d output lacks %q:\n%s", r.code, want, r.stdout)
		}
	}
}

func TestDeploymentsCancelPostsAndReportsTheState(t *testing.T) {
	cancelled := deploymentTestRecord("cancelled")
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"POST " + wire.Path(wire.PathDeploymentCancel, string(cancelled.ID)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, cancelled)
		},
	}))

	r := runWithDeployments(f, "deployments", "cancel", string(cancelled.ID))

	if r.code != 0 || !strings.Contains(r.stdout, "is now cancelled") {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
}

func TestDeploymentCommandsAreRegisteredOnTheRoot(t *testing.T) {
	r := run("deployments")

	for _, want := range []string{"list", "get", "cancel"} {
		if r.code != 0 || !strings.Contains(r.stdout, want) {
			t.Errorf("code=%d, help lacks %q:\n%s", r.code, want, r.stdout)
		}
	}
}
