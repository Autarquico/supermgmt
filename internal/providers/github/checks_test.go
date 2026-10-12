package github

import (
	"context"
	"errors"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

const (
	checksRepoID   = 4242
	checksOwnerID  = 77
	checksWorkflow = ".github/workflows/ci.yml"
	checksOtherApp = 99999
)

var checksCompletedAt = time.Date(2026, 10, 12, 10, 5, 0, 0, time.UTC)

type checksEnv struct {
	fake   *ghfake.Fake
	checks *ghfake.Checks
	client Client
	repo   Repo
}

func newChecksEnv(t *testing.T) checksEnv {
	t.Helper()
	f, c := newEnv(t)
	f.AddRepo(ghfake.Repo{ID: checksRepoID, OwnerID: checksOwnerID, Owner: "acme", Name: "shop"})
	return checksEnv{fake: f, checks: f.ServeChecks(), client: c, repo: Repo{ID: checksRepoID, Owner: "acme", Name: "shop"}}
}

// addActionsRun records a completed GitHub Actions check run in its own suite
// together with a workflow run that satisfies checksPolicy unless altered.
func (e checksEnv) addActionsRun(id int64, conclusion string, alter func(*ghfake.WorkflowRun)) {
	e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{
		ID: id, Name: "test", AppID: ActionsAppID, Status: "completed", Conclusion: conclusion,
		SuiteID: id * 10, CompletedAt: checksCompletedAt,
	})
	wf := ghfake.WorkflowRun{
		ID: id * 100, RunAttempt: 1, Path: checksWorkflow, HeadBranch: "main", HeadSHA: commitA,
		Event: "push", Status: "completed", Conclusion: conclusion,
	}
	if alter != nil {
		alter(&wf)
	}
	e.checks.AddWorkflowRun(checksRepoID, id*10, wf)
}

func checksPolicy() CIPolicy {
	return CIPolicy{
		RepositoryID: checksRepoID, OwnerID: checksOwnerID, Branch: "main",
		AllowedEvents:  []string{"push"},
		RequiredChecks: []RequiredCheck{{Name: "test", AppID: ActionsAppID, WorkflowPath: checksWorkflow}},
	}
}

func TestVerifyChecks_Verdicts(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(e checksEnv)
		policy     func(p *CIPolicy)
		wantStatus string
		wantReason string
	}{
		{
			name:       "passed",
			setup:      func(e checksEnv) { e.addActionsRun(1, "success", nil) },
			wantStatus: VerdictPassed,
		},
		{
			name:       "no check run at all",
			setup:      func(checksEnv) {},
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name: "wrong app id",
			setup: func(e checksEnv) {
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 1, Name: "test", AppID: checksOtherApp, Status: "completed", Conclusion: "success", SuiteID: 10})
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name:       "wrong check name",
			setup:      func(e checksEnv) { e.addActionsRun(1, "success", nil) },
			policy:     func(p *CIPolicy) { p.RequiredChecks[0].Name = "lint" },
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name:       "failure conclusion",
			setup:      func(e checksEnv) { e.addActionsRun(1, "failure", nil) },
			wantStatus: VerdictFailed, wantReason: "CHECK_FAILED",
		},
		{
			name:       "neutral is not success",
			setup:      func(e checksEnv) { e.addActionsRun(1, "neutral", nil) },
			wantStatus: VerdictFailed, wantReason: "CHECK_FAILED",
		},
		{
			name: "still running",
			setup: func(e checksEnv) {
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 1, Name: "test", AppID: ActionsAppID, Status: "in_progress", SuiteID: 10})
				e.checks.AddWorkflowRun(checksRepoID, 10, ghfake.WorkflowRun{ID: 100, RunAttempt: 1, Path: checksWorkflow, HeadBranch: "main", HeadSHA: commitA, Event: "push", Status: "in_progress"})
			},
			wantStatus: VerdictPending,
		},
		{
			name: "older attempt succeeded, newer failed",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "success", nil)
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 2, Name: "test", AppID: ActionsAppID, Status: "completed", Conclusion: "failure", SuiteID: 10})
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_FAILED",
		},
		{
			name: "older attempt failed, newer succeeded",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "failure", nil)
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 2, Name: "test", AppID: ActionsAppID, Status: "completed", Conclusion: "success", SuiteID: 10, CompletedAt: checksCompletedAt})
			},
			wantStatus: VerdictPassed,
		},
		{
			name: "pull_request event",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "success", func(w *ghfake.WorkflowRun) { w.Event = "pull_request" })
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name: "wrong branch",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "success", func(w *ghfake.WorkflowRun) { w.HeadBranch = "feature" })
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name: "wrong workflow path",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "success", func(w *ghfake.WorkflowRun) { w.Path = ".github/workflows/other.yml" })
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name: "wrong workflow commit",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "success", func(w *ghfake.WorkflowRun) { w.HeadSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" })
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name: "actions check without a workflow run",
			setup: func(e checksEnv) {
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 1, Name: "test", AppID: ActionsAppID, Status: "completed", Conclusion: "success", SuiteID: 10})
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_MISSING",
		},
		{
			name: "failing pull_request run does not veto a good push run",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "success", nil)
				e.addActionsRun(2, "failure", func(w *ghfake.WorkflowRun) { w.Event = "pull_request" })
			},
			wantStatus: VerdictPassed,
		},
		{
			name: "passing pull_request run does not vouch for a failed push run",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "failure", nil)
				e.addActionsRun(2, "success", func(w *ghfake.WorkflowRun) { w.Event = "pull_request" })
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_FAILED",
		},
		{
			name: "one of two checks failed",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "success", nil)
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 5, Name: "lint", AppID: checksOtherApp, Status: "completed", Conclusion: "failure", SuiteID: 50})
			},
			policy: func(p *CIPolicy) {
				p.RequiredChecks = append(p.RequiredChecks, RequiredCheck{Name: "lint", AppID: checksOtherApp})
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_FAILED",
		},
		{
			name: "failure outranks pending outranks missing",
			setup: func(e checksEnv) {
				e.addActionsRun(1, "failure", nil)
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 5, Name: "lint", AppID: checksOtherApp, Status: "queued", SuiteID: 50})
			},
			policy: func(p *CIPolicy) {
				p.RequiredChecks = append(p.RequiredChecks,
					RequiredCheck{Name: "lint", AppID: checksOtherApp}, RequiredCheck{Name: "absent", AppID: checksOtherApp})
			},
			wantStatus: VerdictFailed, wantReason: "CHECK_FAILED",
		},
		{
			name: "pending outranks missing",
			setup: func(e checksEnv) {
				e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 5, Name: "lint", AppID: checksOtherApp, Status: "queued", SuiteID: 50})
			},
			policy: func(p *CIPolicy) {
				p.RequiredChecks = []RequiredCheck{{Name: "lint", AppID: checksOtherApp}, {Name: "absent", AppID: checksOtherApp}}
			},
			wantStatus: VerdictPending,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newChecksEnv(t)
			tc.setup(e)
			p := checksPolicy()
			if tc.policy != nil {
				tc.policy(&p)
			}
			got, err := VerifyChecks(context.Background(), e.client, e.repo, commitA, p)
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tc.wantStatus || got.Reason != tc.wantReason {
				t.Errorf("report = {%s %q}, want {%s %q}", got.Verdict, got.Reason, tc.wantStatus, tc.wantReason)
			}
			if got.Verdict != VerdictPassed && len(got.Evidence) != 0 {
				t.Errorf("evidence on a non-passing report: %+v", got.Evidence)
			}
			assertNothingRejected(t, e.fake)
		})
	}
}

func TestVerifyChecks_EvidencePerPassedCheck(t *testing.T) {
	e := newChecksEnv(t)
	e.addActionsRun(3, "success", func(w *ghfake.WorkflowRun) { w.RunAttempt = 2 })
	e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{
		ID: 8, Name: "lint", AppID: checksOtherApp, Status: "completed", Conclusion: "success", SuiteID: 80, CompletedAt: checksCompletedAt,
	})
	p := checksPolicy()
	p.RequiredChecks = append(p.RequiredChecks, RequiredCheck{Name: "lint", AppID: checksOtherApp})
	got, err := VerifyChecks(context.Background(), e.client, e.repo, commitA, p)
	if err != nil {
		t.Fatal(err)
	}
	want := []CheckEvidence{
		{CheckName: "test", AppID: ActionsAppID, WorkflowPath: checksWorkflow, RunID: 300, RunAttempt: 2, Conclusion: "success", CompletedAt: checksCompletedAt},
		{CheckName: "lint", AppID: checksOtherApp, RunID: 8, Conclusion: "success", CompletedAt: checksCompletedAt},
	}
	if got.Verdict != VerdictPassed || len(got.Evidence) != len(want) {
		t.Fatalf("report = %+v", got)
	}
	for i := range want {
		if got.Evidence[i] != want[i] {
			t.Errorf("evidence[%d] = %+v, want %+v", i, got.Evidence[i], want[i])
		}
	}
}

func TestVerifyChecks_IgnoresRunsOfAnotherCommit(t *testing.T) {
	e := newChecksEnv(t)
	e.checks.AddCheckRun(checksRepoID, commitA, ghfake.CheckRun{ID: 1, Name: "test", AppID: checksOtherApp, Status: "completed", Conclusion: "success", SuiteID: 10})
	p := checksPolicy()
	p.RequiredChecks = []RequiredCheck{{Name: "test", AppID: checksOtherApp}}
	got, err := VerifyChecks(context.Background(), staleHeadClient{e.client}, e.repo, commitA, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictFailed || got.Reason != "CHECK_MISSING" {
		t.Errorf("report = %+v, want CHECK_MISSING", got)
	}
}

// staleHeadClient answers check runs that belong to a different commit than
// the one asked for, as a confused or hostile API might.
type staleHeadClient struct{ Client }

func (c staleHeadClient) CheckRuns(ctx context.Context, r Repo, sha string) ([]CheckRun, error) {
	runs, err := c.Client.CheckRuns(ctx, r, sha)
	for i := range runs {
		runs[i].HeadSHA = "cccccccccccccccccccccccccccccccccccccccc"
	}
	return runs, err
}

func TestVerifyChecks_RejectsInvalidPolicy(t *testing.T) {
	tests := []struct {
		name   string
		sha    string
		mutate func(p *CIPolicy)
	}{
		{"short sha", "abc", func(*CIPolicy) {}},
		{"no branch", commitA, func(p *CIPolicy) { p.Branch = "" }},
		{"no required checks", commitA, func(p *CIPolicy) { p.RequiredChecks = nil }},
		{"no allowed events", commitA, func(p *CIPolicy) { p.AllowedEvents = nil }},
		{"pull_request allowed", commitA, func(p *CIPolicy) { p.AllowedEvents = []string{"push", "pull_request"} }},
		{"pull_request_target allowed", commitA, func(p *CIPolicy) { p.AllowedEvents = []string{"pull_request_target"} }},
		{"actions check without workflow path", commitA, func(p *CIPolicy) { p.RequiredChecks[0].WorkflowPath = "" }},
		{"check without app id", commitA, func(p *CIPolicy) { p.RequiredChecks[0].AppID = 0 }},
		{"check without name", commitA, func(p *CIPolicy) { p.RequiredChecks[0].Name = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newChecksEnv(t)
			p := checksPolicy()
			tc.mutate(&p)
			_, err := VerifyChecks(context.Background(), e.client, e.repo, tc.sha, p)
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Errorf("err = %v, want INVALID_ARGUMENT", err)
			}
			if n := len(e.fake.Requests()); n != 0 {
				t.Errorf("an invalid policy must not reach the API (%d requests)", n)
			}
		})
	}
}

func TestVerifyChecks_APIFailureIsAnErrorNotAVerdict(t *testing.T) {
	e := newChecksEnv(t)
	e.addActionsRun(1, "success", nil)
	e.fake.ExhaustRateLimit()
	if _, err := VerifyChecks(context.Background(), e.client, e.repo, commitA, checksPolicy()); err == nil {
		t.Fatal("a rate-limited API must surface as an error")
	}
}

func TestVerifyChecks_WorkflowLookupFailureIsAnError(t *testing.T) {
	e := newChecksEnv(t)
	e.addActionsRun(1, "success", nil)
	boom := errors.New("boom")
	_, err := VerifyChecks(context.Background(), failingWorkflowClient{e.client, boom}, e.repo, commitA, checksPolicy())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the lookup failure", err)
	}
}

type failingWorkflowClient struct {
	Client
	err error
}

func (c failingWorkflowClient) WorkflowRun(context.Context, Repo, int64) (WorkflowRun, error) {
	return WorkflowRun{}, c.err
}
