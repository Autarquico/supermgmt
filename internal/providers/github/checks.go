package github

import (
	"context"
	"errors"
	"fmt"
	"slices"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ActionsAppID is the GitHub App behind GitHub Actions check runs. Checks it
// produced must also name the workflow that ran them (spec §18).
const ActionsAppID int64 = 15368

const (
	reasonCheckFailed  = string(smerr.ReasonCheckFailed)
	reasonCheckMissing = string(smerr.ReasonCheckMissing)
)

type checkOutcome int

const (
	checkPassed checkOutcome = iota
	checkPending
	checkFailed
	checkMissing
)

// VerifyChecks decides whether every required check of p passed on the exact
// commit sha (spec §18). Failure of any check wins over pending, pending over
// missing: a missing check is only reported once nothing else is still
// running or failing. Evidence lists one entry per passed check.
func VerifyChecks(ctx context.Context, c Client, r Repo, sha string, p CIPolicy) (CheckReport, error) {
	if err := validateCIPolicy(sha, p); err != nil {
		return CheckReport{}, err
	}
	runs, err := c.CheckRuns(ctx, r, sha)
	if err != nil {
		return CheckReport{}, fmt.Errorf("github: list check runs: %w", err)
	}
	v := checkVerifier{ctx: ctx, client: c, repo: r, sha: sha, policy: p, workflows: map[int64]workflowLookup{}}
	outcomes := map[checkOutcome]int{}
	var evidence []CheckEvidence
	for _, required := range p.RequiredChecks {
		outcome, ev, err := v.verify(required, runs)
		if err != nil {
			return CheckReport{}, err
		}
		outcomes[outcome]++
		if outcome == checkPassed {
			evidence = append(evidence, ev)
		}
	}
	switch {
	case outcomes[checkFailed] > 0:
		return CheckReport{Verdict: VerdictFailed, Reason: reasonCheckFailed}, nil
	case outcomes[checkPending] > 0:
		return CheckReport{Verdict: VerdictPending}, nil
	case outcomes[checkMissing] > 0:
		return CheckReport{Verdict: VerdictFailed, Reason: reasonCheckMissing}, nil
	}
	return CheckReport{Verdict: VerdictPassed, Evidence: evidence}, nil
}

func validateCIPolicy(sha string, p CIPolicy) error {
	switch {
	case !commitPattern.MatchString(sha):
		return invalidCIPolicy("commit must be a full lowercase sha")
	case p.Branch == "":
		return invalidCIPolicy("branch is required")
	case len(p.RequiredChecks) == 0:
		return invalidCIPolicy("at least one required check is needed")
	case len(p.AllowedEvents) == 0:
		return invalidCIPolicy("allowed_events is required")
	case slices.ContainsFunc(p.AllowedEvents, isPullRequestEvent):
		return invalidCIPolicy("pull_request events are never allowed")
	}
	for _, req := range p.RequiredChecks {
		switch {
		case req.Name == "" || req.AppID <= 0:
			return invalidCIPolicy("every required check needs a name and an app_id")
		case req.AppID == ActionsAppID && req.WorkflowPath == "":
			return invalidCIPolicy("GitHub Actions checks need a workflow_path")
		}
	}
	return nil
}

func isPullRequestEvent(event string) bool {
	return event == "pull_request" || event == "pull_request_target"
}

func invalidCIPolicy(problem string) error {
	return smerr.New(smerr.CodeInvalidArgument, "", "ci policy: "+problem)
}

type workflowLookup struct {
	run   WorkflowRun
	found bool
}

type checkVerifier struct {
	ctx       context.Context
	client    Client
	repo      Repo
	sha       string
	policy    CIPolicy
	workflows map[int64]workflowLookup // by check suite id
}

// verify judges one required check against the commit's check runs. Runs that
// cannot count as that check (other app, name, commit, or an Actions run
// outside the policy) are ignored, so a failing pull-request run of the same
// name cannot veto a good push run, and cannot vouch for a bad one.
func (v *checkVerifier) verify(req RequiredCheck, runs []CheckRun) (checkOutcome, CheckEvidence, error) {
	var (
		latest   CheckRun
		workflow WorkflowRun
		found    bool
	)
	for _, run := range runs {
		if run.Name != req.Name || run.AppID != req.AppID || run.HeadSHA != v.sha {
			continue
		}
		wf, ok, err := v.qualifyingWorkflow(req, run)
		if err != nil {
			return 0, CheckEvidence{}, err
		}
		if ok && (!found || run.ID > latest.ID) {
			latest, workflow, found = run, wf, true
		}
	}
	switch {
	case !found:
		return checkMissing, CheckEvidence{}, nil
	case latest.Status != "completed":
		return checkPending, CheckEvidence{}, nil
	case latest.Conclusion != "success":
		return checkFailed, CheckEvidence{}, nil
	}
	return checkPassed, evidenceOf(req, latest, workflow), nil
}

// qualifyingWorkflow reports whether run may count as req. Non-Actions checks
// always do; Actions checks need a workflow run matching the policy.
func (v *checkVerifier) qualifyingWorkflow(req RequiredCheck, run CheckRun) (WorkflowRun, bool, error) {
	if req.AppID != ActionsAppID {
		return WorkflowRun{}, true, nil
	}
	lookup, err := v.workflowOfSuite(run.SuiteID)
	if err != nil || !lookup.found {
		return WorkflowRun{}, false, err
	}
	wf := lookup.run
	ok := wf.Path == req.WorkflowPath && wf.HeadBranch == v.policy.Branch && wf.HeadSHA == v.sha &&
		slices.Contains(v.policy.AllowedEvents, wf.Event)
	return wf, ok, nil
}

func (v *checkVerifier) workflowOfSuite(suiteID int64) (workflowLookup, error) {
	if cached, ok := v.workflows[suiteID]; ok {
		return cached, nil
	}
	wf, err := v.client.WorkflowRun(v.ctx, v.repo, suiteID)
	lookup := workflowLookup{run: wf, found: err == nil}
	if err != nil && !errors.Is(err, ErrNoWorkflowRun) {
		return workflowLookup{}, fmt.Errorf("github: resolve check suite %d: %w", suiteID, err)
	}
	v.workflows[suiteID] = lookup
	return lookup, nil
}

func evidenceOf(req RequiredCheck, run CheckRun, wf WorkflowRun) CheckEvidence {
	ev := CheckEvidence{
		CheckName: req.Name, AppID: req.AppID, WorkflowPath: req.WorkflowPath,
		RunID: run.ID, Conclusion: run.Conclusion, CompletedAt: run.CompletedAt,
	}
	if req.AppID == ActionsAppID {
		ev.RunID, ev.RunAttempt = wf.ID, wf.RunAttempt
	}
	return ev
}
