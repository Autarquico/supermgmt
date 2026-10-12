package ghfake

import (
	"net/http"
	"slices"
	"strconv"
	"time"
)

// CheckRun is a check run on a commit. Re-running a check adds a new
// CheckRun with a higher ID to the same suite.
type CheckRun struct {
	ID          int64
	Name        string
	AppID       int64
	Status      string // queued | in_progress | completed
	Conclusion  string // empty until completed
	SuiteID     int64
	StartedAt   time.Time
	CompletedAt time.Time
}

// WorkflowRun is the GitHub Actions run behind a check suite.
type WorkflowRun struct {
	ID         int64
	RunAttempt int64
	Path       string
	HeadBranch string
	HeadSHA    string
	Event      string
	Status     string
	Conclusion string
}

type checkRunKey struct {
	repoID int64
	commit string
}

type workflowRunKey struct {
	repoID  int64
	suiteID int64
}

// Checks is the check-run and workflow-run side of a Fake.
type Checks struct {
	fake *Fake
	runs map[checkRunKey][]CheckRun
	flow map[workflowRunKey]WorkflowRun
}

// ServeChecks registers the check-run and workflow-run endpoints. Call it
// once per Fake.
func (f *Fake) ServeChecks() *Checks {
	c := &Checks{fake: f, runs: map[checkRunKey][]CheckRun{}, flow: map[workflowRunKey]WorkflowRun{}}
	f.Handle("GET /repos/{owner}/{repo}/commits/{sha}/check-runs", []string{"filter", "per_page", "page"}, c.listCheckRuns)
	f.Handle("GET /repos/{owner}/{repo}/actions/runs", []string{"check_suite_id"}, c.listWorkflowRuns)
	return c
}

// AddCheckRun records a check run on commit of a registered repository.
func (c *Checks) AddCheckRun(repoID int64, commit string, run CheckRun) {
	c.fake.t.Helper()
	if run.ID <= 0 || run.Name == "" || !commitPattern.MatchString(commit) {
		c.fake.t.Fatalf("ghfake: invalid check run %d@%s %+v", repoID, commit, run)
	}
	c.fake.mu.Lock()
	defer c.fake.mu.Unlock()
	key := checkRunKey{repoID, commit}
	c.runs[key] = append(c.runs[key], run)
}

// AddWorkflowRun records the workflow run behind a check suite.
func (c *Checks) AddWorkflowRun(repoID, suiteID int64, run WorkflowRun) {
	c.fake.t.Helper()
	if suiteID <= 0 || run.ID <= 0 {
		c.fake.t.Fatalf("ghfake: invalid workflow run for suite %d: %+v", suiteID, run)
	}
	c.fake.mu.Lock()
	defer c.fake.mu.Unlock()
	c.flow[workflowRunKey{repoID, suiteID}] = run
}

func (c *Checks) listCheckRuns(w http.ResponseWriter, r *http.Request) {
	repo, ok := c.fake.repoByName(r.PathValue("owner"), r.PathValue("repo"))
	commit := r.PathValue("sha")
	if !ok || !commitPattern.MatchString(commit) {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	filter := r.URL.Query().Get("filter")
	if filter != "" && filter != "all" && filter != "latest" {
		WriteError(w, http.StatusUnprocessableEntity, "Validation Failed: filter")
		return
	}
	c.fake.mu.Lock()
	runs := slices.Clone(c.runs[checkRunKey{repo.ID, commit}])
	c.fake.mu.Unlock()
	if filter != "all" {
		runs = latestPerCheck(runs)
	}
	lo, hi, ok := Paginate(w, r, len(runs))
	if !ok {
		return
	}
	docs := make([]map[string]any, 0, hi-lo)
	for _, run := range runs[lo:hi] {
		docs = append(docs, checkRunDocument(run, commit))
	}
	WriteJSON(w, map[string]any{"total_count": len(runs), "check_runs": docs})
}

// latestPerCheck keeps the newest run (highest ID) of each (name, app), as
// GitHub's default filter=latest does.
func latestPerCheck(runs []CheckRun) []CheckRun {
	var latest []CheckRun
	for _, run := range runs {
		i := slices.IndexFunc(latest, func(o CheckRun) bool { return o.Name == run.Name && o.AppID == run.AppID })
		switch {
		case i < 0:
			latest = append(latest, run)
		case run.ID > latest[i].ID:
			latest[i] = run
		}
	}
	return latest
}

func checkRunDocument(run CheckRun, commit string) map[string]any {
	doc := map[string]any{
		"id": run.ID, "name": run.Name, "status": run.Status, "head_sha": commit,
		"conclusion": nil, "completed_at": nil,
		"app":         map[string]any{"id": run.AppID},
		"check_suite": map[string]any{"id": run.SuiteID},
	}
	if run.Conclusion != "" {
		doc["conclusion"] = run.Conclusion
	}
	if !run.StartedAt.IsZero() {
		doc["started_at"] = run.StartedAt.UTC().Format(time.RFC3339)
	}
	if !run.CompletedAt.IsZero() {
		doc["completed_at"] = run.CompletedAt.UTC().Format(time.RFC3339)
	}
	return doc
}

func (c *Checks) listWorkflowRuns(w http.ResponseWriter, r *http.Request) {
	repo, ok := c.fake.repoByName(r.PathValue("owner"), r.PathValue("repo"))
	suiteID, err := strconv.ParseInt(r.URL.Query().Get("check_suite_id"), 10, 64)
	if !ok || err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	c.fake.mu.Lock()
	run, found := c.flow[workflowRunKey{repo.ID, suiteID}]
	c.fake.mu.Unlock()
	docs := []map[string]any{}
	if found {
		docs = append(docs, map[string]any{
			"id": run.ID, "run_attempt": run.RunAttempt, "path": run.Path, "head_branch": run.HeadBranch,
			"head_sha": run.HeadSHA, "event": run.Event, "status": run.Status, "conclusion": run.Conclusion,
		})
	}
	WriteJSON(w, map[string]any{"total_count": len(docs), "workflow_runs": docs})
}
