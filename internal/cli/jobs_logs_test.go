package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const loggedJob = domain.ID("0192a000-0000-7000-8000-00000000a001")

func TestJobsLogsReadsEveryPageOfTheJobsEvents(t *testing.T) {
	at := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathEvents: func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("resource_type") != "job" || q.Get("resource_id") != string(loggedJob) {
				t.Errorf("query = %s; want the job's events", r.URL.RawQuery)
			}
			if q.Get("cursor") == "" {
				reply(w, 200, wire.Page[wire.Event]{NextCursor: "next", Items: []wire.Event{
					{Seq: 1, Timestamp: at, Action: "job.created", Result: domain.ResultSucceeded, Actor: wire.Actor{Type: "human"}},
				}})
				return
			}
			reply(w, 200, wire.Page[wire.Event]{Items: []wire.Event{
				{Seq: 2, Timestamp: at, Action: "job.failed", Result: domain.ResultFailed, Data: map[string]any{"code": "UNAVAILABLE"}},
			}})
		},
	}))

	r := f.run("jobs", "logs", string(loggedJob))

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"job.created", "job.failed", "failed", `{"code":"UNAVAILABLE"}`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestJobsGetNamesWhatThePlanActsOn(t *testing.T) {
	planID := domain.ID("0192a000-0000-7000-8000-00000000b001")
	plan, _ := json.Marshal(map[string]any{
		"action": "secret.write", "parameters": map[string]any{"operation": "import_secret", "name": "db-password"},
	})
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathJob, string(loggedJob)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.JobDetail{Job: wire.Job{ID: loggedJob, Type: "control_plane.apply", PlanID: &planID}})
		},
		"GET " + wire.Path(wire.PathPlan, string(planID)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.CreatedPlan{PlanID: planID, Plan: plan})
		},
	}))

	r := f.run("jobs", "get", string(loggedJob))

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"secret.write", `"name":"db-password"`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestJobsGetStillShowsTheJobWhenItsPlanCannotBeRead(t *testing.T) {
	planID := domain.ID("0192a000-0000-7000-8000-00000000b002")
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.Path(wire.PathJob, string(loggedJob)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.JobDetail{Job: wire.Job{ID: loggedJob, Type: "control_plane.apply", PlanID: &planID}})
		},
	}))

	r := f.run("jobs", "get", string(loggedJob))

	if r.code != 0 || !strings.Contains(r.stdout, "unreadable: NOT_FOUND") {
		t.Errorf("exit %d stdout %q: want the job and why its plan is missing", r.code, r.stdout)
	}
}
