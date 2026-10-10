package app

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

func TestEveryJobModeActionOnNodesAndServicesHasALockPlan(t *testing.T) {
	for _, spec := range policy.Catalog() {
		if spec.Mode != policy.ModeJob {
			continue
		}
		if spec.Resource != domain.ResourceNode && spec.Resource != domain.ResourceService {
			continue // deployments and backups arrive with their milestones
		}
		if _, ok := lockModeByJobType[spec.Name]; !ok {
			t.Errorf("job action %s targets a %s but has no lock mode", spec.Name, spec.Resource)
		}
	}
}

func TestPlanLocksFollowSpecSection20_5(t *testing.T) {
	f := newFixture(t)
	node := domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID}
	service := domain.ResourceRef{Type: domain.ResourceService, ID: f.service.ID}
	tests := []struct {
		action string
		target domain.ResourceRef
		params map[string]any
		want   []domain.LockSpec
	}{
		{"node.reboot", node, nil, []domain.LockSpec{
			{Key: "node:" + f.node.ID.String(), Mode: domain.LockExclusive},
			{Key: "environment:" + f.env.ID.String(), Mode: domain.LockShared},
		}},
		{"node.probe", node, nil, []domain.LockSpec{
			{Key: "node:" + f.node.ID.String(), Mode: domain.LockShared},
			{Key: "environment:" + f.env.ID.String(), Mode: domain.LockShared},
		}},
		{"service.restart", service, nil, []domain.LockSpec{
			{Key: "service:" + f.service.ID.String(), Mode: domain.LockExclusive},
			{Key: "node:" + f.node.ID.String(), Mode: domain.LockShared},
			{Key: "environment:" + f.env.ID.String(), Mode: domain.LockShared},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			created, err := f.plans.Create(context.Background(), f.caller(f.alice), PlanRequest{
				Action: tt.action, Target: tt.target, Parameters: tt.params,
			})
			if err != nil {
				t.Fatal(err)
			}
			job := jobs.Job{Type: tt.action, Resource: tt.target, PlanID: &created.Record.ID}

			got, err := LockPlanner{}.PlanLocks(context.Background(), f.db.Reader(), job)
			if err != nil {
				t.Fatalf("PlanLocks: %v", err)
			}
			provider := domain.LockSpec{Key: "provider:" + f.provider.ID.String(), Mode: domain.LockShared}
			want := append([]domain.LockSpec{provider}, tt.want...)
			byKey := func(a, b domain.LockSpec) int { return strings.Compare(a.Key, b.Key) }
			slices.SortFunc(got, byKey)
			slices.SortFunc(want, byKey)
			if !slices.Equal(got, want) {
				t.Errorf("locks = %v, want %v", got, want)
			}
		})
	}
}

func TestPlanLocksOfAnUnknownJobTypeIsATypedError(t *testing.T) {
	_, err := LockPlanner{}.PlanLocks(context.Background(), nil, jobs.Job{Type: "deployment.create"})

	wantError(t, err, smerr.CodeInvalidArgument, smerr.ReasonUnknownAction)
}

func TestTwoRebootsOfTheSameNodeDoNotRunTogether(t *testing.T) {
	f := newFixture(t)
	first := approvedReboot(f)
	second := approvedReboot(f)

	claimed, ok := f.claim()
	if !ok || claimed.Job.ID != first {
		t.Fatalf("first claim = %v %v, want job %s", claimed.Job.ID, ok, first)
	}
	if _, ok := f.claim(); ok {
		t.Fatal("second reboot of the same node was claimed while the first holds it exclusively")
	}
	if got := f.job(second).State; got != domain.JobQueued {
		t.Errorf("blocked job state = %s, want it to stay queued", got)
	}
}
