package app

import (
	"context"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

func TestATunnelSetupPlanNamesTheCloudflareObjects(t *testing.T) {
	ts := newTunnelSetting(t)
	params := defaultSetup()
	params["tunnel"] = "true"
	create := func(params map[string]any) CreatedPlan {
		created, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{
			Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: ts.node.ID}, Parameters: params,
		})
		mustf(t, err, "Create")
		return created
	}

	got := create(params).Plan.Steps

	instance, err := database.GetInstance(context.Background(), ts.db.Reader())
	mustf(t, err, "GetInstance")
	want := []string{
		"cloudflare tunnel: " + cloudflare.TunnelName(instance.ID.String(), ts.node.ID.String()),
		"cloudflare access application: " + cloudflare.AccessAppName(instance.ID.String(), ts.node.ID.String()),
		"cloudflare dns record: " + ts.hostname(),
	}
	if !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
	if steps := create(defaultSetup()).Plan.Steps; len(steps) != 0 {
		t.Errorf("a setup without the tunnel lists steps: %q", steps)
	}
}

func TestATunnelSetupPlanGoesStaleWhenTheConfiguredZoneChanges(t *testing.T) {
	ts := newTunnelSetting(t)
	params := defaultSetup()
	params["tunnel"] = "true"
	created, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: ts.node.ID}, Parameters: params,
	})
	mustf(t, err, "Create")
	rec, err := database.GetPlan(context.Background(), ts.db.Reader(), created.Record.ID)
	mustf(t, err, "GetPlan")

	_, err = ts.plans.rebuild(context.Background(), ts.db.Reader(), rec)
	mustf(t, err, "rebuild without a change")

	moved := ts.plans.core
	zone := *moved.cfg.Cloudflare
	zone.Zone = "elsewhere.example"
	moved.cfg.Cloudflare = &zone
	_, err = moved.rebuild(context.Background(), ts.db.Reader(), rec)
	wantError(t, err, smerr.CodeConflict, smerr.ReasonPlanStale)
}

func TestATunnelSetupPlanNamesTheHostnameTheJobDerivesNotTheStoredOne(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		n, err := database.GetNode(ctx, tx, ts.node.ID)
		if err != nil {
			return err
		}
		n.Endpoint.TunnelHostname = "stale." + ts.cfg.Zone
		_, err = database.UpdateNodeSpec(ctx, tx, n, n.SpecRevision)
		return err
	})
	params := defaultSetup()
	params["tunnel"] = "true"

	created, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: ts.node.ID}, Parameters: params,
	})
	mustf(t, err, "Create")

	if want := "cloudflare dns record: " + ts.hostname(); !slices.Contains(created.Plan.Steps, want) {
		t.Errorf("steps = %q, want %q", created.Plan.Steps, want)
	}
}
