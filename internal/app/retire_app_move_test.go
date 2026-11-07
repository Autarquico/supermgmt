package app

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/policy"
)

func TestTokenRotationAndExposeBuildOnANodeWithRoutesWithNoAppMoveGuard(t *testing.T) {
	rs := newRouteSetting(t)
	rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)
	ctx, by := context.Background(), rs.caller(rs.admin)

	if _, err := rs.plans.Create(ctx, by, PlanRequest{Action: policy.ActionCloudflareRotate, Target: rs.instanceRef()}); err != nil {
		t.Errorf("token rotation plan: %v", err)
	}
	if _, err := rs.expose(ExposeRouteRequest{Hostname: "api." + shop, Port: 8081}); err != nil {
		t.Errorf("expose plan: %v", err)
	}
}

func TestTunnelDisableOnANodeWithRoutesIsRefusedForTheRoutesAndNotForAnAppMove(t *testing.T) {
	rs := newRouteSetting(t)
	rs.addRoute(shop, 8080, "public", database.NodeRouteProvisioning)

	_, err := rs.plans.Create(context.Background(), rs.caller(rs.admin), PlanRequest{Action: policy.ActionNodeTunnelDisable, Target: rs.nodeRef()})
	if err == nil || !strings.Contains(err.Error(), "remove them with `sm nodes unexpose`") || strings.Contains(err.Error(), "app move") {
		t.Errorf("disable plan error = %v, want the app routes refusal only", err)
	}
}
